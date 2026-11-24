// Physical PostgreSQL tenant-isolation suite. Run via `npm run test:pg` (Docker) or with AUDITAL_PG_ADMIN_URL.
import test from 'node:test';import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import {mkdtempSync,cpSync,writeFileSync,readFileSync,rmSync} from 'node:fs';import {tmpdir} from 'node:os';import {join} from 'node:path';import {pathToFileURL} from 'node:url';
import pg from 'pg';
import {migrate,SQL_DIR} from '../../src/db/migrate.mjs';
import {createAppLogin,provisionProject} from '../../src/db/admin.mjs';
import {PgTenantStore} from '../../src/db/pg-store.mjs';
import {DevEnvelopeVault} from '../../src/vault.mjs';
import {createObserveServer} from '../../src/server.mjs';
import {ObserveSigner,verifyEnvelope} from '../../../../packages/recipes/src/signing.mjs';
import {reconcile} from '../../../../packages/recipes/src/reconcile.mjs';
import {parseClaim,deriveProjectKey} from '../../../../packages/otel-parser/src/index.mjs';

const ADMIN=process.env.AUDITAL_PG_ADMIN_URL;
const skip=!ADMIN&&'AUDITAL_PG_ADMIN_URL not set (use npm run test:pg)';
const suffix=randomBytes(4).toString('hex'),dbName=`observe_rls_${suffix}`,appRole=`observe_api_${suffix}`,appPw=randomBytes(18).toString('hex');
const withDb=(u,db,user,pw)=>{const x=new URL(u);x.pathname=`/${db}`;if(user){x.username=user;x.password=pw;}return x.toString();};
const HMAC='m'.repeat(40);const KEY_A='key-a-'+'a'.repeat(30),KEY_B='key-b-'+'b'.repeat(30),KEY_A2='key-a2-'+'c'.repeat(30);
let root,admin,pool,store,A,B,A2,vault,signer;

const claimFor=(ctx,id,target='acme/sandbox#1')=>parseClaim({claim_id:id,action:'github.issue.close',provider:'github',target,occurred_at:'2026-11-20T12:00:00Z',claimed_success:true},deriveProjectKey(HMAC,ctx.tenantId,ctx.projectId));
const fixtureResult=c=>reconcile(c,{available:true,complete:true,coverage_start:'2026-11-20T11:00:00Z',observed_at:'2026-11-20T12:05:00Z',current_state:'open',events:[]},{now:Date.parse('2026-11-20T12:05:00Z')});
async function asApp(ctx,fn){const c=await pool.connect();try{await c.query('BEGIN');if(ctx)await c.query("SELECT set_config('audital.tenant_id',$1,true),set_config('audital.project_id',$2,true)",[ctx.tenantId,ctx.projectId]);return await fn(c);}finally{await c.query('ROLLBACK').catch(()=>{});c.release();}}
const pgErr=async(p,code)=>{await assert.rejects(p,e=>{assert.equal(e.code,code,`${e.code}: ${e.message}`);return true;});};

test.before(async()=>{
 if(skip)return;
 root=new pg.Client({connectionString:ADMIN});await root.connect();
 await root.query(`CREATE DATABASE ${dbName}`);
 admin=new pg.Client({connectionString:withDb(ADMIN,dbName)});await admin.connect();
 const applied=await migrate(admin);assert.deepEqual(applied,['001_rls.sql','002_continuous_engine.sql']);
 await createAppLogin(admin,{name:appRole,password:appPw});
 await admin.query(`GRANT CONNECT ON DATABASE ${dbName} TO ${appRole}`);
 A=await provisionProject(admin,{tenantName:'A',apiKey:KEY_A});
 B=await provisionProject(admin,{tenantName:'B',apiKey:KEY_B});
 A2=await provisionProject(admin,{tenantId:A.tenantId,tenantName:'A',projectName:'second',apiKey:KEY_A2});
 pool=new pg.Pool({connectionString:withDb(ADMIN,dbName,appRole,appPw),max:2});
 vault=new DevEnvelopeVault(randomBytes(32));store=new PgTenantStore({pool,vault});signer=new ObserveSigner();signer.rotate();
});
test.after(async()=>{
 if(skip)return;
 await pool?.end();await admin?.end();
 await root.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);await root.query(`DROP ROLE IF EXISTS ${appRole}`);await root.end();
});

test('migrations are idempotent and checksum-protected',{skip},async()=>{
 assert.deepEqual(await migrate(admin),[]);
 const dir=mkdtempSync(join(tmpdir(),'audital-mig-'));cpSync(new URL(SQL_DIR).pathname,dir,{recursive:true});
 writeFileSync(join(dir,'001_rls.sql'),readFileSync(join(dir,'001_rls.sql'),'utf8')+'\n-- tampered\n');
 await assert.rejects(migrate(admin,{dir:pathToFileURL(dir+'/')}),/MIGRATION_CHECKSUM_MISMATCH 001_rls.sql/);rmSync(dir,{recursive:true});
});
test('app role posture: not superuser, NOBYPASSRLS, owns nothing; every observe table has FORCE RLS',{skip},async()=>{
 const r=(await admin.query('SELECT rolsuper,rolbypassrls,rolcreaterole FROM pg_roles WHERE rolname=$1',[appRole])).rows[0];
 assert.deepEqual(r,{rolsuper:false,rolbypassrls:false,rolcreaterole:false});
 const t=(await admin.query(`SELECT c.relname,c.relrowsecurity,c.relforcerowsecurity,pg_get_userbyid(c.relowner) owner FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='observe' AND c.relkind='r' ORDER BY 1`)).rows;
 assert.deepEqual(t.map(x=>x.relname),['alert_endpoints','alert_outbox','api_keys','claim_lookups','claims','evidence_packs','findings','monitors','projects','provider_secrets','shares','tenants']);
 for(const x of t){assert.equal(x.relrowsecurity,true,x.relname);assert.equal(x.relforcerowsecurity,true,x.relname);assert.equal(x.owner,'observe_owner',x.relname);}
 const own=(await admin.query(`SELECT bool_or(pg_has_role($1,'observe_owner','MEMBER')) m`,[appRole])).rows[0].m;assert.equal(own,false);
});
test('no tenant context => no rows and no writes',{skip},async()=>{
 await store.saveClaim(A,claimFor(A,'ctx-check').publicClaim);
 assert.equal((await asApp(null,c=>c.query('SELECT count(*)::int n FROM observe.claims'))).rows[0].n,0);
 await pgErr(asApp(null,c=>c.query(`INSERT INTO observe.claims(tenant_id,project_id,claim_id,provider,action,target_hmac,args_hmac,occurred_at,claimed_success,expected_state) VALUES ($1,$2,'x','github','a',repeat('a',64),repeat('a',64),now(),true,'closed')`,[A.tenantId,A.projectId])),'42501');
 await pgErr(asApp({tenantId:'not-a-uuid',projectId:A.projectId},c=>c.query('SELECT 1 FROM observe.claims')),'22P02');
});
test('Tenant B cannot read Tenant A claims, findings, evidence packs, monitors, shares, alerts or secrets',{skip},async()=>{
 const {publicClaim,lookup}=claimFor(A,'a-claim-1');
 assert.deepEqual(await store.saveClaim(A,publicClaim,lookup,{nextCheckAt:Date.now()}),{inserted:true});
 const packId=await store.storeResults(A,[fixtureResult(publicClaim)],signer);
 await store.addMonitor(A,{provider:'github',interval_seconds:60});
 const ep=await store.addAlertEndpoint(A,{kind:'webhook',url:'https://hooks.example.com/a',secret:'s'.repeat(32)});
 await store.enqueueAlert(A,{endpointId:ep,dedupeKey:'a'.repeat(40),packId,payload:{x:1}});
 await store.saveProviderSecret(A,'github','github_pat_A_secret_value');
 const share=await store.share(A,packId,600);
 // A sees its own
 assert.ok(await store.getClaim(A,'a-claim-1'));assert.ok(await store.getReport(A,packId));assert.equal((await store.listFindings(A)).length,1);
 assert.equal(await store.getProviderSecret(A,'github'),'github_pat_A_secret_value');assert.equal((await store.getLookup(A,'a-claim-1')).target,'acme/sandbox#1');
 // B sees nothing
 for(const ctx of [B,A2]){
  assert.equal(await store.getClaim(ctx,'a-claim-1'),null);assert.equal(await store.getReport(ctx,packId),null);assert.deepEqual(await store.listFindings(ctx),[]);
  assert.deepEqual(await store.listMonitors(ctx),[]);assert.deepEqual(await store.listAlertEndpoints(ctx),[]);assert.deepEqual(await store.listAlerts(ctx),[]);
  assert.equal(await store.getProviderSecret(ctx,'github'),null);assert.equal(await store.getLookup(ctx,'a-claim-1'),null);
  assert.equal((await store.metrics(ctx)).ingested,0);
  await assert.rejects(store.share(ctx,packId,60),/REPORT_NOT_FOUND/);
 }
 // Raw SQL as B, even WITHOUT a tenant WHERE clause: RLS returns zero rows from every table.
 const counts=await asApp(B,async c=>{const o={};for(const t of ['claims','claim_lookups','evidence_packs','findings','monitors','shares','alert_endpoints','alert_outbox','provider_secrets','projects']){o[t]=(await c.query(`SELECT count(*)::int n FROM observe.${t}`)).rows[0].n;}return o;});
 assert.deepEqual(counts,{claims:0,claim_lookups:0,evidence_packs:0,findings:0,monitors:0,shares:0,alert_endpoints:0,alert_outbox:0,provider_secrets:0,projects:1});
 assert.equal((await asApp(B,c=>c.query('SELECT count(*)::int n FROM observe.tenants'))).rows[0].n,1);
 // share token still works for its bearer, scoped to A's snapshot only
 assert.equal((await store.getShare(share.token)).pack.pack_id,packId);
});
test('Tenant B cannot mutate Tenant A rows (UPDATE/DELETE affect 0 rows; cross-tenant INSERT rejected)',{skip},async()=>{
 const {publicClaim}=claimFor(A,'a-claim-2');await store.saveClaim(A,publicClaim,{target:'acme/sandbox#1',provider:'github'});
 const packId=await store.storeResults(A,[fixtureResult(publicClaim)],signer);
 const r=await asApp(B,async c=>({
  upd:(await c.query(`UPDATE observe.claims SET status='final' WHERE claim_id='a-claim-2'`)).rowCount,
  updAll:(await c.query(`UPDATE observe.claims SET attempts=99`)).rowCount,
  delLookup:(await c.query(`DELETE FROM observe.claim_lookups`)).rowCount,
  delSecret:(await c.query(`DELETE FROM observe.provider_secrets`)).rowCount,
  mon:(await c.query(`UPDATE observe.monitors SET enabled=false`)).rowCount,
  out:(await c.query(`UPDATE observe.alert_outbox SET status='delivered'`)).rowCount}));
 assert.deepEqual(r,{upd:0,updAll:0,delLookup:0,delSecret:0,mon:0,out:0});
 assert.equal((await asApp(A,c=>c.query(`SELECT status FROM observe.claims WHERE claim_id='a-claim-2'`))).rows[0].status,'pending');
 // B writing rows labelled as A: WITH CHECK violation
 await pgErr(asApp(B,c=>c.query(`INSERT INTO observe.claims(tenant_id,project_id,claim_id,provider,action,target_hmac,args_hmac,occurred_at,claimed_success,expected_state) VALUES ($1,$2,'forged','github','a',repeat('a',64),repeat('a',64),now(),true,'closed')`,[A.tenantId,A.projectId])),'42501');
 await pgErr(asApp(B,c=>c.query(`INSERT INTO observe.evidence_packs(pack_id,tenant_id,project_id,attestation,kid,pack) VALUES ($1,$2,$3,'hosted_attested','local:abcdef0123','{}')`,[randomUUID(),A.tenantId,A.projectId])),'42501');
 // B attaching a finding to A's pack: RLS WITH CHECK (tenant mismatch) or FK (own tenant, foreign pack)
 await pgErr(asApp(B,c=>c.query(`INSERT INTO observe.findings(tenant_id,project_id,pack_id,assurance,findings,observed_at) VALUES ($1,$2,$3,'CONTRADICTED','{}',now())`,[B.tenantId,B.projectId,packId])),'23503');
 // B cannot re-home its own row into A (tenant_id is not an updatable column)
 await store.saveClaim(B,claimFor(B,'b-claim').publicClaim);
 await pgErr(asApp(B,c=>c.query(`UPDATE observe.claims SET tenant_id=$1 WHERE claim_id='b-claim'`,[A.tenantId])),'42501');
});
test('evidence packs and findings are append-only, even for their own tenant and the superuser',{skip},async()=>{
 const {publicClaim}=claimFor(A,'a-claim-3');await store.saveClaim(A,publicClaim);
 const packId=await store.storeResults(A,[fixtureResult(publicClaim)],signer);
 await pgErr(asApp(A,c=>c.query(`UPDATE observe.evidence_packs SET pack='{}' WHERE pack_id=$1`,[packId])),'42501');
 await pgErr(asApp(A,c=>c.query(`DELETE FROM observe.evidence_packs WHERE pack_id=$1`,[packId])),'42501');
 await pgErr(asApp(A,c=>c.query(`UPDATE observe.findings SET findings='{}'`)),'42501');
 await assert.rejects(admin.query(`UPDATE observe.evidence_packs SET pack='{}' WHERE pack_id=$1`,[packId]),/APPEND_ONLY/);
 await assert.rejects(admin.query(`DELETE FROM observe.findings`),/APPEND_ONLY/);
 await assert.rejects(admin.query(`TRUNCATE observe.evidence_packs CASCADE`),/APPEND_ONLY/);
});
test('RLS cannot be bypassed by the app role',{skip},async()=>{
 await pgErr(asApp(B,async c=>{await c.query('SET LOCAL row_security = off');return c.query('SELECT * FROM observe.claims');}),'42501');
 await pgErr(asApp(B,c=>c.query('ALTER TABLE observe.claims DISABLE ROW LEVEL SECURITY')),'42501');
 await pgErr(asApp(B,c=>c.query('SET LOCAL ROLE observe_owner')),'42501');
 await pgErr(asApp(B,c=>c.query('SELECT * FROM observe.api_keys')),'42501');
 await pgErr(asApp(B,c=>c.query(`CREATE POLICY evil ON observe.claims USING (true)`)),'42501');
});
test('transaction-local identity never leaks across pooled connections',{skip},async()=>{
 const single=new pg.Pool({connectionString:withDb(ADMIN,dbName,appRole,appPw),max:1});
 try{
  const s=new PgTenantStore({pool:single,vault});await s.getClaim(A,'whatever');
  const r=await single.query(`SELECT coalesce(current_setting('audital.tenant_id',true),'') t, (SELECT count(*)::int FROM observe.claims) n`);
  assert.deepEqual(r.rows[0],{t:'',n:0});
 }finally{await single.end();}
});
test('same claim_id in two tenants does not collide (no cross-tenant existence oracle)',{skip},async()=>{
 assert.deepEqual(await store.saveClaim(A,claimFor(A,'shared-id').publicClaim),{inserted:true});
 assert.deepEqual(await store.saveClaim(B,claimFor(B,'shared-id').publicClaim),{inserted:true});
 assert.deepEqual(await store.saveClaim(B,claimFor(B,'shared-id').publicClaim),{inserted:false});
 assert.notEqual((await store.getClaim(A,'shared-id')).target_hash,(await store.getClaim(B,'shared-id')).target_hash,'per-project HMAC keys');
});
test('shares expire by DB clock; scheduler lease exposes metadata only; B cannot complete A monitor',{skip},async()=>{
 const {publicClaim}=claimFor(A,'a-claim-4');await store.saveClaim(A,publicClaim);
 const packId=await store.storeResults(A,[fixtureResult(publicClaim)],signer);const s=await store.share(A,packId,60);
 assert.ok(await store.getShare(s.token));
 const later=new PgTenantStore({pool,vault,now:()=>Date.now()+120000});assert.equal(await later.getShare(s.token),null);
 assert.equal(await store.getShare('A'.repeat(43)),null);
 await pgErr(asApp(A,c=>c.query(`INSERT INTO observe.shares(token_hash,tenant_id,project_id,pack_id,pack,expires_at) VALUES (repeat('b',64),$1,$2,$3,'{}',now()+interval '30 days')`,[A.tenantId,A.projectId,packId])),'23514');
 const monId=await store.addMonitor(A,{provider:'stripe',interval_seconds:60,next_run_at:Date.now()-1000});
 const leases=await store.leaseDueMonitors(Date.now(),60000);const mine=leases.find(l=>l.monitor.id===monId);
 assert.ok(mine);assert.deepEqual(Object.keys(mine).sort(),['monitor','projectId','tenantId']);assert.deepEqual(Object.keys(mine.monitor).sort(),['enabled','id','interval_seconds','provider']);
 assert.equal((await store.leaseDueMonitors(Date.now(),60000)).some(l=>l.monitor.id===monId),false,'leased monitors are not double-issued');
 assert.equal(await store.completeMonitorRun(B,monId,Date.now()),false);assert.equal(await store.completeMonitorRun(A,monId,Date.now()+60000),true);
});
test('signed evidence survives jsonb key reordering and still verifies',{skip},async()=>{
 const {publicClaim}=claimFor(A,'a-claim-5');await store.saveClaim(A,publicClaim);
 const packId=await store.storeResults(A,[fixtureResult(publicClaim)],signer);const pack=await store.getReport(A,packId);
 assert.equal(verifyEnvelope(pack.results[0],{localKeys:pack.public_keys}).valid,true);
});
test('end-to-end HTTP API on PostgreSQL: ingest -> engine -> evidence; other tenant and sibling project get 404',{skip},async(t)=>{
 let clock=Date.parse('2026-11-20T12:00:00Z');
 const gh=async(url)=>({ok:true,status:200,headers:{get:()=>null},json:async()=>String(url).includes('/events')?[]:{state:'open',created_at:'2026-01-01T00:00:00Z'}});
 const httpStore=new PgTenantStore({pool,vault,now:()=>clock});
 const {server,engine}=createObserveServer({store:httpStore,hmacKey:HMAC,now:()=>clock,githubFetch:gh});
 await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>server.close());const base=`http://127.0.0.1:${server.address().port}`;
 const post=(p,b,k)=>fetch(base+p,{method:'POST',headers:{'x-api-key':k,'content-type':'application/json'},body:JSON.stringify(b)});
 assert.equal((await post('/v1/connectors/github',{token:'github_pat_readonly_0123456789'},KEY_A2)).status,202);
 const ing=await post('/v1/claims',{claim_id:'http-1',action:'github.issue.close',provider:'github',target:'acme/sandbox#77',occurred_at:new Date(clock).toISOString(),claimed_success:true},KEY_A2);
 assert.equal(ing.status,202);
 clock+=61000;const runs=(await engine.runDue()).runs.filter(r=>r.status==='RECORDED');assert.ok(runs.length>=1);
 const id=runs.find(r=>r.results_count>=1).id;
 const mine=await fetch(`${base}/v1/evidence/${id}`,{headers:{'x-api-key':KEY_A2}});assert.equal(mine.status,200);
 const pack=await mine.json();assert.ok(pack.results.some(e=>e.payload.result.claim_id==='http-1'&&e.payload.result.findings.includes('PHANTOM_SUCCESS')));
 assert.equal((await fetch(`${base}/v1/evidence/${id}`,{headers:{'x-api-key':KEY_B}})).status,404);
 assert.equal((await fetch(`${base}/v1/evidence/${id}`,{headers:{'x-api-key':KEY_A}})).status,404,'project isolation inside one tenant');
 assert.equal((await post(`/v1/evidence/${id}/github`,{},KEY_B)).status,404);
 const gp=await (await post(`/v1/evidence/${id}/github`,{},KEY_A2)).json();assert.equal(gp.check_run.conclusion,'failure');
 assert.equal((await fetch(gp.share.url)).status,200);
 assert.equal((await fetch(`${base}/v1/evidence/not-a-uuid`,{headers:{'x-api-key':KEY_A2}})).status,404);
 assert.equal((await fetch(`${base}/v1/metrics`,{headers:{'x-api-key':'nope-nope-nope-nope-nope'}})).status,401);
});
