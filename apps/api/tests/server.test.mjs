import test from 'node:test';import assert from 'node:assert/strict';import {randomBytes} from 'node:crypto';
import {DevTenantStore} from '../src/store.mjs';
import {DevEnvelopeVault} from '../src/vault.mjs';
import {createObserveServer} from '../src/server.mjs';
const key='a'.repeat(35),hmac='b'.repeat(35);
test('per-tenant data boundaries do not cross API-key ownership (development store)',()=>{
 const st=new DevTenantStore();st.provision('tenant-A','proj-A',key);st.provision('tenant-B','proj-B','other-token-long-enough');const a=st.authenticate(key),b=st.authenticate('other-token-long-enough');st.saveClaim(a,{claim_id:'a',target_hash:'h'});assert.equal(b.claims.has('a'),false);assert.equal(a.projectId,'proj-A')
});
test('envelope encryption binds to tenant+project as AAD',()=>{const v=new DevEnvelopeVault(randomBytes(32)),sealed=v.encrypt('secret','tenant-1/project-1');assert.equal(v.decrypt(sealed,'tenant-1/project-1'),'secret');assert.throws(()=>v.decrypt(sealed,'tenant-2/project-1'));assert.throws(()=>v.decrypt({...sealed,ciphertext:'AA=='},'tenant-1/project-1'))});
test('API admits claims, computes evidence, rejects caller assurance and exposes expiring share',async(t)=>{
 const {server}=createObserveServer({tenantId:'one',projectId:'first',apiKey:key,hmacKey:hmac,now:()=>Date.parse('2026-11-20T15:00:00Z')});await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>server.close());const root=`http://127.0.0.1:${server.address().port}`,post=(path,x,auth=key)=>fetch(root+path,{method:'POST',headers:{'x-api-key':auth,'content-type':'application/json'},body:JSON.stringify(x)});
 const claim={claim_id:'claim-1',name:'execute_tool',action:'github.issue.close',target:'org/repo#6',provider:'github',occurred_at:'2026-11-20T12:00:00Z',claimed_success:true};
 let v=await post('/v1/claims',{...claim,assurance:'VERIFIED'});assert.equal(v.status,400);
 v=await post('/v1/claims',claim);assert.equal(v.status,202);const ingestion=await v.json();assert.equal(ingestion.accepted,1);
 v=await post('/v1/reconcile',{claim_id:'claim-1',source:'LOCAL_FIXTURE',observation:{available:true,complete:true,observed_at:'2026-11-20T15:00:00Z',coverage_start:'2026-11-20T11:00:00Z',current_state:'open',events:[]}});assert.equal(v.status,200);const done=await v.json();assert.equal(done.result.assurance,'CONTRADICTED');assert.ok(done.result.findings.includes('PHANTOM_SUCCESS'));assert.ok(!JSON.stringify(done).includes('org/repo#6'));
 const report=await fetch(root+'/v1/evidence/'+done.id,{headers:{'x-api-key':key}});assert.equal(report.status,200);
 const bad=await fetch(root+'/v1/evidence/'+done.id,{headers:{'x-api-key':'not-allowed'}});assert.equal(bad.status,401);
 const share=await (await post('/v1/evidence/'+done.id+'/share',{ttl_seconds:60})).json();let shared=await fetch(root+'/v1/shares/'+share.token);assert.equal(shared.status,200);assert.ok((await shared.text()).includes('Observe-level'));
 const mon=await (await post('/v1/monitors',{provider:'github',interval_seconds:60})).json();assert.equal(mon.enabled,false);
 const metrics=await (await fetch(root+'/v1/metrics',{headers:{'x-api-key':key}})).json();assert.equal(metrics.ingested,1);assert.equal(metrics.discrepancies,1);
});
test('read-only worker runs periodic reconciliation through injectable observation source',async()=>{
 const {ObserveWorker}=await import('../src/worker.mjs');const {ObserveSigner}=await import('../../../packages/recipes/src/signing.mjs');
 const store=new DevTenantStore(),secret='q'.repeat(40);store.provision('worker-tenant','worker-project',secret);const tenant=store.authenticate(secret);
 store.saveClaim(tenant,{claim_id:'worker-1',provider:'github',target_hash:'abc',occurred_at:'2026-11-20T10:00:00Z',claimed_success:true,expected_state:'closed'});
 const signer=new ObserveSigner();signer.rotate();let called=0;
 const worker=new ObserveWorker({store,signer,now:()=>Date.parse('2026-11-20T12:00:00Z'),readObservation:async()=>{called++;return {available:true,complete:true,coverage_start:'2026-11-20T09:00:00Z',observed_at:'2026-11-20T12:00:00Z',current_state:'open',events:[]}}});
 const m={id:'monitor-1',provider:'github',enabled:true,interval_seconds:60};const r=await worker.tick(tenant,m);assert.equal(r.status,'RECORDED');assert.equal(called,1);assert.equal(tenant.counters.discrepancies,1);
 const r2=await worker.tick(tenant,m);assert.equal(r2.status,'RECORDED');assert.equal(tenant.counters.repeat_reconciliations,1);
 const stop=worker.start(tenant,m);assert.equal(stop(),true);assert.equal(worker.stop(m.id),false);
});
test('worker does not infer success when provider read fails',async()=>{
 const {ObserveWorker}=await import('../src/worker.mjs');const {ObserveSigner}=await import('../../../packages/recipes/src/signing.mjs');
 const store=new DevTenantStore(),secret='r'.repeat(40);store.provision('t','p',secret);const tenant=store.authenticate(secret);store.saveClaim(tenant,{claim_id:'worker-2',provider:'github',target_hash:'abc',occurred_at:'2026-11-20T10:00:00Z',claimed_success:true,expected_state:'closed'});
 const signer=new ObserveSigner();signer.rotate();const worker=new ObserveWorker({store,signer,readObservation:async()=>{throw Error('provider unavailable')}});
 const r=await worker.tick(tenant,{id:'m2',provider:'github',enabled:true});const signed=store.getReport(tenant,r.id).signed;assert.equal(signed[0].payload.result.assurance,'UNOBSERVABLE');assert.deepEqual(signed[0].payload.result.findings,[]);
});
