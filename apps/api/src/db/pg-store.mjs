import {createHash,randomBytes,randomUUID} from 'node:crypto';
import {buildEvidencePack,checkShareTtl} from '../evidence.mjs';

// PostgreSQL tenant store. Every tenant-scoped call runs in ONE transaction with transaction-local
// audital.tenant_id / audital.project_id (set_config(..., true)), so identity can never leak across pooled
// connections. RLS (sql/001, sql/002) is the enforcement boundary; the WHERE clauses below are
// belt-and-braces, not the guarantee. The login role must be a member of observe_app only.
const sha=t=>createHash('sha256').update(t).digest('hex');
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const iso=v=>v instanceof Date?v.toISOString():v;
const ms=v=>v instanceof Date?v.getTime():v===null?null:Date.parse(v);
function rowToClaim(r){
 return {claim_id:r.claim_id,provider:r.provider,action:r.action,target_hash:r.target_hmac,occurred_at:iso(r.occurred_at),args_hmac:r.args_hmac,
  claimed_success:r.claimed_success,expected_state:r.expected_state,actor_hash:r.actor_hmac??undefined,trace_id:r.trace_id,span_id:r.span_id,source:r.source};
}
export class PgTenantStore {
 kind='postgres';
 constructor({pool,vault,now=()=>Date.now()}){
  if(!pool)throw Error('PG_POOL_REQUIRED');if(!vault)throw Error('VAULT_REQUIRED');
  this.pool=pool;this.vault=vault;this.now=now;
 }
 async tx(ctx,fn){
  const c=await this.pool.connect();
  try{
   await c.query('BEGIN');
   if(ctx){
    if(!UUID.test(ctx.tenantId||'')||!UUID.test(ctx.projectId||''))throw Error('TENANT_CONTEXT_INVALID');
    await c.query("SELECT set_config('audital.tenant_id',$1,true), set_config('audital.project_id',$2,true)",[ctx.tenantId,ctx.projectId]);
   }
   const out=await fn(c);await c.query('COMMIT');return out;
  }catch(e){await c.query('ROLLBACK').catch(()=>{});throw e;}
  finally{c.release();}
 }
 #aad(ctx,kind,id){return `audital.observe/v1|${ctx.tenantId}|${ctx.projectId}|${kind}|${id}`;}
 provision(){throw Error('PROVISION_IS_AN_ADMIN_OPERATION');}
 async authenticate(apiKey){
  if(!apiKey)return null;
  const r=await this.tx(null,c=>c.query('SELECT tenant_id,project_id FROM observe.authenticate($1)',[sha(apiKey)]));
  return r.rows[0]?{tenantId:r.rows[0].tenant_id,projectId:r.rows[0].project_id}:null;
 }
 async saveClaim(ctx,claim,lookup=null,{nextCheckAt=null,lookupTtlMs=8*86400000}={}){
  return this.tx(ctx,async c=>{
   const r=await c.query(`INSERT INTO observe.claims(tenant_id,project_id,claim_id,provider,action,target_hmac,args_hmac,actor_hmac,occurred_at,claimed_success,expected_state,trace_id,span_id,source,next_check_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) ON CONFLICT DO NOTHING RETURNING claim_id`,
    [ctx.tenantId,ctx.projectId,claim.claim_id,claim.provider,claim.action,claim.target_hash,claim.args_hmac,claim.actor_hash??null,claim.occurred_at,claim.claimed_success,claim.expected_state??'closed',claim.trace_id??null,claim.span_id??null,claim.source??'audital',nextCheckAt===null?null:new Date(nextCheckAt)]);
   if(!r.rowCount)return {inserted:false};
   if(lookup){
    const sealed=this.vault.encrypt(JSON.stringify({target:lookup.target,provider:lookup.provider}),this.#aad(ctx,'claim',claim.claim_id));
    await c.query('INSERT INTO observe.claim_lookups(tenant_id,project_id,claim_id,sealed,expires_at) VALUES ($1,$2,$3,$4,$5)',[ctx.tenantId,ctx.projectId,claim.claim_id,sealed,new Date(this.now()+lookupTtlMs)]);
   }
   return {inserted:true};
  });
 }
 async getClaim(ctx,id){const r=await this.tx(ctx,c=>c.query('SELECT * FROM observe.claims WHERE tenant_id=$1 AND project_id=$2 AND claim_id=$3',[ctx.tenantId,ctx.projectId,id]));return r.rows[0]?rowToClaim(r.rows[0]):null;}
 async listDueClaims(ctx,provider,nowMs,limit=100){
  const r=await this.tx(ctx,c=>c.query(`SELECT * FROM observe.claims WHERE tenant_id=$1 AND project_id=$2 AND provider=$3 AND status='pending' AND next_check_at<=$4 ORDER BY next_check_at LIMIT $5`,[ctx.tenantId,ctx.projectId,provider,new Date(nowMs),limit]));
  return r.rows.map(x=>({...rowToClaim(x),attempts:x.attempts}));
 }
 async getLookup(ctx,claimId){
  const r=await this.tx(ctx,c=>c.query('SELECT sealed FROM observe.claim_lookups WHERE tenant_id=$1 AND project_id=$2 AND claim_id=$3 AND expires_at>$4',[ctx.tenantId,ctx.projectId,claimId,new Date(this.now())]));
  return r.rows[0]?JSON.parse(this.vault.decrypt(r.rows[0].sealed,this.#aad(ctx,'claim',claimId))):null;
 }
 async updateClaimSchedule(ctx,claimId,{status,nextCheckAt,attempts,lastAssurance}){
  return this.tx(ctx,async c=>{
   const r=await c.query('UPDATE observe.claims SET status=$4,next_check_at=$5,attempts=$6,last_assurance=$7 WHERE tenant_id=$1 AND project_id=$2 AND claim_id=$3',[ctx.tenantId,ctx.projectId,claimId,status,nextCheckAt===null?null:new Date(nextCheckAt),attempts,lastAssurance]);
   if(status==='final')await c.query('DELETE FROM observe.claim_lookups WHERE tenant_id=$1 AND project_id=$2 AND claim_id=$3',[ctx.tenantId,ctx.projectId,claimId]);
   return r.rowCount===1;
  });
 }
 async storeResults(ctx,results,signer){
  const pack=buildEvidencePack({ctx,results,signer,createdAt:new Date(this.now()).toISOString()});
  await this.tx(ctx,async c=>{
   await c.query('INSERT INTO observe.evidence_packs(pack_id,tenant_id,project_id,attestation,kid,pack) VALUES ($1,$2,$3,$4,$5,$6)',[pack.pack_id,ctx.tenantId,ctx.projectId,pack.attestation,pack.kid,pack]);
   for(const r of results)await c.query('INSERT INTO observe.findings(tenant_id,project_id,pack_id,claim_id,assurance,findings,target_hmac,observed_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',[ctx.tenantId,ctx.projectId,pack.pack_id,r.claim_id,r.assurance,r.findings,r.target_hash,r.observed_at]);
  });
  return pack.pack_id;
 }
 async getReport(ctx,id){
  if(!UUID.test(String(id)))return null;
  const r=await this.tx(ctx,c=>c.query('SELECT pack FROM observe.evidence_packs WHERE tenant_id=$1 AND project_id=$2 AND pack_id=$3',[ctx.tenantId,ctx.projectId,id]));
  return r.rows[0]?.pack??null;
 }
 async listFindings(ctx,limit=100){
  const r=await this.tx(ctx,c=>c.query('SELECT pack_id,claim_id,assurance,findings,target_hmac,observed_at FROM observe.findings WHERE tenant_id=$1 AND project_id=$2 ORDER BY created_at DESC LIMIT $3',[ctx.tenantId,ctx.projectId,limit]));
  return r.rows.map(x=>({...x,observed_at:iso(x.observed_at)}));
 }
 async share(ctx,id,ttlSec=3600){
  checkShareTtl(ttlSec);
  const pack=await this.getReport(ctx,id);if(!pack)throw Error('REPORT_NOT_FOUND');
  const token=randomBytes(32).toString('base64url');
  const r=await this.tx(ctx,c=>c.query(`INSERT INTO observe.shares(token_hash,tenant_id,project_id,pack_id,pack,expires_at) VALUES ($1,$2,$3,$4,$5,now()+make_interval(secs=>$6)) RETURNING expires_at`,[sha(token),ctx.tenantId,ctx.projectId,id,pack,ttlSec]));
  return {token,expires_at:iso(r.rows[0].expires_at)};
 }
 async getShare(token){
  if(!token)return null;
  const r=await this.tx(null,c=>c.query('SELECT pack,expires_at FROM observe.resolve_share($1,$2)',[sha(token),new Date(this.now())]));
  return r.rows[0]?{pack:r.rows[0].pack,expires_at:iso(r.rows[0].expires_at)}:null;
 }
 async addMonitor(ctx,{provider,interval_seconds,enabled=true,next_run_at=null}){
  const r=await this.tx(ctx,c=>c.query(`INSERT INTO observe.monitors(tenant_id,project_id,provider,interval_seconds,enabled,next_run_at) VALUES ($1,$2,$3,$4,$5,$6)
   ON CONFLICT (tenant_id,project_id,provider) DO UPDATE SET interval_seconds=EXCLUDED.interval_seconds,enabled=EXCLUDED.enabled RETURNING monitor_id`,[ctx.tenantId,ctx.projectId,provider,interval_seconds,enabled,new Date(next_run_at??this.now())]));
  return r.rows[0].monitor_id;
 }
 #monitor(m){return {id:m.monitor_id,provider:m.provider,interval_seconds:m.interval_seconds,enabled:m.enabled,read_only:m.read_only,next_run_at:ms(m.next_run_at),lease_until:ms(m.lease_until),last_run_at:ms(m.last_run_at),created_at:iso(m.created_at)};}
 async listMonitors(ctx){const r=await this.tx(ctx,c=>c.query('SELECT * FROM observe.monitors WHERE tenant_id=$1 AND project_id=$2 ORDER BY created_at',[ctx.tenantId,ctx.projectId]));return r.rows.map(m=>this.#monitor(m));}
 async getMonitorByProvider(ctx,provider){const r=await this.tx(ctx,c=>c.query('SELECT * FROM observe.monitors WHERE tenant_id=$1 AND project_id=$2 AND provider=$3',[ctx.tenantId,ctx.projectId,provider]));return r.rows[0]?this.#monitor(r.rows[0]):null;}
 async nudgeMonitor(ctx,provider,atMs){const r=await this.tx(ctx,c=>c.query('UPDATE observe.monitors SET next_run_at=LEAST(next_run_at,$4) WHERE tenant_id=$1 AND project_id=$2 AND provider=$3 AND enabled',[ctx.tenantId,ctx.projectId,provider,new Date(atMs)]));return r.rowCount>0;}
 async completeMonitorRun(ctx,monitorId,nextRunAtMs){const r=await this.tx(ctx,c=>c.query('UPDATE observe.monitors SET next_run_at=$4,lease_until=NULL,last_run_at=$5 WHERE tenant_id=$1 AND project_id=$2 AND monitor_id=$3',[ctx.tenantId,ctx.projectId,monitorId,new Date(nextRunAtMs),new Date(this.now())]));return r.rowCount===1;}
 async leaseDueMonitors(nowMs,leaseMs=120000,max=50){
  const r=await this.tx(null,c=>c.query('SELECT * FROM observe.lease_due_monitors($1,$2,$3)',[new Date(nowMs),max,Math.max(10,Math.min(3600,Math.round(leaseMs/1000)))]));
  return r.rows.map(x=>({tenantId:x.tenant_id,projectId:x.project_id,monitor:{id:x.monitor_id,provider:x.provider,interval_seconds:x.interval_seconds,enabled:true}}));
 }
 async addAlertEndpoint(ctx,{kind,url,secret=null}){
  const id=randomUUID();
  const sealed=this.vault.encrypt(JSON.stringify({url,secret}),this.#aad(ctx,'alert-endpoint',id));
  await this.tx(ctx,c=>c.query('INSERT INTO observe.alert_endpoints(endpoint_id,tenant_id,project_id,kind,sealed) VALUES ($1,$2,$3,$4,$5)',[id,ctx.tenantId,ctx.projectId,kind,sealed]));
  return id;
 }
 async listAlertEndpoints(ctx){
  const r=await this.tx(ctx,c=>c.query('SELECT endpoint_id,kind,sealed FROM observe.alert_endpoints WHERE tenant_id=$1 AND project_id=$2 AND enabled',[ctx.tenantId,ctx.projectId]));
  return r.rows.map(x=>({id:x.endpoint_id,kind:x.kind,...JSON.parse(this.vault.decrypt(x.sealed,this.#aad(ctx,'alert-endpoint',x.endpoint_id))),enabled:true}));
 }
 async enqueueAlert(ctx,{endpointId,dedupeKey,packId,payload,nextAttemptAt=this.now()}){
  const r=await this.tx(ctx,c=>c.query('INSERT INTO observe.alert_outbox(tenant_id,project_id,endpoint_id,dedupe_key,pack_id,payload,next_attempt_at) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING RETURNING alert_id',[ctx.tenantId,ctx.projectId,endpointId,dedupeKey,packId,payload,new Date(nextAttemptAt)]));
  return r.rows[0]?.alert_id??null;
 }
 #alert(a){return {id:a.alert_id,endpoint_id:a.endpoint_id,pack_id:a.pack_id,payload:a.payload,status:a.status,attempts:a.attempts,next_attempt_at:ms(a.next_attempt_at),last_error:a.last_error};}
 async listPendingAlerts(ctx,nowMs,limit=50){const r=await this.tx(ctx,c=>c.query(`SELECT * FROM observe.alert_outbox WHERE tenant_id=$1 AND project_id=$2 AND status='pending' AND next_attempt_at<=$3 ORDER BY created_at LIMIT $4`,[ctx.tenantId,ctx.projectId,new Date(nowMs),limit]));return r.rows.map(a=>this.#alert(a));}
 async listAlerts(ctx){const r=await this.tx(ctx,c=>c.query('SELECT * FROM observe.alert_outbox WHERE tenant_id=$1 AND project_id=$2 ORDER BY created_at',[ctx.tenantId,ctx.projectId]));return r.rows.map(a=>this.#alert(a));}
 async markAlert(ctx,id,{status,attempts,nextAttemptAt=null,lastError=null}){
  const r=await this.tx(ctx,c=>c.query(`UPDATE observe.alert_outbox SET status=$4,attempts=$5,next_attempt_at=COALESCE($6,next_attempt_at),last_error=$7,delivered_at=CASE WHEN $4='delivered' THEN now() ELSE delivered_at END WHERE tenant_id=$1 AND project_id=$2 AND alert_id=$3`,
   [ctx.tenantId,ctx.projectId,id,status,attempts,nextAttemptAt===null?null:new Date(nextAttemptAt),lastError?String(lastError).slice(0,200):null]));
  return r.rowCount===1;
 }
 async saveProviderSecret(ctx,provider,secret){
  const sealed=this.vault.encrypt(String(secret),this.#aad(ctx,'provider-secret',provider));
  await this.tx(ctx,async c=>{
   await c.query('DELETE FROM observe.provider_secrets WHERE tenant_id=$1 AND project_id=$2 AND provider=$3',[ctx.tenantId,ctx.projectId,provider]);
   await c.query('INSERT INTO observe.provider_secrets(tenant_id,project_id,provider,sealed) VALUES ($1,$2,$3,$4)',[ctx.tenantId,ctx.projectId,provider,sealed]);
  });
 }
 async getProviderSecret(ctx,provider){
  const r=await this.tx(ctx,c=>c.query('SELECT sealed FROM observe.provider_secrets WHERE tenant_id=$1 AND project_id=$2 AND provider=$3',[ctx.tenantId,ctx.projectId,provider]));
  return r.rows[0]?this.vault.decrypt(r.rows[0].sealed,this.#aad(ctx,'provider-secret',provider)):null;
 }
 async metrics(ctx){
  const r=await this.tx(ctx,c=>c.query(`SELECT
   (SELECT count(*) FROM observe.claims WHERE tenant_id=$1 AND project_id=$2)::int AS ingested,
   (SELECT count(*) FROM observe.evidence_packs WHERE tenant_id=$1 AND project_id=$2)::int AS reconciled,
   (SELECT coalesce(sum(cardinality(findings)),0) FROM observe.findings WHERE tenant_id=$1 AND project_id=$2)::int AS discrepancies,
   (SELECT count(*) FROM observe.monitors WHERE tenant_id=$1 AND project_id=$2 AND enabled)::int AS active_monitors,
   (SELECT count(*) FROM observe.claims WHERE tenant_id=$1 AND project_id=$2 AND status='pending')::int AS pending_claims`,[ctx.tenantId,ctx.projectId]));
  const m=r.rows[0];return {...m,repeat_reconciliations:Math.max(0,m.reconciled-1)};
 }
}
