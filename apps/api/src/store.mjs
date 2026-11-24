import {randomUUID,createHash,randomBytes} from 'node:crypto';
import {buildEvidencePack,checkShareTtl} from './evidence.mjs';
// Local process-only store. NOT approved for public/production hosting. Same async-tolerant interface as
// PgTenantStore (apps/api/src/db/pg-store.mjs); methods may return values or promises, callers always await.
const hash=t=>createHash('sha256').update(t).digest('hex');
export class DevTenantStore {
 #projects=new Map();#keys=new Map();#tokens=new Map();#now;
 kind='dev-memory';
 constructor(now=()=>Date.now()){this.#now=now;}
 #p(ctx){const p=this.#projects.get(`${ctx?.tenantId}\u0000${ctx?.projectId}`);if(!p)throw Error('TENANT_CONTEXT_INVALID');return p;}
 provision(tenantId,projectId,apiKey){
  if(!tenantId||!projectId||!apiKey)throw Error('PROVISION_INVALID');
  const k=`${tenantId}\u0000${projectId}`;
  if(!this.#projects.has(k))this.#projects.set(k,{claims:new Map(),lookups:new Map(),packs:new Map(),findings:[],monitors:new Map(),endpoints:new Map(),outbox:new Map(),secrets:new Map(),counters:{ingested:0,reconciled:0,repeat_reconciliations:0,discrepancies:0}});
  this.#keys.set(hash(apiKey),{tenantId,projectId});return {tenantId,projectId};
 }
 authenticate(apiKey){const c=this.#keys.get(hash(apiKey||''));return c?{...c}:null;}
 saveClaim(ctx,claim,lookup=null,{nextCheckAt=null,lookupTtlMs=8*86400000}={}){
  const p=this.#p(ctx);if(p.claims.size>=10000)throw Error('DEMO_STORAGE_LIMIT');
  if(p.claims.has(claim.claim_id))return {inserted:false};
  p.claims.set(claim.claim_id,{...claim,status:'pending',next_check_at:nextCheckAt,attempts:0,last_assurance:null});p.counters.ingested++;
  if(lookup)p.lookups.set(claim.claim_id,{...lookup,expires_at:this.#now()+lookupTtlMs});
  return {inserted:true};
 }
 getClaim(ctx,id){const c=this.#p(ctx).claims.get(id);return c?publicPart(c):null;}
 listDueClaims(ctx,provider,nowMs,limit=100){
  return [...this.#p(ctx).claims.values()].filter(c=>c.provider===provider&&c.status==='pending'&&c.next_check_at!==null&&c.next_check_at<=nowMs)
   .sort((a,b)=>a.next_check_at-b.next_check_at).slice(0,limit).map(c=>({...publicPart(c),attempts:c.attempts}));
 }
 getLookup(ctx,claimId){const l=this.#p(ctx).lookups.get(claimId);if(!l||l.expires_at<this.#now())return null;return {target:l.target,provider:l.provider};}
 updateClaimSchedule(ctx,claimId,{status,nextCheckAt,attempts,lastAssurance}){
  const p=this.#p(ctx),c=p.claims.get(claimId);if(!c)return false;
  Object.assign(c,{status,next_check_at:nextCheckAt,attempts,last_assurance:lastAssurance});
  if(status==='final')p.lookups.delete(claimId);return true;
 }
 storeResults(ctx,results,signer){
  const p=this.#p(ctx);const pack=buildEvidencePack({ctx,results,signer,createdAt:new Date(this.#now()).toISOString()});
  p.packs.set(pack.pack_id,pack);
  for(const r of results)p.findings.push({pack_id:pack.pack_id,claim_id:r.claim_id,assurance:r.assurance,findings:[...r.findings],target_hmac:r.target_hash,observed_at:r.observed_at});
  p.counters.reconciled++;if(p.counters.reconciled>1)p.counters.repeat_reconciliations++;p.counters.discrepancies+=results.reduce((n,r)=>n+r.findings.length,0);
  return pack.pack_id;
 }
 getReport(ctx,id){return this.#p(ctx).packs.get(id)||null;}
 listFindings(ctx,limit=100){return this.#p(ctx).findings.slice(-limit).reverse();}
 share(ctx,id,ttlSec=3600){
  const pack=this.getReport(ctx,id);if(!pack)throw Error('REPORT_NOT_FOUND');checkShareTtl(ttlSec);
  const token=randomBytes(32).toString('base64url'),expires=this.#now()+ttlSec*1000;
  this.#tokens.set(hash(token),{pack:structuredClone(pack),expires});
  return {token,expires_at:new Date(expires).toISOString()};
 }
 getShare(token){const x=this.#tokens.get(hash(token||''));if(!x||x.expires<=this.#now())return null;return {pack:x.pack,expires_at:new Date(x.expires).toISOString()};}
 addMonitor(ctx,{provider,interval_seconds,enabled=true,next_run_at=null}){
  const p=this.#p(ctx);const existing=[...p.monitors.values()].find(m=>m.provider===provider);
  if(existing){Object.assign(existing,{interval_seconds,enabled});return existing.id;}
  const id=randomUUID();p.monitors.set(id,{id,provider,interval_seconds,enabled,read_only:true,next_run_at:next_run_at??this.#now(),lease_until:null,last_run_at:null,created_at:new Date(this.#now()).toISOString()});return id;
 }
 listMonitors(ctx){return [...this.#p(ctx).monitors.values()].map(m=>({...m}));}
 getMonitorByProvider(ctx,provider){const m=[...this.#p(ctx).monitors.values()].find(m=>m.provider===provider);return m?{...m}:null;}
 nudgeMonitor(ctx,provider,atMs){const m=[...this.#p(ctx).monitors.values()].find(m=>m.provider===provider&&m.enabled);if(m)m.next_run_at=Math.min(m.next_run_at,atMs);return !!m;}
 completeMonitorRun(ctx,monitorId,nextRunAtMs){const m=this.#p(ctx).monitors.get(monitorId);if(!m)return false;Object.assign(m,{next_run_at:nextRunAtMs,lease_until:null,last_run_at:this.#now()});return true;}
 leaseDueMonitors(nowMs,leaseMs=120000,max=50){
  const out=[];
  for(const [k,p] of this.#projects){const [tenantId,projectId]=k.split('\u0000');
   for(const m of p.monitors.values())if(out.length<max&&m.enabled&&m.next_run_at<=nowMs&&(!m.lease_until||m.lease_until<nowMs)){m.lease_until=nowMs+leaseMs;out.push({tenantId,projectId,monitor:{...m}});}}
  return out;
 }
 addAlertEndpoint(ctx,{kind,url,secret=null}){const id=randomUUID();this.#p(ctx).endpoints.set(id,{id,kind,url,secret,enabled:true});return id;}
 listAlertEndpoints(ctx){return [...this.#p(ctx).endpoints.values()].filter(e=>e.enabled).map(e=>({...e}));}
 enqueueAlert(ctx,{endpointId,dedupeKey,packId,payload,nextAttemptAt=this.#now()}){
  const p=this.#p(ctx),k=`${endpointId}:${dedupeKey}`;if([...p.outbox.values()].some(a=>a.key===k))return null;
  const id=randomUUID();p.outbox.set(id,{id,key:k,endpoint_id:endpointId,pack_id:packId,payload,status:'pending',attempts:0,next_attempt_at:nextAttemptAt,last_error:null});return id;
 }
 listPendingAlerts(ctx,nowMs,limit=50){return [...this.#p(ctx).outbox.values()].filter(a=>a.status==='pending'&&a.next_attempt_at<=nowMs).slice(0,limit).map(a=>({...a}));}
 listAlerts(ctx){return [...this.#p(ctx).outbox.values()].map(a=>({...a}));}
 markAlert(ctx,id,{status,attempts,nextAttemptAt=null,lastError=null}){const a=this.#p(ctx).outbox.get(id);if(!a)return false;Object.assign(a,{status,attempts,next_attempt_at:nextAttemptAt??a.next_attempt_at,last_error:lastError});return true;}
 saveProviderSecret(ctx,provider,secret){this.#p(ctx).secrets.set(provider,secret);}
 getProviderSecret(ctx,provider){return this.#p(ctx).secrets.get(provider)??null;}
 metrics(ctx){const p=this.#p(ctx);return {...p.counters,active_monitors:[...p.monitors.values()].filter(m=>m.enabled).length,pending_claims:[...p.claims.values()].filter(c=>c.status==='pending').length};}
}
function publicPart(c){const {status,next_check_at,attempts,last_assurance,...claim}=c;return claim;}
