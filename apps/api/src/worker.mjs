import {reconcile} from '../../../packages/recipes/src/reconcile.mjs';
import {shouldAlert,alertDedupeKey,buildAlertBody,deliverAlert} from './alerts.mjs';
import {DEFAULT_SHARE_TTL_SECONDS} from './evidence.mjs';

// Continuous, read-only reconciliation engine.
//  scheduler: store.leaseDueMonitors() (cross-tenant, metadata only) -> tick(ctx, monitor) per lease
//  tick:      due claims -> read-only observation -> reconcile -> signed pack -> reschedule/finalize
//             -> alerts (Slack/webhook outbox, signed expiring share link) -> dispatch
// Provider access is ONLY through injected `readers[provider]` (GET-only connectors). No write path exists.
const PENDING=new Set(['CLAIMED','UNOBSERVABLE']);
export class ObserveWorker {
 #active=new Set();#timers=new Map();#loop=null;#running=false;
 constructor({store,signer,readers={},readObservation=null,hmacKeyFor=()=>null,onResults=async()=>{},now=()=>Date.now(),
  graceMs=60000,deadlineMs=300000,maxAttempts=12,maxAgeMs=7*86400000,maxBackoffMs=3600000,batchSize=100,pollMs=5000,leaseMs=120000,
  alertFetch=fetch,allowInsecureLoopback=false,publicBaseUrl=()=>null,shareTtlSeconds=DEFAULT_SHARE_TTL_SECONDS,maxAlertAttempts=5,log=()=>{}}){
  if(!store||!signer)throw Error('STORE_AND_SIGNER_REQUIRED');
  if(readObservation&&typeof readObservation!=='function')throw Error('READ_OBSERVATION_CALLBACK_REQUIRED');
  if(!readObservation&&!Object.keys(readers).length)throw Error('READ_OBSERVATION_CALLBACK_REQUIRED');
  Object.assign(this,{store,signer,readers,readObservation,hmacKeyFor,onResults,now,graceMs,deadlineMs,maxAttempts,maxAgeMs,maxBackoffMs,batchSize,pollMs,leaseMs,alertFetch,allowInsecureLoopback,publicBaseUrl,shareTtlSeconds,maxAlertAttempts,log});
 }
 hasReader(provider){return !!(this.readObservation||this.readers[provider]);}
 async #observe(ctx,provider,claim){
  const fail=reason=>({available:false,complete:false,observed_at:new Date(this.now()).toISOString(),events:[],reason});
  try{
   const lookup=await this.store.getLookup(ctx,claim.claim_id);
   const read=this.readObservation||this.readers[provider];
   if(!read)return fail('NO_READER_FOR_PROVIDER');
   if(!lookup&&!this.readObservation)return fail('LOOKUP_EXPIRED_OR_MISSING');
   return await read({tenantId:ctx.tenantId,projectId:ctx.projectId,ctx,provider,claim,lookup,hmacKey:this.hmacKeyFor(ctx)});
  }catch(e){if(e?.message==='WRITE_CAPABLE_TOKEN_REFUSED')this.log(`refused write-capable ${provider} token for project ${ctx.projectId}`);return fail(e?.message||'READ_FAILED');}
 }
 async tick(ctx,monitor){
  if(!monitor?.enabled)return {status:'HOLD',reason:'MONITOR_DISABLED'};
  if(this.#active.has(monitor.id))return {status:'HOLD',reason:'MONITOR_ALREADY_RUNNING'};
  this.#active.add(monitor.id);
  try{
   const now=this.now();
   const claims=await this.store.listDueClaims(ctx,monitor.provider,now,this.batchSize);
   if(!claims.length){await this.dispatchAlerts(ctx);return {status:'NO_CLAIMS'};}
   const results=[];
   for(const {attempts=0,...claim} of claims){
    const observation=await this.#observe(ctx,monitor.provider,claim);
    const result=reconcile(claim,observation,{now,graceMs:this.graceMs,deadlineMs:this.deadlineMs});
    results.push(result);
    const age=now-Date.parse(claim.occurred_at),n=attempts+1;
    const final=!PENDING.has(result.assurance)||n>=this.maxAttempts||age>=this.maxAgeMs;
    await this.store.updateClaimSchedule(ctx,claim.claim_id,{status:final?'final':'pending',
     nextCheckAt:final?null:now+Math.min(this.maxBackoffMs,Math.max(this.graceMs,1000)*2**Math.min(n-1,20)),attempts:n,lastAssurance:result.assurance});
   }
   const id=await this.store.storeResults(ctx,results,this.signer);
   const alerts=await this.#enqueueAlerts(ctx,id,results);
   // Best-effort hooks must never change stored evidence or trigger provider writes.
   try{await this.onResults({tenantId:ctx.tenantId,projectId:ctx.projectId,id,results})}catch{}
   const delivery=await this.dispatchAlerts(ctx);
   return {status:'RECORDED',id,results_count:results.length,alerts_enqueued:alerts,alerts_delivered:delivery.delivered};
  }finally{this.#active.delete(monitor.id)}
 }
 async #enqueueAlerts(ctx,packId,results){
  const alertable=results.filter(shouldAlert);if(!alertable.length)return 0;
  const endpoints=await this.store.listAlertEndpoints(ctx);if(!endpoints.length)return 0;
  const shared=await this.store.share(ctx,packId,this.shareTtlSeconds);
  const base=this.publicBaseUrl();
  const link={url:base?`${base.replace(/\/$/,'')}/v1/shares/${shared.token}`:null,expires_at:shared.expires_at};
  let n=0;
  for(const ep of endpoints)for(const r of alertable){
   const payload=buildAlertBody(ep.kind,[r],{link,packId,projectId:ctx.projectId,attestation:this.signer.attestation});
   if(await this.store.enqueueAlert(ctx,{endpointId:ep.id,dedupeKey:alertDedupeKey(r),packId,payload,nextAttemptAt:this.now()}))n++;
  }
  return n;
 }
 async dispatchAlerts(ctx){
  const now=this.now();const pending=await this.store.listPendingAlerts(ctx,now);
  if(!pending.length)return {delivered:0,failed:0};
  const eps=new Map((await this.store.listAlertEndpoints(ctx)).map(e=>[e.id,e]));
  let delivered=0,failed=0;
  for(const a of pending){
   const ep=eps.get(a.endpoint_id);const attempts=a.attempts+1;
   try{
    if(!ep)throw Error('ENDPOINT_DISABLED');
    await deliverAlert(ep,a.payload,{fetcher:this.alertFetch,now:this.now,allowInsecureLoopback:this.allowInsecureLoopback});
    await this.store.markAlert(ctx,a.id,{status:'delivered',attempts});delivered++;
   }catch(e){
    const give=attempts>=this.maxAlertAttempts;failed++;
    await this.store.markAlert(ctx,a.id,{status:give?'failed':'pending',attempts,nextAttemptAt:now+30000*2**Math.min(attempts,10),lastError:e?.message});
   }
  }
  return {delivered,failed};
 }
 /** One scheduler pass across all tenants. Each lease is processed under its own tenant context. */
 async runDue(){
  if(this.#running)return {status:'HOLD',reason:'SCHEDULER_BUSY'};
  this.#running=true;
  try{
   const leases=await this.store.leaseDueMonitors(this.now(),this.leaseMs);const out=[];
   for(const {tenantId,projectId,monitor} of leases){
    const ctx={tenantId,projectId};
    try{out.push({monitor:monitor.id,...await this.tick(ctx,monitor)});}
    catch(e){this.log(`tick failed for monitor ${monitor.id}: ${e?.message}`);out.push({monitor:monitor.id,status:'ERROR',reason:e?.message});}
    finally{await Promise.resolve().then(()=>this.store.completeMonitorRun(ctx,monitor.id,this.now()+monitor.interval_seconds*1000)).catch(()=>{});}
   }
   return {status:'OK',runs:out};
  }finally{this.#running=false;}
 }
 startScheduler(){
  if(this.#loop)return ()=>this.stopScheduler();
  this.#loop=setInterval(()=>{void this.runDue().catch(e=>this.log(`scheduler error: ${e?.message}`))},this.pollMs);
  this.#loop.unref?.();return ()=>this.stopScheduler();
 }
 stopScheduler(){if(this.#loop){clearInterval(this.#loop);this.#loop=null;return true}return false}
 // v0.1-compatible single-monitor timer.
 start(ctx,monitor){
  if(!monitor?.enabled)throw Error('MONITOR_NOT_ENABLED');
  if(!Number.isSafeInteger(monitor.interval_seconds)||monitor.interval_seconds<60)throw Error('INTERVAL_TOO_SHORT');
  if(this.#timers.has(monitor.id))throw Error('ALREADY_STARTED');
  const interval=setInterval(()=>{void this.tick(ctx,monitor).catch(()=>{})},monitor.interval_seconds*1000);
  interval.unref?.();this.#timers.set(monitor.id,interval);return ()=>this.stop(monitor.id);
 }
 stop(id){const t=this.#timers.get(id);if(t){clearInterval(t);this.#timers.delete(id)}return !!t}
 stopAll(){for(const id of this.#timers.keys())this.stop(id);this.stopScheduler();}
}
