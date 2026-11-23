import {reconcile} from '../../../packages/recipes/src/reconcile.mjs';

// Runnable, read-only reconciliation worker. The production API DOES NOT start it.
// A future provider client can be injected after independent read-only scope review.
export class ObserveWorker {
 #active=new Set();#timers=new Map();
 constructor({store,signer,readObservation,onResults=async()=>{},now=()=>Date.now(),graceMs=60000}){
  if(typeof readObservation!=='function')throw Error('READ_OBSERVATION_CALLBACK_REQUIRED');
  this.store=store;this.signer=signer;this.readObservation=readObservation;this.onResults=onResults;this.now=now;this.graceMs=graceMs;
 }
 async tick(tenant,monitor){
  if(!monitor?.enabled)return {status:'HOLD',reason:'MONITOR_DISABLED'};
  if(this.#active.has(monitor.id))return {status:'HOLD',reason:'MONITOR_ALREADY_RUNNING'};
  this.#active.add(monitor.id);
  try{
   const claims=[...tenant.claims.values()].filter(x=>x.provider===monitor.provider);
   if(!claims.length)return {status:'NO_CLAIMS'};
   const results=[];
   for(const claim of claims){
    let observation;
    try{observation=await this.readObservation({tenantId:tenant.tenantId,projectId:tenant.projectId,provider:monitor.provider,claim});}
    catch{observation={available:false,complete:false,observed_at:new Date(this.now()).toISOString(),events:[]};}
    results.push(reconcile(claim,observation,{now:this.now(),graceMs:this.graceMs}));
   }
   const id=this.store.storeResults(tenant,results,this.signer);
   // Best effort notifications must never change stored evidence or trigger provider writes.
   try{await this.onResults({tenantId:tenant.tenantId,projectId:tenant.projectId,id,results})}catch{}
   return {status:'RECORDED',id,results_count:results.length};
  }finally{this.#active.delete(monitor.id)}
 }
 start(tenant,monitor){
  if(!monitor?.enabled)throw Error('MONITOR_NOT_ENABLED');
  if(!Number.isSafeInteger(monitor.interval_seconds)||monitor.interval_seconds<60)throw Error('INTERVAL_TOO_SHORT');
  if(this.#timers.has(monitor.id))throw Error('ALREADY_STARTED');
  const interval=setInterval(()=>{void this.tick(tenant,monitor)},monitor.interval_seconds*1000);
  interval.unref?.();this.#timers.set(monitor.id,interval);return ()=>this.stop(monitor.id);
 }
 stop(id){const t=this.#timers.get(id);if(t){clearInterval(t);this.#timers.delete(id)}return !!t}
 stopAll(){for(const id of this.#timers.keys())this.stop(id)}
}
