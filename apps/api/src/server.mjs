import http from 'node:http';
import {randomBytes} from 'node:crypto';
import {parseClaim,parseOTLPJson} from '../../../packages/otel-parser/src/index.mjs';
import {reconcile} from '../../../packages/recipes/src/reconcile.mjs';
import {ObserveSigner} from '../../../packages/recipes/src/signing.mjs';
import {githubCheckPayload,webhookAlertPayload} from '../../../packages/recipes/src/ci.mjs';
import {DevTenantStore} from './store.mjs';

function json(res,code,value){res.writeHead(code,{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'});res.end(JSON.stringify(value));}
async function body(req){
 if(req.headers['content-type'] && !req.headers['content-type'].includes('application/json'))throw Error('JSON_ONLY_OTLP_HTTP_PROTOPBUF_NOT_SUPPORTED');
 let size=0,chunks=[];for await(const chunk of req){size+=chunk.length;if(size>2*1024*1024)throw Error('PAYLOAD_TOO_LARGE');chunks.push(chunk)}
 return JSON.parse(Buffer.concat(chunks).toString('utf8')||'{}');
}
const bad=new Set(['CALLER_SUPPLIED_ASSURANCE_FORBIDDEN','CLAIM_TARGET_TOOL_OR_PROVIDER_MISSING']);
export function createObserveServer({tenantId='local-tenant',projectId='local-project',apiKey,hmacKey,store=new DevTenantStore(),signer=new ObserveSigner(),now=()=>Date.now()}={}){
 if(!apiKey||String(apiKey).length<20||!hmacKey||String(hmacKey).length<16)throw Error('STRONG_DEVELOPMENT_KEYS_REQUIRED');
 signer.current||signer.rotate();store.provision(tenantId,projectId,apiKey);
 const server=http.createServer(async(req,res)=>{
  try{
   const pathname=new URL(req.url,'http://localhost').pathname;
   if(req.method==='GET'&&pathname==='/health')return json(res,200,{status:'dev-only',production_ready:false});
   if(req.method==='GET'&&pathname.startsWith('/v1/shares/')){const value=store.getShare(pathname.split('/')[3]);return value?json(res,200,{...value,share_notice:'Read-only; Observe-level evidence, NOT Guard proof'}):json(res,404,{error:'SHARE_NOT_FOUND'});}
   const key=req.headers['x-api-key'];const ten=store.authenticate(typeof key==='string'?key:'');
   if(!ten)return json(res,401,{error:'UNAUTHORIZED'});
   if(req.method==='POST'&&(pathname==='/v1/claims'||pathname==='/v1/otlp/traces')){
    const data=await body(req);
    const parsed=pathname.endsWith('/claims')?[parseClaim(data,hmacKey)]:parseOTLPJson(data,hmacKey);
    for(const x of parsed)store.saveClaim(ten,x.publicClaim);
    return json(res,202,{accepted:parsed.length,projectId:ten.projectId,notice:'Only HMAC identifiers and arguments are retained; no raw tool payloads'});
   }
   if(req.method==='POST'&&pathname==='/v1/reconcile'){
    const data=await body(req);
    if('assurance' in data||'result' in data)throw Error('CALLER_SUPPLIED_ASSURANCE_FORBIDDEN');
    // No provider-write capability. Local-only test route; provider snapshots are UNTRUSTED test inputs.
    // Production must replace with independently fetched read-only observations.
    if(data.source!=='LOCAL_FIXTURE')throw Error('NO_LIVE_RECONCILER_CONFIGURED');
    const c=ten.claims.get(data.claim_id);if(!c)return json(res,404,{error:'CLAIM_NOT_FOUND'});
    const observation=data.observation;if(!observation||typeof observation!=='object')throw Error('OBSERVATION_REQUIRED');
    const result=reconcile(c,observation,{now:now(),graceMs:Number(data.grace_ms??60000)});
    const id=store.storeResults(ten,[result],signer);return json(res,200,{id,result,signed:signer.signResult(result),notice:'LOCAL FIXTURE, not an independent provider observation'});
   }
   if(req.method==='GET'&&pathname.startsWith('/v1/evidence/')){
    const v=store.getReport(ten,pathname.split('/')[3]);return v?json(res,200,v):json(res,404,{error:'REPORT_NOT_FOUND'});
   }
   if(req.method==='POST'&&/^\/v1\/evidence\/[^/]+\/share$/.test(pathname)){
    const id=pathname.split('/')[3],data=await body(req);return json(res,200,{token:store.share(ten,id,data.ttl_seconds??3600),max_ttl_seconds:3600,notice:'Link bearer can read this redacted report until expiry'});
   }
   if(req.method==='GET'&&pathname==='/v1/metrics')return json(res,200,{...ten.counters,mode:'development-in-memory'});
   if(req.method==='POST'&&pathname==='/v1/monitors'){
    const data=await body(req);if(!['github','stripe','mock'].includes(data.provider)||data.interval_seconds<60||data.interval_seconds>86400)throw Error('INVALID_MONITOR');
    const id=store.addMonitor(ten,{provider:data.provider,interval_seconds:data.interval_seconds,read_only:true,enabled:false});return json(res,202,{id,enabled:false,reason:'Live scheduling disabled until durable tenant and provider isolation implemented'});
   }
   if(req.method==='GET'&&pathname.startsWith('/v1/checks/')){
    const v=store.getReport(ten,pathname.split('/')[3]);return v?json(res,200,githubCheckPayload(v.signed.map(s=>s.payload.result))):json(res,404,{error:'REPORT_NOT_FOUND'});
   }
   if(req.method==='GET'&&pathname.startsWith('/v1/alerts/')){
    const v=store.getReport(ten,pathname.split('/')[3]);return v?json(res,200,webhookAlertPayload(v.signed.map(s=>s.payload.result))):json(res,404,{error:'REPORT_NOT_FOUND'});
   }
   return json(res,404,{error:'NOT_FOUND'});
  }catch(e){const msg=e?.message||'UNKNOWN';return json(res,bad.has(msg)?400:msg==='PAYLOAD_TOO_LARGE'?413:400,{error:msg});}
 });return {server,store,signer};
}
if(import.meta.url===`file://${process.argv[1]}`){
 if(process.env.AUDITAL_OBSERVE_MODE!=='development')throw Error('HOSTING_DISABLED: this memory-only prototype is not a production hosted service');
 const apiKey=process.env.AUDITAL_API_KEY;const hmacKey=process.env.AUDITAL_HMAC_KEY;
 if(!apiKey||!hmacKey)throw Error('AUDITAL_API_KEY and AUDITAL_HMAC_KEY required (dev only)');
 const s=createObserveServer({tenantId:process.env.AUDITAL_TENANT_ID||'dev',projectId:process.env.AUDITAL_PROJECT_ID||'dev',apiKey,hmacKey});
 s.server.listen(Number(process.env.PORT||8787),'127.0.0.1',()=>console.log('Audital Observe development API listening on loopback; NOT production-ready'));
}
