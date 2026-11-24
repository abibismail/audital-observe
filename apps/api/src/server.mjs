import http from 'node:http';
import {randomBytes} from 'node:crypto';
import {parseClaim,parseOTLPTraces,parseOTLPLogs,deriveProjectKey} from '../../../packages/otel-parser/src/index.mjs';
import {reconcile} from '../../../packages/recipes/src/reconcile.mjs';
import {ObserveSigner,HostedObserveSigner} from '../../../packages/recipes/src/signing.mjs';
import {readGithubIssue} from '../../../packages/recipes/src/github.mjs';
import {githubCheckPayload,githubPrCommentPayload,webhookAlertPayload} from '../../../packages/recipes/src/ci.mjs';
import {DevTenantStore} from './store.mjs';
import {ObserveWorker} from './worker.mjs';
import {validateEndpointUrl} from './alerts.mjs';
import {resultsOf,DEFAULT_SHARE_TTL_SECONDS,MAX_SHARE_TTL_SECONDS} from './evidence.mjs';

function json(res,code,value){res.writeHead(code,{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff'});res.end(JSON.stringify(value));}
async function body(req){
 if(req.headers['content-type'] && !req.headers['content-type'].includes('application/json'))throw Error('JSON_ONLY_OTLP_HTTP_PROTOBUF_NOT_SUPPORTED');
 let size=0,chunks=[];for await(const chunk of req){size+=chunk.length;if(size>2*1024*1024)throw Error('PAYLOAD_TOO_LARGE');chunks.push(chunk)}
 try{const v=JSON.parse(Buffer.concat(chunks).toString('utf8')||'{}');if(!v||typeof v!=='object'||Array.isArray(v))throw 0;return v;}catch{throw Error('INVALID_JSON')}
}
const httpError=(status,code)=>Object.assign(Error(code),{status});
const CLIENT_ERROR=/^[A-Z][A-Z0-9_]{2,80}$/;

/** Default GitHub reader: read-only GET connector, token from the project's sealed connector secret or dev env. */
export function defaultGithubReader({store,fetcher=fetch,env=process.env}={}){
 return async({ctx,claim,lookup,hmacKey})=>{
  const token=(await store.getProviderSecret(ctx,'github'))||(store.kind==='dev-memory'?env.GITHUB_READ_TOKEN:null);
  if(!token)return {available:false,complete:false,observed_at:new Date().toISOString(),events:[],reason:'NO_GITHUB_READ_CONNECTOR'};
  return readGithubIssue({target:lookup.target,token,hmacKey,coverageStart:claim.occurred_at,fetcher});
 };
}

export function createObserveServer({tenantId='local-tenant',projectId='local-project',apiKey,hmacKey,store=null,
 signer=null,localSigner=new ObserveSigner(),allowLocalFixtures=null,now=()=>Date.now(),graceMs=60000,
 readers=null,githubFetch=fetch,alertFetch=fetch,allowInsecureAlertLoopback=false,publicBaseUrl=null,autoMonitorIntervalSeconds=300,
 scheduler=false,pollMs=5000,log=()=>{}}={}){
 store??=new DevTenantStore(now);
 if(!hmacKey||String(hmacKey).length<32)throw Error('STRONG_HMAC_MASTER_KEY_REQUIRED');
 if(store.kind==='dev-memory'){if(!apiKey||String(apiKey).length<20)throw Error('STRONG_DEVELOPMENT_KEYS_REQUIRED');store.provision(tenantId,projectId,apiKey);}
 localSigner.current||localSigner.rotate();
 signer??=localSigner;signer.current||signer.rotate();
 // A caller-supplied fixture must never be signed by the hosted key: fixture route is local-signer only,
 // and disabled by default whenever a hosted signer is configured.
 allowLocalFixtures??=signer.attestation==='local_unattested';
 const projectKey=ctx=>deriveProjectKey(hmacKey,ctx.tenantId,ctx.projectId);
 let server;
 const baseUrl=()=>publicBaseUrl||(server?.address()?`http://127.0.0.1:${server.address().port}`:null);
 const engine=new ObserveWorker({store,signer,readers:readers??{github:defaultGithubReader({store,fetcher:githubFetch})},hmacKeyFor:projectKey,now,graceMs,
  alertFetch,allowInsecureLoopback:allowInsecureAlertLoopback,publicBaseUrl:baseUrl,pollMs,log});
 async function shareLink(ten,id,ttl){const s=await store.share(ten,id,ttl);return {token:s.token,url:`${baseUrl()}/v1/shares/${s.token}`,expires_at:s.expires_at};}
 async function ingest(ten,parsed){
  let accepted=0,duplicates=0;
  for(const {publicClaim,lookup} of parsed){
   const nextCheckAt=Math.max(Date.parse(publicClaim.occurred_at)+graceMs,now());
   const r=await store.saveClaim(ten,publicClaim,lookup,{nextCheckAt});
   if(!r.inserted){duplicates++;continue;}
   accepted++;
   if(engine.hasReader(publicClaim.provider)&&!(await store.getMonitorByProvider(ten,publicClaim.provider)))
    await store.addMonitor(ten,{provider:publicClaim.provider,interval_seconds:autoMonitorIntervalSeconds,enabled:true,next_run_at:nextCheckAt});
   await store.nudgeMonitor(ten,publicClaim.provider,nextCheckAt);
  }
  return {accepted,duplicates};
 }
 server=http.createServer(async(req,res)=>{
  try{
   const pathname=new URL(req.url,'http://localhost').pathname;
   if(req.method==='GET'&&pathname==='/health')return json(res,200,{status:store.kind==='postgres'?'ok':'dev-only',store:store.kind,attestation:signer.attestation,scheduler:!!scheduler,production_ready:false});
   if(req.method==='GET'&&/^\/v1\/shares\/[A-Za-z0-9_-]{20,100}$/.test(pathname)){
    const v=await store.getShare(pathname.split('/')[3]);
    return v?json(res,200,{...v.pack,share_expires_at:v.expires_at,share_notice:'Read-only; Observe-level evidence, NOT Guard proof'}):json(res,404,{error:'SHARE_NOT_FOUND'});
   }
   const key=req.headers['x-api-key'];const ten=await store.authenticate(typeof key==='string'?key:'');
   if(!ten)return json(res,401,{error:'UNAUTHORIZED'});
   if(req.method==='POST'&&['/v1/claims','/v1/otlp/traces','/v1/otlp/logs','/v1/traces','/v1/logs'].includes(pathname)){
    const data=await body(req);const k=projectKey(ten);
    const {claims,skipped}=pathname==='/v1/claims'?{claims:[parseClaim(data,k)],skipped:[]}:pathname.endsWith('logs')?parseOTLPLogs(data,k):parseOTLPTraces(data,k);
    const r=await ingest(ten,claims);
    return json(res,202,{...r,skipped:skipped.length,skipped_reasons:[...new Set(skipped.map(s=>s.reason))],projectId:ten.projectId,
     reconciliation:'scheduled read-only readback after the consistency window',notice:store.kind==='postgres'?'Claims retain only per-project keyed HMAC identifiers; target refs are AES-GCM sealed and deleted when the claim is final':'Claims retain only per-project keyed HMAC identifiers; target refs are held in process memory (dev store) and dropped when the claim is final'});
   }
   if(req.method==='POST'&&pathname==='/v1/reconcile'){
    const data=await body(req);
    if('assurance' in data||'result' in data||'attestation' in data)throw Error('CALLER_SUPPLIED_ASSURANCE_FORBIDDEN');
    if(!allowLocalFixtures)throw httpError(403,'LOCAL_FIXTURES_DISABLED_ON_HOSTED_SIGNER');
    if(data.source!=='LOCAL_FIXTURE')throw Error('USE_SCHEDULED_RECONCILIATION');
    const c=await store.getClaim(ten,data.claim_id);if(!c)return json(res,404,{error:'CLAIM_NOT_FOUND'});
    const observation=data.observation;if(!observation||typeof observation!=='object')throw Error('OBSERVATION_REQUIRED');
    const result=reconcile(c,observation,{now:now(),graceMs:Number(data.grace_ms??graceMs)});
    const id=await store.storeResults(ten,[result],localSigner);
    return json(res,200,{id,result,signed:(await store.getReport(ten,id)).results[0],notice:'LOCAL FIXTURE, not an independent provider observation; signed local_unattested'});
   }
   let m;
   if(req.method==='GET'&&(m=/^\/v1\/evidence\/([^/]+)$/.exec(pathname))){const v=await store.getReport(ten,m[1]);return v?json(res,200,v):json(res,404,{error:'REPORT_NOT_FOUND'});}
   if(req.method==='POST'&&(m=/^\/v1\/evidence\/([^/]+)\/share$/.exec(pathname))){
    const data=await body(req);const l=await shareLink(ten,m[1],data.ttl_seconds??3600);
    return json(res,200,{token:l.token,url:l.url,expires_at:l.expires_at,max_ttl_seconds:MAX_SHARE_TTL_SECONDS,notice:'Link bearer can read this evidence pack snapshot until expiry'});
   }
   if(req.method==='POST'&&(m=/^\/v1\/evidence\/([^/]+)\/github$/.exec(pathname))){
    const data=await body(req);const pack=await store.getReport(ten,m[1]);if(!pack)return json(res,404,{error:'REPORT_NOT_FOUND'});
    if(data.head_sha!==undefined&&!/^[0-9a-f]{40}$/.test(String(data.head_sha)))throw Error('INVALID_HEAD_SHA');
    const link=await shareLink(ten,m[1],data.ttl_seconds??DEFAULT_SHARE_TTL_SECONDS),results=resultsOf(pack);
    const opts={packId:pack.pack_id,attestation:pack.attestation,link};
    return json(res,200,{check_run:githubCheckPayload(results,null,{...opts,headSha:data.head_sha??null}),pr_comment:githubPrCommentPayload(results,opts),share:{url:link.url,expires_at:link.expires_at},
     notice:'Payloads only. Publish with YOUR workflow token (checks:write / pull-requests:write); Audital holds no GitHub write credential.'});
   }
   if(req.method==='GET'&&(m=/^\/v1\/checks\/([^/]+)$/.exec(pathname))){const v=await store.getReport(ten,m[1]);return v?json(res,200,githubCheckPayload(resultsOf(v),null,{packId:v.pack_id,attestation:v.attestation})):json(res,404,{error:'REPORT_NOT_FOUND'});}
   if(req.method==='GET'&&(m=/^\/v1\/alerts\/([^/]+)$/.exec(pathname))){const v=await store.getReport(ten,m[1]);return v?json(res,200,webhookAlertPayload(resultsOf(v),null,{packId:v.pack_id,projectId:ten.projectId,attestation:v.attestation})):json(res,404,{error:'REPORT_NOT_FOUND'});}
   if(req.method==='GET'&&pathname==='/v1/findings')return json(res,200,{findings:await store.listFindings(ten)});
   if(req.method==='GET'&&pathname==='/v1/metrics')return json(res,200,{...await store.metrics(ten),mode:store.kind});
   if(req.method==='POST'&&pathname==='/v1/monitors'){
    const data=await body(req);if(!['github','stripe','mock'].includes(data.provider)||!Number.isSafeInteger(data.interval_seconds)||data.interval_seconds<60||data.interval_seconds>86400)throw Error('INVALID_MONITOR');
    const live=engine.hasReader(data.provider);
    const id=await store.addMonitor(ten,{provider:data.provider,interval_seconds:data.interval_seconds,enabled:live&&data.enabled!==false});
    return json(res,202,{id,enabled:live&&data.enabled!==false,read_only:true,reason:live?'Scheduled read-only reconciliation':'No read-only connector for this provider'});
   }
   if(req.method==='GET'&&pathname==='/v1/monitors')return json(res,200,{monitors:await store.listMonitors(ten)});
   if(req.method==='POST'&&(m=/^\/v1\/monitors\/([^/]+)\/run$/.exec(pathname))){
    const mon=(await store.listMonitors(ten)).find(x=>x.id===m[1]);if(!mon)return json(res,404,{error:'MONITOR_NOT_FOUND'});
    const r=await engine.tick(ten,mon);await store.completeMonitorRun(ten,mon.id,now()+mon.interval_seconds*1000);return json(res,200,r);
   }
   if(req.method==='POST'&&pathname==='/v1/connectors/github'){
    const data=await body(req);if(typeof data.token!=='string'||data.token.length<20||data.token.length>255)throw Error('INVALID_TOKEN');
    await store.saveProviderSecret(ten,'github',data.token);
    return json(res,202,{provider:'github',stored:'sealed',notice:'Read-only use only. Tokens advertising write-capable OAuth scopes are refused at read time.'});
   }
   if(req.method==='POST'&&pathname==='/v1/alert-endpoints'){
    const data=await body(req);if(!['slack','webhook'].includes(data.kind))throw Error('INVALID_ALERT_KIND');
    validateEndpointUrl(data.kind,data.url,{allowInsecureLoopback:allowInsecureAlertLoopback});
    let secret=null;if(data.kind==='webhook')secret=randomBytes(32).toString('base64url');
    const id=await store.addAlertEndpoint(ten,{kind:data.kind,url:data.url,secret});
    return json(res,201,{id,kind:data.kind,...(secret?{signing_secret:secret,signature_header:'x-audital-signature: t=<unix>,v1=<hex hmac-sha256(secret, "<t>.<body>")>'}:{})});
   }
   return json(res,404,{error:'NOT_FOUND'});
  }catch(e){
   const msg=e?.message||'UNKNOWN';
   if(e?.status)return json(res,e.status,{error:msg});
   if(msg==='PAYLOAD_TOO_LARGE')return json(res,413,{error:msg});
   if(msg==='REPORT_NOT_FOUND')return json(res,404,{error:msg});
   // Our validation errors are UPPER_SNAKE codes; anything else (DB, runtime) is internal and not echoed.
   if(CLIENT_ERROR.test(msg.split(' ')[0])&&!e?.code)return json(res,400,{error:msg.split(' ')[0]});
   log(`internal error: ${e?.code||''} ${msg}`);return json(res,500,{error:'INTERNAL_ERROR'});
  }
 });
 if(scheduler)engine.startScheduler();
 server.on('close',()=>engine.stopAll());
 return {server,store,signer,localSigner,engine};
}

export async function createFromEnv(env=process.env){
 const mode=env.AUDITAL_OBSERVE_MODE;
 if(mode!=='development'&&mode!=='hosted-preview')throw Error('HOSTING_DISABLED: set AUDITAL_OBSERVE_MODE=development (memory) or hosted-preview (PostgreSQL); production is gated');
 if(!env.AUDITAL_HMAC_KEY)throw Error('AUDITAL_HMAC_KEY required (>=32 bytes)');
 let signer=null;
 if(env.AUDITAL_HOSTED_SIGNING_KEY_PEM_FILE){const {readFileSync}=await import('node:fs');signer=new HostedObserveSigner({privateKeyPem:readFileSync(env.AUDITAL_HOSTED_SIGNING_KEY_PEM_FILE,'utf8'),kid:env.AUDITAL_HOSTED_SIGNING_KID});}
 const common={hmacKey:env.AUDITAL_HMAC_KEY,signer,publicBaseUrl:env.AUDITAL_PUBLIC_BASE_URL||null,scheduler:env.AUDITAL_SCHEDULER!=='off',log:m=>console.error(m)};
 if(mode==='development'){
  if(!env.AUDITAL_API_KEY)throw Error('AUDITAL_API_KEY required (dev only)');
  return createObserveServer({...common,tenantId:env.AUDITAL_TENANT_ID||'dev',projectId:env.AUDITAL_PROJECT_ID||'dev',apiKey:env.AUDITAL_API_KEY});
 }
 const pg=(await import('pg')).default;const {PgTenantStore}=await import('./db/pg-store.mjs');const {DevEnvelopeVault}=await import('./vault.mjs');
 if(!env.AUDITAL_PG_APP_URL||!env.AUDITAL_VAULT_KEY_HEX)throw Error('AUDITAL_PG_APP_URL and AUDITAL_VAULT_KEY_HEX required');
 const store=new PgTenantStore({pool:new pg.Pool({connectionString:env.AUDITAL_PG_APP_URL,max:10}),vault:new DevEnvelopeVault(Buffer.from(env.AUDITAL_VAULT_KEY_HEX,'hex'))});
 return createObserveServer({...common,store});
}
if(import.meta.url===`file://${process.argv[1]}`){
 const s=await createFromEnv();
 s.server.listen(Number(process.env.PORT||8787),'127.0.0.1',()=>console.log(`Audital Observe ${s.store.kind} API on loopback; attestation=${s.signer.attestation}; NOT production-ready`));
}
