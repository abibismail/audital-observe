import test from 'node:test';import assert from 'node:assert/strict';import {randomBytes,generateKeyPairSync,createHash} from 'node:crypto';import http from 'node:http';
import {DevTenantStore} from '../src/store.mjs';
import {DevEnvelopeVault} from '../src/vault.mjs';
import {createObserveServer} from '../src/server.mjs';
import {ObserveWorker} from '../src/worker.mjs';
import {verifyWebhookSignature,validateEndpointUrl} from '../src/alerts.mjs';
import {ObserveSigner,HostedObserveSigner,loadTrustRegistry,verifyEnvelope} from '../../../packages/recipes/src/signing.mjs';
const key='a'.repeat(35),hmac='b'.repeat(40);
const T='5b8efff798038103d269b633813fc60c';
const listen=s=>new Promise(r=>s.listen(0,'127.0.0.1',()=>r(`http://127.0.0.1:${s.address().port}`)));
const toolSpan=(spanId,callId,issue,startMs)=>({traceId:T,spanId,name:'execute_tool update_issue',startTimeUnixNano:String(BigInt(startMs)*1000000n),attributes:[
 {key:'gen_ai.operation.name',value:{stringValue:'execute_tool'}},{key:'gen_ai.tool.name',value:{stringValue:'update_issue'}},{key:'gen_ai.tool.call.id',value:{stringValue:callId}},
 {key:'gen_ai.tool.call.arguments',value:{stringValue:JSON.stringify({owner:'acme',repo:'sandbox',issue_number:issue,state:'closed'})}}]});
function fakeGithub(issues,{scopes=null}={}){
 const calls=[];
 const fetcher=async(url,init)=>{calls.push({url:String(url),method:init.method,auth:init.headers.Authorization});
  const m=/\/repos\/acme\/sandbox\/issues\/(\d+)(\/events)?/.exec(new URL(url).pathname);const issue=issues[m[1]];
  const headers={get:k=>({'x-ratelimit-remaining':'4999','x-ratelimit-reset':'9999999999',...(scopes!==null?{'x-oauth-scopes':scopes}:{})})[k.toLowerCase()]??null};
  return {ok:true,status:200,headers,json:async()=>m[2]?issue.events:{state:issue.state,created_at:'2026-01-01T00:00:00Z'}};};
 return {fetcher,calls};
}

test('dev store: per-tenant/project boundaries are enforced by context',async()=>{
 const st=new DevTenantStore();st.provision('tenant-A','proj-A',key);st.provision('tenant-B','proj-B','other-token-long-enough');
 const a=st.authenticate(key),b=st.authenticate('other-token-long-enough');
 st.saveClaim(a,{claim_id:'a',target_hash:'h',provider:'github',occurred_at:'2026-11-20T00:00:00Z'});
 assert.equal(st.getClaim(b,'a'),null);assert.equal(a.projectId,'proj-A');
 const s=new ObserveSigner();s.rotate();
 assert.throws(()=>st.getClaim({tenantId:'tenant-A',projectId:'proj-B'},'a'),/TENANT_CONTEXT_INVALID/);
});
test('envelope vault binds to tenant+project as AAD with a KEYED binding tag',()=>{
 const v=new DevEnvelopeVault(randomBytes(32)),sealed=v.encrypt('secret','tenant-1/project-1');
 assert.equal(v.decrypt(sealed,'tenant-1/project-1'),'secret');assert.throws(()=>v.decrypt(sealed,'tenant-2/project-1'));assert.throws(()=>v.decrypt({...sealed,ciphertext:'AA=='},'tenant-1/project-1'));
 assert.notEqual(sealed.aad_binding,createHash('sha256').update('tenant-1/project-1').digest('hex'),'v0.1 unkeyed digest is gone');
 assert.notEqual(sealed.aad_binding,new DevEnvelopeVault(randomBytes(32)).encrypt('secret','tenant-1/project-1').aad_binding);
});

test('API: claims, local fixture evidence, caller assurance rejected, expiring share, GitHub payloads',async(t)=>{
 const {server}=createObserveServer({tenantId:'one',projectId:'first',apiKey:key,hmacKey:hmac,now:()=>Date.parse('2026-11-20T15:00:00Z')});
 const root=await listen(server);t.after(()=>server.close());
 const post=(path,x,auth=key)=>fetch(root+path,{method:'POST',headers:{'x-api-key':auth,'content-type':'application/json'},body:JSON.stringify(x)});
 const claim={claim_id:'claim-1',name:'execute_tool',action:'github.issue.close',target:'org/repo#6',provider:'github',occurred_at:'2026-11-20T12:00:00Z',claimed_success:true};
 let v=await post('/v1/claims',{...claim,assurance:'EFFECT_OBSERVED'});assert.equal(v.status,400);
 v=await post('/v1/claims',{...claim,attestation:'hosted_attested'});assert.equal(v.status,400);
 v=await post('/v1/claims',claim);assert.equal(v.status,202);const ingestion=await v.json();assert.equal(ingestion.accepted,1);
 v=await post('/v1/claims',claim);assert.equal((await v.json()).duplicates,1);
 v=await post('/v1/reconcile',{claim_id:'claim-1',source:'LOCAL_FIXTURE',observation:{available:true,complete:true,observed_at:'2026-11-20T15:00:00Z',coverage_start:'2026-11-20T11:00:00Z',current_state:'open',events:[]}});
 assert.equal(v.status,200);const done=await v.json();assert.equal(done.result.assurance,'CONTRADICTED');assert.ok(done.result.findings.includes('PHANTOM_SUCCESS'));
 assert.equal(done.signed.attestation,'local_unattested');assert.ok(!JSON.stringify(done).includes('org/repo#6'));
 const report=await fetch(root+'/v1/evidence/'+done.id,{headers:{'x-api-key':key}});assert.equal(report.status,200);const pack=await report.json();
 assert.equal(pack.schema,'audital.observe.pack/v2');assert.equal(pack.attestation,'local_unattested');assert.equal(verifyEnvelope(pack.results[0],{localKeys:pack.public_keys}).valid,true);
 assert.equal((await fetch(root+'/v1/evidence/'+done.id,{headers:{'x-api-key':'not-allowed'}})).status,401);
 const share=await (await post('/v1/evidence/'+done.id+'/share',{ttl_seconds:60})).json();
 let shared=await fetch(share.url);assert.equal(shared.status,200);assert.ok((await shared.text()).includes('Observe-level'));
 assert.equal((await post('/v1/evidence/'+done.id+'/share',{ttl_seconds:8*86400})).status,400);
 const gh=await (await post('/v1/evidence/'+done.id+'/github',{head_sha:'c'.repeat(40)})).json();
 assert.equal(gh.check_run.conclusion,'failure');assert.equal(gh.check_run.head_sha,'c'.repeat(40));assert.equal(gh.check_run.details_url,gh.share.url);
 assert.match(gh.pr_comment.body,/audital-observe:evidence/);assert.equal((await fetch(gh.share.url)).status,200);
 const mon=await (await post('/v1/monitors',{provider:'mock',interval_seconds:60})).json();assert.equal(mon.enabled,false);
 const mon2=await (await post('/v1/monitors',{provider:'github',interval_seconds:60})).json();assert.equal(mon2.enabled,true);
 const metrics=await (await fetch(root+'/v1/metrics',{headers:{'x-api-key':key}})).json();assert.equal(metrics.ingested,1);assert.equal(metrics.discrepancies,1);
});

test('continuous engine: OTLP ingest -> scheduled read-only GitHub readback -> signed pack -> Slack + signed webhook alerts with expiring link',async(t)=>{
 let clock=Date.parse('2026-11-20T12:00:00Z');const now=()=>clock;
 const hooks=[];const receiver=http.createServer(async(req,res)=>{let b='';for await(const c of req)b+=c;hooks.push({sig:req.headers['x-audital-signature'],body:b});res.end('ok')});
 const hookUrl=await listen(receiver);t.after(()=>receiver.close());
 const slack=[];const alertFetch=async(url,init)=>{if(url.hostname==='hooks.slack.com'){slack.push(JSON.parse(init.body));return {ok:true,status:200}}return fetch(url,init)};
 const gh=fakeGithub({42:{state:'open',events:[]},43:{state:'closed',events:[{id:9,event:'closed',created_at:'2026-11-20T12:00:10Z',actor:{login:'agent'}}]}});
 const {server,engine,store}=createObserveServer({tenantId:'t',projectId:'p',apiKey:key,hmacKey:hmac,now,githubFetch:gh.fetcher,alertFetch,allowInsecureAlertLoopback:true});
 const root=await listen(server);t.after(()=>server.close());
 const post=(path,x)=>fetch(root+path,{method:'POST',headers:{'x-api-key':key,'content-type':'application/json'},body:JSON.stringify(x)});
 assert.equal((await post('/v1/connectors/github',{token:'github_pat_readonly_0123456789'})).status,202);
 const wh=await (await post('/v1/alert-endpoints',{kind:'webhook',url:`${hookUrl}/hook`})).json();assert.ok(wh.signing_secret);
 assert.equal((await post('/v1/alert-endpoints',{kind:'slack',url:'https://hooks.slack.com/services/T000/B000/XXXX'})).status,201);
 assert.equal((await post('/v1/alert-endpoints',{kind:'webhook',url:'https://api.github.com/repos/x/y/issues'})).status,400,'provider hosts refused');
 const ing=await (await post('/v1/otlp/traces',{resourceSpans:[{scopeSpans:[{spans:[toolSpan('1111111111111111','call_A',42,clock),toolSpan('2222222222222222','call_B',43,clock)]}]}]})).json();
 assert.equal(ing.accepted,2);
 const ctx=store.authenticate(key);const [mon]=store.listMonitors(ctx);assert.equal(mon.provider,'github');assert.equal(mon.enabled,true);
 assert.deepEqual((await engine.runDue()).runs,[],'inside consistency window: nothing leased yet');
 clock+=61000;
 const run=(await engine.runDue()).runs[0];
assert.equal(run.status,'RECORDED');assert.equal(run.results_count,2);assert.equal(run.alerts_enqueued,2);assert.equal(run.alerts_delivered,2);
 assert.ok(gh.calls.length>=4&&gh.calls.every(c=>c.method==='GET'&&c.url.startsWith('https://api.github.com/repos/acme/sandbox/issues/')&&c.auth==='Bearer github_pat_readonly_0123456789'));
 const pack=store.getReport(ctx,run.id);const byId=Object.fromEntries(pack.results.map(e=>[e.payload.result.claim_id,e.payload.result]));
 assert.equal(byId.call_A.assurance,'CONTRADICTED');assert.deepEqual(byId.call_A.findings,['PHANTOM_SUCCESS']);
 assert.equal(byId.call_B.assurance,'EFFECT_CORRELATED');assert.deepEqual(byId.call_B.cannot_assert.slice(0,2),['exclusive causation','no same-identity competitor']);
 assert.equal(hooks.length,1);assert.equal(verifyWebhookSignature(wh.signing_secret,hooks[0].sig,hooks[0].body,{now}),true);
 const alert=JSON.parse(hooks[0].body);assert.equal(alert.schema,'audital.observe.alert/v1');assert.deepEqual(alert.findings,['PHANTOM_SUCCESS']);assert.ok(alert.url_expires_at);
 assert.ok(!hooks[0].body.includes('acme/sandbox'),'no raw target in alerts');
 const viaLink=await fetch(alert.url);assert.equal(viaLink.status,200);assert.equal((await viaLink.json()).pack_id,run.id);
 assert.equal(slack.length,1);assert.match(slack[0].text,/1 priority/);
 clock+=301000;const again=(await engine.runDue()).runs[0];assert.equal(again.status,'NO_CLAIMS','final claims are not re-reconciled');assert.equal(hooks.length,1,'no duplicate alerts');
 const f=await (await fetch(root+'/v1/findings',{headers:{'x-api-key':key}})).json();assert.ok(f.findings.some(x=>x.findings.includes('PHANTOM_SUCCESS')));
});

test('engine: write-capable token is refused -> UNOBSERVABLE, retried with backoff, never alerts',async(t)=>{
 let clock=Date.parse('2026-11-20T12:00:00Z');const gh=fakeGithub({42:{state:'open',events:[]}},{scopes:'repo'});
 const {server,engine,store}=createObserveServer({tenantId:'t',projectId:'p',apiKey:key,hmacKey:hmac,now:()=>clock,githubFetch:gh.fetcher});t.after(()=>server.close());
 const ctx=store.authenticate(key);store.saveProviderSecret(ctx,'github','ghp_classic_token_with_repo_scope');
 const {parseOTLPTraces,deriveProjectKey}=await import('../../../packages/otel-parser/src/index.mjs');
 const [c]=parseOTLPTraces({resourceSpans:[{scopeSpans:[{spans:[toolSpan('1111111111111111','call_W',42,clock)]}]}]},deriveProjectKey(hmac,'t','p')).claims;
 store.saveClaim(ctx,c.publicClaim,c.lookup,{nextCheckAt:clock});store.addMonitor(ctx,{provider:'github',interval_seconds:60,enabled:true,next_run_at:clock});
 clock+=61000;const r=(await engine.runDue()).runs[0];
 const res=store.getReport(ctx,r.id).results[0].payload.result;assert.equal(res.assurance,'UNOBSERVABLE');assert.deepEqual(res.findings,[]);
 assert.equal(store.metrics(ctx).pending_claims,1,'kept pending for retry');
});

test('hosted signer: scheduled evidence is hosted_attested; caller fixtures are refused',async(t)=>{
 const {publicKey,privateKey}=generateKeyPairSync('ed25519');const kid='audital-hosted:test';
 const registry=loadTrustRegistry({schema:'audital.observe.trust-registry/v1',keys:[{kid,alg:'Ed25519',public_key_pem:publicKey.export({type:'spki',format:'pem'})}]});
 const signer=new HostedObserveSigner({privateKeyPem:privateKey.export({type:'pkcs8',format:'pem'}),kid,registry});
 let clock=Date.parse('2026-11-20T12:00:00Z');const gh=fakeGithub({42:{state:'closed',events:[]}});
 const {server,engine,store}=createObserveServer({tenantId:'t',projectId:'p',apiKey:key,hmacKey:hmac,now:()=>clock,signer,githubFetch:gh.fetcher});
 const root=await listen(server);t.after(()=>server.close());
 const post=(path,x)=>fetch(root+path,{method:'POST',headers:{'x-api-key':key,'content-type':'application/json'},body:JSON.stringify(x)});
 await post('/v1/connectors/github',{token:'github_pat_readonly_0123456789'});
 await post('/v1/otlp/traces',{resourceSpans:[{scopeSpans:[{spans:[toolSpan('1111111111111111','call_H',42,clock)]}]}]});
 const fx=await post('/v1/reconcile',{claim_id:'call_H',source:'LOCAL_FIXTURE',observation:{available:true,complete:true,observed_at:'2026-11-20T12:00:00Z',current_state:'closed',events:[]}});
 assert.equal(fx.status,403);assert.equal((await fx.json()).error,'LOCAL_FIXTURES_DISABLED_ON_HOSTED_SIGNER');
 clock+=61000;const r=(await engine.runDue()).runs[0];const pack=store.getReport(store.authenticate(key),r.id);
 assert.equal(pack.attestation,'hosted_attested');assert.deepEqual(pack.public_keys,{});
 assert.equal(verifyEnvelope(pack.results[0],{hostedRegistry:registry}).valid,true);assert.equal(verifyEnvelope(pack.results[0]).valid,false,'not pinned in shipped registry');
 assert.equal((await (await fetch(root+'/health')).json()).attestation,'hosted_attested');
});

test('cross-tenant access through the API is denied (dev store)',async(t)=>{
 const store=new DevTenantStore();const other='z'.repeat(40);
 const {server}=createObserveServer({tenantId:'A',projectId:'pa',apiKey:key,hmacKey:hmac,store,now:()=>Date.parse('2026-11-20T15:00:00Z')});store.provision('B','pb',other);
 const root=await listen(server);t.after(()=>server.close());
 const post=(path,x,auth)=>fetch(root+path,{method:'POST',headers:{'x-api-key':auth,'content-type':'application/json'},body:JSON.stringify(x)});
 await post('/v1/claims',{claim_id:'c',action:'close',target:'o/r#1',provider:'github',occurred_at:'2026-11-20T12:00:00Z'},key);
 const done=await (await post('/v1/reconcile',{claim_id:'c',source:'LOCAL_FIXTURE',observation:{available:false}},key)).json();
 assert.equal((await fetch(root+'/v1/evidence/'+done.id,{headers:{'x-api-key':other}})).status,404);
 assert.equal((await post('/v1/evidence/'+done.id+'/share',{ttl_seconds:60},other)).status,404);
 assert.equal((await post('/v1/reconcile',{claim_id:'c',source:'LOCAL_FIXTURE',observation:{available:false}},other)).status,404);
});

test('internal errors are not echoed to clients',async(t)=>{
 const store=new DevTenantStore();const {server}=createObserveServer({apiKey:key,hmacKey:hmac,store});
 store.listFindings=()=>{throw Object.assign(Error('relation "observe.findings" does not exist'),{code:'42P01'})};
 const root=await listen(server);t.after(()=>server.close());
 const r=await fetch(root+'/v1/findings',{headers:{'x-api-key':key}});assert.equal(r.status,500);assert.deepEqual(await r.json(),{error:'INTERNAL_ERROR'});
});

test('worker does not infer success when provider read fails',async()=>{
 const store=new DevTenantStore(),secret='r'.repeat(40);store.provision('t','p',secret);const ctx=store.authenticate(secret);
 store.saveClaim(ctx,{claim_id:'worker-2',provider:'github',target_hash:'abc',args_hmac:'x',action:'close',occurred_at:'2026-11-20T10:00:00Z',claimed_success:true,expected_state:'closed'},{target:'o/r#1',provider:'github'},{nextCheckAt:0});
 const signer=new ObserveSigner();signer.rotate();const worker=new ObserveWorker({store,signer,readObservation:async()=>{throw Error('provider unavailable')}});
 const r=await worker.tick(ctx,{id:'m2',provider:'github',enabled:true});const res=store.getReport(ctx,r.id).results[0].payload.result;
 assert.equal(res.assurance,'UNOBSERVABLE');assert.deepEqual(res.findings,[]);
 const stop=worker.start(ctx,{id:'m3',provider:'github',enabled:true,interval_seconds:60});assert.equal(stop(),true);assert.equal(worker.stop('m3'),false);
});

test('alert endpoint SSRF guard',()=>{
 for(const u of ['http://example.com/h','https://10.0.0.1/h','https://[::1]/h','https://metadata.internal/h','https://intranet/h','https://user:pw@example.com/h','https://api.stripe.com/v1/refunds'])assert.throws(()=>validateEndpointUrl('webhook',u),u);
 assert.throws(()=>validateEndpointUrl('slack','https://example.com/x'),/SLACK/);
 validateEndpointUrl('webhook','https://hooks.example.com/audital');validateEndpointUrl('slack','https://hooks.slack.com/services/a/b/c');
});
