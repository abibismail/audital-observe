// OPT-IN live GitHub integration test: `npm run test:live-github`.
// Requires a real issue/PR and EITHER a read-only token OR explicit anonymous mode (public repos only):
//   AUDITAL_LIVE_GITHUB_ISSUE=owner/repo#n            (a CLOSED issue/PR with >= 2 events, e.g. cli/cli#1)
//   AUDITAL_LIVE_GITHUB_TOKEN=<fine-grained token, Issues:read + Metadata:read ONLY>
//   or AUDITAL_LIVE_GITHUB_ANONYMOUS=1               (no credential at all; 60 req/h budget)
//   AUDITAL_LIVE_GITHUB_PER_PAGE=5                    (small page size forces real Link-header pagination)
// Spends roughly 15-20 GET requests. Never writes. Classic tokens with write scopes are refused.
import test from 'node:test';import assert from 'node:assert/strict';
import {readGithubIssue,GithubReader,parseGithubTarget} from '../../../../packages/recipes/src/github.mjs';
import {reconcile} from '../../../../packages/recipes/src/reconcile.mjs';
import {hmacIdentifier,parseClaim} from '../../../../packages/otel-parser/src/index.mjs';
import {createObserveServer} from '../../src/server.mjs';

const ISSUE=process.env.AUDITAL_LIVE_GITHUB_ISSUE,TOKEN=process.env.AUDITAL_LIVE_GITHUB_TOKEN||null,ANON=process.env.AUDITAL_LIVE_GITHUB_ANONYMOUS==='1';
const PER_PAGE=Number(process.env.AUDITAL_LIVE_GITHUB_PER_PAGE||5);
const skip=(!ISSUE||(!TOKEN&&!ANON))&&'set AUDITAL_LIVE_GITHUB_ISSUE and AUDITAL_LIVE_GITHUB_TOKEN (read-only) or AUDITAL_LIVE_GITHUB_ANONYMOUS=1';
const HK='live-test-hmac-key-'+'x'.repeat(24);
const auth=TOKEN?{token:TOKEN}:{anonymous:true};
const methods=[];const fetcher=async(url,init)=>{methods.push(init.method);return fetch(url,init);};
let small,big;

test('live: read-only posture — token is not write-capable; every request is GET',{skip},async()=>{
 small=await readGithubIssue({target:ISSUE,...auth,hmacKey:HK,fetcher,perPage:PER_PAGE,maxPages:100,coverageStart:'2000-01-01T00:00:00Z'});
 assert.equal(small.available,true,`read failed: ${small.reason}`);
 assert.ok(methods.length>0&&methods.every(m=>m==='GET'));
 console.error(`[live] ${ISSUE}: state=${small.current_state} events=${small.events.length} pages=${small.pages} requests=${small.requests} rate=${JSON.stringify(small.rate_limit)} auth=${TOKEN?'token':'anonymous'}`);
});
test('live: real Link-header pagination enumerates exactly the same events as a single large page',{skip},async()=>{
 assert.ok(small.events.length>=2,'pick an issue with >= 2 events');
 assert.equal(small.complete,true);assert.equal(small.pages,Math.ceil(small.events.length/PER_PAGE));assert.ok(small.pages>1,'pagination exercised');
 big=await readGithubIssue({target:ISSUE,...auth,hmacKey:HK,fetcher,perPage:100,maxPages:100,coverageStart:'2000-01-01T00:00:00Z'});
 const ids=o=>o.events.map(e=>e.id).sort();
 // Eventual consistency between two reads: the later read may only ADD events, never lose them.
 const later=new Set(ids(big));for(const id of ids(small))assert.ok(later.has(id),`event ${id} vanished between reads`);
 assert.ok(big.events.length>=small.events.length);
 assert.equal(new Set(ids(small)).size,small.events.length,'no duplicate events across pages');
});
test('live: truncated pagination is reported incomplete and reconciles to UNOBSERVABLE, never PHANTOM',{skip},async()=>{
 const cut=await readGithubIssue({target:ISSUE,...auth,hmacKey:HK,fetcher,perPage:1,maxPages:1,coverageStart:'2000-01-01T00:00:00Z'});
 assert.equal(cut.available,true);assert.equal(cut.complete,false);
 const claim={claim_id:'live-cut',target_hash:hmacIdentifier(HK,parseGithubTarget(ISSUE).canonical,'target'),args_hmac:'a',occurred_at:new Date(Date.now()-3600000).toISOString(),claimed_success:true,expected_state:'closed',provider:'github',action:'x'};
 const r=reconcile(claim,cut);assert.equal(r.assurance,'UNOBSERVABLE');assert.deepEqual(r.findings,[]);
});
test('live: rate-limit headers are parsed and the budget floor stops spending after one request',{skip},async()=>{
 const rl=small.rate_limit;assert.ok(Number.isFinite(rl.limit)&&Number.isFinite(rl.remaining),JSON.stringify(rl));assert.ok(Date.parse(rl.reset_at)>Date.now()-60000);
 const reader=new GithubReader({...auth,fetcher,minRemaining:rl.limit+1});
 const x=await readGithubIssue({target:ISSUE,reader,hmacKey:HK,perPage:100});
 assert.equal(x.available,false);assert.equal(x.reason,'GITHUB_RATE_BUDGET_EXHAUSTED');assert.equal(reader.requests,1);
});
test('live: consistency windows on real data — CLAIMED inside the window, decided after it',{skip},async()=>{
 const t=parseGithubTarget(ISSUE),th=hmacIdentifier(HK,t.canonical,'target');
 const state=big.current_state,closedAt=big.events.filter(e=>e.kind==='closed').map(e=>e.time).sort().at(-1);
 const other=state==='closed'?'open':'closed';
 const base={target_hash:th,args_hmac:'a',claimed_success:true,provider:'github',action:'github.issue.update'};
 const now=Date.now();
 const fresh=reconcile({...base,claim_id:'fresh',occurred_at:new Date(now-5000).toISOString(),expected_state:other},big,{now,graceMs:60000});
 assert.equal(fresh.assurance,'CLAIMED','inside the eventual-consistency window we wait, not accuse');
 const stale=reconcile({...base,claim_id:'stale',occurred_at:new Date(now-5000).toISOString(),expected_state:other},big,{now:now+61000,graceMs:60000});
 assert.equal(stale.assurance,'CONTRADICTED');assert.ok(stale.findings.includes('PHANTOM_SUCCESS'));
 if(state==='closed'&&closedAt){
  const real=reconcile({...base,claim_id:'real',occurred_at:closedAt,expected_state:'closed'},big,{now,graceMs:60000,deadlineMs:3600000});
  assert.equal(real.assurance,'EFFECT_CORRELATED');assert.ok(real.cannot_assert.includes('exclusive causation')&&real.cannot_assert.includes('no same-identity competitor'));
 }
});
test('live: continuous engine end-to-end against real GitHub (dev store, scheduled read-only tick)',{skip},async(t)=>{
 let clock=Date.now();
 const readers=TOKEN?null:{github:async({claim,lookup,hmacKey})=>readGithubIssue({target:lookup.target,anonymous:true,hmacKey,coverageStart:claim.occurred_at,fetcher})};
 const {server,engine,store}=createObserveServer({apiKey:'live-'+'k'.repeat(30),hmacKey:HK,now:()=>clock,githubFetch:fetcher,...(readers?{readers}:{})});
 t.after(()=>server.close());const ctx=store.authenticate('live-'+'k'.repeat(30));
 if(TOKEN)store.saveProviderSecret(ctx,'github',TOKEN);
 const c=parseClaim({claim_id:'live-engine',action:'github.issue.close',provider:'github',target:ISSUE,occurred_at:new Date(clock-120000).toISOString(),claimed_success:true,expected_state:big.current_state},(await import('../../../../packages/otel-parser/src/index.mjs')).deriveProjectKey(HK,ctx.tenantId,ctx.projectId));
 store.saveClaim(ctx,c.publicClaim,c.lookup,{nextCheckAt:clock});store.addMonitor(ctx,{provider:'github',interval_seconds:300,enabled:true,next_run_at:clock});
 const run=(await engine.runDue()).runs[0];assert.equal(run.status,'RECORDED',JSON.stringify(run));
 const result=store.getReport(ctx,run.id).results[0].payload.result;
 console.error(`[live] engine result: ${result.assurance} findings=${JSON.stringify(result.findings)} reasons=${JSON.stringify(result.reason_codes)}`);
 assert.ok(['EFFECT_OBSERVED','EFFECT_CORRELATED'].includes(result.assurance),'claim matching real final state is observed/correlated');
 assert.ok(methods.every(m=>m==='GET'));
});
