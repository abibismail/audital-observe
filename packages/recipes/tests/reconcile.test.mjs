import test from 'node:test';import assert from 'node:assert/strict';
import {reconcile,findGhostWrites} from '../src/reconcile.mjs';
import {ObserveSigner} from '../src/signing.mjs';
import {githubCheckPayload,githubPrCommentPayload,slackAlertPayload,PR_COMMENT_MARKER} from '../src/ci.mjs';
import {readGithubIssue,writeCapableScopes} from '../src/github.mjs';
import {readStripeEvents} from '../src/stripe.mjs';
const HK='abcdefghijklmnop0123456789ABCDEFGH';
const c={claim_id:'c',target_hash:'hashed-a',args_hmac:'args',occurred_at:'2026-11-20T12:00:00Z',claimed_success:true,expected_state:'closed',provider:'github',action:'close'};
const base={available:true,complete:true,coverage_start:'2026-11-20T11:00:00Z',observed_at:'2026-11-20T12:05:00Z',current_state:'open',events:[]};
const event=(more={})=>({kind:'closed',target_hash:'hashed-a',time:'2026-11-20T12:01:00Z',...more});
test('phantom success requires grace window over and complete history',()=>{const x=reconcile(c,base,{now:Date.parse('2026-11-20T12:03:00Z')});assert.equal(x.assurance,'CONTRADICTED');assert.deepEqual(x.findings,['PHANTOM_SUCCESS'])});
test('eventual consistency postpones phantom',()=>{const x=reconcile(c,base,{now:Date.parse('2026-11-20T12:00:30Z')});assert.equal(x.assurance,'CLAIMED');assert.equal(x.findings.length,0)});
test('unavailable or incomplete becomes UNOBSERVABLE, not phantom',()=>{for(const b of [{...base,available:false},{...base,complete:false},{...base,coverage_start:'2026-11-20T12:05:00Z'}]){const r=reconcile(c,b);assert.equal(r.assurance,'UNOBSERVABLE');assert.equal(r.findings.length,0)}});
test('EFFECT_CORRELATED always carries both causation limits',()=>{const x=reconcile(c,{...base,current_state:'closed',events:[event()]});assert.equal(x.assurance,'EFFECT_CORRELATED');assert.ok(x.cannot_assert.includes('exclusive causation'));assert.ok(x.cannot_assert.includes('no same-identity competitor'))});
test('state-only observation is not causality',()=>{const x=reconcile(c,{...base,current_state:'closed'});assert.equal(x.assurance,'EFFECT_OBSERVED');assert.ok(x.cannot_assert.includes('exclusive causation'));assert.ok(x.cannot_assert.includes('no same-identity competitor'))});
test('duplicate, late, partial effects flagged',()=>{const x=reconcile(c,{...base,current_state:'closed',events:[event(),event({time:'2026-11-20T12:20:00Z',attributes:{partial:'true'}})]});for(const a of ['DUPLICATE_EFFECT','LATE_EFFECT','PARTIAL_EFFECT'])assert.ok(x.findings.includes(a))});
test('wrong-target claim id is contradicted',()=>{const x=reconcile(c,{...base,events:[event({target_hash:'other',claim_id:'c'})]});assert.ok(x.findings.includes('WRONG_TARGET'))});
test('ghost write when provider changes without ingested claim',()=>{const x=findGhostWrites([c],{...base,events:[event({target_hash:'unknown'})]});assert.equal(x[0].findings[0],'GHOST_WRITE')});
test('failed claim but effect observed is ghost write',()=>{const x=reconcile({...c,claimed_success:false},{...base,current_state:'closed',events:[event()]});assert.ok(x.findings.includes('GHOST_WRITE'))});
test('effect observed then reverted by someone else is CONTRADICTED but not PHANTOM_SUCCESS (v0.1 bug)',()=>{
 const x=reconcile(c,{...base,current_state:'open',events:[event(),event({kind:'reopened',time:'2026-11-20T12:02:00Z'})]},{now:Date.parse('2026-11-20T12:10:00Z')});
 assert.equal(x.assurance,'CONTRADICTED');assert.ok(!x.findings.includes('PHANTOM_SUCCESS'));assert.ok(x.reason_codes.includes('EFFECT_OBSERVED_THEN_STATE_DIVERGED'));
});
test('local signer: rotation verifies old and new, Guard domain cannot masquerade, attestation is local_unattested',()=>{const s=new ObserveSigner();const k1=s.rotate();const p1=s.signResult(reconcile(c,base));const k2=s.rotate();const p2=s.signResult(reconcile(c,base));const keys=s.exportPublicKeys();assert.notEqual(k1,k2);assert.equal(p1.attestation,'local_unattested');assert.equal(p1.payload.attestation,'local_unattested');assert.equal(p1.v,2);assert.ok(ObserveSigner.verifyPack(p1,keys));assert.ok(ObserveSigner.verifyPack(p2,keys));assert.equal(ObserveSigner.verifyPack({...p1,domain:'audital.guard/v1'},keys),false);assert.equal(ObserveSigner.verifyPack({...p1,payload:{...p1.payload,domain:'audital.guard/v1'}},keys),false);assert.equal(ObserveSigner.verifyPack({...p1,signature:'abc'},keys),false)});
test('GitHub Check + PR comment payloads: crisp, linked, formatted only',()=>{
 const results=[reconcile(c,base),reconcile({...c,claim_id:'ok|pipe'},{...base,current_state:'closed',events:[event()]})];
 const link={url:'https://observe.example/v1/shares/tok',expires_at:'2026-11-21T00:00:00.000Z'};
 const x=githubCheckPayload(results,null,{headSha:'a'.repeat(40),packId:'p1',attestation:'local_unattested',link});
 assert.equal(x.conclusion,'failure');assert.equal(x.head_sha,'a'.repeat(40));assert.equal(x.details_url,link.url);assert.equal(x.external_id,'p1');
 assert.ok(x.output.title.includes('Audital'));assert.match(x.output.summary,/expires 2026-11-21/);assert.match(x.output.summary,/local, unattested/);assert.match(x.output.text,/PHANTOM_SUCCESS/);
 const pr=githubPrCommentPayload(results,{link,attestation:'hosted_attested',packId:'p1'});
 assert.ok(pr.body.startsWith(PR_COMMENT_MARKER));assert.match(pr.body,/ok\\\|pipe/);assert.match(pr.body,/Signed evidence pack\]\(https:\/\/observe\.example/);assert.match(pr.body,/exclusive causation/);
 const sl=slackAlertPayload(results,{link});assert.match(sl.text,/1 priority/);assert.match(JSON.stringify(sl.blocks),/Signed evidence pack/);
});
const res=(body,{status=200,headers={}}={})=>({ok:status>=200&&status<300,status,json:async()=>body,headers:{get:k=>headers[k.toLowerCase()]??null}});
test('GitHub connector only GETs and returns incomplete when insufficient coverage',async()=>{
 const seen=[],fetcher=async(url,init)=>{seen.push([String(url),init.method]);return res(String(url).includes('/events')?[{id:1,event:'closed',created_at:'2026-11-20T12:03:00Z',actor:{login:'bot'}}]:{state:'closed'})};
 const x=await readGithubIssue({target:'org/repo#3',token:'read-only',hmacKey:HK,coverageStart:'2026-11-20T12:00:00Z',fetcher});
 assert.equal(x.available,true);assert.equal(x.complete,false);assert.ok(seen.every(([u,m])=>u.startsWith('https://api.github.com/')&&m==='GET'))
});
test('GitHub connector: Link-header pagination, coverage anchored at issue created_at',async()=>{
 const pages={1:[{id:1,event:'labeled',created_at:'2026-11-20T12:30:00Z'}],2:[{id:2,event:'closed',created_at:'2026-11-20T12:31:00Z'}]};
 const fetcher=async url=>{const u=new URL(url);if(!u.pathname.endsWith('/events'))return res({state:'closed',created_at:'2026-11-01T00:00:00Z'});
  const p=Number(u.searchParams.get('page')||1);return res(pages[p],{headers:p===1?{link:`<https://api.github.com/repos/o/r/issues/1/events?per_page=1&page=2>; rel="next", <https://api.github.com/repos/o/r/issues/1/events?per_page=1&page=2>; rel="last"`}:{}})};
 const x=await readGithubIssue({target:'O/R#1',token:'t',hmacKey:HK,coverageStart:'2026-11-20T12:00:00Z',fetcher,perPage:1});
 assert.equal(x.complete,true);assert.equal(x.pages,2);assert.equal(x.events.length,2);assert.equal(x.coverage_start,'2026-11-01T00:00:00.000Z');
 const r=reconcile({...c,target_hash:x.events[0].target_hash},x,{now:Date.parse('2026-11-20T13:00:00Z')});assert.equal(r.assurance,'EFFECT_CORRELATED');
});
test('GitHub connector: pagination cut off by maxPages is incomplete -> UNOBSERVABLE',async()=>{
 const fetcher=async url=>String(url).includes('/events')?res([{id:Math.random(),event:'labeled',created_at:'2026-11-20T12:30:00Z'}],{headers:{link:'<https://api.github.com/repos/o/r/issues/1/events?page=9>; rel="next"'}}):res({state:'closed',created_at:'2026-11-01T00:00:00Z'});
 const x=await readGithubIssue({target:'o/r#1',token:'t',hmacKey:HK,coverageStart:'2026-11-20T12:00:00Z',fetcher,maxPages:3});
 assert.equal(x.complete,false);assert.equal(reconcile(c,x).assurance,'UNOBSERVABLE');
});
test('GitHub connector: primary rate limit waits until reset then retries; secondary uses retry-after',async()=>{
 let n=0;const slept=[];const now=Date.parse('2026-11-20T12:00:00Z');
 const fetcher=async url=>{n++;if(n===1)return res({message:'API rate limit exceeded'},{status:403,headers:{'x-ratelimit-remaining':'0','x-ratelimit-reset':String(now/1000+5)}});
  if(n===2)return res({message:'secondary'},{status:429,headers:{'retry-after':'2'}});
  return String(url).includes('/events')?res([],{headers:{'x-ratelimit-remaining':'4999','x-ratelimit-reset':String(now/1000+3600)}}):res({state:'open',created_at:'2026-11-01T00:00:00Z'},{headers:{'x-ratelimit-remaining':'4998'}})};
 const x=await readGithubIssue({target:'o/r#1',token:'t',hmacKey:HK,coverageStart:'2026-11-20T11:00:00Z',fetcher,sleep:async ms=>{slept.push(ms)},now:()=>now});
 assert.equal(x.available,true);assert.deepEqual(slept,[6000,2000]);assert.equal(x.retries,2);assert.equal(x.rate_limit.remaining,4999);
});
test('GitHub connector: rate limit beyond maxWait degrades to UNOBSERVABLE with reason, never PHANTOM',async()=>{
 const now=Date.parse('2026-11-20T12:00:00Z');
 const fetcher=async()=>res({},{status:403,headers:{'x-ratelimit-remaining':'0','x-ratelimit-reset':String(now/1000+3000)}});
 const x=await readGithubIssue({target:'o/r#1',token:'t',hmacKey:HK,fetcher,now:()=>now,sleep:async()=>{},maxWaitMs:1000});
 assert.equal(x.available,false);assert.equal(x.reason,'GITHUB_RATE_LIMITED');assert.equal(reconcile(c,x).assurance,'UNOBSERVABLE');
});
test('GitHub connector: budget floor stops spending before reset',async()=>{
 const now=Date.parse('2026-11-20T12:00:00Z');let n=0;
 const fetcher=async()=>{n++;return res({state:'open'},{headers:{'x-ratelimit-remaining':'3','x-ratelimit-reset':String(now/1000+600)}})};
 const x=await readGithubIssue({target:'o/r#1',token:'t',hmacKey:HK,fetcher,now:()=>now,minRemaining:5});
 assert.equal(n,1);assert.equal(x.reason,'GITHUB_RATE_BUDGET_EXHAUSTED');
});
test('GitHub connector refuses classic tokens with write-capable scopes',async()=>{
 assert.deepEqual(writeCapableScopes('read:org, read:user'),[]);assert.deepEqual(writeCapableScopes('repo, read:org'),['repo']);assert.deepEqual(writeCapableScopes(''),[]);
 const fetcher=async()=>res({state:'open'},{headers:{'x-oauth-scopes':'repo, workflow'}});
 await assert.rejects(readGithubIssue({target:'o/r#1',token:'t',hmacKey:HK,fetcher}),/WRITE_CAPABLE_TOKEN_REFUSED/);
});
test('GitHub connector requires a token or explicit anonymous mode, and an HMAC key',async()=>{
 await assert.rejects(readGithubIssue({target:'o/r#1',hmacKey:HK}),/READ_TOKEN_AND_HMAC_REQUIRED/);
 await assert.rejects(readGithubIssue({target:'o/r#1',token:'t'}),/READ_TOKEN_AND_HMAC_REQUIRED/);
 let auth='unset';const x=await readGithubIssue({target:'o/r#1',anonymous:true,hmacKey:HK,coverageStart:'2026-11-20T00:00:00Z',fetcher:async(u,i)=>{auth=i.headers.Authorization;return res(String(u).includes('/events')?[]:{state:'open',created_at:'2026-11-01T00:00:00Z'})}});
 assert.equal(auth,undefined);assert.equal(x.complete,true);
});
test('Stripe paged event read remains conservative about history (mocked)',async()=>{let fetcher=async()=>({ok:true,json:async()=>({data:[{id:'evt_test',created:1795190400,type:'charge.refunded',data:{object:{id:'re_test'}}}],has_more:false})});const x=await readStripeEvents({token:'rk_test_mock',hmacKey:HK,coverageStart:'2026-09-01T00:00:00Z',fetcher});assert.equal(x.complete,false)});
test('GitHub connector follows numeric /repositories/<id> Link pagination (seen live) but refuses foreign origins',async()=>{
 const fetcher=async url=>{const u=new URL(url);if(!u.pathname.includes('/events'))return res({state:'closed',created_at:'2026-11-01T00:00:00Z'});
  if(u.pathname.startsWith('/repos/'))return res([{id:1,event:'closed',created_at:'2026-11-20T12:01:00Z'}],{headers:{link:'<https://api.github.com/repositories/212613049/issues/1/events?per_page=1&page=2>; rel="next"'}});
  return res([{id:2,event:'labeled',created_at:'2026-11-20T12:02:00Z'}])};
 const x=await readGithubIssue({target:'o/r#1',token:'t',hmacKey:HK,coverageStart:'2026-11-20T12:00:00Z',fetcher,perPage:1});
 assert.equal(x.complete,true);assert.equal(x.events.length,2);
 const evil=async url=>String(url).includes('/events')?res([],{headers:{link:'<https://evil.example/repos/o/r/issues/1/events?page=2>; rel="next"'}}):res({state:'open',created_at:'2026-11-01T00:00:00Z'});
 const y=await readGithubIssue({target:'o/r#1',token:'t',hmacKey:HK,fetcher:evil});assert.equal(y.available,false);assert.equal(y.reason,'PAGINATION_ORIGIN_DENIED');
});
