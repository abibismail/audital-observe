import test from 'node:test';import assert from 'node:assert/strict';
import {reconcile,findGhostWrites} from '../src/reconcile.mjs';
import {ObserveSigner} from '../src/signing.mjs';
import {githubCheckPayload} from '../src/ci.mjs';
import {readGithubIssue} from '../src/github.mjs';
import {readStripeEvents} from '../src/stripe.mjs';
const c={claim_id:'c',target_hash:'hashed-a',args_hmac:'args',occurred_at:'2026-11-20T12:00:00Z',claimed_success:true,expected_state:'closed',provider:'github',action:'close'};
const base={available:true,complete:true,coverage_start:'2026-11-20T11:00:00Z',observed_at:'2026-11-20T12:05:00Z',current_state:'open',events:[]};
const event=(more={})=>({kind:'closed',target_hash:'hashed-a',time:'2026-11-20T12:01:00Z',...more});
test('phantom success requires grace window over and complete history',()=>{const x=reconcile(c,base,{now:Date.parse('2026-11-20T12:03:00Z')});assert.equal(x.assurance,'CONTRADICTED');assert.deepEqual(x.findings,['PHANTOM_SUCCESS'])});
test('eventual consistency postpones phantom',()=>{const x=reconcile(c,base,{now:Date.parse('2026-11-20T12:00:30Z')});assert.equal(x.assurance,'CLAIMED');assert.equal(x.findings.length,0)});
test('unavailable or incomplete becomes UNOBSERVABLE, not phantom',()=>{for(const b of [{...base,available:false},{...base,complete:false},{...base,coverage_start:'2026-11-20T12:05:00Z'}]){const r=reconcile(c,b);assert.equal(r.assurance,'UNOBSERVABLE');assert.equal(r.findings.length,0)}});
test('correlated event cannot claim exclusive causation',()=>{const x=reconcile(c,{...base,current_state:'closed',events:[event()]});assert.equal(x.assurance,'EFFECT_CORRELATED');assert.ok(x.cannot_assert.includes('exclusive causation'));assert.ok(x.cannot_assert.includes('no same-identity competitor'))});
test('state-only observation is not causality',()=>{const x=reconcile(c,{...base,current_state:'closed'});assert.equal(x.assurance,'EFFECT_OBSERVED');assert.ok(x.cannot_assert.includes('exclusive causation'))});
test('duplicate, late, partial effects flagged',()=>{const x=reconcile(c,{...base,current_state:'closed',events:[event(),event({time:'2026-11-20T12:20:00Z',attributes:{partial:'true'}})]});for(const a of ['DUPLICATE_EFFECT','LATE_EFFECT','PARTIAL_EFFECT'])assert.ok(x.findings.includes(a))});
test('wrong-target claim id is contradicted',()=>{const x=reconcile(c,{...base,events:[event({target_hash:'other',claim_id:'c'})]});assert.ok(x.findings.includes('WRONG_TARGET'))});
test('ghost write when provider changes without ingested claim',()=>{const x=findGhostWrites([c],{...base,events:[event({target_hash:'unknown'})]});assert.equal(x[0].findings[0],'GHOST_WRITE')});
test('failed claim but effect observed is ghost write',()=>{const x=reconcile({...c,claimed_success:false},{...base,current_state:'closed',events:[event()]});assert.ok(x.findings.includes('GHOST_WRITE'))});
test('signing rotation verifies old and new, Guard domain cannot masquerade',()=>{const s=new ObserveSigner();const k1=s.rotate();const p1=s.signResult(reconcile(c,base));const k2=s.rotate();const p2=s.signResult(reconcile(c,base));const keys=s.exportPublicKeys();assert.notEqual(k1,k2);assert.ok(ObserveSigner.verifyPack(p1,keys));assert.ok(ObserveSigner.verifyPack(p2,keys));assert.equal(ObserveSigner.verifyPack({...p1,domain:'audital.guard/v1'},keys),false);assert.equal(ObserveSigner.verifyPack({...p1,payload:{...p1.payload,domain:'audital.guard/v1'}},keys),false);assert.equal(ObserveSigner.verifyPack({...p1,signature:'abc'},keys),false)});
test('GitHub Checks are formatted only, never posted',()=>{let x=githubCheckPayload([reconcile(c,base)]);assert.equal(x.conclusion,'failure');assert.ok(x.output.title.includes('Audital'))});
test('GitHub connector only GETs and returns incomplete when insufficient coverage',async()=>{
 const seen=[],fetcher=async url=>{seen.push(String(url));return {ok:true,json:async()=>String(url).includes('/events')?[{id:1,event:'closed',created_at:'2026-11-20T12:03:00Z',actor:{login:'bot'}}]:{state:'closed'},headers:{get:()=>null}}};
 const x=await readGithubIssue({target:'org/repo#3',token:'read-only',hmacKey:'abcdefghijklmnop0123456789',coverageStart:'2026-11-20T12:00:00Z',fetcher});assert.equal(x.complete,false);assert.ok(seen.every(x=>x.startsWith('https://api.github.com/')))
});
test('Stripe paged event read remains conservative about history',async()=>{let fetcher=async()=>({ok:true,json:async()=>({data:[{id:'evt_test',created:1795190400,type:'charge.refunded',data:{object:{id:'re_test'}}}],has_more:false})});const x=await readStripeEvents({token:'rk_test',hmacKey:'abcdefghijklmnop0123456789',coverageStart:'2026-09-01T00:00:00Z',fetcher});assert.equal(x.complete,false)});
