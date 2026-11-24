// Repository-wide strict invariants (v0.2). These are deliberately static + runtime checks.
import test from 'node:test';import assert from 'node:assert/strict';
import {readFileSync,readdirSync,statSync,mkdtempSync,rmSync} from 'node:fs';import {join,relative} from 'node:path';import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {ASSURANCE} from '../packages/observe-contract/dist/index.js';
import {reconcile} from '../packages/recipes/src/reconcile.mjs';
import {readStripeEvents} from '../packages/recipes/src/stripe.mjs';
import {deliverAlert} from '../apps/api/src/alerts.mjs';
const ROOT=fileURLToPath(new URL('..',import.meta.url));
const GUARD_WORD=['VERI','FIED'].join('');
function walk(dir,out=[]){for(const n of readdirSync(dir)){if(['node_modules','.git'].includes(n))continue;const p=join(dir,n);statSync(p).isDirectory()?walk(p,out):out.push(p);}return out;}
const files=walk(ROOT).map(p=>relative(ROOT,p));
const read=f=>readFileSync(join(ROOT,f),'utf8');
const src=files.filter(f=>/^(packages\/[^/]+\/(src|bin)|apps\/api\/src)\/.*\.(mjs|ts|js)$/.test(f));

test('zero Guard dependencies: no package, lockfile entry or import references Guard',()=>{
 for(const f of files.filter(f=>f.endsWith('package.json'))){const p=JSON.parse(read(f));
  for(const k of ['dependencies','devDependencies','peerDependencies','optionalDependencies'])for(const d of Object.keys(p[k]||{}))assert.ok(!/guard/i.test(d),`${f}: ${d}`);}
 const lock=JSON.parse(read('package-lock.json'));for(const k of Object.keys(lock.packages||{}))assert.ok(!/guard/i.test(k),`lockfile: ${k}`);
 for(const f of src)for(const m of read(f).matchAll(/(?:import|from)\s*\(?\s*['"]([^'"]+)['"]/g))assert.ok(!/guard/i.test(m[1]),`${f} imports ${m[1]}`);
});
test('the Guard-only status never exists in any schema, SQL migration, signer or contract build',()=>{
 const guarded=files.filter(f=>/(\.schema\.json|\.sql)$/.test(f)||/^packages\/observe-contract\/(src|dist|trust)\//.test(f)||/^packages\/recipes\/src\/(signing|canonical)\.mjs$/.test(f)||f==='apps/api/src/evidence.mjs');
 assert.ok(guarded.length>=10,`scanned ${guarded.length}`);
 for(const f of guarded)assert.ok(!read(f).includes(GUARD_WORD),`${f} contains the Guard-only word`);
 assert.ok(!ASSURANCE.includes(GUARD_WORD));
});
test('zero write credentials: only the notification dispatcher issues a non-GET request, and never to provider hosts',async()=>{
 const writers=src.filter(f=>/method\s*:\s*['"](POST|PUT|PATCH|DELETE)['"]/i.test(read(f)));
 assert.deepEqual(writers,['apps/api/src/alerts.mjs']);
 for(const f of ['packages/recipes/src/github.mjs','packages/recipes/src/stripe.mjs'])assert.match(read(f),/method:'GET'/,f);
 for(const u of ['https://api.github.com/repos/o/r/issues/1/comments','https://api.stripe.com/v1/refunds'])
  await assert.rejects(deliverAlert({kind:'webhook',url:u,secret:'s'.repeat(32)},{},{fetcher:async()=>{throw Error('must not be called')}}),/PROVIDER_HOST_FORBIDDEN/);
 await assert.rejects(readStripeEvents({token:'sk_live_xxxxxxxx',hmacKey:'k'.repeat(40)}),/RESTRICTED_READ_KEY_REQUIRED/);
 for(const f of src)assert.ok(!/process\.env\.[A-Z_]*(WRITE|ADMIN_TOKEN)[A-Z_]*|STRIPE_SECRET_KEY|GITHUB_WRITE/.test(read(f)),`${f} reads a write credential`);
 assert.ok(!/sk_live|ghp_[A-Za-z0-9]{20}|github_pat_[A-Za-z0-9_]{30}/.test(read('.env.example')));
 // The GitHub Check / PR comment module only formats: it has no network call at all.
 assert.ok(!/fetch\(|https?\.request/.test(read('packages/recipes/src/ci.mjs')));
});
test('EFFECT_CORRELATED / EFFECT_OBSERVED always carry both causation limits (randomized)',()=>{
 const kinds=['closed','reopened','labeled','effect','updated','refund'],states=['open','closed',undefined];let seen=0;
 for(let i=0;i<3000;i++){
  const r=Math.random,claim={claim_id:'c'+i,target_hash:'t',args_hmac:'a',occurred_at:'2026-11-20T12:00:00Z',claimed_success:r()<0.7,expected_state:r()<0.5?'closed':'open',provider:'github',action:'x'};
  const events=Array.from({length:Math.floor(r()*4)},()=>({kind:kinds[Math.floor(r()*kinds.length)],target_hash:r()<0.8?'t':'u',time:new Date(Date.parse(claim.occurred_at)+Math.floor((r()-0.2)*600000)).toISOString(),...(r()<0.1?{claim_id:claim.claim_id}:{}),...(r()<0.1?{attributes:{partial:'true'}}:{})}));
  const x=reconcile(claim,{available:r()<0.9,complete:r()<0.9,coverage_start:'2026-11-20T11:00:00Z',observed_at:'2026-11-20T12:30:00Z',current_state:states[Math.floor(r()*3)],events},{now:Date.parse('2026-11-20T12:00:00Z')+Math.floor(r()*600000)});
  if(x.assurance==='EFFECT_CORRELATED'||x.assurance==='EFFECT_OBSERVED'){seen++;assert.ok(x.cannot_assert.includes('exclusive causation')&&x.cannot_assert.includes('no same-identity competitor'),JSON.stringify(x));}
  if(!x.observation_complete)assert.ok(['UNOBSERVABLE','CLAIMED'].includes(x.assurance));
 }
 assert.ok(seen>50,`exercised ${seen} correlated/observed results`);
});
test('the CLI can only emit local_unattested evidence',async()=>{
 const cli=read('packages/cli/bin/audital.mjs');assert.ok(!/HostedObserveSigner|hosted_attested/.test(cli));
 const {run}=await import('../packages/cli/bin/audital.mjs');const dir=mkdtempSync(join(tmpdir(),'audital-cli-'));
 try{
  const out=join(dir,'pack.json'),pr=join(dir,'pr.json'),otel=join(dir,'otel.json');
  const code=await run(['reconcile','--demo','--out',out,'--pr-comment-out',pr,'--otel-out',otel,'--fail-on','phantom'],{AUDITAL_HMAC_KEY:'k'.repeat(40)},{log(){},error(){}});
  assert.equal(code,3);
  const pack=JSON.parse(readFileSync(out,'utf8'));assert.equal(pack.attestation,'local_unattested');
  assert.ok(pack.results.length>=3&&pack.results.every(e=>e.attestation==='local_unattested'&&e.payload.attestation==='local_unattested'&&e.v===2));
  assert.match(JSON.parse(readFileSync(pr,'utf8')).body,/local, unattested/);
  assert.equal(JSON.parse(readFileSync(otel,'utf8')).resourceLogs[0].scopeLogs[0].logRecords[0].eventName,'gen_ai.evaluation.result');
  assert.ok(!readFileSync(out,'utf8').includes('acme/sandbox'),'no raw targets in evidence');
 }finally{rmSync(dir,{recursive:true});}
});
