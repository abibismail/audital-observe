#!/usr/bin/env node
import {readFileSync,writeFileSync} from 'node:fs';
import {randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {resolve,dirname,join} from 'node:path';
import {parseSpansJSONL,hmacIdentifier,otelEvaluationEvent} from '../../otel-parser/src/index.mjs';
import {reconcile,findGhostWrites} from '../../recipes/src/reconcile.mjs';
import {readGithubIssue} from '../../recipes/src/github.mjs';
import {readStripeEvents} from '../../recipes/src/stripe.mjs';
import {ObserveSigner} from '../../recipes/src/signing.mjs';
import {githubCheckPayload} from '../../recipes/src/ci.mjs';

function args(argv){let o={};for(let i=0;i<argv.length;i++){
 const x=argv[i];if(x==='reconcile')continue;
 if(x==='--demo'||x==='--otel-events'){o[x.slice(2)]=true;continue}
 if(!x.startsWith('--'))throw Error('UNRECOGNISED_ARGUMENT '+x);
 if(!argv[i+1]||argv[i+1].startsWith('--'))throw Error('MISSING_VALUE '+x);
 o[x.slice(2)]=argv[++i];
}return o}
function demoDir(){return resolve(dirname(fileURLToPath(import.meta.url)),'../../../examples/phantom-success-demo')}
function toObservation(fixture,target,key){
 return {available:fixture.available===true,complete:fixture.complete===true,coverage_start:fixture.coverage_start,observed_at:fixture.observed_at,current_state:fixture.states?.[target],events:(fixture.events||[]).map(e=>({id:e.id,kind:e.kind,target_hash:hmacIdentifier(key,e.target,'target'),time:e.time,actor_hash:hmacIdentifier(key,e.actor||'unknown','actor'),claim_id:e.claim_id,attributes:e.attributes}))};
}
export async function run(argv,env=process.env,io=console){
 const opt=args(argv);const demo=!!opt.demo;const base=demoDir();
 const claimsPath=opt.claims||join(base,'spans.jsonl');const provider=opt.provider||'github';
 if(!['github','stripe','mock'].includes(provider))throw Error('UNKNOWN_PROVIDER');
 const fixture=demo||opt.fixture?JSON.parse(readFileSync(opt.fixture||join(base,'provider-github.json'),'utf8')):null;
 const key=env.AUDITAL_HMAC_KEY||randomBytes(32).toString('hex');
 if(!env.AUDITAL_HMAC_KEY)io.error('NOTICE: ephemeral HMAC key; cross-run hashes will differ. Set AUDITAL_HMAC_KEY for stable project joins.');
 const parsed=parseSpansJSONL(readFileSync(claimsPath,'utf8'),key);
 const results=[];let joined={available:true,complete:true,observed_at:new Date().toISOString(),events:[]};
 for(const {publicClaim,lookup} of parsed){
  if(provider!=='mock'&&publicClaim.provider!==provider)throw Error('PROVIDER_MISMATCH');
  let observation=fixture?toObservation(fixture,lookup.target,key):provider==='github'
   ?await readGithubIssue({target:lookup.target,token:env.GITHUB_READ_TOKEN,hmacKey:key,coverageStart:publicClaim.occurred_at}):await readStripeEvents({token:env.STRIPE_READ_KEY,hmacKey:key,coverageStart:publicClaim.occurred_at});
  if(!observation.complete)joined.complete=false;
  joined.events.push(...observation.events);
  const result=reconcile(publicClaim,observation,{now:Date.now(),graceMs:Number(opt['grace-ms']??60000)});
  results.push(result);
 }
 if(fixture){const all=toObservation(fixture,'',key);results.push(...findGhostWrites(parsed.map(x=>x.publicClaim),all));}
 const signer=new ObserveSigner();const kid=signer.rotate();
 const pack={schema:'audital.observe.pack/v1',key_id:kid,results:results.map(r=>signer.signResult(r)),public_keys:signer.exportPublicKeys(),limitations:['Read-only observed/correlated evidence does NOT prove exclusive causation','Fixture runs are synthetic; live provider history may be incomplete']};
 for(const r of results)io.log(`${r.assurance.padEnd(18)} ${r.findings.length?r.findings.join(', '):'(no discrepancy)'} ${r.claim_id||'(unclaimed event)'}\n  Can assert: ${r.asserts.join('; ')||'none'}\n  Cannot assert: ${r.cannot_assert.join('; ')}`);
 io.log(`Evidence pack key: ${kid}; results: ${results.length}; fixture: ${!!fixture}`);
 if(opt.out)writeFileSync(opt.out,JSON.stringify(pack,null,2)+'\n',{mode:0o600});
 if(opt['check-out'])writeFileSync(opt['check-out'],JSON.stringify(githubCheckPayload(results,opt['report-url']),null,2)+'\n',{mode:0o600});
 if(opt['otel-out'])writeFileSync(opt['otel-out'],results.map(otelEvaluationEvent).map(JSON.stringify).join('\n')+'\n',{mode:0o600});
 const failOn=(opt['fail-on']||'').split(',').filter(Boolean).map(x=>x.toUpperCase().replace(/-/g,'_'));
 return results.some(r=>r.findings.some(f=>failOn.some(x=>f.includes(x))))?3:0;
}
if(import.meta.url===`file://${process.argv[1]}`)run(process.argv.slice(2)).then(code=>{process.exitCode=code}).catch(e=>{console.error(`AUDITAL_CLI_ERROR: ${e.message}`);process.exitCode=2});
