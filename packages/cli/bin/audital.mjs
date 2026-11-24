#!/usr/bin/env node
import {readFileSync,writeFileSync,realpathSync} from 'node:fs';
import {randomBytes} from 'node:crypto';
import {fileURLToPath} from 'node:url';
import {resolve,dirname,join} from 'node:path';
import {parseSpansJSONL,hmacIdentifier,canonicalTarget,otelEvaluationLogs} from '../../otel-parser/src/index.mjs';
import {reconcile,findGhostWrites} from '../../recipes/src/reconcile.mjs';
import {readGithubIssue} from '../../recipes/src/github.mjs';
import {readStripeEvents} from '../../recipes/src/stripe.mjs';
import {ObserveSigner} from '../../recipes/src/signing.mjs';
import {githubCheckPayload,githubPrCommentPayload} from '../../recipes/src/ci.mjs';
import {randomUUID} from 'node:crypto';

function args(argv){let o={};for(let i=0;i<argv.length;i++){
 const x=argv[i];if(x==='reconcile')continue;
 if(x==='--demo'||x==='--otel-events'){o[x.slice(2)]=true;continue}
 if(!x.startsWith('--'))throw Error('UNRECOGNISED_ARGUMENT '+x);
 if(!argv[i+1]||argv[i+1].startsWith('--'))throw Error('MISSING_VALUE '+x);
 o[x.slice(2)]=argv[++i];
}return o}
function demoDir(){return resolve(dirname(fileURLToPath(import.meta.url)),'../../../examples/phantom-success-demo')}
function toObservation(fixture,target,key,provider='github'){
 const states=Object.fromEntries(Object.entries(fixture.states||{}).map(([k,v])=>[canonicalTarget(provider,k),v]));
 return {available:fixture.available===true,complete:fixture.complete===true,coverage_start:fixture.coverage_start,observed_at:fixture.observed_at,current_state:states[canonicalTarget(provider,target)],events:(fixture.events||[]).map(e=>({id:e.id,kind:e.kind,target_hash:hmacIdentifier(key,canonicalTarget(provider,e.target),'target'),time:e.time,actor_hash:hmacIdentifier(key,e.actor||'unknown','actor'),claim_id:e.claim_id,attributes:e.attributes}))};
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
  let observation=fixture?toObservation(fixture,lookup.target,key,publicClaim.provider):provider==='github'
   ?await readGithubIssue({target:lookup.target,token:env.GITHUB_READ_TOKEN,hmacKey:key,coverageStart:publicClaim.occurred_at}):await readStripeEvents({token:env.STRIPE_READ_KEY,hmacKey:key,coverageStart:publicClaim.occurred_at});
  if(!observation.complete)joined.complete=false;
  joined.events.push(...observation.events);
  const result=reconcile(publicClaim,observation,{now:Date.now(),graceMs:Number(opt['grace-ms']??60000)});
  results.push(result);
 }
 if(fixture){const all=toObservation(fixture,'',key,provider==='mock'?'github':provider);results.push(...findGhostWrites(parsed.map(x=>x.publicClaim),all));}
 // The CLI can only ever produce local_unattested evidence: integrity under an ephemeral key it generated itself.
 const signer=new ObserveSigner();const kid=signer.rotate();const packId=randomUUID();
 const pack={schema:'audital.observe.pack/v2',pack_id:packId,created_at:new Date().toISOString(),attestation:signer.attestation,kid,results:results.map(r=>signer.signResult(r)),public_keys:signer.exportPublicKeys(),limitations:['local_unattested: proves this file was not altered after signing under the embedded key; it is NOT third-party attestation','Read-only observed/correlated evidence does NOT prove exclusive causation','Fixture runs are synthetic; live provider history may be incomplete']};
 for(const r of results)io.log(`${r.assurance.padEnd(18)} ${r.findings.length?r.findings.join(', '):'(no discrepancy)'} ${r.claim_id||'(unclaimed event)'}\n  Can assert: ${r.asserts.join('; ')||'none'}\n  Cannot assert: ${r.cannot_assert.join('; ')}`);
 io.log(`Evidence pack ${packId} key: ${kid}; attestation: ${signer.attestation}; results: ${results.length}; fixture: ${!!fixture}`);
 if(opt.out)writeFileSync(opt.out,JSON.stringify(pack,null,2)+'\n',{mode:0o600});
 const link=opt['report-url']?{url:opt['report-url']}:null;
 if(opt['check-out'])writeFileSync(opt['check-out'],JSON.stringify(githubCheckPayload(results,opt['report-url'],{headSha:opt['head-sha']||null,packId,attestation:signer.attestation,link}),null,2)+'\n',{mode:0o600});
 if(opt['pr-comment-out'])writeFileSync(opt['pr-comment-out'],JSON.stringify(githubPrCommentPayload(results,{link,attestation:signer.attestation,packId}),null,2)+'\n',{mode:0o600});
 if(opt['otel-out'])writeFileSync(opt['otel-out'],JSON.stringify(otelEvaluationLogs(results,new Map(parsed.map(x=>[x.publicClaim.claim_id,x.publicClaim]))),null,2)+'\n',{mode:0o600});
 const failOn=(opt['fail-on']||'').split(',').filter(Boolean).map(x=>x.toUpperCase().replace(/-/g,'_'));
 return results.some(r=>r.findings.some(f=>failOn.some(x=>f.includes(x))))?3:0;
}
const invokedDirectly=(()=>{try{return realpathSync(fileURLToPath(import.meta.url))===realpathSync(process.argv[1]||'')}catch{return false}})();
if(invokedDirectly)run(process.argv.slice(2)).then(code=>{process.exitCode=code}).catch(e=>{console.error(`AUDITAL_CLI_ERROR: ${e.message}`);process.exitCode=2});
