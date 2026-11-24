import test from 'node:test';import assert from 'node:assert/strict';import {createHash} from 'node:crypto';
import {parseSpansJSONL,parseOTLPJson,parseOTLPTraces,parseOTLPLogs,parseClaim,hmacIdentifier,deriveProjectKey,canonicalTarget,otelEvaluationEvent,otelEvaluationLogs,EVALUATION_NAME} from '../src/index.mjs';
const key='0123456789abcdefghijklmnopqrstuvwxyz';
const s=v=>({stringValue:v});
const attrs=o=>Object.entries(o).map(([k,v])=>({key:k,value:typeof v==='boolean'?{boolValue:v}:typeof v==='number'?{intValue:String(v)}:s(v)}));
const traces=spans=>({resourceSpans:[{resource:{attributes:attrs({'service.name':'agent-svc'})},scopeSpans:[{spans}]}]});
const T='5b8efff798038103d269b633813fc60c',S='eee19b7ec3c1b174',S2='eee19b7ec3c1b175';

test('keyed identifiers differ between keys; short keys refused',()=>{assert.notEqual(hmacIdentifier(key,'account-123'),hmacIdentifier(key+'x','account-123'));assert.throws(()=>hmacIdentifier('short-key-only-20chr','x'),/HMAC_KEY_REQUIRED/)});
test('per-project keys: same target in two projects never joins',()=>{
 const a=deriveProjectKey(key,'t1','p1'),b=deriveProjectKey(key,'t1','p2'),c=deriveProjectKey(key,'t2','p1');
 assert.notEqual(hmacIdentifier(a,'org/repo#1'),hmacIdentifier(b,'org/repo#1'));assert.notEqual(hmacIdentifier(a,'org/repo#1'),hmacIdentifier(c,'org/repo#1'));
 assert.equal(hmacIdentifier(a,'org/repo#1'),hmacIdentifier(deriveProjectKey(key,'t1','p1'),'org/repo#1'));
});
test('small-domain identifiers cannot be reversed by enumeration without the key',()=>{
 const {publicClaim}=parseClaim({claim_id:'c1',action:'github.issue.close',provider:'github',target:'acme/sandbox#123',args:{issue:123},occurred_at:'2026-11-20T00:00:00Z'},key);
 // attacker enumerates every plausible issue number with unkeyed digests and wrong-key HMACs
 const guesses=new Set();
 for(let n=1;n<=5000;n++){const t=`acme/sandbox#${n}`;guesses.add(createHash('sha256').update(t).digest('hex'));guesses.add(createHash('sha256').update(`audital.observe/v1:target:${t}`).digest('hex'));guesses.add(hmacIdentifier('x'.repeat(32),t,'target'));}
 assert.equal(guesses.has(publicClaim.target_hash),false);
 for(const v of Object.values(publicClaim))assert.ok(!String(v).includes('123')||String(v).length===64,`raw value leaked: ${v}`);
});
test('canonical targets join case/URL variants before hashing',()=>{
 assert.equal(canonicalTarget('github','Acme/SandBox#7'),'acme/sandbox#7');
 assert.equal(canonicalTarget('github','https://github.com/Acme/sandbox/issues/7'),'acme/sandbox#7');
 const a=parseClaim({claim_id:'1',action:'x',provider:'github',target:'Acme/Sandbox#7'},key).publicClaim.target_hash;
 const b=parseClaim({claim_id:'2',action:'x',provider:'github',target:'https://github.com/acme/sandbox/pull/7'},key).publicClaim.target_hash;
 assert.equal(a,b);
});
test('parser strips raw arguments and target from persistent claim; args hashed canonically',()=>{
 let p=parseSpansJSONL(JSON.stringify({name:'execute_tool',provider:'github',target:'org/sandbox#123',args:{secret:'never-persist',b:1,a:2},claimed_success:true,occurred_at:'2026-11-20T00:00:00Z'}),key)[0];
 assert.equal(p.lookup.target,'org/sandbox#123');assert.equal(p.publicClaim.target,undefined);
 assert.ok(!JSON.stringify(p.publicClaim).includes('never-persist'));assert.ok(!JSON.stringify(p.publicClaim).includes('org/sandbox'));
 const q=parseSpansJSONL(JSON.stringify({name:'execute_tool',provider:'github',target:'org/sandbox#123',args:{a:2,b:1,secret:'never-persist'},occurred_at:'2026-11-20T00:00:00Z'}),key)[0];
 assert.equal(p.publicClaim.args_hmac,q.publicClaim.args_hmac);
});
test('semconv execute_tool span: gen_ai.tool.name, gen_ai.tool.call.id, trace context, GitHub MCP target inference',()=>{
 const r=parseOTLPTraces(traces([{traceId:T,spanId:S,name:'execute_tool update_issue',kind:1,startTimeUnixNano:'1795190400000000000',status:{code:1},
  attributes:attrs({'gen_ai.operation.name':'execute_tool','gen_ai.tool.name':'update_issue','gen_ai.tool.call.id':'call_9xYz','gen_ai.tool.type':'function','gen_ai.provider.name':'anthropic','gen_ai.agent.name':'triage',
   'gen_ai.tool.call.arguments':JSON.stringify({owner:'Acme',repo:'Sandbox',issue_number:42,state:'closed'})})}]),key);
 assert.equal(r.claims.length,1);const c=r.claims[0].publicClaim;
 assert.equal(c.claim_id,'call_9xYz');assert.equal(c.trace_id,T);assert.equal(c.span_id,S);assert.equal(c.source,'otel.gen_ai');
 assert.equal(c.provider,'github');assert.equal(c.expected_state,'closed');assert.equal(c.claimed_success,true);assert.equal(r.claims[0].lookup.target,'acme/sandbox#42');
 assert.equal(c.occurred_at,'2026-11-20T16:00:00.000Z');
});
test('gen_ai.tool.call.arguments as structured kvlist AnyValue',()=>{
 const r=parseOTLPTraces(traces([{traceId:T,spanId:S,name:'execute_tool',startTimeUnixNano:'1795190400000000000',attributes:[
  {key:'gen_ai.operation.name',value:s('execute_tool')},{key:'gen_ai.tool.name',value:s('github_close_issue')},{key:'gen_ai.tool.call.id',value:s('toolu_01')},
  {key:'gen_ai.tool.call.arguments',value:{kvlistValue:{values:[{key:'owner',value:s('o')},{key:'repo',value:s('r')},{key:'issue_number',value:{intValue:'5'}}]}}}]}]),key);
 assert.equal(r.claims[0].lookup.target,'o/r#5');assert.equal(r.claims[0].publicClaim.expected_state,'closed');
});
test('error.type or ERROR status marks claimed_success=false',()=>{
 const base={traceId:T,name:'execute_tool',startTimeUnixNano:'1795190400000000000'};
 const a=parseOTLPTraces(traces([{...base,spanId:S,status:{code:'STATUS_CODE_ERROR'},attributes:attrs({'gen_ai.operation.name':'execute_tool','gen_ai.tool.name':'close_issue','gen_ai.tool.call.id':'a','audital.target':'o/r#1'})},
  {...base,spanId:S2,attributes:attrs({'gen_ai.operation.name':'execute_tool','gen_ai.tool.name':'close_issue','gen_ai.tool.call.id':'b','audital.target':'o/r#2','error.type':'timeout'})}]),key);
 assert.deepEqual(a.claims.map(c=>c.publicClaim.claimed_success),[false,false]);
});
test('invoke_agent / chat spans are not tool effects; unknown effects are skipped, not guessed',()=>{
 const r=parseOTLPTraces(traces([{traceId:T,spanId:S,name:'invoke_agent triage',startTimeUnixNano:'1',attributes:attrs({'gen_ai.operation.name':'invoke_agent','audital.target':'o/r#1'})},
  {traceId:T,spanId:S2,name:'execute_tool add_issue_comment',startTimeUnixNano:'1795190400000000000',attributes:attrs({'gen_ai.operation.name':'execute_tool','gen_ai.tool.name':'add_issue_comment','gen_ai.tool.call.arguments':JSON.stringify({owner:'o',repo:'r',issue_number:1,body:'hi'})})},
  {traceId:T,spanId:'aaaaaaaaaaaaaaa1',name:'execute_tool Bash',startTimeUnixNano:'1795190400000000000',attributes:attrs({'gen_ai.operation.name':'execute_tool','gen_ai.tool.name':'Bash'})}]),key);
 assert.equal(r.claims.length,0);assert.deepEqual(r.skipped.map(x=>x.reason).sort(),['CLAIM_TARGET_TOOL_OR_PROVIDER_MISSING','EXPECTED_EFFECT_UNKNOWN']);
});
test('Claude Code beta tracing: claude_code.tool + child claude_code.tool.execution success',()=>{
 const r=parseOTLPTraces(traces([
  {traceId:T,spanId:S,name:'claude_code.tool',startTimeUnixNano:'1795190400000000000',attributes:attrs({tool_name:'mcp__github__update_issue',tool_use_id:'toolu_01ABC','gen_ai.tool.call.id':'toolu_01ABC',tool_input:JSON.stringify({owner:'o',repo:'r',issue_number:9,state:'closed'})})},
  {traceId:T,spanId:S2,parentSpanId:S,name:'claude_code.tool.execution',startTimeUnixNano:'1795190400000000001',status:{code:2},attributes:attrs({success:'false','gen_ai.tool.call.id':'toolu_01ABC'})}]),key);
 assert.equal(r.claims.length,1);const c=r.claims[0].publicClaim;
 assert.equal(c.source,'claude_code');assert.equal(c.claim_id,'toolu_01ABC');assert.equal(c.claimed_success,false);assert.equal(r.claims[0].lookup.target,'o/r#9');
});
test('LangSmith, Langfuse and OpenInference tool spans map to claims',()=>{
 const mk=(spanId,a)=>({traceId:T,spanId,name:'close_issue',startTimeUnixNano:'1795190400000000000',attributes:attrs({...a,'audital.target':'o/r#3'})});
 const r=parseOTLPTraces(traces([mk('1000000000000001',{'langsmith.span.kind':'tool','gen_ai.tool.name':'close_issue',call_id:'ls-1'}),
  mk('1000000000000002',{'langfuse.observation.type':'tool','langfuse.observation.level':'ERROR',call_id:'lf-1'}),
  mk('1000000000000003',{'openinference.span.kind':'TOOL','tool.name':'close_issue','tool_call.id':'oi-1'})]),key);
 assert.deepEqual(r.claims.map(c=>[c.publicClaim.source,c.publicClaim.claim_id,c.publicClaim.claimed_success]),[['langsmith','ls-1',true],['langfuse','lf-1',false],['openinference','oi-1',true]]);
});
test('OTLP logs: claude_code.tool_result and codex.tool_result events',()=>{
 const doc={resourceLogs:[{resource:{attributes:attrs({'service.name':'claude-code'})},scopeLogs:[{logRecords:[
  {timeUnixNano:'1795190400000000000',body:s('claude_code.tool_result'),attributes:attrs({'event.name':'tool_result',tool_name:'mcp__github__update_issue',tool_use_id:'toolu_x',success:'true',tool_parameters:JSON.stringify({owner:'o',repo:'r',issue_number:4,state:'closed'})})},
  {timeUnixNano:'1795190400000000000',eventName:'codex.tool_result',attributes:attrs({tool_name:'github.close_issue',call_id:'call_c',success:'false',arguments:JSON.stringify({owner:'o',repo:'r',issue_number:5})})},
  {timeUnixNano:'1795190400000000000',body:s('claude_code.api_request'),attributes:attrs({'event.name':'api_request'})}]}]}]};
 const r=parseOTLPLogs(doc,key);
 assert.deepEqual(r.claims.map(c=>[c.publicClaim.source,c.publicClaim.claim_id,c.publicClaim.claimed_success,c.lookup.target]),[['claude_code','toolu_x',true,'o/r#4'],['codex','call_c',false,'o/r#5']]);
});
test('legacy OTLP/JSON execute_tool span with audital.* attributes still parses',()=>{const a=parseOTLPJson({resourceSpans:[{scopeSpans:[{spans:[{name:'execute_tool',spanId:'01',startTimeUnixNano:'1795190400000000000',attributes:[{key:'gen_ai.tool.name',value:{stringValue:'github.issue.close'}},{key:'audital.target',value:{stringValue:'org/repo#4'}},{key:'audital.provider',value:{stringValue:'github'}}]}]}]}]},key);assert.equal(a.length,1);assert.equal(a[0].publicClaim.claim_id,'01')});
test('caller supplied assurance rejected before storage (JSONL and OTLP attribute)',()=>{
 assert.throws(()=>parseSpansJSONL(JSON.stringify({target:'org/repo#1',action:'x',assurance:'EFFECT_OBSERVED'}),key));
 assert.throws(()=>parseOTLPTraces(traces([{traceId:T,spanId:S,name:'execute_tool',startTimeUnixNano:'1',attributes:attrs({'gen_ai.operation.name':'execute_tool','audital.attestation':'hosted_attested'})}]),key),/CALLER_SUPPLIED/);
});
test('overlong targets are rejected, never silently truncated into collisions',()=>assert.throws(()=>parseClaim({claim_id:'x',action:'a',provider:'mock',target:'x'.repeat(251)},key),/TARGET_TOO_LONG/));
test('gen_ai.evaluation.result event follows semconv and is parented to the tool span',()=>{
 const result={schema:'audital.observe/v1',claim_id:'call_9xYz',assurance:'CONTRADICTED',findings:['PHANTOM_SUCCESS'],cannot_assert:['exclusive causation'],observed_at:'2026-11-20T00:00:00.000Z',observation_complete:true};
 const ev=otelEvaluationEvent(result,{trace_id:T,span_id:S});
 assert.equal(ev.name,'gen_ai.evaluation.result');assert.equal(ev.attributes['gen_ai.evaluation.name'],EVALUATION_NAME);
 assert.equal(ev.attributes['gen_ai.evaluation.score.label'],'CONTRADICTED');assert.match(ev.attributes['gen_ai.evaluation.explanation'],/PHANTOM_SUCCESS/);
 assert.equal(ev.attributes['gen_ai.evaluation.result'],undefined,'v0.1 used a non-semconv attribute');
 assert.equal(ev.trace_id,T);assert.equal(ev.span_id,S);
 const doc=otelEvaluationLogs([result],new Map([['call_9xYz',{trace_id:T,span_id:S}]]));
 const rec=doc.resourceLogs[0].scopeLogs[0].logRecords[0];
 assert.equal(rec.eventName,'gen_ai.evaluation.result');assert.equal(rec.traceId,T);assert.equal(rec.spanId,S);assert.equal(rec.timeUnixNano,'1795132800000000000');
 assert.ok(!/\bVERIFIED\b/.test(JSON.stringify(doc)));
});
