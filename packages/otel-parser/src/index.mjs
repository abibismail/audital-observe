import { createHmac, randomUUID } from 'node:crypto';

// Raw tool arguments and target refs may be held in memory for a one-time lookup only.
// Persist ONLY normalized.publicClaim. Never log normalized.lookup.
export const hmacIdentifier = (key, value, namespace='id') => {
  if (!key || Buffer.byteLength(String(key)) < 16) throw Error('HMAC_KEY_REQUIRED');
  return createHmac('sha256', key).update(`audital.observe/v1:${namespace}:`).update(String(value)).digest('hex');
};
function attrsOf(raw) {
  const a=raw?.attributes||raw?.resource?.attributes||{};
  if(Array.isArray(a)) return Object.fromEntries(a.map(v=>[v.key,v.value?.stringValue??v.value?.intValue??v.value?.boolValue??v.value]));
  return a&&typeof a==='object'?a:{};
}
const limited = (s,max=250)=>String(s??'').slice(0,max);
function normalized(raw,key) {
  if (!raw || typeof raw!=='object') throw Error('CLAIM_INVALID');
  if (Object.hasOwn(raw,'assurance') || Object.hasOwn(raw,'signature') || Object.hasOwn(raw,'asserts')) throw Error('CALLER_SUPPLIED_ASSURANCE_FORBIDDEN');
  const a=attrsOf(raw);
  const name=limited(raw.name??a['gen_ai.operation.name']??a['gen_ai.tool.name']??a['tool.name']??raw.action);
  const tool=limited(raw.action??a['gen_ai.tool.name']??a['tool.name']??name);
  const target=limited(raw.target??a['audital.target']??a['tool.target']??a['gen_ai.tool.call.target']??'');
  const provider=limited(raw.provider??a['audital.provider']??(tool.toLowerCase().includes('stripe')?'stripe':'github'));
  const t=raw.occurred_at??raw.startTime??raw.start_time??raw.startTimeUnixNano??new Date().toISOString();
  const time=(typeof t==='string'&&/^\d{15,}$/.test(t))?new Date(Number(BigInt(t)/1000000n)).toISOString():new Date(t).toISOString();
  if(!target || !tool || !['github','stripe','mock'].includes(provider)) throw Error('CLAIM_TARGET_TOOL_OR_PROVIDER_MISSING');
  const argumentString=typeof raw.args==='string'?raw.args:JSON.stringify(raw.args??a['gen_ai.tool.call.arguments']??'');
  const actor=limited(raw.actor??a['gen_ai.agent.id']??a['enduser.id']??'anonymous');
  const claimSuccess=raw.claimed_success??a['audital.claim.success']??(raw.status?.code===2?false:true);
  const claimed_success=claimSuccess===true||claimSuccess==='true'||claimSuccess===200||claimSuccess==='200';
  const claim_id=limited(raw.claim_id??a['gen_ai.tool.call.id']??raw.spanId??raw.span_id??randomUUID(),130);
  const publicClaim={claim_id,provider,action:tool,target_hash:hmacIdentifier(key,target,'target'),occurred_at:time,args_hmac:hmacIdentifier(key,argumentString,'args'),claimed_success,expected_state:limited(raw.expected_state??a['audital.expected_state']??'closed',80),actor_hash:hmacIdentifier(key,actor,'actor')};
  return {publicClaim,lookup:Object.freeze({target,provider})};
}
export function parseClaim(value,key){return normalized(value,key);}
export function parseSpansJSONL(text,key){
  const lines=String(text).split(/\r?\n/).filter(x=>x.trim());
  if(lines.length>10000)throw Error('SPAN_LIMIT');
  return lines.map(line=>normalized(JSON.parse(line),key));
}
export function parseOTLPJson(doc,key){
  if(!doc||typeof doc!=='object')throw Error('OTLP_INVALID');
  const spans=[];
  if(Array.isArray(doc.spans))spans.push(...doc.spans);
  for(const rs of doc.resourceSpans||[])for(const ss of rs.scopeSpans||[])spans.push(...(ss.spans||[]));
  if(spans.length>10000)throw Error('SPAN_LIMIT');
  return spans.filter(s=>/execute_tool|invoke_agent|tool/i.test(s.name??attrsOf(s)['gen_ai.operation.name']??'')).map(s=>normalized(s,key));
}
export function otelEvaluationEvent(result){
  return {name:'gen_ai.evaluation.result',timestamp:result.observed_at,attributes:{'audital.observe.schema':result.schema,'gen_ai.evaluation.name':'audital.claim_effect_reconciliation','gen_ai.evaluation.result':result.assurance,'audital.findings':result.findings.join(','),'audital.cannot_assert':result.cannot_assert.join(';')}};
}
