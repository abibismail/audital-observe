// Audital Observe is a separate, strictly lower-assurance namespace than Guard.
export const OBSERVE_SCHEMA = 'audital.observe/v1' as const;
export const OBSERVE_DOMAIN = 'audital.observe/v1' as const;
export const ASSURANCE = ['CLAIMED','EFFECT_OBSERVED','EFFECT_CORRELATED','CONTRADICTED','UNOBSERVABLE'] as const;
export const FINDINGS = ['PHANTOM_SUCCESS','GHOST_WRITE','DUPLICATE_EFFECT','WRONG_TARGET','PARTIAL_EFFECT','LATE_EFFECT'] as const;
export type Assurance = typeof ASSURANCE[number];
export type Finding = typeof FINDINGS[number];
export type Observation = { complete:boolean; available:boolean; events:Array<{kind:string;target_hash:string;time:string;actor_hash?:string;id?:string;attributes?:Record<string,string>}>; current_state?:string; observed_at:string; coverage_start?:string };
export type Claim = { claim_id:string; provider:'github'|'stripe'|'mock'; action:string; target_hash:string; occurred_at:string; args_hmac:string; claimed_success:boolean; expected_state?:string; actor_hash?:string };
export type Result = { schema:typeof OBSERVE_SCHEMA; claim_id:string|null; assurance:Assurance; findings:Finding[]; asserts:string[]; cannot_assert:string[]; observed_at:string; target_hash:string|null; observation_complete:boolean; reason_codes:string[] };
const FORBIDDEN = new Set(['VERIFIED','causally verified','exclusive causation established']);
const CAUSATION_LIMITS = ['exclusive causation','no same-identity competitor'] as const;
const ORDER = new Set<string>(ASSURANCE);
const FINDING_SET = new Set<string>(FINDINGS);
function isRecord(x:unknown): x is Record<string,unknown> { return !!x && typeof x==='object' && !Array.isArray(x); }
function stringArr(x:unknown, label:string): string[] {
  if (!Array.isArray(x) || x.length>50 || !x.every(v=>typeof v==='string' && v.length<=250)) throw Error(`INVALID_${label}`);
  return x as string[];
}
export function validateResult(value:unknown): asserts value is Result {
  if (!isRecord(value)) throw Error('INVALID_RESULT');
  const keys = ['schema','claim_id','assurance','findings','asserts','cannot_assert','observed_at','target_hash','observation_complete','reason_codes'];
  if (Object.keys(value).sort().join('|') !== keys.sort().join('|')) throw Error('UNKNOWN_RESULT_FIELDS');
  if (value.schema!==OBSERVE_SCHEMA || typeof value.assurance!=='string' || !ORDER.has(value.assurance)) throw Error('INVALID_ASSURANCE');
  if (typeof value.claim_id!=='string' && value.claim_id!==null) throw Error('INVALID_CLAIM_ID');
  if (typeof value.target_hash!=='string' && value.target_hash!==null) throw Error('INVALID_TARGET_HASH');
  if (typeof value.observed_at!=='string' || !Number.isFinite(Date.parse(value.observed_at))) throw Error('INVALID_OBSERVED_AT');
  if (typeof value.observation_complete!=='boolean') throw Error('INVALID_COMPLETENESS');
  const findings=stringArr(value.findings,'FINDINGS'); if(findings.some(v=>!FINDING_SET.has(v))) throw Error('UNKNOWN_FINDING');
  const asserts=stringArr(value.asserts,'ASSERTS'); const limits=stringArr(value.cannot_assert,'CANNOT_ASSERT');stringArr(value.reason_codes,'REASONS');
  if (asserts.some(v=>FORBIDDEN.has(v) || /\bverified\b/i.test(v))) throw Error('FORBIDDEN_ASSURANCE_CLAIM');
  if (value.assurance==='EFFECT_CORRELATED' || value.assurance==='EFFECT_OBSERVED') {
    for(const v of CAUSATION_LIMITS) if(!limits.includes(v)) throw Error('MISSING_CAUSATION_LIMIT');
  }
  if (!value.observation_complete && !['UNOBSERVABLE','CLAIMED'].includes(value.assurance)) throw Error('INCOMPLETE_EVIDENCE_OVERCLAIM');
}
export function makeResult(input:Omit<Result,'schema'>): Result {
  if ('schema' in input) throw Error('CALLER_SCHEMA_FORBIDDEN');
  const result:Result={schema:OBSERVE_SCHEMA,...input}; validateResult(result); return Object.freeze(result);
}
export function rejectCallerAssurance(input:unknown):void {
  if(isRecord(input) && ('assurance' in input || 'signature' in input || 'asserts' in input || 'cannot_assert' in input)) throw Error('CALLER_SUPPLIED_ASSURANCE_FORBIDDEN');
}
export function assertObserveDomain(domain:string):void { if(domain!==OBSERVE_DOMAIN) throw Error('WRONG_SIGNING_DOMAIN'); }
