import {makeResult, rejectCallerAssurance} from '../../observe-contract/dist/index.js';
const CAUSAL = ['exclusive causation','no same-identity competitor'];
export const CAUSATION_CANNOT_ASSERT = CAUSAL;
const LIMITS = [...CAUSAL,'provider event completeness beyond inspected window','external mutations outside this read-only connector'];
const stamp = () => new Date().toISOString();
function safeTime(s){const t=Date.parse(s||'');return Number.isFinite(t)?t:null;}
const fresh=(claim,now,grace)=>safeTime(claim.occurred_at)!==null && now-safeTime(claim.occurred_at)<grace;
const unique=x=>[...new Set(x)];
function create(claim, assurance, findings, asserts, reasons, complete, observedAt=stamp()){
  return makeResult({claim_id:claim?.claim_id??null, assurance, findings:unique(findings), asserts:unique(asserts), cannot_assert:assurance==='UNOBSERVABLE'?[...LIMITS,'effect outcome']:assurance==='CLAIMED'?[...LIMITS,'the effect occurred']:assurance==='CONTRADICTED'?[...CAUSAL,'whether an external writer changed the final state']:CAUSAL.slice(), observed_at:observedAt,target_hash:claim?.target_hash??null, observation_complete:complete,reason_codes:unique(reasons)});
}
// If coverage is incomplete or inaccessible, no negative claim about external execution is permitted.
export function reconcile(claim,observation,{now=Date.now(),graceMs=60000,deadlineMs=300000}={}) {
  rejectCallerAssurance(claim);
  if(!claim || !claim.claim_id || !claim.target_hash || !claim.occurred_at)throw Error('CLAIM_INVALID');
  if(graceMs<0 || deadlineMs<0 || !Number.isFinite(graceMs+deadlineMs))throw Error('INVALID_WINDOW');
  const seen=observation?.observed_at||stamp();
  if(!observation || observation.available!==true || observation.complete!==true || !Array.isArray(observation.events)
     || (observation.coverage_start && safeTime(observation.coverage_start)>safeTime(claim.occurred_at))) {
    return create(claim,'UNOBSERVABLE',[],[],['PROVIDER_UNAVAILABLE_OR_INCOMPLETE'],false,seen);
  }
  const events=observation.events;
  const t0=safeTime(claim.occurred_at);
  if(t0===null)throw Error('CLAIM_TIMESTAMP_INVALID');
  const matching=events.filter(e=>e.target_hash===claim.target_hash && safeTime(e.time)!==null && safeTime(e.time)>=t0-graceMs);
  const wrong=events.filter(e=>e.claim_id===claim.claim_id && e.target_hash!==claim.target_hash);
  const effects=matching.filter(e=>e.kind==='effect'||e.kind==='closed'||e.kind==='refund'||e.kind==='updated');
  const findings=[];const reasons=[];
  if(wrong.length){findings.push('WRONG_TARGET');reasons.push('CLAIM_ID_LINKED_TO_DIFFERENT_TARGET');}
  if(effects.length>1){findings.push('DUPLICATE_EFFECT');reasons.push('MORE_THAN_ONE_MATCHING_EVENT');}
  if(effects.some(e=>safeTime(e.time)>t0+deadlineMs)){findings.push('LATE_EFFECT');reasons.push('EFFECT_AFTER_DEADLINE');}
  const expected=claim.expected_state||'closed';const state=observation.current_state;
  const stateMatches=state!==undefined && state===expected;
  const changedPartially=effects.some(e=>e.attributes?.partial==='true');
  if(changedPartially){findings.push('PARTIAL_EFFECT');reasons.push('PARTIAL_PROVIDER_EFFECT');}
  if(wrong.length)return create(claim,'CONTRADICTED',findings,[],reasons,true,seen);
  if(!claim.claimed_success && effects.length>0){findings.push('GHOST_WRITE');reasons.push('PROVIDER_EFFECT_AFTER_CLAIMED_FAILURE');}
  if(!effects.length && !stateMatches){
    if(fresh(claim,now,graceMs))return create(claim,'CLAIMED',[],[],['WAITING_FOR_CONSISTENCY_WINDOW'],true,seen);
    if(claim.claimed_success){findings.push('PHANTOM_SUCCESS');reasons.push('CLAIMED_SUCCESS_BUT_NO_OBSERVED_EFFECT');}
    return create(claim,'CONTRADICTED',findings,['readback does not match expected state'],reasons,true,seen);
  }
  if(!stateMatches && state!==undefined){
    // A matching effect WAS observed, then the final state diverged (e.g. reopened by someone else).
    // That is a contradiction of the end state, not a phantom: the claimed effect did happen.
    reasons.push('FINAL_STATE_CONTRADICTS_EXPECTED','EFFECT_OBSERVED_THEN_STATE_DIVERGED');
    return create(claim,'CONTRADICTED',findings,['current readback contradicts expected state'],reasons,true,seen);
  }
  if(effects.length) return create(claim,'EFFECT_CORRELATED',findings,['matching provider event observed','provider event and claim target hashes agree'],reasons,true,seen);
  return create(claim,'EFFECT_OBSERVED',findings,['current provider state matches expected state'],reasons,true,seen);
}
export function findGhostWrites(claims,observation){
  if(!observation?.available||!observation?.complete)return [];
  const keys=new Set(claims.map(x=>x.target_hash));
  return observation.events.filter(e=>e.target_hash&&!keys.has(e.target_hash)&&['effect','closed','refund','updated'].includes(e.kind)).map(e=>create(null,'CONTRADICTED',['GHOST_WRITE'],['provider effect without matching ingested claim'],['UNCLAIMED_EFFECT'],true,observation.observed_at));
}
