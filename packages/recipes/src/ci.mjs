// Output-only formatter: the consumer's own CI token must publish its own GitHub Check.
// This package has no GitHub write-capable credential or API call.
export function githubCheckPayload(results,reportUrl){
 const issues=results.flatMap(r=>r.findings.map(f=>({finding:f,assurance:r.assurance,claim_id:r.claim_id})));
 const severe=issues.filter(x=>['PHANTOM_SUCCESS','GHOST_WRITE','WRONG_TARGET'].includes(x.finding));
 return {name:'Audital Observe',status:'completed',conclusion:severe.length?'failure':'neutral',output:{title:`Audital Observe: ${issues.length} finding(s)`,summary:`${severe.length} priority discrepancy finding(s). Observation is not unique causal proof. ${reportUrl||'Open the signed evidence locally.'}`.slice(0,65535),text:issues.map(x=>`${x.finding} (${x.assurance})`).join('\n').slice(0,65535)}};
}
export function webhookAlertPayload(results,reportUrl){return {schema:'audital.observe.alert/v1',count:results.reduce((n,r)=>n+r.findings.length,0),url:reportUrl||null,findings:results.flatMap(r=>r.findings),assurance_limit:'not Guard causal verification'};}
