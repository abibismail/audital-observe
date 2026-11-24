// Output-only formatters. Audital holds NO GitHub write credential and makes no GitHub write call:
// the consumer's own CI token (e.g. the workflow GITHUB_TOKEN with checks:write) publishes these.
export const SEVERE=['PHANTOM_SUCCESS','GHOST_WRITE','WRONG_TARGET'];
export const PR_COMMENT_MARKER='<!-- audital-observe:evidence v0.2 -->';
const md=s=>String(s??'').replace(/[|\\`*_<>[\]]/g,c=>`\\${c}`).replace(/\r?\n/g,' ');
const short=h=>h?`${String(h).slice(0,10)}…`:'—';
const ATTEST_LABEL={local_unattested:'local, unattested (file integrity only)',hosted_attested:'hosted-attested by Audital'};
function summarize(results){
 const issues=results.flatMap(r=>r.findings.map(f=>({finding:f,assurance:r.assurance,claim_id:r.claim_id})));
 const severe=issues.filter(x=>SEVERE.includes(x.finding));
 const counts=results.reduce((m,r)=>(m[r.assurance]=(m[r.assurance]||0)+1,m),{});
 return {issues,severe,counts};
}
function linkLine(link){
 if(!link?.url)return 'Signed evidence pack: available to project members via the Audital API.';
 return `[Signed evidence pack](${link.url})${link.expires_at?` · link expires ${link.expires_at}`:''}`;
}
function table(results){
 const rows=results.slice(0,50).map(r=>`| \`${md(r.claim_id||'(unclaimed effect)')}\` | **${r.assurance}** | ${r.findings.length?r.findings.join(', '):'—'} | \`${short(r.target_hash)}\` |`);
 return ['| Claim | Assurance | Findings | Target (HMAC) |','|---|---|---|---|',...rows,results.length>50?`\n_…and ${results.length-50} more in the evidence pack._`:''].join('\n');
}
const LIMITS='Observe correlates claims with read-only provider readback. It cannot assert exclusive causation or the absence of a same-identity competitor, and is not Guard proof.';

/** GitHub Checks API `POST /repos/{o}/{r}/check-runs` body. `link` = {url, expires_at} of an expiring share. */
export function githubCheckPayload(results,reportUrl,{headSha=null,packId=null,attestation=null,link=null}={}){
 const {issues,severe,counts}=summarize(results);
 const l=link||(reportUrl?{url:reportUrl}:null);
 const title=severe.length?`${severe.length} priority discrepancy finding(s)`:issues.length?`${issues.length} finding(s), none priority`:'No claim/effect discrepancy found';
 const summary=[`**Audital Observe: ${issues.length} finding(s)** across ${results.length} reconciled claim(s).`,
  Object.entries(counts).map(([k,v])=>`\`${k}\` ×${v}`).join(' · '),
  attestation?`Attestation: ${ATTEST_LABEL[attestation]||attestation}.`:'',
  linkLine(l),'',`_${LIMITS}_`].filter(x=>x!=='').join('\n');
 const payload={name:'Audital Observe',status:'completed',conclusion:severe.length?'failure':'neutral',
  output:{title:`Audital Observe: ${title}`.slice(0,255),summary:summary.slice(0,65535),text:table(results).slice(0,65535)}};
 if(headSha)payload.head_sha=headSha;
 if(packId)payload.external_id=String(packId);
 if(l?.url)payload.details_url=l.url;
 return payload;
}
/** Issue/PR comment body (`POST /repos/{o}/{r}/issues/{n}/comments`). Marker enables idempotent upsert. */
export function githubPrCommentPayload(results,{link=null,attestation=null,packId=null}={}){
 const {issues,severe}=summarize(results);
 const head=severe.length?`### ❌ Audital Observe: ${severe.length} priority finding(s)`:issues.length?`### ⚠️ Audital Observe: ${issues.length} finding(s)`:'### ✅ Audital Observe: claims match observed effects';
 const body=[PR_COMMENT_MARKER,head,'',table(results),'',linkLine(link),
  attestation?`<sub>Attestation: ${ATTEST_LABEL[attestation]||attestation}${packId?` · pack \`${md(packId)}\``:''}</sub>`:'',
  `<sub>${LIMITS}</sub>`].filter(x=>x!=='').join('\n');
 return {body:body.slice(0,65536),marker:PR_COMMENT_MARKER};
}
export function webhookAlertPayload(results,reportUrl,{packId=null,projectId=null,attestation=null,expiresAt=null}={}){
 return {schema:'audital.observe.alert/v1',pack_id:packId,project_id:projectId,attestation,count:results.reduce((n,r)=>n+r.findings.length,0),url:reportUrl||null,url_expires_at:expiresAt,
  findings:results.flatMap(r=>r.findings),
  results:results.map(r=>({claim_id:r.claim_id,assurance:r.assurance,findings:r.findings,target_hash:r.target_hash})),
  assurance_limit:'not Guard causal verification'};
}
export function slackAlertPayload(results,{link=null,projectLabel='project'}={}){
 const {issues,severe}=summarize(results);
 const lines=results.filter(r=>r.findings.length||r.assurance==='CONTRADICTED').slice(0,10).map(r=>`• \`${r.claim_id||'unclaimed effect'}\` *${r.assurance}* ${r.findings.join(', ')}`);
 const text=`Audital Observe: ${severe.length} priority / ${issues.length} total finding(s) in ${projectLabel}`;
 return {text,blocks:[{type:'section',text:{type:'mrkdwn',text:`*${text}*\n${lines.join('\n')}`.slice(0,2900)}},
  {type:'context',elements:[{type:'mrkdwn',text:`${link?.url?`<${link.url}|Signed evidence pack>${link.expires_at?` (expires ${link.expires_at})`:''} · `:''}Not proof of exclusive causation.`}]}]};
}
