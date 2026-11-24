// A GET-only connector. It does not post comments, write Checks, or request issue permissions.
// It REFUSES classic tokens whose X-OAuth-Scopes include any write-capable scope (only `read:*` or no
// scopes are accepted). Fine-grained / App tokens do not advertise scopes; grant them read-only
// "Issues: read" + "Metadata: read" and nothing else.
import {hmacIdentifier,canonicalTarget} from '../../otel-parser/src/index.mjs';
const API='https://api.github.com';
const sleepReal=ms=>new Promise(r=>setTimeout(r,ms));
// Real GitHub Link headers may address a repo by numeric id (/repositories/<id>/...), found by the live
// test against cli/cli. Both forms are accepted; anything off the API origin or outside a repo is refused.
function allowedNext(u){const url=new URL(u);if(url.origin!==API || !/^\/(repos\/[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+|repositories\/\d+)\//.test(url.pathname))throw Error('PAGINATION_ORIGIN_DENIED');return url;}
export function writeCapableScopes(header){
 if(header===null||header===undefined)return [];
 return String(header).split(',').map(s=>s.trim()).filter(Boolean).filter(s=>!/^read:/.test(s));
}
function rateOf(h){
 const n=k=>{const v=h.get(k);return v===null||v===undefined||v===''?null:Number(v)};
 return {limit:n('x-ratelimit-limit'),remaining:n('x-ratelimit-remaining'),reset_at:n('x-ratelimit-reset')!==null?new Date(n('x-ratelimit-reset')*1000).toISOString():null,resource:h.get('x-ratelimit-resource')||null,retry_after_s:n('retry-after')};
}
export class GithubReader {
 constructor({token=null,anonymous=false,fetcher=fetch,sleep=sleepReal,now=()=>Date.now(),maxRetries=3,maxWaitMs=60000,minRemaining=0,userAgent='audital-observe-readonly'}={}){
  if(!token&&!anonymous)throw Error('READ_TOKEN_REQUIRED');
  Object.assign(this,{token,fetcher,sleep,now,maxRetries,maxWaitMs,minRemaining,userAgent});this.rate=null;this.requests=0;this.retries=0;
 }
 async get(path){
  const url=allowedNext(path.startsWith('https:')?path:`${API}${path}`);
  for(let attempt=0;;attempt++){
   // Preserve the caller's budget: never spend below minRemaining before the window resets.
   if(this.rate?.remaining!==null&&this.rate?.remaining!==undefined&&this.rate.remaining<=this.minRemaining&&this.rate.reset_at&&Date.parse(this.rate.reset_at)>this.now())
    throw Object.assign(Error('GITHUB_RATE_BUDGET_EXHAUSTED'),{rate:this.rate});
   const headers={'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':this.userAgent};
   if(this.token)headers.Authorization=`Bearer ${this.token}`;
   const r=await this.fetcher(url,{method:'GET',redirect:'error',headers});this.requests++;
   const h=r.headers&&typeof r.headers.get==='function'?r.headers:{get:()=>null};
   const scopes=writeCapableScopes(h.get('x-oauth-scopes'));
   if(scopes.length)throw Object.assign(Error('WRITE_CAPABLE_TOKEN_REFUSED'),{scopes});
   this.rate=rateOf(h);
   const limited=(r.status===403||r.status===429)&&(this.rate.remaining===0||this.rate.retry_after_s!==null);
   if(limited){
    const wait=this.rate.retry_after_s!==null?this.rate.retry_after_s*1000:Math.max(0,Date.parse(this.rate.reset_at||0)-this.now())+1000;
    if(attempt<this.maxRetries&&wait<=this.maxWaitMs){this.retries++;await this.sleep(wait);this.rate=null;continue;} // waited past reset/retry-after
    throw Object.assign(Error('GITHUB_RATE_LIMITED'),{rate:this.rate});
   }
   if(r.status>=500&&attempt<this.maxRetries){this.retries++;await this.sleep(Math.min(this.maxWaitMs,500*2**attempt));continue;}
   if(!r.ok)throw Error(`GITHUB_READ_UNAVAILABLE_${r.status}`);
   return {data:await r.json(),next:/<([^>]+)>;\s*rel="next"/.exec(h.get('link')||'')?.[1]||null};
  }
 }
}
export function parseGithubTarget(target){
 const m=/^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)#([1-9]\d*)$/.exec(canonicalTarget('github',target));
 if(!m)throw Error('GITHUB_TARGET_FORMAT_EXPECTED_OWNER_REPO_HASH_ISSUE');
 return {owner:m[1],repo:m[2],number:Number(m[3]),canonical:`${m[1]}/${m[2]}#${m[3]}`};
}
export async function readGithubIssue({target,token,anonymous=false,hmacKey,coverageStart,fetcher=fetch,maxPages=10,perPage=100,reader=null,sleep,now,maxRetries,maxWaitMs,minRemaining}){
 if((!token&&!anonymous&&!reader)||!hmacKey)throw Error('READ_TOKEN_AND_HMAC_REQUIRED');
 if(!Number.isSafeInteger(perPage)||perPage<1||perPage>100)throw Error('INVALID_PER_PAGE');
 const t=parseGithubTarget(target);
 const gh=reader||new GithubReader({token,anonymous,fetcher,sleep,now,maxRetries,maxWaitMs,minRemaining});
 const p=`/repos/${t.owner}/${t.repo}/issues/${t.number}`;
 const meta=()=>({rate_limit:gh.rate,requests:gh.requests,retries:gh.retries});
 try{
  const state=(await gh.get(p)).data;
  let url=`${p}/events?per_page=${perPage}`,events=[],complete=true,pages=0;
  while(url && pages<maxPages){const z=await gh.get(url);if(!Array.isArray(z.data))throw Error('GITHUB_EVENT_SHAPE_INVALID');events.push(...z.data);url=z.next;pages++}
  if(url)complete=false;
  const ids=new Set(events.map(e=>String(e.id)));if(ids.size!==events.length)complete=false; // page drift during read
  // Pagination exhausted proves enumeration of this issue's event log, not actor exclusivity.
  // Coverage begins at the issue's creation; without created_at fall back to the earliest event seen.
  const created=Date.parse(state?.created_at||'');
  let coverage=coverageStart;
  if(Number.isFinite(created)){if(coverageStart&&created<=Date.parse(coverageStart))coverage=new Date(created).toISOString();}
  else{const times=events.map(e=>Date.parse(e.created_at)).filter(Number.isFinite);if(coverageStart&&(!times.length||Math.min(...times)>Date.parse(coverageStart)))complete=false;}
  const targetHash=hmacIdentifier(hmacKey,t.canonical,'target');
  return {available:true,complete,pages,observed_at:new Date().toISOString(),coverage_start:complete?coverage:undefined,current_state:state.state,
   events:events.map(e=>({id:String(e.id),kind:e.event==='closed'?'closed':e.event,target_hash:targetHash,time:e.created_at,actor_hash:hmacIdentifier(hmacKey,e.actor?.login||'unknown','actor')})),...meta()};
 }catch(e){
  if(e.message==='WRITE_CAPABLE_TOKEN_REFUSED')throw e; // configuration error, never degrade silently
  return {available:false,complete:false,observed_at:new Date().toISOString(),events:[],reason:e.message,...meta()};
 }
}
