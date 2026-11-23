// A GET-only connector. It does not post comments, write Checks, or request issue permissions.
import {hmacIdentifier} from '../../otel-parser/src/index.mjs';
const API='https://api.github.com';
function allowedNext(u){const url=new URL(u);if(url.origin!==API || !url.pathname.startsWith('/repos/'))throw Error('PAGINATION_ORIGIN_DENIED');return url;}
async function getJSON(path,token,fetcher){
 const url=allowedNext(path.startsWith('https:')?path:`${API}${path}`);
 const r=await fetcher(url,{method:'GET',redirect:'error',headers:{'Accept':'application/vnd.github+json','User-Agent':'audital-observe-readonly','Authorization':`Bearer ${token}`}});
 if(!r.ok)throw Error(`GITHUB_READ_UNAVAILABLE_${r.status}`);return {data:await r.json(),next:/<([^>]+)>; rel="next"/.exec(r.headers.get('link')||'')?.[1]||null};
}
export async function readGithubIssue({target,token,hmacKey,coverageStart,fetcher=fetch,maxPages=10}){
 if(!token||!hmacKey)throw Error('READ_TOKEN_AND_HMAC_REQUIRED');
 const m=/^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)#([1-9]\d*)$/.exec(target);
 if(!m)throw Error('GITHUB_TARGET_FORMAT_EXPECTED_OWNER_REPO_HASH_ISSUE');
 const p=`/repos/${m[1]}/${m[2]}/issues/${m[3]}`;
 try{
  const state=(await getJSON(p,token,fetcher)).data;
  let url=`${p}/events?per_page=100`,events=[],complete=true,pages=0;
  while(url && pages<maxPages){const z=await getJSON(url,token,fetcher);if(!Array.isArray(z.data))throw Error('GITHUB_EVENT_SHAPE_INVALID');events.push(...z.data);url=z.next;pages++}
  if(url)complete=false;
  const eventTimes=events.map(e=>Date.parse(e.created_at)).filter(Number.isFinite);
  // Pagination exhausted proves enumeration within API retention, not actor exclusivity.
  // If latest history cannot cover the requested interval, downgrade to UNOBSERVABLE.
  if(coverageStart && (!eventTimes.length || Math.min(...eventTimes)>Date.parse(coverageStart)))complete=false;
  return {available:true,complete,observed_at:new Date().toISOString(),coverage_start:complete?coverageStart:undefined,current_state:state.state,events:events.map(e=>({id:String(e.id),kind:e.event==='closed'?'closed':e.event,target_hash:hmacIdentifier(hmacKey,target,'target'),time:e.created_at,actor_hash:hmacIdentifier(hmacKey,e.actor?.login||'unknown','actor')}))};
 }catch(e){return {available:false,complete:false,observed_at:new Date().toISOString(),events:[],reason:e.message};}
}
