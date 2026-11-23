// Stripe Events API reads only; 30-day-ish event retention and per-object timelines
// cannot establish exhaustive historical coverage or unique causation by themselves.
import {hmacIdentifier} from '../../otel-parser/src/index.mjs';
export async function readStripeEvents({token,hmacKey,coverageStart,fetcher=fetch,maxPages=10}){
 if(!token||!hmacKey)throw Error('READ_KEY_AND_HMAC_REQUIRED');
 let events=[],startingAfter=null,complete=true;
 try{
  for(let page=0;page<maxPages;page++){
   const url=new URL('https://api.stripe.com/v1/events');url.searchParams.set('limit','100');if(startingAfter)url.searchParams.set('starting_after',startingAfter);
   const r=await fetcher(url,{method:'GET',headers:{Authorization:`Bearer ${token}`}});
   if(!r.ok)throw Error(`STRIPE_READ_UNAVAILABLE_${r.status}`);
   const x=await r.json();if(!Array.isArray(x.data))throw Error('STRIPE_EVENT_SHAPE_INVALID');
   events.push(...x.data);
   if(!x.has_more)break;
   if(!x.data.length)throw Error('STRIPE_PAGINATION_EMPTY');
   startingAfter=x.data.at(-1).id;
   if(page===maxPages-1)complete=false;
  }
  const oldest=events.length?Math.min(...events.map(e=>Number(e.created)*1000)):Infinity;
  // Stripe Events alone do not guarantee history coverage. Require all pages and a recent bounded window.
  if(coverageStart && (oldest>Date.parse(coverageStart)||Date.now()-Date.parse(coverageStart)>24*86400000))complete=false;
  return {available:true,complete,observed_at:new Date().toISOString(),coverage_start:complete?coverageStart:undefined,events:events.map(e=>({id:e.id,kind:/refund|credit|subscription/.test(e.type)?'effect':e.type,target_hash:hmacIdentifier(hmacKey,e.data?.object?.id||'unknown','target'),time:new Date(e.created*1000).toISOString()}))};
 }catch(e){return {available:false,complete:false,observed_at:new Date().toISOString(),events:[],reason:e.message};}
}
