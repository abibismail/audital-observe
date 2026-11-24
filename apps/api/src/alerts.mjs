import {createHmac,createHash,timingSafeEqual} from 'node:crypto';
import {isIP} from 'node:net';
import {slackAlertPayload,webhookAlertPayload,SEVERE} from '../../../packages/recipes/src/ci.mjs';

// Outbound notifications go ONLY to customer-registered notification endpoints. Provider API hosts are
// refused outright, so this dispatcher can never become a provider write path.
const PROVIDER_HOSTS=new Set(['api.github.com','github.com','uploads.github.com','api.stripe.com','files.stripe.com']);
export function validateEndpointUrl(kind,raw,{allowInsecureLoopback=false}={}){
 let u;try{u=new URL(raw)}catch{throw Error('ALERT_URL_INVALID')}
 const host=u.hostname.toLowerCase().replace(/^\[|\]$/g,'');
 if(PROVIDER_HOSTS.has(host))throw Error('ALERT_URL_PROVIDER_HOST_FORBIDDEN');
 if(u.username||u.password)throw Error('ALERT_URL_CREDENTIALS_FORBIDDEN');
 const loopback=host==='127.0.0.1'||host==='localhost'||host==='::1';
 if(allowInsecureLoopback&&loopback&&(u.protocol==='http:'||u.protocol==='https:'))return u;
 if(u.protocol!=='https:')throw Error('ALERT_URL_HTTPS_REQUIRED');
 // Basic SSRF guard: no IP literals, no single-label/internal names. DNS-rebinding defence is a production gate.
 if(isIP(host)||!host.includes('.')||/\.(internal|local|localhost|lan|corp)$/.test(host))throw Error('ALERT_URL_PRIVATE_HOST_FORBIDDEN');
 if(kind==='slack'&&host!=='hooks.slack.com')throw Error('SLACK_URL_MUST_BE_HOOKS_SLACK_COM');
 return u;
}
export function shouldAlert(result){return result.assurance==='CONTRADICTED'||result.findings.some(f=>SEVERE.includes(f));}
export function alertDedupeKey(result){
 return createHash('sha256').update(JSON.stringify([result.claim_id,result.target_hash,result.assurance,[...result.findings].sort()])).digest('hex').slice(0,40);
}
export function buildAlertBody(kind,results,{link,packId,projectId,attestation}){
 return kind==='slack'?slackAlertPayload(results,{link,projectLabel:projectId?`project ${projectId}`:'project'})
  :webhookAlertPayload(results,link?.url,{packId,projectId,attestation,expiresAt:link?.expires_at??null});
}
/** Delivers one alert. Generic webhooks are signed: `x-audital-signature: t=<unix>,v1=<hex HMAC-SHA256(secret, t.body)>`. */
export async function deliverAlert(endpoint,body,{fetcher=fetch,now=()=>Date.now(),timeoutMs=5000,allowInsecureLoopback=false}={}){
 const url=validateEndpointUrl(endpoint.kind,endpoint.url,{allowInsecureLoopback});
 const text=JSON.stringify(body);
 const headers={'content-type':'application/json','user-agent':'audital-observe-alerts/0.2'};
 if(endpoint.kind==='webhook'){
  if(!endpoint.secret||String(endpoint.secret).length<16)throw Error('WEBHOOK_SECRET_REQUIRED');
  const t=Math.floor(now()/1000);headers['x-audital-signature']=`t=${t},v1=${createHmac('sha256',endpoint.secret).update(`${t}.${text}`).digest('hex')}`;
 }
 const r=await fetcher(url,{method:'POST',redirect:'error',headers,body:text,signal:AbortSignal.timeout(timeoutMs)});
 if(!r.ok)throw Error(`ALERT_DELIVERY_HTTP_${r.status}`);
 return {status:r.status};
}
export function verifyWebhookSignature(secret,header,text,{now=()=>Date.now(),toleranceS=300}={}){
 const m=/^t=(\d+),v1=([0-9a-f]{64})$/.exec(header||'');if(!m)return false;
 if(Math.abs(now()/1000-Number(m[1]))>toleranceS)return false;
 const want=createHmac('sha256',secret).update(`${m[1]}.${text}`).digest();
 const got=Buffer.from(m[2],'hex');return got.length===want.length&&timingSafeEqual(want,got);
}
