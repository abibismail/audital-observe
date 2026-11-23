import {randomUUID,createHash,randomBytes} from 'node:crypto';
// Local process-only store. NOT approved for public/production hosting.
const hash=t=>createHash('sha256').update(t).digest('hex');
export class DevTenantStore {
 #tenants=new Map();#tokens=new Map();#now;
 constructor(now=()=>Date.now()){this.#now=now;}
 provision(tenantId,projectId,apiKey){if(!tenantId||!projectId||!apiKey)throw Error('PROVISION_INVALID');const id=hash(apiKey);this.#tenants.set(id,{tenantId,projectId,claims:new Map(),results:new Map(),monitors:new Map(),counters:{ingested:0,reconciled:0,repeat_reconciliations:0,discrepancies:0,active_monitors:0}});return id;}
 authenticate(apiKey){const id=hash(apiKey||'');return this.#tenants.get(id)||null;}
 saveClaim(tenant,claim){if(tenant.claims.size>=10000)throw Error('DEMO_STORAGE_LIMIT');if(!tenant.claims.has(claim.claim_id))tenant.counters.ingested++;tenant.claims.set(claim.claim_id,claim);return claim.claim_id;}
 storeResults(tenant,results,signer){const id=randomUUID();const signed=results.map(r=>signer.signResult(r));tenant.results.set(id,{id,tenantId:tenant.tenantId,projectId:tenant.projectId,created_at:new Date(this.#now()).toISOString(),signed,public_keys:signer.exportPublicKeys()});tenant.counters.reconciled++;if(tenant.counters.reconciled>1)tenant.counters.repeat_reconciliations++;tenant.counters.discrepancies+=results.reduce((n,r)=>n+r.findings.length,0);return id;}
 getReport(tenant,id){return tenant.results.get(id)||null;}
 share(tenant,id,ttlSec=3600){if(!this.getReport(tenant,id))throw Error('REPORT_NOT_FOUND');if(!Number.isSafeInteger(ttlSec)||ttlSec<60||ttlSec>3600)throw Error('INVALID_SHARE_TTL');const token=randomBytes(32).toString('base64url');this.#tokens.set(hash(token),{tenantKey:tenant.tenantId,projectId:tenant.projectId,reportId:id,expires:this.#now()+ttlSec*1000});return token;}
 getShare(token){const x=this.#tokens.get(hash(token||''));if(!x||x.expires<this.#now())return null;for(const ten of this.#tenants.values()){if(ten.tenantId===x.tenantKey&&ten.projectId===x.projectId)return ten.results.get(x.reportId)||null}return null;}
 addMonitor(tenant,monitor){const id=randomUUID();tenant.monitors.set(id,{id,...monitor,created_at:new Date(this.#now()).toISOString()});tenant.counters.active_monitors=tenant.monitors.size;return id;}
}
