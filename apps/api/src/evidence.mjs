import {randomUUID} from 'node:crypto';
export const MAX_SHARE_TTL_SECONDS=7*86400;
export const DEFAULT_SHARE_TTL_SECONDS=86400;
export const PACK_LIMITATIONS=Object.freeze([
 'Read-only observed/correlated evidence does NOT prove exclusive causation',
 'Provider history may be incomplete beyond the inspected window; incomplete reads are UNOBSERVABLE',
 'local_unattested = file integrity under a self-supplied key only; hosted_attested verifies ONLY against the pinned Audital trust registry',
]);
/** Builds a signed evidence pack. The attestation level is the signer's, never caller-chosen. */
export function buildEvidencePack({ctx,results,signer,createdAt,packId=randomUUID()}){
 const envelopes=results.map(r=>signer.signResult(r));
 return {schema:'audital.observe.pack/v2',pack_id:packId,project_id:ctx.projectId,created_at:createdAt,
  attestation:signer.attestation,kid:signer.current,results:envelopes,public_keys:signer.exportPublicKeys(),limitations:[...PACK_LIMITATIONS]};
}
export const resultsOf=pack=>pack.results.map(e=>e.payload.result);
export function checkShareTtl(ttl){if(!Number.isSafeInteger(ttl)||ttl<60||ttl>MAX_SHARE_TTL_SECONDS)throw Error('INVALID_SHARE_TTL');return ttl;}
