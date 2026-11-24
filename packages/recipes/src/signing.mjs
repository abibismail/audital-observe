import {generateKeyPairSync,sign,verify,createPublicKey,createPrivateKey,createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {assertObserveDomain,validateResult,validateEnvelope,containsGuardOnlyClaim} from '../../observe-contract/dist/index.js';
import {canonicalJSON} from './canonical.mjs';

// Attestation boundary:
//  - ObserveSigner (CLI, local dev) ALWAYS emits `local_unattested`: integrity under a self-supplied,
//    usually ephemeral key. It proves the file was not altered after signing — nothing about who ran it.
//  - HostedObserveSigner emits `hosted_attested` and refuses to construct unless its private key matches
//    a key pinned in the hosted trust registry. Verifiers accept `hosted_attested` ONLY against that
//    registry, never against keys embedded in a pack.
const DOMAIN='audital.observe/v1';
const LOCAL='local_unattested',HOSTED='hosted_attested';
const fingerprint=publicKey=>createHash('sha256').update(publicKey.export({type:'spki',format:'der'})).digest('hex');
const bytesFor=payload=>Buffer.from(`${DOMAIN}\n${canonicalJSON(payload)}`);

function signEnvelope(privateKey,kid,attestation,result){
 validateResult(result);assertObserveDomain(DOMAIN);
 if(containsGuardOnlyClaim(result))throw Error('FORBIDDEN_ASSURANCE_CLAIM');
 const payload={domain:DOMAIN,attestation,result};
 const envelope={v:2,domain:DOMAIN,kid,alg:'Ed25519',attestation,payload,signature:sign(null,bytesFor(payload),privateKey).toString('base64url')};
 validateEnvelope(envelope);
 return Object.freeze(envelope);
}

export class ObserveSigner {
 constructor(options={}){
  if(options.attestation!==undefined&&options.attestation!==LOCAL)throw Error('LOCAL_SIGNER_CANNOT_ATTEST');
  this.keys=new Map();this.current=null;
 }
 get attestation(){return LOCAL;}
 rotate(kid=null){
  const {publicKey,privateKey}=generateKeyPairSync('ed25519');
  const keyId=kid||`local:${fingerprint(publicKey).slice(0,24)}`;
  if(this.keys.has(keyId))throw Error('DUPLICATE_KEY_ID');
  this.keys.set(keyId,{publicKey,privateKey});this.current=keyId;return keyId;
 }
 signResult(result){if(!this.current)throw Error('NO_SIGNING_KEY');return signEnvelope(this.keys.get(this.current).privateKey,this.current,LOCAL,result);}
 exportPublicKeys(){return Object.fromEntries([...this.keys].map(([kid,p])=>[kid,p.publicKey.export({type:'spki',format:'pem'})]));}
 /** Back-compat boolean check for local packs. Use verifyEnvelope() to learn the attestation level. */
 static verifyPack(pack,keys){return verifyEnvelope(pack,{localKeys:keys}).valid;}
}

export function loadTrustRegistry(source){
 const doc=typeof source==='string'?JSON.parse(source):source;
 if(!doc||doc.schema!=='audital.observe.trust-registry/v1'||!Array.isArray(doc.keys))throw Error('TRUST_REGISTRY_INVALID');
 const map=new Map();
 for(const k of doc.keys){
  if(!k||typeof k.kid!=='string'||!/^[A-Za-z0-9_.:-]{8,64}$/.test(k.kid)||k.alg!=='Ed25519'||typeof k.public_key_pem!=='string')throw Error('TRUST_REGISTRY_ENTRY_INVALID');
  if(k.kid.startsWith('local:'))throw Error('TRUST_REGISTRY_LOCAL_KID_FORBIDDEN');
  if(map.has(k.kid))throw Error('TRUST_REGISTRY_DUPLICATE_KID');
  const publicKey=createPublicKey(k.public_key_pem);if(publicKey.asymmetricKeyType!=='ed25519')throw Error('TRUST_REGISTRY_KEY_TYPE');
  map.set(k.kid,{publicKey,fingerprint:fingerprint(publicKey),not_before:k.not_before?Date.parse(k.not_before):null,not_after:k.not_after?Date.parse(k.not_after):null});
 }
 return Object.freeze(map);
}
let defaultRegistry=null;
export function defaultTrustRegistry(){
 defaultRegistry??=loadTrustRegistry(readFileSync(new URL('../../observe-contract/trust/hosted-keys.json',import.meta.url),'utf8'));
 return defaultRegistry;
}

export class HostedObserveSigner {
 #privateKey;
 constructor({privateKeyPem,kid,registry=defaultTrustRegistry()}){
  if(!privateKeyPem||!kid)throw Error('HOSTED_KEY_AND_KID_REQUIRED');
  const entry=registry.get(kid);if(!entry)throw Error('HOSTED_KEY_NOT_PINNED');
  const privateKey=createPrivateKey(privateKeyPem);if(privateKey.asymmetricKeyType!=='ed25519')throw Error('HOSTED_KEY_TYPE');
  if(fingerprint(createPublicKey(privateKey))!==entry.fingerprint)throw Error('HOSTED_KEY_FINGERPRINT_MISMATCH');
  this.#privateKey=privateKey;this.current=kid;
 }
 get attestation(){return HOSTED;}
 rotate(){throw Error('HOSTED_ROTATION_IS_A_REGISTRY_CEREMONY');}
 signResult(result){return signEnvelope(this.#privateKey,this.current,HOSTED,result);}
 // Hosted packs deliberately embed no keys: verifiers must use the pinned registry.
 exportPublicKeys(){return {};}
}

/** Returns {valid, attestation, integrity_only, reason}. Never throws. */
export function verifyEnvelope(envelope,{localKeys={},hostedRegistry=defaultTrustRegistry()}={}){
 const no=reason=>({valid:false,attestation:null,integrity_only:true,reason});
 try{validateEnvelope(envelope);}catch(e){return no(e.message);}
 if(containsGuardOnlyClaim(envelope.payload))return no('FORBIDDEN_ASSURANCE_CLAIM');
 const data=bytesFor(envelope.payload),sig=Buffer.from(envelope.signature,'base64url');
 try{
  if(envelope.attestation===HOSTED){
   const entry=hostedRegistry.get(envelope.kid);if(!entry)return no('HOSTED_KID_NOT_PINNED');
   const t=Date.parse(envelope.payload.result.observed_at);
   if((entry.not_before&&t<entry.not_before)||(entry.not_after&&t>entry.not_after))return no('HOSTED_KEY_OUTSIDE_VALIDITY');
   return verify(null,data,entry.publicKey,sig)?{valid:true,attestation:HOSTED,integrity_only:false,reason:null}:no('BAD_SIGNATURE');
  }
  if(hostedRegistry.has(envelope.kid))return no('LOCAL_ENVELOPE_USES_HOSTED_KID');
  const pem=localKeys[envelope.kid];if(!pem)return no('UNKNOWN_LOCAL_KID');
  return verify(null,data,createPublicKey(pem),sig)?{valid:true,attestation:LOCAL,integrity_only:true,reason:null}:no('BAD_SIGNATURE');
 }catch{return no('VERIFY_ERROR');}
}
