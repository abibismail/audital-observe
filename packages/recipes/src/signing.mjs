import {generateKeyPairSync,sign,verify,createPublicKey,createHash} from 'node:crypto';
import {assertObserveDomain,validateResult} from '../../observe-contract/dist/index.js';
const DOMAIN='audital.observe/v1';
const canonical=x=>JSON.stringify(Object.fromEntries(Object.entries(x).sort(([a],[b])=>a.localeCompare(b))));
export class ObserveSigner {
 constructor(){this.keys=new Map();this.current=null;}
 rotate(kid=null){
  const {publicKey,privateKey}=generateKeyPairSync('ed25519');
  const keyId=kid||createHash('sha256').update(publicKey.export({type:'spki',format:'der'})).digest('hex').slice(0,24);
  if(this.keys.has(keyId))throw Error('DUPLICATE_KEY_ID');
  this.keys.set(keyId,{publicKey,privateKey});this.current=keyId;return keyId;
 }
 signResult(result){validateResult(result);assertObserveDomain(DOMAIN);if(!this.current)throw Error('NO_SIGNING_KEY');
  const payload={domain:DOMAIN,result};const bytes=Buffer.from(`${DOMAIN}\n${canonical(payload)}`);
  return Object.freeze({domain:DOMAIN,kid:this.current,alg:'Ed25519',payload,signature:sign(null,bytes,this.keys.get(this.current).privateKey).toString('base64url')});
 }
 exportPublicKeys(){return Object.fromEntries([...this.keys].map(([kid,p])=>[kid,p.publicKey.export({type:'spki',format:'pem'})]));}
 static verifyPack(pack,keys){if(pack?.domain!==DOMAIN || pack?.payload?.domain!==DOMAIN || pack?.alg!=='Ed25519')return false;
  try{validateResult(pack.payload.result);const key=keys[pack.kid];if(!key)return false;
   return verify(null,Buffer.from(`${DOMAIN}\n${canonical(pack.payload)}`),createPublicKey(key),Buffer.from(pack.signature,'base64url'));
  }catch{return false;}
 }
}
