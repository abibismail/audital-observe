import {randomBytes,createCipheriv,createDecipheriv,createHmac,hkdfSync,timingSafeEqual} from 'node:crypto';
// Dev-only example: production needs cloud KMS, audited access, and durable encrypted storage.
// v0.2: the AAD binding tag is a KEYED HMAC (subkey via HKDF). v0.1 stored an unkeyed SHA-256 of
// "tenant/project", which is a small-domain value anyone could reverse by guessing tenant names.
export class DevEnvelopeVault {
 #key;#bindKey;
 constructor(masterKey){
  if(!(masterKey instanceof Buffer)||masterKey.length!==32)throw Error('MASTER_KEY_32_BYTES_REQUIRED');
  this.#key=Buffer.from(hkdfSync('sha256',masterKey,'audital.observe/v1','vault:aes-256-gcm',32));
  this.#bindKey=Buffer.from(hkdfSync('sha256',masterKey,'audital.observe/v1','vault:aad-binding',32));
 }
 #bind(aad){return createHmac('sha256',this.#bindKey).update(String(aad)).digest('hex');}
 encrypt(plaintext,aad){const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',this.#key,iv);cipher.setAAD(Buffer.from(aad));const body=Buffer.concat([cipher.update(Buffer.from(plaintext)),cipher.final()]);return {v:2,ciphertext:body.toString('base64'),nonce:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64'),aad_binding:this.#bind(aad)};}
 decrypt(blob,aad){
  if(!blob||blob.v!==2)throw Error('VAULT_BLOB_VERSION');
  const a=Buffer.from(String(blob.aad_binding||''),'hex'),b=Buffer.from(this.#bind(aad),'hex');
  if(a.length!==b.length||!timingSafeEqual(a,b))throw Error('CREDENTIAL_BINDING_MISMATCH');
  const d=createDecipheriv('aes-256-gcm',this.#key,Buffer.from(blob.nonce,'base64'));d.setAAD(Buffer.from(aad));d.setAuthTag(Buffer.from(blob.tag,'base64'));return Buffer.concat([d.update(Buffer.from(blob.ciphertext,'base64')),d.final()]).toString('utf8');
 }
}
