import {randomBytes,createCipheriv,createDecipheriv,createHash} from 'node:crypto';
// Dev-only example: production needs cloud KMS, audited access, and durable encrypted storage.
export class DevEnvelopeVault {
 constructor(masterKey){if(!(masterKey instanceof Buffer)||masterKey.length!==32)throw Error('MASTER_KEY_32_BYTES_REQUIRED');this.key=masterKey;}
 encrypt(plaintext,aad){const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',this.key,iv);cipher.setAAD(Buffer.from(aad));const body=Buffer.concat([cipher.update(Buffer.from(plaintext)),cipher.final()]);return {ciphertext:body.toString('base64'),nonce:iv.toString('base64'),tag:cipher.getAuthTag().toString('base64'),aad_hmac:createHash('sha256').update(aad).digest('hex')};}
 decrypt(blob,aad){if(blob.aad_hmac!==createHash('sha256').update(aad).digest('hex'))throw Error('CREDENTIAL_BINDING_MISMATCH');const d=createDecipheriv('aes-256-gcm',this.key,Buffer.from(blob.nonce,'base64'));d.setAAD(Buffer.from(aad));d.setAuthTag(Buffer.from(blob.tag,'base64'));return Buffer.concat([d.update(Buffer.from(blob.ciphertext,'base64')),d.final()]).toString('utf8');}
}
