import test from 'node:test';import assert from 'node:assert/strict';
import {generateKeyPairSync} from 'node:crypto';
import {ObserveSigner,HostedObserveSigner,verifyEnvelope,loadTrustRegistry,defaultTrustRegistry} from '../src/signing.mjs';
import {canonicalJSON} from '../src/canonical.mjs';
import {reconcile} from '../src/reconcile.mjs';
const claim={claim_id:'c',target_hash:'h',args_hmac:'a',occurred_at:'2026-11-20T12:00:00Z',claimed_success:true,expected_state:'closed',provider:'github',action:'close'};
const result=reconcile(claim,{available:true,complete:true,coverage_start:'2026-11-20T11:00:00Z',observed_at:'2026-11-20T12:05:00Z',current_state:'closed',events:[]});
function hostedFixture(kid='audital-hosted:test-2026'){
 const {publicKey,privateKey}=generateKeyPairSync('ed25519');
 const registry=loadTrustRegistry({schema:'audital.observe.trust-registry/v1',keys:[{kid,alg:'Ed25519',public_key_pem:publicKey.export({type:'spki',format:'pem'})}]});
 return {kid,registry,privateKeyPem:privateKey.export({type:'pkcs8',format:'pem'})};
}
test('local signer can never emit hosted_attested',()=>{
 assert.throws(()=>new ObserveSigner({attestation:'hosted_attested'}),/LOCAL_SIGNER_CANNOT_ATTEST/);
 const s=new ObserveSigner();s.rotate();const e=s.signResult(result);
 assert.equal(e.attestation,'local_unattested');assert.match(e.kid,/^local:/);
 const v=verifyEnvelope(e,{localKeys:s.exportPublicKeys()});assert.deepEqual([v.valid,v.attestation,v.integrity_only],[true,'local_unattested',true]);
});
test('relabelling a local envelope as hosted_attested fails verification',()=>{
 const s=new ObserveSigner();s.rotate();const e=s.signResult(result);const keys=s.exportPublicKeys();
 const outer={...e,attestation:'hosted_attested'};assert.equal(verifyEnvelope(outer,{localKeys:keys}).valid,false);
 const both={...e,attestation:'hosted_attested',payload:{...e.payload,attestation:'hosted_attested'}};
 const r=verifyEnvelope(both,{localKeys:keys});assert.equal(r.valid,false);assert.equal(r.reason,'HOSTED_KID_NOT_PINNED');
});
test('hosted signer requires a key pinned in the trust registry',()=>{
 const f=hostedFixture();
 assert.throws(()=>new HostedObserveSigner({privateKeyPem:f.privateKeyPem,kid:f.kid}),/HOSTED_KEY_NOT_PINNED/,'default registry is empty');
 const other=generateKeyPairSync('ed25519').privateKey.export({type:'pkcs8',format:'pem'});
 assert.throws(()=>new HostedObserveSigner({privateKeyPem:other,kid:f.kid,registry:f.registry}),/FINGERPRINT_MISMATCH/);
 const h=new HostedObserveSigner(f);const e=h.signResult(result);
 assert.equal(e.attestation,'hosted_attested');assert.deepEqual(h.exportPublicKeys(),{});
 const v=verifyEnvelope(e,{hostedRegistry:f.registry});assert.deepEqual([v.valid,v.attestation,v.integrity_only],[true,'hosted_attested',false]);
});
test('hosted_attested NEVER verifies against embedded/local keys, only the pinned registry',()=>{
 const f=hostedFixture();const h=new HostedObserveSigner(f);const e=h.signResult(result);
 assert.equal(verifyEnvelope(e).valid,false,'default (empty) registry');
 // attacker crafts their own "hosted" key, embeds it as a local key with the same kid
 const evil=hostedFixture(f.kid);const forged=new HostedObserveSigner(evil).signResult(result);
 const r=verifyEnvelope(forged,{localKeys:{[f.kid]:'ignored'},hostedRegistry:f.registry});assert.equal(r.valid,false);assert.equal(r.reason,'BAD_SIGNATURE');
});
test('registry refuses local: kids; default registry ships empty',()=>{
 assert.equal(defaultTrustRegistry().size,0);
 assert.throws(()=>loadTrustRegistry({schema:'audital.observe.trust-registry/v1',keys:[{kid:'local:abcdef12',alg:'Ed25519',public_key_pem:'x'}]}),/LOCAL_KID_FORBIDDEN/);
});
test('signatures survive key reordering (PostgreSQL jsonb round-trip)',()=>{
 const s=new ObserveSigner();s.rotate();const e=s.signResult(result);
 const shuffle=x=>Array.isArray(x)?x.map(shuffle):x&&typeof x==='object'?Object.fromEntries(Object.entries(x).reverse().map(([k,v])=>[k,shuffle(v)])):x;
 const reordered=shuffle(JSON.parse(JSON.stringify(e)));
 assert.notEqual(JSON.stringify(reordered),JSON.stringify(e));assert.equal(canonicalJSON(reordered),canonicalJSON(e));
 assert.equal(verifyEnvelope(reordered,{localKeys:s.exportPublicKeys()}).valid,true);
});
test('tampering with any nested result field breaks the signature',()=>{
 const s=new ObserveSigner();s.rotate();const e=JSON.parse(JSON.stringify(s.signResult(result)));
 e.payload.result.findings=[];e.payload.result.assurance='EFFECT_OBSERVED';e.payload.result.reason_codes=['x'];
 assert.equal(verifyEnvelope(e,{localKeys:s.exportPublicKeys()}).valid,false);
});
