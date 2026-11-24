import test from 'node:test';import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import Ajv2020 from 'ajv/dist/2020.js';
import {ASSURANCE,ATTESTATION,OBSERVE_DOMAIN,makeResult,validateResult,validateEnvelope,rejectCallerAssurance,assertObserveDomain,containsGuardOnlyClaim} from '../dist/index.js';
const GUARD_WORD=['VERI','FIED'].join('');
const schema=n=>JSON.parse(readFileSync(new URL(`../schema/${n}`,import.meta.url),'utf8'));
const ajv=new Ajv2020({strict:false,validateFormats:false});
ajv.addSchema(schema('observe.v1.schema.json'));
const validateV1=ajv.getSchema('https://audital.ai/schemas/observe.v1.schema.json');
const validateEnvSchema=ajv.compile(schema('observe.envelope.v2.schema.json'));
const ok={schema:'audital.observe/v1',claim_id:'a',assurance:'EFFECT_CORRELATED',findings:[],asserts:[],cannot_assert:['exclusive causation','no same-identity competitor'],observed_at:'2026-11-20T00:00:00.000Z',target_hash:'h',observation_complete:true,reason_codes:[]};

test('Observe namespace forbids the Guard-only status',()=>{assert.ok(!ASSURANCE.includes(GUARD_WORD));assert.equal(OBSERVE_DOMAIN,'audital.observe/v1');assert.throws(()=>assertObserveDomain('audital.guard/v1'))});
test('cannot inject caller assurance or attestation',()=>{assert.throws(()=>rejectCallerAssurance({assurance:GUARD_WORD}));assert.throws(()=>rejectCallerAssurance({signature:'abc'}));assert.throws(()=>rejectCallerAssurance({attestation:'hosted_attested'}))});
test('correlation without exclusive causation rejected',()=>{assert.throws(()=>makeResult({...ok,schema:undefined,cannot_assert:[]}));});
test('both causation limits required for EFFECT_CORRELATED and EFFECT_OBSERVED (contract)',()=>{
 for(const assurance of ['EFFECT_CORRELATED','EFFECT_OBSERVED'])for(const one of [['exclusive causation'],['no same-identity competitor']])
  assert.throws(()=>validateResult({...ok,assurance,cannot_assert:one}),/MISSING_CAUSATION_LIMIT/);
 validateResult(ok);
});
test('unknown fields and Guard-only words anywhere are rejected',()=>{
 assert.throws(()=>validateResult({...ok,asserts:['verified']}));
 assert.throws(()=>validateResult({...ok,reason_codes:[`CLAIM_${GUARD_WORD}`]}),/FORBIDDEN/);
 assert.throws(()=>validateResult({...ok,extra:'yes'}));
 assert.equal(containsGuardOnlyClaim({a:['UNVERIFIABLE','fine']}),false);
 assert.equal(containsGuardOnlyClaim({deep:{x:[GUARD_WORD.toLowerCase()]}}),true);
});
test('incomplete evidence cannot produce correlated assurance',()=>{assert.throws(()=>validateResult({...ok,observation_complete:false}));});
test('JSON schema matches contract: both causation limits required, incomplete cannot overclaim',()=>{
 assert.equal(validateV1(ok),true,JSON.stringify(validateV1.errors));
 for(const assurance of ['EFFECT_CORRELATED','EFFECT_OBSERVED'])for(const one of [['exclusive causation'],['no same-identity competitor'],[]])
  assert.equal(validateV1({...ok,assurance,cannot_assert:one}),false,`${assurance} ${one}`);
 assert.equal(validateV1({...ok,observation_complete:false}),false);
 assert.equal(validateV1({...ok,assurance:GUARD_WORD}),false);
 assert.equal(validateV1({...ok,assurance:'CLAIMED',cannot_assert:[]}),true);
});
test('envelope v2: attestation enum, payload binding, schema parity',()=>{
 assert.deepEqual([...ATTESTATION],['local_unattested','hosted_attested']);
 const env={v:2,domain:'audital.observe/v1',kid:'local:0123456789ab',alg:'Ed25519',attestation:'local_unattested',payload:{domain:'audital.observe/v1',attestation:'local_unattested',result:ok},signature:'A'.repeat(86)};
 validateEnvelope(env);assert.equal(validateEnvSchema(env),true,JSON.stringify(validateEnvSchema.errors));
 assert.throws(()=>validateEnvelope({...env,attestation:'hosted_attested'}),/ATTESTATION_MISMATCH/);
 assert.throws(()=>validateEnvelope({...env,attestation:'self_attested',payload:{...env.payload,attestation:'self_attested'}}),/INVALID_ATTESTATION/);
 assert.equal(validateEnvSchema({...env,attestation:'self_attested'}),false);
 assert.throws(()=>validateEnvelope({...env,v:1}),/UNSUPPORTED_ENVELOPE_VERSION/);
 assert.throws(()=>validateEnvelope({...env,domain:'audital.guard/v1'}));
});
