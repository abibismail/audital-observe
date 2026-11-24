// Audital Observe is a separate, strictly lower-assurance namespace than Guard.
// Invariants (enforced here, in the JSON schemas, the signer and tests/invariants.test.mjs):
//  - the Guard-only top status word never exists as an Observe assurance value, assert, or signed string;
//  - EFFECT_CORRELATED and EFFECT_OBSERVED always carry both CAUSATION_LIMITS in cannot_assert;
//  - local CLI output is `local_unattested`; `hosted_attested` is reserved for the hosted service key.
export const OBSERVE_SCHEMA = 'audital.observe/v1';
export const OBSERVE_DOMAIN = 'audital.observe/v1';
export const ENVELOPE_VERSION = 2;
export const ASSURANCE = ['CLAIMED', 'EFFECT_OBSERVED', 'EFFECT_CORRELATED', 'CONTRADICTED', 'UNOBSERVABLE'];
export const FINDINGS = ['PHANTOM_SUCCESS', 'GHOST_WRITE', 'DUPLICATE_EFFECT', 'WRONG_TARGET', 'PARTIAL_EFFECT', 'LATE_EFFECT'];
export const ATTESTATION = ['local_unattested', 'hosted_attested'];
export const CAUSATION_LIMITS = ['exclusive causation', 'no same-identity competitor'];
// Built from char codes so the forbidden word itself never appears in this source or its build output.
const GUARD_ONLY_WORD = String.fromCharCode(86, 69, 82, 73, 70, 73, 69, 68);
const FORBIDDEN = new Set([GUARD_ONLY_WORD, 'causally verified', 'exclusive causation established']);
const ORDER = new Set(ASSURANCE);
const FINDING_SET = new Set(FINDINGS);
const ATTESTATION_SET = new Set(ATTESTATION);
function isRecord(x) { return !!x && typeof x === 'object' && !Array.isArray(x); }
function stringArr(x, label) {
    if (!Array.isArray(x) || x.length > 50 || !x.every(v => typeof v === 'string' && v.length <= 250))
        throw Error(`INVALID_${label}`);
    return x;
}
/** Deep scan: true if any string or key anywhere contains the Guard-only status word (any case, as a token). */
export function containsGuardOnlyClaim(value, depth = 0) {
    if (depth > 32)
        return true;
    // Alphanumeric boundaries (not \b): `_` separates tokens, so CLAIM_<word> is caught; UN<word>ABLE is not.
    const re = new RegExp(`(?<![A-Za-z0-9])${GUARD_ONLY_WORD}(?![A-Za-z0-9])`, 'i');
    if (typeof value === 'string')
        return re.test(value);
    if (Array.isArray(value))
        return value.some(v => containsGuardOnlyClaim(v, depth + 1));
    if (isRecord(value))
        return Object.entries(value).some(([k, v]) => re.test(k) || containsGuardOnlyClaim(v, depth + 1));
    return false;
}
export function validateResult(value) {
    if (!isRecord(value))
        throw Error('INVALID_RESULT');
    const keys = ['schema', 'claim_id', 'assurance', 'findings', 'asserts', 'cannot_assert', 'observed_at', 'target_hash', 'observation_complete', 'reason_codes'];
    if (Object.keys(value).sort().join('|') !== keys.sort().join('|'))
        throw Error('UNKNOWN_RESULT_FIELDS');
    if (value.schema !== OBSERVE_SCHEMA || typeof value.assurance !== 'string' || !ORDER.has(value.assurance))
        throw Error('INVALID_ASSURANCE');
    if (typeof value.claim_id !== 'string' && value.claim_id !== null)
        throw Error('INVALID_CLAIM_ID');
    if (typeof value.target_hash !== 'string' && value.target_hash !== null)
        throw Error('INVALID_TARGET_HASH');
    if (typeof value.observed_at !== 'string' || !Number.isFinite(Date.parse(value.observed_at)))
        throw Error('INVALID_OBSERVED_AT');
    if (typeof value.observation_complete !== 'boolean')
        throw Error('INVALID_COMPLETENESS');
    const findings = stringArr(value.findings, 'FINDINGS');
    if (findings.some(v => !FINDING_SET.has(v)))
        throw Error('UNKNOWN_FINDING');
    if (new Set(findings).size !== findings.length)
        throw Error('DUPLICATE_FINDING');
    const asserts = stringArr(value.asserts, 'ASSERTS');
    const limits = stringArr(value.cannot_assert, 'CANNOT_ASSERT');
    stringArr(value.reason_codes, 'REASONS');
    if (asserts.some(v => FORBIDDEN.has(v)) || containsGuardOnlyClaim(value))
        throw Error('FORBIDDEN_ASSURANCE_CLAIM');
    if (value.assurance === 'EFFECT_CORRELATED' || value.assurance === 'EFFECT_OBSERVED') {
        for (const v of CAUSATION_LIMITS)
            if (!limits.includes(v))
                throw Error('MISSING_CAUSATION_LIMIT');
    }
    if (!value.observation_complete && !['UNOBSERVABLE', 'CLAIMED'].includes(value.assurance))
        throw Error('INCOMPLETE_EVIDENCE_OVERCLAIM');
}
export function makeResult(input) {
    if ('schema' in input)
        throw Error('CALLER_SCHEMA_FORBIDDEN');
    const result = { schema: OBSERVE_SCHEMA, ...input };
    validateResult(result);
    return Object.freeze(result);
}
export function rejectCallerAssurance(input) {
    if (isRecord(input) && ('assurance' in input || 'signature' in input || 'asserts' in input || 'cannot_assert' in input || 'attestation' in input))
        throw Error('CALLER_SUPPLIED_ASSURANCE_FORBIDDEN');
}
export function assertObserveDomain(domain) { if (domain !== OBSERVE_DOMAIN)
    throw Error('WRONG_SIGNING_DOMAIN'); }
export function assertAttestation(value) { if (typeof value !== 'string' || !ATTESTATION_SET.has(value))
    throw Error('INVALID_ATTESTATION'); }
/** Structural validation only. Cryptographic verification and trust-registry pinning live in the verifier. */
export function validateEnvelope(value) {
    if (!isRecord(value))
        throw Error('INVALID_ENVELOPE');
    if (Object.keys(value).sort().join('|') !== ['alg', 'attestation', 'domain', 'kid', 'payload', 'signature', 'v'].join('|'))
        throw Error('UNKNOWN_ENVELOPE_FIELDS');
    if (value.v !== ENVELOPE_VERSION)
        throw Error('UNSUPPORTED_ENVELOPE_VERSION');
    assertObserveDomain(String(value.domain));
    if (value.alg !== 'Ed25519')
        throw Error('UNSUPPORTED_ALG');
    if (typeof value.kid !== 'string' || !/^[A-Za-z0-9_.:-]{8,64}$/.test(value.kid))
        throw Error('INVALID_KID');
    assertAttestation(value.attestation);
    if (typeof value.signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(value.signature))
        throw Error('INVALID_SIGNATURE_ENCODING');
    const p = value.payload;
    if (!isRecord(p) || Object.keys(p).sort().join('|') !== 'attestation|domain|result')
        throw Error('INVALID_PAYLOAD');
    assertObserveDomain(String(p.domain));
    if (p.attestation !== value.attestation)
        throw Error('ATTESTATION_MISMATCH');
    validateResult(p.result);
}
