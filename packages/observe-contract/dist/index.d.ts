export declare const OBSERVE_SCHEMA: "audital.observe/v1";
export declare const OBSERVE_DOMAIN: "audital.observe/v1";
export declare const ENVELOPE_VERSION: 2;
export declare const ASSURANCE: readonly ["CLAIMED", "EFFECT_OBSERVED", "EFFECT_CORRELATED", "CONTRADICTED", "UNOBSERVABLE"];
export declare const FINDINGS: readonly ["PHANTOM_SUCCESS", "GHOST_WRITE", "DUPLICATE_EFFECT", "WRONG_TARGET", "PARTIAL_EFFECT", "LATE_EFFECT"];
export declare const ATTESTATION: readonly ["local_unattested", "hosted_attested"];
export declare const CAUSATION_LIMITS: readonly ["exclusive causation", "no same-identity competitor"];
export type Assurance = typeof ASSURANCE[number];
export type Finding = typeof FINDINGS[number];
export type Attestation = typeof ATTESTATION[number];
export type Observation = {
    complete: boolean;
    available: boolean;
    events: Array<{
        kind: string;
        target_hash: string;
        time: string;
        actor_hash?: string;
        id?: string;
        attributes?: Record<string, string>;
    }>;
    current_state?: string;
    observed_at: string;
    coverage_start?: string;
};
export type Claim = {
    claim_id: string;
    provider: 'github' | 'stripe' | 'mock';
    action: string;
    target_hash: string;
    occurred_at: string;
    args_hmac: string;
    claimed_success: boolean;
    expected_state?: string;
    actor_hash?: string;
    trace_id?: string | null;
    span_id?: string | null;
    source?: string;
};
export type Result = {
    schema: typeof OBSERVE_SCHEMA;
    claim_id: string | null;
    assurance: Assurance;
    findings: Finding[];
    asserts: string[];
    cannot_assert: string[];
    observed_at: string;
    target_hash: string | null;
    observation_complete: boolean;
    reason_codes: string[];
};
export type EnvelopePayload = {
    domain: typeof OBSERVE_DOMAIN;
    attestation: Attestation;
    result: Result;
};
export type Envelope = {
    v: typeof ENVELOPE_VERSION;
    domain: typeof OBSERVE_DOMAIN;
    kid: string;
    alg: 'Ed25519';
    attestation: Attestation;
    payload: EnvelopePayload;
    signature: string;
};
/** Deep scan: true if any string or key anywhere contains the Guard-only status word (any case, as a token). */
export declare function containsGuardOnlyClaim(value: unknown, depth?: number): boolean;
export declare function validateResult(value: unknown): asserts value is Result;
export declare function makeResult(input: Omit<Result, 'schema'>): Result;
export declare function rejectCallerAssurance(input: unknown): void;
export declare function assertObserveDomain(domain: string): void;
export declare function assertAttestation(value: unknown): asserts value is Attestation;
/** Structural validation only. Cryptographic verification and trust-registry pinning live in the verifier. */
export declare function validateEnvelope(value: unknown): asserts value is Envelope;
