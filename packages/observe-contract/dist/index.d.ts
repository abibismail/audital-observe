export declare const OBSERVE_SCHEMA: "audital.observe/v1";
export declare const OBSERVE_DOMAIN: "audital.observe/v1";
export declare const ASSURANCE: readonly ["CLAIMED", "EFFECT_OBSERVED", "EFFECT_CORRELATED", "CONTRADICTED", "UNOBSERVABLE"];
export declare const FINDINGS: readonly ["PHANTOM_SUCCESS", "GHOST_WRITE", "DUPLICATE_EFFECT", "WRONG_TARGET", "PARTIAL_EFFECT", "LATE_EFFECT"];
export type Assurance = typeof ASSURANCE[number];
export type Finding = typeof FINDINGS[number];
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
export declare function validateResult(value: unknown): asserts value is Result;
export declare function makeResult(input: Omit<Result, 'schema'>): Result;
export declare function rejectCallerAssurance(input: unknown): void;
export declare function assertObserveDomain(domain: string): void;
