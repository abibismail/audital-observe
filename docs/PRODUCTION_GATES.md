# Audital Observe production-readiness blockers (HOLD)

This implementation is a verified **local-development prototype** only. It is not a hosted or deployed production service and does not create MRR by itself.

1. **Durable tenant isolation:** Wire PostgreSQL migration `apps/api/sql/001_rls.sql` into a non-owner, non-BYPASSRLS application role. Require physical PostgreSQL cross-tenant read/write denial, transaction-local tenant identity and migration tests. In-memory `DevTenantStore` proves only application routing semantics.
2. **Provider credential custody:** Replace `DevEnvelopeVault` with a production KMS/envelope encryption scheme, per-tenant keys or key hierarchy, audited read permissions, rotation, revocation, and connector-specific read-only scopes. No API key should be exposed in CI, webhook text or signed evidence.
3. **Real reconciliation workers:** Queue, retry, backoff, grace windows, per-tenant quotas, durable checkpoints, idempotent schedules, event-watermark completeness, timeout and provider API quota handling. Worker registration is intentionally disabled.
4. **OTLP compatibility:** Current parser handles a documented subset of JSONL and OTLP/JSON `execute_tool` spans. Add complete OTLP HTTP protocol support (including protobuf), schema versions, framework-specific mappings, signed ingestion auth, batch size limits and validation of provider target IDs.
5. **Webhook/PR distribution:** CI payload is only a formatter; Audital holds no write tokens. A customer's own GitHub Action or integration, with explicit consent and scoped write permissions, may publish Checks. Provide opt-in GitHub App installation and avoid automatic noisy comments; include opt-out, rate limits and signed/expiring evidence URLs.
6. **Privacy:** Document UK GDPR basis, retention/deletion, export, HMAC rotation and cryptographic erasure, SOC2-oriented controls if serving enterprise. HMACs are pseudonymous, **not anonymous**; generated share URLs may still expose data and require audit logging.
7. **Evidence integrity:** Stable signing keys, public-key discovery, rotation, append-only storage, per-tenant custody, audit trails, and independent tamper tests. Ephemeral local keys do not establish durable authenticity.
8. **Assurance:** Reconciler matching is not independent Guard causal proof. Provider event API limitations and unchanged-state ambiguity must remain `UNOBSERVABLE` or lower confidence as appropriate; test every adapter against real read-only provider permissions and incomplete logs.
9. **Operating readiness:** Auth brute-force protections, TLS, quotas, abuse resistance, sandbox isolation, redaction in logs, accessibility, metrics, SLOs, secure deployment pipeline and penetration/security review.
10. **Commercial readiness:** Onboarding, billing (after approved payment flows), metering, subscription lifecycle, usage caps, API/CLI compatibility policy and upgrade path to **Audital Guard** without conflating assurance claims.

Do not enable production, live write actions, paid billing, or self-service customer exposure until relevant gates independently pass. Existing Audital Guard G01–G12 remain HOLD.
