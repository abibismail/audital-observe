# Audital Observe v0.1 local validation — 2026-11-23

## Execution and integrity

- Environment: Ubuntu Linux container, Node.js v22.16.0, global TypeScript 5.8.3.
- `npm run test`: **28/28 PASS**, 0 FAIL, 0 SKIP. Full output in `LOCAL_TEST_RUN.log`.
- `npm run demo:phantom-success`: **exit 0**, emitted `PHANTOM_SUCCESS`, `GHOST_WRITE`, and a separate `EFFECT_CORRELATED` outcome. Full output in `LOCAL_DEMO_RUN.log`.
- Synthetic fixtures only. No real GitHub/Stripe API credentials or provider effects, no AWS resources, no paid API calls, no production deployment.
- Typescript contract build succeeded; no complete hosted production API, payment integrations, RLS deployment, authenticated live monitoring or npm publishing is claimed.

## Important boundaries

1. The local API uses a process-memory data store; the SQL migration is a *proposal* and has not been tested against a physical PostgreSQL server.
2. A worker class can process injected read-only observations and has tested lifecycle handling; it is not started by the local API. SaaS scheduling, queue durability and provider credential management remain HOLD.
3. GitHub/Stripe adapters are read-only GET clients and were tested with mocked HTTP responses only. They have not undergone real-provider authorization or retention-completeness testing.
4. Signing keys are ephemeral in local demos. Durable signer custody, rotation distribution and independent verification remain HOLD.
5. Share tokens are local, bearer-based and at most one hour; their persistence, revocation and abuse controls must be built before public use.
6. This code does not use or depend on Audital Guard; it cannot report Guard `VERIFIED`.
7. CI can install pinned TypeScript 5.8.3 via npm, but a resolved npm lockfile is not included because the execution environment lacked npm registry access. Generate, review and commit a lockfile before public GitHub release.
