# Audital Observe v0.2 local validation: 2026-11-24

## Environment
- macOS (Darwin 24.6.0, arm64), Node.js v22.22.2, TypeScript 5.8.3, `pg` 8.23.1, `ajv` 8.17.1 (dev only)
- Docker 29.9.2, image `postgres:16-alpine` (PostgreSQL 16.15), one throwaway container per run, removed afterwards
- No AWS resources, no npm publish, no provider writes, no paid API calls

## Results (exact)
| Suite | Command | Result | Log |
|---|---|---|---|
| Syntax | `npm run lint:syntax` | exit 0 | — |
| Unit + contract + schema + invariants | `npm test` | **68/68 pass**, 0 fail, 0 skip | `LOCAL_TEST_RUN.log` |
| PostgreSQL RLS (Docker) | `npm run test:pg` | **12/12 pass**, 0 fail, 0 skip | `LOCAL_PG_RLS_RUN.log` |
| Live GitHub (opt-in) | `AUDITAL_LIVE_GITHUB_ISSUE='cli/cli#1' AUDITAL_LIVE_GITHUB_ANONYMOUS=1 npm run test:live-github` | **6/6 pass** against real api.github.com | `LIVE_GITHUB_RUN.log` |
| Live GitHub, no env | `npm run test:live-github` | 6/6 skipped (opt-in) | — |
| Demo | `npm run demo:phantom-success` | exit 0; PHANTOM_SUCCESS, GHOST_WRITE, EFFECT_CORRELATED; `local_unattested` | `LOCAL_DEMO_RUN.log` |

The live run used **anonymous** (zero-credential) mode against a public closed PR (`cli/cli#1`: 26 events, 6 pages at per_page=5, about 16 GET requests). It was **not** run with a read-only token. Run it with `AUDITAL_LIVE_GITHUB_TOKEN` (fine-grained, Issues:read + Metadata:read) to prove private-repo access and authenticated rate limits.

## Defects found and fixed during the v0.1 → v0.2 audit
1. `observe.v1.schema.json` was **not valid JSON** (unbalanced braces); now validated by Ajv in CI.
2. The schema required only one causation limit per state (EFFECT_CORRELATED → "exclusive causation", EFFECT_OBSERVED → "no same-identity competitor"); it now requires both for both.
3. The signer canonicalised only top-level keys, so signatures would break after a PostgreSQL `jsonb` round-trip. It now uses deep canonical JSON (tested against real PG).
4. The vault stored an **unkeyed** SHA-256 of `tenant/project` (reversible by guessing); it is now a keyed HMAC binding tag.
5. A single HMAC key was shared by every tenant in the API; keys are now derived per project with HKDF.
6. The SQL had a global uuid `claim_id` PK (cross-tenant existence oracle; real tool-call ids are not uuids), no RLS on `tenants`, no roles or grants, mutable evidence and no project isolation.
7. The parser treated `invoke_agent` spans as tool effects, silently truncated long targets (collision risk), defaulted unknown tools to `expected_state: closed` (manufactured PHANTOM_SUCCESS), and emitted the non-semconv `gen_ai.evaluation.result` *attribute* instead of `gen_ai.evaluation.score.label`.
8. The reconciler labelled "effect observed, then reverted by someone else" as PHANTOM_SUCCESS.
9. The `/v1/reconcile` fixture route would have signed caller-supplied observations with whatever service key was configured; it is now local-signer only and disabled under a hosted signer.
10. **Found by the live test:** GitHub's real Link headers paginate via `/repositories/<id>/...`, which the v0.1 allow-list rejected (every multi-page issue went UNOBSERVABLE).
11. The Stripe connector accepted `sk_` secret keys (write-capable); it now requires restricted `rk_` keys.
12. Internal errors (including DB messages) were echoed to clients as HTTP 400; they are now a generic 500.

## Boundaries that remain
See `PRODUCTION_GATES.md`. Notably, the hosted trust registry is **empty**, so no output is `hosted_attested` yet. The vault is a dev vault (no KMS), Stripe is mocked, and OTLP protobuf is unsupported.
