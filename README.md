# Audital Observe v0.2 — continuous claims-versus-effects engine

**Your agent returned `200 OK`. Did the world actually change?**

Audital Observe ingests what an AI agent *claimed* it did (OTel GenAI `execute_tool` spans, Claude Code / Codex tool-result events, or plain JSON claims), re-reads the provider **read-only** after an eventual-consistency window, and emits signed evidence: `PHANTOM_SUCCESS`, `GHOST_WRITE`, `WRONG_TARGET`, `DUPLICATE_EFFECT`, `PARTIAL_EFFECT`, `LATE_EFFECT`.

It is a standalone, lower-assurance entry point to Audital. It is **not Guard**, never emits Guard's top status, and every output carries explicit `asserts` and `cannot_assert`.

## What's new in v0.2

| Area | v0.2 |
|---|---|
| **Attestation boundary** | Every envelope (`v: 2`) carries `attestation`. CLI and local signers only ever emit `local_unattested`: file integrity under a self-supplied key, **not** third-party attestation. `hosted_attested` requires a private key whose public half is pinned in `packages/observe-contract/trust/hosted-keys.json`, and verifiers accept it **only** against that registry, never against keys embedded in a pack. The registry ships **empty**. |
| **Keyed HMAC everywhere** | Targets, actors and argument blobs are HMAC-SHA256 under a **per-project** key (HKDF from a ≥32-byte master). Targets are canonicalised first (`Org/Repo#3` = `org/repo#3` = the issue URL). The v0.1 vault stored an unkeyed SHA-256 of `tenant/project`, which was reversible by guessing; v0.2 replaces it with a keyed binding tag. |
| **OTel GenAI semconv** | `execute_tool` spans (`gen_ai.operation.name`, `gen_ai.tool.name`, `gen_ai.tool.call.id`, `gen_ai.tool.call.arguments` as string or structured AnyValue, `error.type`, ERROR status). Vendor mappings: Claude Code beta tracing (`claude_code.tool` + `claude_code.tool.execution`), Claude Code `claude_code.tool_result` log events, Codex `codex.tool_result` (best effort), LangSmith `langsmith.span.kind=tool`, Langfuse `langfuse.observation.type=tool`, OpenInference `openinference.span.kind=TOOL`. GitHub MCP argument shapes (`owner`/`repo`/`issue_number`) infer the target. Output: `gen_ai.evaluation.result` events with `gen_ai.evaluation.name`, `gen_ai.evaluation.score.label` (the assurance level) and `gen_ai.evaluation.explanation`, parented to the evaluated tool span (`traceId`/`spanId`), as OTLP/JSON logs. |
| **PostgreSQL + RLS** | Real checksummed migrations (`apps/api/sql/001_rls.sql`, `002_continuous_engine.sql`). FORCE RLS on all 12 tables, with tenant **and project** isolation. The app role is `NOBYPASSRLS`, owns nothing and gets column-level grants. Evidence and findings are append-only (no grant plus a trigger, even for the superuser). Cross-tenant paths exist only via narrow `SECURITY DEFINER` functions (auth, share resolution, scheduler lease returning metadata only). |
| **Continuous engine** | Ingest schedules readback at `occurred_at + grace`. The scheduler leases due monitors across tenants, then runs each tick under that tenant's RLS context: read-only GitHub readback, reconcile, signed evidence pack, backoff for `CLAIMED`/`UNOBSERVABLE`, finalisation, and deletion of the sealed target lookup. |
| **Viral hooks** | Slack and signed-webhook alerts (`x-audital-signature`, HMAC-SHA256) carrying an **expiring share link** (≤ 7 days, DB-clock authoritative). There is an outbox with dedupe and retries, plus an SSRF guard, and provider API hosts are refused outright. GitHub Check Run and PR-comment payloads (marker-based upsert) come from `POST /v1/evidence/:id/github`. They are published by **your** workflow token ([example](examples/github-action/audital-observe.yml)); Audital holds no GitHub write credential. |
| **Live GitHub wedge** | `npm run test:live-github`: real Link-header pagination (including numeric `/repositories/<id>` links, a bug the live test found), primary/secondary rate-limit backoff, a budget floor, coverage anchored at issue `created_at`, consistency windows. Classic tokens advertising write scopes are **refused**. Stripe stays mocked and now requires restricted `rk_` keys. |

## Quick start

Requirements: Node.js 22+. `npm ci` installs the pinned `typescript`, `pg` and `ajv` (dev). Docker is needed only for the PostgreSQL suite.

```sh
npm ci
npm run demo:phantom-success      # synthetic, offline; emits PHANTOM_SUCCESS + GHOST_WRITE, local_unattested
npm test                          # unit + contract + invariants (no network, no Docker)
npm run test:pg                   # starts a throwaway postgres:16-alpine container, proves RLS isolation, removes it
npm run test:all                  # both of the above
# opt-in, real GitHub (read-only token, or anonymous for a public issue):
AUDITAL_LIVE_GITHUB_ISSUE='cli/cli#1' AUDITAL_LIVE_GITHUB_TOKEN=<fine-grained Issues:read> npm run test:live-github
AUDITAL_LIVE_GITHUB_ISSUE='cli/cli#1' AUDITAL_LIVE_GITHUB_ANONYMOUS=1 npm run test:live-github
```

CLI (from this checkout, **not published to npm**):

```sh
node packages/cli/bin/audital.mjs reconcile --demo --out /tmp/pack.json --check-out /tmp/check.json \
  --pr-comment-out /tmp/comment.json --otel-out /tmp/eval-logs.json --fail-on phantom,ghost
```

## API (development or hosted-preview; never production)

```sh
export AUDITAL_OBSERVE_MODE=development
export AUDITAL_API_KEY="$(openssl rand -hex 32)" AUDITAL_HMAC_KEY="$(openssl rand -hex 32)"
npm run api:dev        # loopback only; scheduler on (AUDITAL_SCHEDULER=off to disable)
```

`AUDITAL_OBSERVE_MODE=hosted-preview` uses PostgreSQL (`AUDITAL_PG_APP_URL`, `AUDITAL_VAULT_KEY_HEX`; run `npm run db:migrate` with `AUDITAL_PG_ADMIN_URL` first). See `.env.example`.

| Endpoint | Purpose |
|---|---|
| `POST /v1/claims`, `POST /v1/otlp/traces` (or `/v1/traces`), `POST /v1/otlp/logs` (or `/v1/logs`) | Ingest. OTLP/**JSON** only. Schedules read-only reconciliation; auto-creates a monitor. |
| `POST /v1/connectors/github` | Store a read-only GitHub token (sealed in PostgreSQL mode). |
| `POST /v1/monitors`, `GET /v1/monitors`, `POST /v1/monitors/:id/run` | Schedules; manual tick. |
| `POST /v1/alert-endpoints` | `slack` (hooks.slack.com) or `webhook` (returns a signing secret). |
| `GET /v1/evidence/:id`, `GET /v1/findings`, `GET /v1/metrics` | Signed packs, findings, counters. |
| `POST /v1/evidence/:id/share`, `GET /v1/shares/:token` | Expiring bearer snapshot (≤ 7 days). |
| `POST /v1/evidence/:id/github` | `{check_run, pr_comment, share}` payloads for your CI to publish. |
| `POST /v1/reconcile` | `LOCAL_FIXTURE` only, always signed `local_unattested`; **disabled** when a hosted signer is configured, so caller-supplied observations can never get the hosted key. |

## What the evidence statuses mean

- `CLAIMED`: an action was reported and the consistency window is still open.
- `EFFECT_OBSERVED`: the provider's current state matches the expected state. **Cannot assert** exclusive causation or the absence of a same-identity competitor.
- `EFFECT_CORRELATED`: a target/time-matching provider event exists. Same two `cannot_assert` limits, enforced by contract, JSON schema and a randomised invariant test.
- `CONTRADICTED`: a complete readback conflicts with the claim (for example `PHANTOM_SUCCESS`). An effect that was observed and then reverted by someone else is `CONTRADICTED` **without** `PHANTOM_SUCCESS` (fixed in v0.2).
- `UNOBSERVABLE`: readback unavailable, rate-limited, paginated past the limit, or the coverage window is unproven.

## Strict invariants (enforced by `tests/invariants.test.mjs`)

1. Zero Guard dependencies (packages, lockfile, imports).
2. Zero write credentials. Only the notification dispatcher issues non-GET requests, and never to provider hosts. Write-scoped GitHub classic tokens and Stripe `sk_` keys are refused.
3. Guard's top status never appears in any schema, SQL migration, signer or contract build. The signer and validator refuse it as a token anywhere in a result.
4. `EFFECT_CORRELATED` and `EFFECT_OBSERVED` always carry `cannot_assert: ["exclusive causation", "no same-identity competitor"]`.
5. The CLI can only emit `local_unattested`.

## Limits and status

Not deployed, not published, not independently audited. The hosted trust registry is empty, so nothing is `hosted_attested` yet. See [`docs/PRODUCTION_GATES.md`](docs/PRODUCTION_GATES.md) and [`docs/LOCAL_VALIDATION.md`](docs/LOCAL_VALIDATION.md). Apache-2.0. Not affiliated with the named providers.
