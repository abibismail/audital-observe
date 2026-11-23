# Audital Observe v0.1 — claims versus effects

**Your agent returned `200 OK`. Did the world actually change?**

This is a **standalone, independent horizontal developer entry point** to Audital, designed to become part of the unified Audital platform. It is not Guard and never returns Guard's `VERIFIED` status. Its output makes the evidence boundary explicit with `asserts` and `cannot_assert` fields.

## 60-second synthetic demonstration

Requirements: Node.js 22+ and TypeScript 5.8.3 (`tsc` in PATH, or `npm install` for the pinned development dependency). Demo execution makes no cloud or network calls.

```sh
npm run demo:phantom-success
npm run test
```

The demo uses a fictional GitHub issue workflow with a claimed successful closure, a mismatched readback, an observed unrelated change, and another correlated event. Expected findings include `PHANTOM_SUCCESS` and `GHOST_WRITE`. They **do not** prove real-world causation.

From this checkout, the CLI runs with:

```sh
node packages/cli/bin/audital.mjs reconcile --demo --out /tmp/audital-evidence-pack.json
node packages/cli/bin/audital.mjs reconcile --claims examples/phantom-success-demo/spans.jsonl --provider github --fixture examples/phantom-success-demo/provider-github.json --fail-on phantom,ghost
```

This package is **not published to npm**; `npx audital reconcile` would work only after package ownership/publishing. Do not imply it is already live.

## Development-only hosted API

The API has request ingress, HMAC normalization, a scoped in-memory store, signed evidence output, temporary opt-in bearer share links, CI Check output formatting, monitor registration and telemetry. `ObserveWorker` has a tested timer and read-only observation callback for local integration, but the API does not activate it. **It deliberately rejects production mode**. Background provider monitoring, durable Postgres/RLS, cloud KMS credential custody, live connectors from the API and outbound alerts **are not enabled**. See [`docs/PRODUCTION_GATES.md`](docs/PRODUCTION_GATES.md).

```sh
export AUDITAL_OBSERVE_MODE=development
export AUDITAL_API_KEY="$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")"
export AUDITAL_HMAC_KEY="$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))")"
npm run api:dev
```

Supported development endpoints: `POST /v1/claims`, `POST /v1/otlp/traces` (JSON **only**, not protobuf), `POST /v1/reconcile` (local fixtures only), `GET /v1/evidence/:id`, `POST /v1/evidence/:id/share`, `GET /v1/shares/:token`, `GET /v1/checks/:id`, `GET /v1/alerts/:id`, `POST /v1/monitors` (disabled by default), `GET /v1/metrics`.

## What the evidence statuses mean

- `CLAIMED` — an action was reported and an observation grace period remains open.
- `EFFECT_OBSERVED` — the provider's current state matches an expected state; **not** exclusive causation.
- `EFFECT_CORRELATED` — target/timestamp-matching provider event exists; **not** exclusive causation.
- `CONTRADICTED` — a complete readback conflicts with the claim, possibly `PHANTOM_SUCCESS`.
- `UNOBSERVABLE` — readback or event-history completeness cannot be established.

Each output contains explicit `asserts` and `cannot_assert`; some findings can co-exist with correlated effects (for example, duplicate effects). Signed outputs are domain-separated under `audital.observe/v1`, with explicit key IDs for rotation.

## Read-only adapters and privacy

The CLI supports GitHub issue GET/readback and Stripe Events GET. Supply `GITHUB_READ_TOKEN` or `STRIPE_READ_KEY` **only with appropriate read-only privileges**. Live reads are conservative: incomplete pagination, insufficient event history, or unavailable provider data produce `UNOBSERVABLE`. Ordinary state agreement **never** implies uniquely caused action. API ingress stores HMAC-protected target/argument identifiers, not raw tool-call arguments. Each project needs its own independently managed HMAC secret.

## License and contribution

Apache-2.0; see `LICENSE`. This is a v0.1 executable development prototype. It has **not** been independently security audited or approved for production or regulated deployments. Not affiliated with the named API providers.
