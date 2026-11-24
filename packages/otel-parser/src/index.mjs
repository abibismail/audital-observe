import { createHmac, hkdfSync, randomUUID } from 'node:crypto';
import { canonicalJSON } from '../../recipes/src/canonical.mjs';

// Raw tool arguments and target refs may be held in memory for a one-time lookup only.
// Persist ONLY normalized.publicClaim (keyed HMACs). Never log normalized.lookup.
//
// Every small-domain identifier (issue numbers, repo names, actor logins, argument blobs) is hashed with a
// KEYED HMAC under a per-project secret. An unkeyed digest of `org/repo#123` could be reversed by enumerating
// issue numbers; a keyed HMAC cannot be without the project secret.
export const MIN_HMAC_KEY_BYTES = 32;
const keyLength = key => Buffer.isBuffer(key) ? key.length : Buffer.byteLength(String(key ?? ''));
export const hmacIdentifier = (key, value, namespace='id') => {
  if (!key || keyLength(key) < MIN_HMAC_KEY_BYTES) throw Error('HMAC_KEY_REQUIRED');
  return createHmac('sha256', key).update(`audital.observe/v1:${namespace}:`).update(String(value)).digest('hex');
};
/** Per-project HMAC key derived from a service master secret (HKDF-SHA256). Distinct projects never share hashes. */
export function deriveProjectKey(master, tenantId, projectId) {
  if (!master || keyLength(master) < MIN_HMAC_KEY_BYTES) throw Error('HMAC_MASTER_KEY_REQUIRED');
  if (!tenantId || !projectId) throw Error('PROJECT_SCOPE_REQUIRED');
  return Buffer.from(hkdfSync('sha256', Buffer.isBuffer(master) ? master : Buffer.from(String(master)), 'audital.observe/v1:hmac-project-key', `${tenantId}\u0000${projectId}`, 32));
}
/** Canonical form BEFORE hashing, so `Org/Repo#3`, `org/repo#3` and the issue URL join to one target_hash. */
export function canonicalTarget(provider, target) {
  const t = String(target ?? '').trim();
  if (provider === 'github') {
    const url = /^https:\/\/github\.com\/([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)\/(?:issues|pull)\/([1-9]\d*)\/?$/.exec(t);
    const ref = url || /^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)#([1-9]\d*)$/.exec(t);
    if (ref) return `${ref[1].toLowerCase()}/${ref[2].toLowerCase()}#${ref[3]}`;
  }
  return t;
}

// ---- OTLP/JSON decoding -------------------------------------------------------------------------
function anyValue(v) {
  if (v === null || typeof v !== 'object') return v;
  if ('stringValue' in v) return v.stringValue;
  if ('boolValue' in v) return v.boolValue;
  if ('intValue' in v) { const n = Number(v.intValue); return Number.isSafeInteger(n) ? n : String(v.intValue); }
  if ('doubleValue' in v) return Number(v.doubleValue);
  if ('arrayValue' in v) return (v.arrayValue?.values || []).map(anyValue);
  if ('kvlistValue' in v) return Object.fromEntries((v.kvlistValue?.values || []).filter(x => typeof x?.key === 'string').map(x => [x.key, anyValue(x.value)]));
  if ('bytesValue' in v) return v.bytesValue;
  return v;
}
function attrsOf(raw) {
  const a = raw?.attributes;
  if (Array.isArray(a)) return Object.fromEntries(a.filter(x => x && typeof x.key === 'string').map(x => [x.key, anyValue(x.value)]));
  return a && typeof a === 'object' ? a : {};
}
const isErrorStatus = s => s?.code === 2 || s?.code === 'STATUS_CODE_ERROR' || s?.code === 'ERROR';
const hexId = (v, len) => typeof v === 'string' && new RegExp(`^[0-9a-fA-F]{${len}}$`).test(v) && !/^0+$/.test(v) ? v.toLowerCase() : null;
function toISO(t) {
  if (t === undefined || t === null || t === '') return null;
  if (typeof t === 'number') return new Date(t > 1e15 ? Math.floor(t / 1e6) : t > 1e12 ? t : t * 1000).toISOString();
  if (typeof t === 'string' && /^\d{15,}$/.test(t)) return new Date(Number(BigInt(t) / 1000000n)).toISOString();
  const d = new Date(t); if (!Number.isFinite(d.getTime())) throw Error('CLAIM_TIMESTAMP_INVALID');
  return d.toISOString();
}
function parseMaybeJSON(v) {
  if (typeof v !== 'string') return v;
  const s = v.trim(); if (!/^[[{]/.test(s)) return v;
  try { return JSON.parse(s); } catch { return v; }
}
const truthy = v => v === true || v === 'true' || v === 200 || v === '200';
const falsy = v => v === false || v === 'false';

// ---- Vendor mapping ----------------------------------------------------------------------------
// Which spans are tool executions. `invoke_agent`/`chat` spans are NOT tool effects and are ignored.
function toolSpanSource(span, a) {
  const name = String(span?.name ?? '');
  if (a['gen_ai.operation.name'] === 'execute_tool' || /^execute_tool(\s|$)/.test(name)) return 'otel.gen_ai';
  if (name === 'claude_code.tool') return 'claude_code';              // Claude Code beta tracing
  if (String(a['langsmith.span.kind'] ?? '').toLowerCase() === 'tool') return 'langsmith';
  if (String(a['langfuse.observation.type'] ?? '').toLowerCase() === 'tool') return 'langfuse';
  if (String(a['openinference.span.kind'] ?? '').toUpperCase() === 'TOOL') return 'openinference';
  return null;
}
const toolNameOf = (span, a) => a['gen_ai.tool.name'] ?? a['tool_name'] ?? a['tool.name']
  ?? (/^execute_tool\s+(\S+)/.exec(String(span?.name ?? ''))?.[1]) ?? a['langsmith.trace.name'] ?? span?.name;
const callIdOf = a => a['gen_ai.tool.call.id'] ?? a['tool_use_id'] ?? a['tool_call.id'] ?? a['call_id'];
const argsOf = a => parseMaybeJSON(a['gen_ai.tool.call.arguments'] ?? a['tool_parameters'] ?? a['tool_input'] ?? a['tool.parameters']
  ?? a['input.value'] ?? a['langfuse.observation.input'] ?? a['arguments']);

/** Infer a provider target from well-known tool argument shapes (e.g. GitHub MCP `update_issue`). */
export function inferTarget(tool, args) {
  if (!args || typeof args !== 'object') return null;
  const n = args.issue_number ?? args.pull_number ?? args.number ?? args.issueNumber;
  if (typeof args.owner === 'string' && typeof args.repo === 'string' && (Number.isSafeInteger(Number(n)) && Number(n) > 0))
    return { provider: 'github', target: `${args.owner}/${args.repo}#${Number(n)}` };
  if (typeof args.url === 'string' && /^https:\/\/github\.com\/[^/]+\/[^/]+\/(issues|pull)\/\d+/.test(args.url)) return { provider: 'github', target: args.url };
  if (/stripe/i.test(String(tool))) {
    const id = Object.values(args).find(v => typeof v === 'string' && /^(ch|pi|re|sub|in|cus)_[A-Za-z0-9]{6,}$/.test(v));
    if (id) return { provider: 'stripe', target: id };
  }
  return null;
}
function inferExpectedState(tool, args) {
  if (args && typeof args === 'object' && (args.state === 'closed' || args.state === 'open')) return args.state;
  if (/reopen/i.test(tool)) return 'open';
  if (/close/i.test(tool)) return 'closed';
  return null;
}

const limited = (s, max = 250) => String(s ?? '').slice(0, max);
function checked(s, max, label) { const v = String(s ?? ''); if (v.length > max) throw Error(`${label}_TOO_LONG`); return v; }

/**
 * Normalize one claim. `inferred:true` (OTLP ingestion) means: skip, don't guess, when the expected
 * effect or target cannot be determined — a guessed expectation would manufacture PHANTOM_SUCCESS.
 */
function normalized(raw, key, { inferred = false, source = 'audital', childSuccess, resource = {} } = {}) {
  if (!raw || typeof raw !== 'object') throw Error('CLAIM_INVALID');
  if (['assurance', 'signature', 'asserts', 'cannot_assert', 'attestation'].some(k => Object.hasOwn(raw, k))) throw Error('CALLER_SUPPLIED_ASSURANCE_FORBIDDEN');
  const a = attrsOf(raw);
  if (['audital.assurance', 'audital.attestation'].some(k => Object.hasOwn(a, k))) throw Error('CALLER_SUPPLIED_ASSURANCE_FORBIDDEN');
  const tool = limited(raw.action ?? toolNameOf(raw, a) ?? raw.name);
  const args = raw.args ?? argsOf(a);
  const guess = inferTarget(tool, args);
  const rawTarget = raw.target ?? a['audital.target'] ?? guess?.target ?? '';
  const provider = limited(raw.provider ?? a['audital.provider'] ?? guess?.provider ?? (/stripe/i.test(tool) ? 'stripe' : 'github'));
  if (!rawTarget || !tool || !['github', 'stripe', 'mock'].includes(provider)) throw Error('CLAIM_TARGET_TOOL_OR_PROVIDER_MISSING');
  const target = canonicalTarget(provider, checked(rawTarget, 250, 'TARGET'));
  const expected = raw.expected_state ?? a['audital.expected_state'] ?? inferExpectedState(tool, args) ?? (inferred ? null : 'closed');
  if (!expected) throw Error('EXPECTED_EFFECT_UNKNOWN');
  const time = toISO(raw.occurred_at ?? raw.startTime ?? raw.start_time ?? raw.startTimeUnixNano ?? raw.timeUnixNano ?? raw.observedTimeUnixNano ?? a['event.timestamp'])
    ?? (inferred ? null : new Date().toISOString());
  if (!time) throw Error('CLAIM_TIMESTAMP_MISSING');
  const argumentString = typeof args === 'string' ? args : canonicalJSON(args ?? '');
  const actor = limited(raw.actor ?? a['gen_ai.agent.id'] ?? a['agent_id'] ?? a['gen_ai.agent.name'] ?? a['enduser.id'] ?? resource['service.name'] ?? 'anonymous');
  const explicit = raw.claimed_success ?? a['audital.claim.success'];
  const failed = isErrorStatus(raw.status) || a['error.type'] !== undefined || falsy(a['success']) || falsy(childSuccess)
    || String(a['langfuse.observation.level'] ?? '').toUpperCase() === 'ERROR';
  const claimed_success = explicit !== undefined ? truthy(explicit) : !failed;
  const callId = raw.claim_id ?? callIdOf(a) ?? raw.spanId ?? raw.span_id ?? (inferred ? null : randomUUID());
  if (!callId) throw Error('CLAIM_ID_MISSING');
  const publicClaim = {
    claim_id: checked(callId, 130, 'CLAIM_ID'), provider, action: tool,
    target_hash: hmacIdentifier(key, target, 'target'), occurred_at: time,
    args_hmac: hmacIdentifier(key, argumentString, 'args'), claimed_success,
    expected_state: limited(expected, 80), actor_hash: hmacIdentifier(key, actor, 'actor'),
    trace_id: hexId(raw.traceId ?? raw.trace_id, 32), span_id: hexId(raw.spanId ?? raw.span_id, 16), source,
  };
  return { publicClaim, lookup: Object.freeze({ target, provider }) };
}

export function parseClaim(value, key) { return normalized(value, key); }
export function parseSpansJSONL(text, key) {
  const lines = String(text).split(/\r?\n/).filter(x => x.trim());
  if (lines.length > 10000) throw Error('SPAN_LIMIT');
  return lines.map(line => normalized(JSON.parse(line), key));
}

/** OTLP/JSON traces (ExportTraceServiceRequest). Returns {claims, skipped}. */
export function parseOTLPTraces(doc, key) {
  if (!doc || typeof doc !== 'object') throw Error('OTLP_INVALID');
  const spans = [];
  if (Array.isArray(doc.spans)) for (const s of doc.spans) spans.push({ span: s, resource: {} });
  for (const rs of doc.resourceSpans || []) { const resource = attrsOf(rs.resource); for (const ss of rs.scopeSpans || []) for (const s of ss.spans || []) spans.push({ span: s, resource }); }
  if (spans.length > 10000) throw Error('SPAN_LIMIT');
  // Claude Code puts success on the child `claude_code.tool.execution` span.
  const childSuccess = new Map();
  for (const { span } of spans) if (span?.name === 'claude_code.tool.execution' && span.parentSpanId) {
    const a = attrsOf(span); childSuccess.set(String(span.parentSpanId).toLowerCase(), isErrorStatus(span.status) ? false : a.success);
  }
  const claims = [], skipped = [], seen = new Set();
  for (const { span, resource } of spans) {
    const a = attrsOf(span), source = toolSpanSource(span, a);
    if (!source) continue;
    try {
      const c = normalized(span, key, { inferred: true, source, resource, childSuccess: childSuccess.get(String(span.spanId ?? '').toLowerCase()) });
      if (seen.has(c.publicClaim.claim_id)) { skipped.push({ span_id: hexId(span.spanId, 16), reason: 'DUPLICATE_TOOL_CALL_ID' }); continue; }
      seen.add(c.publicClaim.claim_id); claims.push(c);
    } catch (e) {
      if (e.message === 'CALLER_SUPPLIED_ASSURANCE_FORBIDDEN') throw e;
      skipped.push({ span_id: hexId(span.spanId, 16), reason: e.message });
    }
  }
  return { claims, skipped };
}
/** Back-compat: array of claims. */
export function parseOTLPJson(doc, key) { return parseOTLPTraces(doc, key).claims; }

// Tool-result LOG EVENTS. Claude Code: `claude_code.tool_result` (attrs tool_name, tool_use_id, success,
// tool_parameters when OTEL_LOG_TOOL_DETAILS=1). Codex: `codex.tool_result` (attribute names per
// Codex docs are not fully published; we accept tool_name/call_id/arguments/success best-effort).
function logEventSource(rec, a) {
  const name = rec?.eventName ?? a['event.name'] ?? (typeof anyValue(rec?.body) === 'string' ? anyValue(rec.body) : '');
  if (name === 'claude_code.tool_result' || (name === 'tool_result' && (a['tool_use_id'] !== undefined || String(rec?.body?.stringValue ?? '').startsWith('claude_code')))) return 'claude_code';
  if (name === 'codex.tool_result') return 'codex';
  return null;
}
/** OTLP/JSON logs (ExportLogsServiceRequest). Returns {claims, skipped}. */
export function parseOTLPLogs(doc, key) {
  if (!doc || typeof doc !== 'object') throw Error('OTLP_INVALID');
  const records = [];
  for (const rl of doc.resourceLogs || []) { const resource = attrsOf(rl.resource); for (const sl of rl.scopeLogs || []) for (const r of sl.logRecords || []) records.push({ rec: r, resource }); }
  if (records.length > 10000) throw Error('LOG_LIMIT');
  const claims = [], skipped = [], seen = new Set();
  for (const { rec, resource } of records) {
    const a = attrsOf(rec), source = logEventSource(rec, a);
    if (!source) continue;
    try {
      const c = normalized({ ...rec, name: undefined }, key, { inferred: true, source, resource });
      if (seen.has(c.publicClaim.claim_id)) { skipped.push({ reason: 'DUPLICATE_TOOL_CALL_ID' }); continue; }
      seen.add(c.publicClaim.claim_id); claims.push(c);
    } catch (e) {
      if (e.message === 'CALLER_SUPPLIED_ASSURANCE_FORBIDDEN') throw e;
      skipped.push({ reason: e.message });
    }
  }
  return { claims, skipped };
}

// ---- Output: OTel GenAI evaluation events ---------------------------------------------------------
export const EVALUATION_NAME = 'audital.claim_effect_reconciliation';
/**
 * `gen_ai.evaluation.result` event per OTel GenAI semconv: gen_ai.evaluation.name (required),
 * gen_ai.evaluation.score.label (assurance level; documented values = Observe ASSURANCE enum),
 * gen_ai.evaluation.explanation. Parented to the evaluated execute_tool span when trace context is known.
 */
export function otelEvaluationEvent(result, claim = null) {
  const explanation = `${result.findings?.length ? result.findings.join(', ') : 'no discrepancy found'}; cannot assert: ${(result.cannot_assert || []).join('; ')}`;
  const attributes = {
    'gen_ai.evaluation.name': EVALUATION_NAME,
    'gen_ai.evaluation.score.label': result.assurance,
    'gen_ai.evaluation.explanation': explanation.slice(0, 1000),
    'audital.observe.schema': result.schema,
    'audital.findings': (result.findings || []).join(','),
    'audital.cannot_assert': (result.cannot_assert || []).join(';'),
  };
  if (result.claim_id) attributes['gen_ai.tool.call.id'] = result.claim_id;
  if (typeof result.observation_complete === 'boolean') attributes['audital.observation_complete'] = result.observation_complete;
  return { name: 'gen_ai.evaluation.result', timestamp: result.observed_at, trace_id: claim?.trace_id ?? null, span_id: claim?.span_id ?? null, attributes };
}
const toAny = v => typeof v === 'boolean' ? { boolValue: v } : { stringValue: String(v) };
/** OTLP/JSON ExportLogsServiceRequest carrying evaluation events, ready to POST to any collector /v1/logs. */
export function otelEvaluationLogs(results, claimsById = new Map(), { serviceName = 'audital-observe' } = {}) {
  const logRecords = results.map(r => {
    const ev = otelEvaluationEvent(r, r.claim_id ? claimsById.get(r.claim_id) : null);
    const rec = { timeUnixNano: String(BigInt(Date.parse(ev.timestamp)) * 1000000n), eventName: ev.name,
      attributes: [{ key: 'event.name', value: { stringValue: ev.name } }, ...Object.entries(ev.attributes).map(([k, v]) => ({ key: k, value: toAny(v) }))] };
    if (ev.trace_id && ev.span_id) { rec.traceId = ev.trace_id; rec.spanId = ev.span_id; }
    return rec;
  });
  return { resourceLogs: [{ resource: { attributes: [{ key: 'service.name', value: { stringValue: serviceName } }] }, scopeLogs: [{ scope: { name: 'audital.observe', version: '0.2.0' }, logRecords }] }] };
}
