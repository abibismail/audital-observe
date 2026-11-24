-- AUDITAL OBSERVE 002: continuous engine — monitors, expiring shares, alert endpoints and outbox.
SET LOCAL ROLE observe_owner;

CREATE TABLE observe.monitors (
  monitor_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  provider text NOT NULL CHECK (provider IN ('github','stripe','mock')),
  interval_seconds integer NOT NULL CHECK (interval_seconds BETWEEN 60 AND 86400),
  enabled boolean NOT NULL DEFAULT true,
  read_only boolean NOT NULL DEFAULT true CHECK (read_only),
  next_run_at timestamptz NOT NULL DEFAULT now(),
  lease_until timestamptz,
  last_run_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, project_id, provider),
  FOREIGN KEY (tenant_id, project_id) REFERENCES observe.projects(tenant_id, project_id)
);
CREATE INDEX monitors_due_idx ON observe.monitors (next_run_at) WHERE enabled;

-- Share = immutable snapshot of one evidence pack behind a bearer token (only its SHA-256 is stored;
-- the token is 256 random bits, so an unkeyed digest is not guessable). Expiry is DB-clock authoritative.
CREATE TABLE observe.shares (
  token_hash text PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  pack_id uuid NOT NULL,
  pack jsonb NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (expires_at > created_at AND expires_at <= created_at + interval '7 days'),
  FOREIGN KEY (tenant_id, project_id, pack_id) REFERENCES observe.evidence_packs(tenant_id, project_id, pack_id)
);

CREATE TABLE observe.alert_endpoints (
  endpoint_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('slack','webhook')),
  sealed jsonb NOT NULL,
  enabled boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, project_id, endpoint_id),
  FOREIGN KEY (tenant_id, project_id) REFERENCES observe.projects(tenant_id, project_id)
);
CREATE TABLE observe.alert_outbox (
  alert_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  endpoint_id uuid NOT NULL,
  dedupe_key text NOT NULL CHECK (dedupe_key ~ '^[0-9a-f]{40}$'),
  pack_id uuid,
  payload jsonb NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','delivered','failed')),
  attempts integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  last_error text CHECK (length(last_error) <= 200),
  created_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz,
  UNIQUE (tenant_id, project_id, endpoint_id, dedupe_key),
  FOREIGN KEY (tenant_id, project_id, endpoint_id) REFERENCES observe.alert_endpoints(tenant_id, project_id, endpoint_id)
);

ALTER TABLE observe.monitors ENABLE ROW LEVEL SECURITY;        ALTER TABLE observe.monitors FORCE ROW LEVEL SECURITY;
ALTER TABLE observe.shares ENABLE ROW LEVEL SECURITY;          ALTER TABLE observe.shares FORCE ROW LEVEL SECURITY;
ALTER TABLE observe.alert_endpoints ENABLE ROW LEVEL SECURITY; ALTER TABLE observe.alert_endpoints FORCE ROW LEVEL SECURITY;
ALTER TABLE observe.alert_outbox ENABLE ROW LEVEL SECURITY;    ALTER TABLE observe.alert_outbox FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON observe.monitors FOR ALL TO observe_app
  USING (tenant_id = observe.current_tenant() AND project_id = observe.current_project())
  WITH CHECK (tenant_id = observe.current_tenant() AND project_id = observe.current_project());
CREATE POLICY tenant_isolation ON observe.shares FOR ALL TO observe_app
  USING (tenant_id = observe.current_tenant() AND project_id = observe.current_project())
  WITH CHECK (tenant_id = observe.current_tenant() AND project_id = observe.current_project());
CREATE POLICY tenant_isolation ON observe.alert_endpoints FOR ALL TO observe_app
  USING (tenant_id = observe.current_tenant() AND project_id = observe.current_project())
  WITH CHECK (tenant_id = observe.current_tenant() AND project_id = observe.current_project());
CREATE POLICY tenant_isolation ON observe.alert_outbox FOR ALL TO observe_app
  USING (tenant_id = observe.current_tenant() AND project_id = observe.current_project())
  WITH CHECK (tenant_id = observe.current_tenant() AND project_id = observe.current_project());
-- Narrow cross-tenant paths, reachable only through the SECURITY DEFINER functions below.
CREATE POLICY definer_scheduler ON observe.monitors FOR ALL TO observe_owner USING (true) WITH CHECK (true);
CREATE POLICY definer_share_lookup ON observe.shares FOR SELECT TO observe_owner USING (true);

GRANT SELECT, INSERT ON observe.monitors TO observe_app;
GRANT UPDATE (interval_seconds, enabled, next_run_at, lease_until, last_run_at) ON observe.monitors TO observe_app;
GRANT SELECT ON observe.shares TO observe_app;
GRANT INSERT (token_hash, tenant_id, project_id, pack_id, pack, expires_at) ON observe.shares TO observe_app;
GRANT SELECT, INSERT ON observe.alert_endpoints TO observe_app;
GRANT UPDATE (enabled) ON observe.alert_endpoints TO observe_app;
GRANT SELECT, INSERT ON observe.alert_outbox TO observe_app;
GRANT UPDATE (status, attempts, next_attempt_at, last_error, delivered_at) ON observe.alert_outbox TO observe_app;

-- Scheduler: leases due monitors across tenants, returning ONLY scheduling metadata (no claims/evidence).
-- The worker then processes each lease inside its own tenant-scoped transaction under RLS.
CREATE FUNCTION observe.lease_due_monitors(p_now timestamptz, p_max integer, p_lease_seconds integer)
  RETURNS TABLE (tenant_id uuid, project_id uuid, monitor_id uuid, provider text, interval_seconds integer)
  LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, observe
AS $$
#variable_conflict use_column
BEGIN
  IF p_max < 1 OR p_max > 1000 OR p_lease_seconds < 10 OR p_lease_seconds > 3600 THEN
    RAISE EXCEPTION 'INVALID_LEASE_REQUEST' USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
  WITH due AS (
    SELECT m.monitor_id FROM observe.monitors m
     WHERE m.enabled AND m.next_run_at <= p_now AND (m.lease_until IS NULL OR m.lease_until < p_now)
     ORDER BY m.next_run_at LIMIT p_max FOR UPDATE SKIP LOCKED)
  UPDATE observe.monitors m SET lease_until = p_now + make_interval(secs => p_lease_seconds)
    FROM due WHERE m.monitor_id = due.monitor_id
  RETURNING m.tenant_id, m.project_id, m.monitor_id, m.provider, m.interval_seconds;
END $$;
REVOKE ALL ON FUNCTION observe.lease_due_monitors(timestamptz, integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION observe.lease_due_monitors(timestamptz, integer, integer) TO observe_app;

-- Unauthenticated share resolution: exact token-hash match, unexpired by the LATER of DB clock and caller clock.
CREATE FUNCTION observe.resolve_share(p_token_hash text, p_now timestamptz)
  RETURNS TABLE (pack jsonb, expires_at timestamptz)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, observe
  AS $$ SELECT s.pack, s.expires_at FROM observe.shares s
         WHERE s.token_hash = p_token_hash AND s.expires_at > GREATEST(p_now, now()) $$;
REVOKE ALL ON FUNCTION observe.resolve_share(text, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION observe.resolve_share(text, timestamptz) TO observe_app;
