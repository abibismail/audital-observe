-- AUDITAL OBSERVE 001: tenant schema with FORCE ROW LEVEL SECURITY.
-- Applied by apps/api/src/db/migrate.mjs inside one transaction (no BEGIN/COMMIT here).
-- Verified by apps/api/tests/pg/*.test.mjs against a physical PostgreSQL server (npm run test:pg).
--
-- Roles:
--   observe_owner  NOLOGIN. Owns every object. Subject to FORCE RLS like everyone else; it only sees
--                  cross-tenant rows through the narrow SECURITY DEFINER functions defined below.
--   observe_app    NOLOGIN, NOBYPASSRLS. Granted to the API/worker login role. Never owner/superuser.
-- Tenant identity is transaction-local:  SELECT set_config('audital.tenant_id', $1, true),
--                                        SELECT set_config('audital.project_id', $2, true)
-- Missing/empty identity => NULL => every policy evaluates false => deny.
--
-- v0.1 -> v0.2 audit fixes: claim_id was a global uuid PK (cross-tenant existence oracle and
-- collision DoS, and real tool-call ids are not uuids); tenants table had no RLS; no role/grant
-- model; evidence was mutable; no project-level isolation.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'observe_owner') THEN
    CREATE ROLE observe_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'observe_app') THEN
    CREATE ROLE observe_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB;
  END IF;
  IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
    EXECUTE format('GRANT observe_owner TO %I', current_user);
  END IF;
END $$;

CREATE SCHEMA observe AUTHORIZATION observe_owner;
REVOKE ALL ON SCHEMA observe FROM PUBLIC;
SET LOCAL ROLE observe_owner;
GRANT USAGE ON SCHEMA observe TO observe_app;

CREATE FUNCTION observe.current_tenant() RETURNS uuid LANGUAGE sql STABLE
  AS $$ SELECT NULLIF(current_setting('audital.tenant_id', true), '')::uuid $$;
CREATE FUNCTION observe.current_project() RETURNS uuid LANGUAGE sql STABLE
  AS $$ SELECT NULLIF(current_setting('audital.project_id', true), '')::uuid $$;

CREATE TABLE observe.tenants (
  tenant_id uuid PRIMARY KEY,
  name text NOT NULL CHECK (length(name) <= 200),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE observe.projects (
  tenant_id uuid NOT NULL REFERENCES observe.tenants(tenant_id),
  project_id uuid NOT NULL UNIQUE,
  name text NOT NULL DEFAULT '' CHECK (length(name) <= 200),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, project_id)
);
CREATE TABLE observe.api_keys (
  key_hash text PRIMARY KEY CHECK (key_hash ~ '^[0-9a-f]{64}$'),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  FOREIGN KEY (tenant_id, project_id) REFERENCES observe.projects(tenant_id, project_id)
);
CREATE TABLE observe.claims (
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  claim_id text NOT NULL CHECK (length(claim_id) BETWEEN 1 AND 130),
  provider text NOT NULL CHECK (provider IN ('github','stripe','mock')),
  action text NOT NULL CHECK (length(action) BETWEEN 1 AND 250),
  target_hmac text NOT NULL CHECK (target_hmac ~ '^[0-9a-f]{64}$'),
  args_hmac text NOT NULL CHECK (args_hmac ~ '^[0-9a-f]{64}$'),
  actor_hmac text CHECK (actor_hmac ~ '^[0-9a-f]{64}$'),
  occurred_at timestamptz NOT NULL,
  claimed_success boolean NOT NULL,
  expected_state text NOT NULL CHECK (length(expected_state) <= 80),
  trace_id text CHECK (trace_id ~ '^[0-9a-f]{32}$'),
  span_id text CHECK (span_id ~ '^[0-9a-f]{16}$'),
  source text NOT NULL DEFAULT 'audital' CHECK (length(source) <= 40),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','final')),
  next_check_at timestamptz,
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  last_assurance text CHECK (last_assurance IN ('CLAIMED','EFFECT_OBSERVED','EFFECT_CORRELATED','CONTRADICTED','UNOBSERVABLE')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, project_id, claim_id),
  FOREIGN KEY (tenant_id, project_id) REFERENCES observe.projects(tenant_id, project_id)
);
CREATE INDEX claims_due_idx ON observe.claims (tenant_id, project_id, provider, next_check_at) WHERE status = 'pending';
-- Raw target refs needed for scheduled readback, sealed (AES-256-GCM, AAD bound to tenant/project/claim)
-- and deleted as soon as the claim is final or expires_at passes. Never part of evidence.
CREATE TABLE observe.claim_lookups (
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  claim_id text NOT NULL,
  sealed jsonb NOT NULL,
  expires_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, project_id, claim_id),
  FOREIGN KEY (tenant_id, project_id, claim_id) REFERENCES observe.claims(tenant_id, project_id, claim_id) ON DELETE CASCADE
);
CREATE TABLE observe.evidence_packs (
  pack_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  attestation text NOT NULL CHECK (attestation IN ('local_unattested','hosted_attested')),
  kid text NOT NULL CHECK (kid ~ '^[A-Za-z0-9_.:-]{8,64}$'),
  pack jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, project_id, pack_id),
  FOREIGN KEY (tenant_id, project_id) REFERENCES observe.projects(tenant_id, project_id)
);
CREATE TABLE observe.findings (
  finding_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  pack_id uuid NOT NULL,
  claim_id text,
  assurance text NOT NULL CHECK (assurance IN ('CLAIMED','EFFECT_OBSERVED','EFFECT_CORRELATED','CONTRADICTED','UNOBSERVABLE')),
  findings text[] NOT NULL,
  target_hmac text,
  observed_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id, project_id, pack_id) REFERENCES observe.evidence_packs(tenant_id, project_id, pack_id)
);
CREATE INDEX findings_project_idx ON observe.findings (tenant_id, project_id, created_at DESC);
CREATE TABLE observe.provider_secrets (
  secret_id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  project_id uuid NOT NULL,
  provider text NOT NULL CHECK (provider IN ('github','stripe')),
  sealed jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, project_id, provider),
  FOREIGN KEY (tenant_id, project_id) REFERENCES observe.projects(tenant_id, project_id)
);

-- Evidence and findings are append-only for everyone, including the owner.
CREATE FUNCTION observe.forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'APPEND_ONLY: % on observe.% is forbidden', TG_OP, TG_TABLE_NAME USING ERRCODE = '42501';
END $$;
CREATE TRIGGER evidence_append_only BEFORE UPDATE OR DELETE ON observe.evidence_packs FOR EACH ROW EXECUTE FUNCTION observe.forbid_mutation();
CREATE TRIGGER evidence_no_truncate BEFORE TRUNCATE ON observe.evidence_packs FOR EACH STATEMENT EXECUTE FUNCTION observe.forbid_mutation();
CREATE TRIGGER findings_append_only BEFORE UPDATE OR DELETE ON observe.findings FOR EACH ROW EXECUTE FUNCTION observe.forbid_mutation();
CREATE TRIGGER findings_no_truncate BEFORE TRUNCATE ON observe.findings FOR EACH STATEMENT EXECUTE FUNCTION observe.forbid_mutation();

ALTER TABLE observe.tenants ENABLE ROW LEVEL SECURITY;          ALTER TABLE observe.tenants FORCE ROW LEVEL SECURITY;
ALTER TABLE observe.projects ENABLE ROW LEVEL SECURITY;         ALTER TABLE observe.projects FORCE ROW LEVEL SECURITY;
ALTER TABLE observe.api_keys ENABLE ROW LEVEL SECURITY;         ALTER TABLE observe.api_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE observe.claims ENABLE ROW LEVEL SECURITY;           ALTER TABLE observe.claims FORCE ROW LEVEL SECURITY;
ALTER TABLE observe.claim_lookups ENABLE ROW LEVEL SECURITY;    ALTER TABLE observe.claim_lookups FORCE ROW LEVEL SECURITY;
ALTER TABLE observe.evidence_packs ENABLE ROW LEVEL SECURITY;   ALTER TABLE observe.evidence_packs FORCE ROW LEVEL SECURITY;
ALTER TABLE observe.findings ENABLE ROW LEVEL SECURITY;         ALTER TABLE observe.findings FORCE ROW LEVEL SECURITY;
ALTER TABLE observe.provider_secrets ENABLE ROW LEVEL SECURITY; ALTER TABLE observe.provider_secrets FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON observe.tenants FOR ALL TO observe_app
  USING (tenant_id = observe.current_tenant()) WITH CHECK (tenant_id = observe.current_tenant());
CREATE POLICY tenant_isolation ON observe.projects FOR ALL TO observe_app
  USING (tenant_id = observe.current_tenant() AND project_id = observe.current_project())
  WITH CHECK (tenant_id = observe.current_tenant() AND project_id = observe.current_project());
CREATE POLICY tenant_isolation ON observe.claims FOR ALL TO observe_app
  USING (tenant_id = observe.current_tenant() AND project_id = observe.current_project())
  WITH CHECK (tenant_id = observe.current_tenant() AND project_id = observe.current_project());
CREATE POLICY tenant_isolation ON observe.claim_lookups FOR ALL TO observe_app
  USING (tenant_id = observe.current_tenant() AND project_id = observe.current_project())
  WITH CHECK (tenant_id = observe.current_tenant() AND project_id = observe.current_project());
CREATE POLICY tenant_isolation ON observe.evidence_packs FOR ALL TO observe_app
  USING (tenant_id = observe.current_tenant() AND project_id = observe.current_project())
  WITH CHECK (tenant_id = observe.current_tenant() AND project_id = observe.current_project());
CREATE POLICY tenant_isolation ON observe.findings FOR ALL TO observe_app
  USING (tenant_id = observe.current_tenant() AND project_id = observe.current_project())
  WITH CHECK (tenant_id = observe.current_tenant() AND project_id = observe.current_project());
CREATE POLICY tenant_isolation ON observe.provider_secrets FOR ALL TO observe_app
  USING (tenant_id = observe.current_tenant() AND project_id = observe.current_project())
  WITH CHECK (tenant_id = observe.current_tenant() AND project_id = observe.current_project());
-- api_keys: no observe_app policy and no grant. Only observe.authenticate() reads it.
CREATE POLICY definer_lookup ON observe.api_keys FOR SELECT TO observe_owner USING (true);

GRANT SELECT ON observe.tenants, observe.projects TO observe_app;
GRANT SELECT, INSERT ON observe.claims TO observe_app;
GRANT UPDATE (status, next_check_at, attempts, last_assurance) ON observe.claims TO observe_app;
GRANT SELECT, INSERT, DELETE ON observe.claim_lookups TO observe_app;
GRANT SELECT, INSERT ON observe.evidence_packs, observe.findings TO observe_app;
GRANT SELECT, INSERT, DELETE ON observe.provider_secrets TO observe_app;

CREATE FUNCTION observe.authenticate(p_key_hash text)
  RETURNS TABLE (tenant_id uuid, project_id uuid)
  LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, observe
  AS $$ SELECT k.tenant_id, k.project_id FROM observe.api_keys k WHERE k.key_hash = p_key_hash AND k.revoked_at IS NULL $$;
REVOKE ALL ON FUNCTION observe.authenticate(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION observe.authenticate(text) TO observe_app;
REVOKE ALL ON FUNCTION observe.forbid_mutation() FROM PUBLIC;
