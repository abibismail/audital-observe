-- AUDITAL OBSERVE RLS DESIGN. NOT YET CONNECTED TO THE DEVELOPMENT SERVER.
-- Do not deploy until migrations, service roles, auth session binding, migrations rollback and
-- a physical PostgreSQL cross-tenant privilege-denial integration suite independently pass.
BEGIN;
CREATE SCHEMA IF NOT EXISTS observe;
CREATE TABLE IF NOT EXISTS observe.tenants (
 tenant_id uuid PRIMARY KEY, name text NOT NULL
);
CREATE TABLE IF NOT EXISTS observe.projects (
 project_id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES observe.tenants(tenant_id), created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(tenant_id,project_id)
);
CREATE TABLE IF NOT EXISTS observe.claims (
 claim_id uuid PRIMARY KEY, tenant_id uuid NOT NULL, project_id uuid NOT NULL,
 target_hmac text NOT NULL, args_hmac text NOT NULL, action text NOT NULL,
 occurred_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(tenant_id,project_id) REFERENCES observe.projects(tenant_id,project_id)
);
CREATE TABLE IF NOT EXISTS observe.evidence (
 evidence_id uuid PRIMARY KEY, tenant_id uuid NOT NULL, project_id uuid NOT NULL,
 signed_result jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(tenant_id,project_id) REFERENCES observe.projects(tenant_id,project_id)
);
CREATE TABLE IF NOT EXISTS observe.provider_secrets (
 secret_id uuid PRIMARY KEY, tenant_id uuid NOT NULL, project_id uuid NOT NULL,
 key_id text NOT NULL, nonce bytea NOT NULL, ciphertext bytea NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(),
 FOREIGN KEY(tenant_id,project_id) REFERENCES observe.projects(tenant_id,project_id)
);
ALTER TABLE observe.projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE observe.claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE observe.evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE observe.provider_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE observe.projects FORCE ROW LEVEL SECURITY;
ALTER TABLE observe.claims FORCE ROW LEVEL SECURITY;
ALTER TABLE observe.evidence FORCE ROW LEVEL SECURITY;
ALTER TABLE observe.provider_secrets FORCE ROW LEVEL SECURITY;
-- Application role MUST NOT be owner, superuser or BYPASSRLS. Always use SET LOCAL
-- inside a transaction after server-side auth. Empty/missing tenant id => deny.
CREATE POLICY tenant_projects ON observe.projects USING (tenant_id= NULLIF(current_setting('audital.tenant_id',true),'')::uuid) WITH CHECK (tenant_id= NULLIF(current_setting('audital.tenant_id',true),'')::uuid);
CREATE POLICY tenant_claims ON observe.claims USING (tenant_id= NULLIF(current_setting('audital.tenant_id',true),'')::uuid) WITH CHECK (tenant_id= NULLIF(current_setting('audital.tenant_id',true),'')::uuid);
CREATE POLICY tenant_evidence ON observe.evidence USING (tenant_id= NULLIF(current_setting('audital.tenant_id',true),'')::uuid) WITH CHECK (tenant_id= NULLIF(current_setting('audital.tenant_id',true),'')::uuid);
CREATE POLICY tenant_secrets ON observe.provider_secrets USING (tenant_id= NULLIF(current_setting('audital.tenant_id',true),'')::uuid) WITH CHECK (tenant_id= NULLIF(current_setting('audital.tenant_id',true),'')::uuid);
COMMIT;
