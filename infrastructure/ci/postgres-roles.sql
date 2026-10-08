-- CI only. Not used by any deployment.
--
-- The integration tests prove that PostgreSQL itself blocks cross-tenant
-- access, which only means something if the tests connect the way the API
-- does: as `cloudguard_app`, a role that owns no tables and therefore cannot
-- bypass a policy. Running them as the owner would pass while proving nothing
-- (see docs/DECISIONS.md #1).
--
-- GitHub Actions starts a bare postgres service container, so the Supabase
-- roles have to be created here. On Supabase itself they already exist --
-- infrastructure/supabase/roles.sql is the deployment-side equivalent and
-- creates only `cloudguard_app`.

CREATE ROLE authenticated NOLOGIN;
CREATE ROLE anon NOLOGIN;
CREATE ROLE service_role NOLOGIN BYPASSRLS;

CREATE ROLE cloudguard_app LOGIN PASSWORD 'cloudguard_app' NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT authenticated TO cloudguard_app;
GRANT anon TO cloudguard_app;

GRANT CONNECT ON DATABASE cloudguard TO cloudguard_app;

-- The worker's role. Migration 0012 creates it NOLOGIN so its policies have
-- something to name; giving it a password is the operator's decision, and in
-- CI the operator is this file. Without it the integration tests would prove
-- the worker's isolation against the owner connection, which bypasses RLS and
-- would therefore pass while proving nothing -- the same trap the comment
-- above describes for cloudguard_app.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cloudguard_worker') THEN
    CREATE ROLE cloudguard_worker LOGIN PASSWORD 'cloudguard_worker'
      NOSUPERUSER NOCREATEDB NOCREATEROLE;
  ELSE
    ALTER ROLE cloudguard_worker LOGIN PASSWORD 'cloudguard_worker';
  END IF;
END $$;

GRANT CONNECT ON DATABASE cloudguard TO cloudguard_worker;

-- Supabase's record of each user's authenticator apps, reduced to the columns
-- `app.has_verified_factor()` reads (migration 0051, DECISIONS.md #217). On
-- Supabase the table already exists; here it lets the integration tests prove
-- that a session which skipped a verified factor is refused.
CREATE SCHEMA auth;
CREATE TABLE auth.mfa_factors (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  factor_type text NOT NULL DEFAULT 'totp',
  status text NOT NULL
);

-- Supabase's users, reduced to the columns `app.forget_guests()` reads
-- (migration 0052, DECISIONS.md #219): which are guests, and since when. Here
-- it lets the integration tests prove a stale guest is forgotten and an
-- account is not.
CREATE TABLE auth.users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  is_anonymous boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);
