"""Grants: an auditor reads one sealed package, as the person the owner named.

Revision ID: 0050
Revises: 0049

An auditor is not a member of the organization, and a membership would reach every table whose
policy asks ``app.is_member`` (DECISIONS.md section 211). So the policies on ``audit_packages``,
``audit_package_items`` and ``evidence_blobs`` are not touched, and none of them mentions an
auditor. The auditor reads through ``SECURITY DEFINER`` functions, each of which begins with the
same check.

* ``audit_grants`` -- one package, one address, one expiry, and the SHA-256 of a single-use token,
  never the token. Owners and admins read and insert, and may set ``revoked_at`` and
  ``revoked_by`` once, by column grant and by policy: nothing else can change, and nothing can
  un-revoke. ``opened_by`` and ``opened_at`` are written only by ``app.open_audit_grant``: the
  insert policy refuses a row that arrives with them set.
  The package and the organization are one composite foreign key, so a grant cannot name another
  tenant's package whoever writes it.
* ``audit_grant_events`` -- what the grant's functions did, one row each. Owners and admins read it;
  no role can insert, so the only way to read through a grant is the way that records it.
* ``app.live_audit_grant(grant_id)`` -- internal, granted to no role. The grant is bound to this
  user, addressed to this verified address, not revoked and not expired, on every call.
* ``app.open_audit_grant(token_hash)`` -- spends the link: checks the same, binds the grant to the
  caller on the first open, and refuses any other user after that.
* ``app.audit_grant_package``, ``app.audit_grant_items``, ``app.audit_grant_blobs`` and
  ``app.audit_grant_held_hashes`` -- the package, its readings, the payloads they name and which
  of those are still stored. A payload is returned only if the granted package names its hash.
* ``app.record_audit_grant_download`` -- the one event besides opening, written by the caller's
  own request before the archive is built. It takes no free text, so an entry cannot be stuffed.
* ``app.my_audit_grants()`` and ``app.audit_grant_header`` -- the grants the caller opened and
  that are still live, and one of them.

A function that refuses raises, which rolls back its own writes: a refused attempt leaves no
event (DECISIONS.md section 211). Every function's EXECUTE is taken from PUBLIC first, so ``anon``
cannot call them either.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0050"
down_revision: str | None = "0049"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ADMIN = "app.has_role(organization_id, ARRAY['OWNER','ADMIN'])"

UPGRADE_SQL = f"""
-- A grant names a package and its organization together, so the pair cannot disagree.
CREATE UNIQUE INDEX uq_audit_packages_id_org ON audit_packages (id, organization_id);

CREATE TABLE audit_grants (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL,
  package_id      uuid NOT NULL,
  email           varchar(320) NOT NULL,
  token_hash      char(64) NOT NULL UNIQUE,
  created_by      uuid NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL,
  opened_by       uuid,
  opened_at       timestamptz,
  revoked_at      timestamptz,
  revoked_by      uuid,
  FOREIGN KEY (package_id, organization_id)
    REFERENCES audit_packages (id, organization_id) ON DELETE CASCADE,
  FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE,
  CHECK (email = lower(email)),
  CHECK (expires_at > created_at),
  CHECK (expires_at <= created_at + interval '90 days'),
  CHECK ((opened_by IS NULL) = (opened_at IS NULL)),
  CHECK ((revoked_by IS NULL) = (revoked_at IS NULL))
);
CREATE INDEX ix_audit_grants_package ON audit_grants (organization_id, package_id, created_at DESC);
-- At most one grant per package and address that has not been revoked.
CREATE UNIQUE INDEX uq_audit_grants_one_live
  ON audit_grants (package_id, email) WHERE revoked_at IS NULL;

ALTER TABLE audit_grants ENABLE ROW LEVEL SECURITY;
CREATE POLICY audit_grants_admin_select ON audit_grants FOR SELECT USING ({_ADMIN});
CREATE POLICY audit_grants_admin_insert ON audit_grants FOR INSERT
  WITH CHECK (
    {_ADMIN}
    AND created_by = app.user_id()
    AND opened_by IS NULL AND opened_at IS NULL
    AND revoked_by IS NULL AND revoked_at IS NULL
  );
-- One way only: a live grant may be revoked, and a revoked one is never touched again.
CREATE POLICY audit_grants_admin_revoke ON audit_grants FOR UPDATE
  USING ({_ADMIN} AND revoked_at IS NULL)
  WITH CHECK ({_ADMIN} AND revoked_at IS NOT NULL AND revoked_by = app.user_id());
GRANT SELECT ON audit_grants TO authenticated;
-- Every column but created_at, which is the database's. The ORM sends the four nullable ones as
-- NULL on every insert, and the insert policy above is what holds them at NULL.
GRANT INSERT (id, organization_id, package_id, email, token_hash, created_by, expires_at,
              opened_by, opened_at, revoked_at, revoked_by)
  ON audit_grants TO authenticated;
GRANT UPDATE (revoked_at, revoked_by) ON audit_grants TO authenticated;

CREATE TABLE audit_grant_events (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  grant_id        uuid NOT NULL REFERENCES audit_grants(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id         uuid NOT NULL,
  event           varchar(32) NOT NULL CHECK (event IN ('OPENED', 'ARCHIVE_DOWNLOADED')),
  detail          jsonb NOT NULL DEFAULT '{{}}'::jsonb,
  at              timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_audit_grant_events_grant ON audit_grant_events (grant_id, at DESC);

ALTER TABLE audit_grant_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY audit_grant_events_admin_select ON audit_grant_events FOR SELECT USING ({_ADMIN});
GRANT SELECT ON audit_grant_events TO authenticated;

-- The check every read begins with. Not granted to any role: the functions below call it as
-- their owner. "not found" covers a grant that is somebody else's, so a stranger learns nothing
-- from the difference.
CREATE OR REPLACE FUNCTION app.live_audit_grant(p_grant uuid) RETURNS public.audit_grants
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  v_user  uuid := app.user_id();
  v_email text := app.user_email();
  v_grant public.audit_grants%ROWTYPE;
BEGIN
  IF v_user IS NULL THEN
    RAISE EXCEPTION 'not authenticated' USING ERRCODE = '28000';
  END IF;
  SELECT * INTO v_grant FROM public.audit_grants WHERE id = p_grant;
  IF NOT FOUND OR v_grant.opened_by IS DISTINCT FROM v_user THEN
    RAISE EXCEPTION 'grant not found' USING ERRCODE = 'P0002';
  END IF;
  IF v_grant.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'grant not open' USING ERRCODE = 'P0001';
  END IF;
  IF v_grant.expires_at <= now() THEN
    RAISE EXCEPTION 'grant expired' USING ERRCODE = 'P0001';
  END IF;
  IF v_email IS NULL OR v_email <> v_grant.email THEN
    RAISE EXCEPTION 'grant is for another address' USING ERRCODE = '42501';
  END IF;
  RETURN v_grant;
END;
$$;

CREATE OR REPLACE FUNCTION app.open_audit_grant(p_token_hash text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  v_user  uuid := app.user_id();
  v_email text := app.user_email();
  v_grant public.audit_grants%ROWTYPE;
BEGIN
  IF v_user IS NULL THEN
    RAISE EXCEPTION 'not authenticated' USING ERRCODE = '28000';
  END IF;

  SELECT * INTO v_grant FROM public.audit_grants WHERE token_hash = p_token_hash FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'grant not found' USING ERRCODE = 'P0002';
  END IF;
  IF v_grant.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'grant not open' USING ERRCODE = 'P0001';
  END IF;
  IF v_grant.expires_at <= now() THEN
    RAISE EXCEPTION 'grant expired' USING ERRCODE = 'P0001';
  END IF;
  IF v_email IS NULL OR v_email <> v_grant.email THEN
    RAISE EXCEPTION 'grant is for another address' USING ERRCODE = '42501';
  END IF;
  -- The same address under another account: the link is for the first person who opened it.
  IF v_grant.opened_by IS NOT NULL AND v_grant.opened_by <> v_user THEN
    RAISE EXCEPTION 'grant already opened' USING ERRCODE = 'P0001';
  END IF;

  UPDATE public.audit_grants
  SET opened_by = v_user, opened_at = COALESCE(opened_at, now())
  WHERE id = v_grant.id;

  INSERT INTO public.audit_grant_events (grant_id, organization_id, user_id, event, detail)
  VALUES (v_grant.id, v_grant.organization_id, v_user, 'OPENED',
          jsonb_build_object('first', v_grant.opened_by IS NULL));

  RETURN v_grant.id;
END;
$$;

CREATE OR REPLACE FUNCTION app.my_audit_grants()
RETURNS TABLE (
  grant_id uuid, package_id uuid, package_name text, organization_name text,
  email text, opened_at timestamptz, expires_at timestamptz
)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT g.id, g.package_id, p.name::text, o.name::text, g.email::text, g.opened_at, g.expires_at
  FROM public.audit_grants g
  JOIN public.audit_packages p ON p.id = g.package_id AND p.organization_id = g.organization_id
  JOIN public.organizations o ON o.id = g.organization_id
  WHERE g.opened_by = app.user_id()
    AND g.email = app.user_email()
    AND g.revoked_at IS NULL
    AND g.expires_at > now()
  ORDER BY g.opened_at DESC, g.id
$$;

CREATE OR REPLACE FUNCTION app.audit_grant_header(p_grant uuid)
RETURNS TABLE (
  grant_id uuid, package_id uuid, package_name text, organization_name text,
  email text, opened_at timestamptz, expires_at timestamptz
)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT g.id, g.package_id, p.name::text, o.name::text, g.email::text, g.opened_at, g.expires_at
  FROM app.live_audit_grant(p_grant) g
  JOIN public.audit_packages p ON p.id = g.package_id AND p.organization_id = g.organization_id
  JOIN public.organizations o ON o.id = g.organization_id
$$;

CREATE OR REPLACE FUNCTION app.audit_grant_package(p_grant uuid)
RETURNS SETOF public.audit_packages
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT p.*
  FROM app.live_audit_grant(p_grant) g
  JOIN public.audit_packages p ON p.id = g.package_id AND p.organization_id = g.organization_id
$$;

CREATE OR REPLACE FUNCTION app.audit_grant_items(p_grant uuid)
RETURNS SETOF public.audit_package_items
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT i.*
  FROM app.live_audit_grant(p_grant) g
  JOIN public.audit_package_items i
    ON i.package_id = g.package_id AND i.organization_id = g.organization_id
$$;

-- Only a payload the granted package names: the hash is the key, and the package's own items
-- are what say which hashes are its.
CREATE OR REPLACE FUNCTION app.audit_grant_blobs(p_grant uuid, p_hashes text[])
RETURNS TABLE (content_hash text, payload_compressed bytea, payload jsonb)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT b.content_hash::text, b.payload_compressed, b.payload
  FROM app.live_audit_grant(p_grant) g
  JOIN public.evidence_blobs b ON b.organization_id = g.organization_id
  WHERE b.content_hash = ANY(p_hashes)
    AND EXISTS (
      SELECT 1 FROM public.audit_package_items i
      WHERE i.package_id = g.package_id
        AND i.organization_id = g.organization_id
        AND i.content_hash = b.content_hash
    )
$$;

CREATE OR REPLACE FUNCTION app.audit_grant_held_hashes(p_grant uuid)
RETURNS TABLE (content_hash text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT b.content_hash::text
  FROM app.live_audit_grant(p_grant) g
  JOIN public.evidence_blobs b ON b.organization_id = g.organization_id
  WHERE EXISTS (
    SELECT 1 FROM public.audit_package_items i
    WHERE i.package_id = g.package_id
      AND i.organization_id = g.organization_id
      AND i.content_hash = b.content_hash
  )
$$;

CREATE OR REPLACE FUNCTION app.record_audit_grant_download(p_grant uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  v_grant public.audit_grants%ROWTYPE;
  v_hash  text;
BEGIN
  v_grant := app.live_audit_grant(p_grant);
  SELECT manifest_sha256 INTO v_hash FROM public.audit_packages WHERE id = v_grant.package_id;
  INSERT INTO public.audit_grant_events (grant_id, organization_id, user_id, event, detail)
  VALUES (v_grant.id, v_grant.organization_id, v_grant.opened_by, 'ARCHIVE_DOWNLOADED',
          jsonb_build_object('manifest_sha256', v_hash));
END;
$$;

REVOKE ALL ON FUNCTION app.live_audit_grant(uuid) FROM PUBLIC, authenticated, anon;
REVOKE ALL ON FUNCTION app.open_audit_grant(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.my_audit_grants() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.audit_grant_header(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.audit_grant_package(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.audit_grant_items(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.audit_grant_blobs(uuid, text[]) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.audit_grant_held_hashes(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION app.record_audit_grant_download(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.open_audit_grant(text) TO authenticated;
GRANT EXECUTE ON FUNCTION app.my_audit_grants() TO authenticated;
GRANT EXECUTE ON FUNCTION app.audit_grant_header(uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION app.audit_grant_package(uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION app.audit_grant_items(uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION app.audit_grant_blobs(uuid, text[]) TO authenticated;
GRANT EXECUTE ON FUNCTION app.audit_grant_held_hashes(uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION app.record_audit_grant_download(uuid) TO authenticated;
"""

DOWNGRADE_SQL = """
DROP FUNCTION IF EXISTS app.record_audit_grant_download(uuid);
DROP FUNCTION IF EXISTS app.audit_grant_held_hashes(uuid);
DROP FUNCTION IF EXISTS app.audit_grant_blobs(uuid, text[]);
DROP FUNCTION IF EXISTS app.audit_grant_items(uuid);
DROP FUNCTION IF EXISTS app.audit_grant_package(uuid);
DROP FUNCTION IF EXISTS app.audit_grant_header(uuid);
DROP FUNCTION IF EXISTS app.my_audit_grants();
DROP FUNCTION IF EXISTS app.open_audit_grant(text);
DROP FUNCTION IF EXISTS app.live_audit_grant(uuid);
DROP TABLE IF EXISTS audit_grant_events;
DROP TABLE IF EXISTS audit_grants;
DROP INDEX IF EXISTS uq_audit_packages_id_org;
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute(DOWNGRADE_SQL)
