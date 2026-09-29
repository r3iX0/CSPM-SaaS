"""Invite colleagues into an organization, and say who each member is.

An organization had exactly one way to gain a member: be created by them. The
membership policies are right to refuse everything else -- only an OWNER or
ADMIN may insert a membership row, which is what stops anybody writing
themselves into another tenant -- and nothing had been built on top of them.
So the person who connected the cloud was also the only person who could ever
see it (DECISIONS.md section 162).

Four pieces:

* ``organization_members.email``. A membership was a user id and nothing a
  person could read, because the address lives in Supabase's ``auth`` schema,
  which the application role cannot see. It is copied from the verified token:
  at acceptance from the invitation, and on any request by
  ``app.record_member_email()`` when the token's address differs from what is
  stored. Nullable, because the rows that exist today have none until their
  person next signs in.

* ``organization_invitations``. An address, a role, and the SHA-256 of a
  single-use token -- never the token, so a read of this table cannot join
  anybody to anything. Readable and writable by the organization's owners and
  admins only, and never deleted through the API: a revoked or accepted
  invitation is history. At most one open invitation per address, so inviting
  somebody again replaces the link rather than leaving two live.

* ``app.accept_invitation(token_hash)``. The invitee is not a member yet, so no
  membership policy lets them insert themselves -- correctly. The same
  SECURITY DEFINER door ``app.join_demo_organization`` uses, with three checks
  inside it: the invitation is open, it has not expired, and **it names the
  address on the caller's own verified token**, read from the request's claims
  rather than taken as an argument. A forwarded link is useless to anybody
  else.

* ``app.peek_invitation(token_hash)``. What the acceptance page shows before
  the invitee commits: which organization, which role, and whether the link is
  still good. Only to a holder of the token.

Revision ID: 0044
Revises: 0043
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0044"
down_revision: str | None = "0043"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


UPGRADE_SQL = """
ALTER TABLE organization_members ADD COLUMN IF NOT EXISTS email varchar(320);

CREATE TABLE organization_invitations (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email           varchar(320) NOT NULL,
  role            varchar(32) NOT NULL CHECK (role <> 'OWNER'),
  token_hash      char(64) NOT NULL UNIQUE,
  invited_by      uuid NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL,
  accepted_at     timestamptz,
  accepted_by     uuid,
  revoked_at      timestamptz,
  CHECK (email = lower(email))
);
CREATE INDEX ix_organization_invitations_org
  ON organization_invitations (organization_id, created_at DESC);
CREATE UNIQUE INDEX organization_invitations_one_open
  ON organization_invitations (organization_id, email)
  WHERE accepted_at IS NULL AND revoked_at IS NULL;

ALTER TABLE organization_invitations ENABLE ROW LEVEL SECURITY;
CREATE POLICY invitations_admin_select ON organization_invitations FOR SELECT
USING (app.has_role(organization_id, ARRAY['OWNER','ADMIN']));
CREATE POLICY invitations_admin_insert ON organization_invitations FOR INSERT
WITH CHECK (app.has_role(organization_id, ARRAY['OWNER','ADMIN']));
CREATE POLICY invitations_admin_update ON organization_invitations FOR UPDATE
USING (app.has_role(organization_id, ARRAY['OWNER','ADMIN']))
WITH CHECK (app.has_role(organization_id, ARRAY['OWNER','ADMIN']));
GRANT SELECT, INSERT, UPDATE ON organization_invitations TO authenticated;

-- The caller's address, as their verified token states it. NULL when the token
-- carries none, which every check below treats as "cannot accept".
CREATE OR REPLACE FUNCTION app.user_email() RETURNS text
LANGUAGE sql STABLE AS $$
  SELECT NULLIF(lower(current_setting('request.jwt.claims', true)::jsonb ->> 'email'), '')
$$;

CREATE OR REPLACE FUNCTION app.peek_invitation(p_token_hash text)
RETURNS TABLE (organization_name text, role text, email text, status text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT o.name::text,
         i.role::text,
         i.email::text,
         CASE
           WHEN i.accepted_at IS NOT NULL THEN 'ACCEPTED'
           WHEN i.revoked_at IS NOT NULL THEN 'REVOKED'
           WHEN i.expires_at <= now() THEN 'EXPIRED'
           ELSE 'OPEN'
         END
  FROM public.organization_invitations i
  JOIN public.organizations o ON o.id = i.organization_id
  WHERE i.token_hash = p_token_hash
    AND app.user_id() IS NOT NULL
$$;

CREATE OR REPLACE FUNCTION app.accept_invitation(p_token_hash text) RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  v_user  uuid := app.user_id();
  v_email text := app.user_email();
  v_inv   public.organization_invitations%ROWTYPE;
BEGIN
  IF v_user IS NULL THEN
    RAISE EXCEPTION 'not authenticated' USING ERRCODE = '28000';
  END IF;

  SELECT * INTO v_inv FROM public.organization_invitations
  WHERE token_hash = p_token_hash
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'invitation not found' USING ERRCODE = 'P0002';
  END IF;
  IF v_inv.accepted_at IS NOT NULL OR v_inv.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'invitation not open' USING ERRCODE = 'P0001';
  END IF;
  IF v_inv.expires_at <= now() THEN
    RAISE EXCEPTION 'invitation expired' USING ERRCODE = 'P0001';
  END IF;
  IF v_email IS NULL OR v_email <> v_inv.email THEN
    RAISE EXCEPTION 'invitation is for another address' USING ERRCODE = '42501';
  END IF;

  -- Already a member: the invitation is spent and the existing role stands.
  -- An invitation is a way in, not a way to change somebody's role.
  INSERT INTO public.organization_members (organization_id, user_id, role, email)
  VALUES (v_inv.organization_id, v_user, v_inv.role, v_email)
  ON CONFLICT (organization_id, user_id) DO NOTHING;

  UPDATE public.organization_invitations
  SET accepted_at = now(), accepted_by = v_user
  WHERE id = v_inv.id;

  RETURN v_inv.organization_id;
END;
$$;

-- Keep a member's stored address in step with their verified token. Only the
-- caller's own rows, and only to the address the token states.
CREATE OR REPLACE FUNCTION app.record_member_email() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  v_user  uuid := app.user_id();
  v_email text := app.user_email();
BEGIN
  IF v_user IS NULL OR v_email IS NULL THEN
    RETURN;
  END IF;
  UPDATE public.organization_members
  SET email = v_email
  WHERE user_id = v_user AND email IS DISTINCT FROM v_email;
END;
$$;

GRANT EXECUTE ON FUNCTION app.user_email() TO authenticated;
GRANT EXECUTE ON FUNCTION app.peek_invitation(text) TO authenticated;
GRANT EXECUTE ON FUNCTION app.accept_invitation(text) TO authenticated;
GRANT EXECUTE ON FUNCTION app.record_member_email() TO authenticated;
"""

DOWNGRADE_SQL = """
DROP FUNCTION IF EXISTS app.record_member_email();
DROP FUNCTION IF EXISTS app.accept_invitation(text);
DROP FUNCTION IF EXISTS app.peek_invitation(text);
DROP FUNCTION IF EXISTS app.user_email();
DROP TABLE IF EXISTS organization_invitations;
ALTER TABLE organization_members DROP COLUMN IF EXISTS email;
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute(DOWNGRADE_SQL)
