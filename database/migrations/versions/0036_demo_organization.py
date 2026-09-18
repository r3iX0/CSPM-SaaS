"""One shared, read-only demo organization that anybody may join.

A new organization met an empty product: nothing could be shown until a Global
Administrator consented and somebody deployed a role, which is precisely the
point at which a trial is most likely to be abandoned. The demo is a real
estate -- a recorded Azure capture run through the real normalizer, rules and
risk engine by ``database/seed/demo_environment.py --shared`` -- that a signed-in
user can open before connecting anything.

Four pieces, all in the database because they are all about who may see what:

* ``organizations.is_demo``, with a partial unique index so there is at most
  one. The flag is what the API reads to make the organization read-only
  regardless of role, and what the UI reads to say "this is the demo".

* ``app.join_demo_organization()``. A caller is not yet a member, so no
  membership policy lets them insert themselves -- which is exactly right for
  every other organization. The same SECURITY DEFINER pattern that
  ``app.create_organization`` uses lets them join *this one*, and only as
  VIEWER: the role is fixed in the function, not taken from the caller.

* ``app.leave_demo_organization()``. ``member_delete`` needs OWNER or ADMIN,
  and nobody is either in the demo, so leaving needs the same kind of door.

* A narrower ``member_select``. Every member of an organization could read its
  whole membership list. In the demo the members are strangers -- every person
  who ever clicked "explore" -- so there a member sees only their own row.

Revision ID: 0036
Revises: 0035
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0036"
down_revision: str | None = "0035"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


UPGRADE_SQL = """
ALTER TABLE organizations ADD COLUMN is_demo boolean NOT NULL DEFAULT false;
CREATE UNIQUE INDEX organizations_single_demo ON organizations (is_demo) WHERE is_demo;

CREATE OR REPLACE FUNCTION app.is_demo_organization(p_org uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
  SELECT COALESCE((SELECT o.is_demo FROM public.organizations o WHERE o.id = p_org), false)
$$;

CREATE OR REPLACE FUNCTION app.join_demo_organization() RETURNS uuid
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  v_user uuid := app.user_id();
  v_org  uuid;
BEGIN
  IF v_user IS NULL THEN
    RAISE EXCEPTION 'not authenticated' USING ERRCODE = '28000';
  END IF;

  SELECT id INTO v_org FROM public.organizations WHERE is_demo LIMIT 1;
  IF v_org IS NULL THEN
    RAISE EXCEPTION 'no demo organization' USING ERRCODE = 'P0002';
  END IF;

  -- VIEWER, always. Joining twice is not an error; it is a second click.
  INSERT INTO public.organization_members (organization_id, user_id, role)
  VALUES (v_org, v_user, 'VIEWER')
  ON CONFLICT (organization_id, user_id) DO NOTHING;

  RETURN v_org;
END;
$$;

CREATE OR REPLACE FUNCTION app.leave_demo_organization() RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  v_user uuid := app.user_id();
BEGIN
  IF v_user IS NULL THEN
    RAISE EXCEPTION 'not authenticated' USING ERRCODE = '28000';
  END IF;

  DELETE FROM public.organization_members m
  USING public.organizations o
  WHERE m.organization_id = o.id AND o.is_demo AND m.user_id = v_user;
END;
$$;

DROP POLICY member_select ON organization_members;
CREATE POLICY member_select ON organization_members FOR SELECT
USING (
  user_id = app.user_id()
  OR (app.is_member(organization_id) AND NOT app.is_demo_organization(organization_id))
);

GRANT EXECUTE ON FUNCTION app.is_demo_organization(uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION app.join_demo_organization() TO authenticated;
GRANT EXECUTE ON FUNCTION app.leave_demo_organization() TO authenticated;
"""

DOWNGRADE_SQL = """
DROP POLICY member_select ON organization_members;
CREATE POLICY member_select ON organization_members FOR SELECT
USING (app.is_member(organization_id));

DROP FUNCTION IF EXISTS app.leave_demo_organization();
DROP FUNCTION IF EXISTS app.join_demo_organization();
DROP FUNCTION IF EXISTS app.is_demo_organization(uuid);

DROP INDEX IF EXISTS organizations_single_demo;
ALTER TABLE organizations DROP COLUMN is_demo;
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute(DOWNGRADE_SQL)
