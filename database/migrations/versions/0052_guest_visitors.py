"""Guests: a visitor who opens the demo without an account.

Revision ID: 0052
Revises: 0051

Supabase's anonymous sign-in gives a visitor a real session with no email, marked by the
``is_anonymous`` claim, and the API carries that claim into ``request.jwt.claims`` as it carries
the email (DECISIONS.md section 219). A guest joins the shared demo and nothing else.

``app.is_guest()`` reads the claim the way ``app.user_id()`` reads ``sub``.

The trigger on ``organization_members`` is the database's half of "nothing else". Every way into
an organization ends in a membership row -- creating one, accepting an invitation, joining the
demo -- so refusing a guest every row whose organization is not the demo covers the paths that
exist and any that are added, whatever function or policy they go through. The API refuses the
same requests first (``get_account_user``); this is the lock that does not depend on a route
having asked. It is SECURITY DEFINER only to read ``organizations.is_demo`` past RLS, since the
guest is not yet a member of the organization it is being refused.

``app.forget_guests()`` deletes the guests who signed in before a cutoff and never made an
account, with the rows they left: their demo membership and what they marked read or dismissed.
``organization_members.user_id`` has no foreign key to ``auth.users``, so nothing cascades from
Supabase's delete and each table is named here. A guest who made an account is no longer
anonymous and is never touched. It runs as the owner from the daily sweep and is granted to
nobody else. Like ``app.has_verified_factor()``, it answers 0 on a PostgreSQL with no ``auth``
schema rather than failing.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0052"
down_revision: str | None = "0051"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UPGRADE_SQL = """
CREATE OR REPLACE FUNCTION app.is_guest() RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT COALESCE(
    NULLIF(current_setting('request.jwt.claims', true), '')::jsonb ->> 'is_anonymous' = 'true',
    false
  )
$$;

CREATE OR REPLACE FUNCTION app.keep_guests_in_the_demo() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
BEGIN
  IF app.is_guest() AND NOT EXISTS (
    SELECT 1 FROM organizations WHERE id = NEW.organization_id AND is_demo
  ) THEN
    RAISE EXCEPTION 'a guest can only join the demo' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER trg_organization_members_guests
BEFORE INSERT OR UPDATE OF organization_id ON organization_members
FOR EACH ROW EXECUTE FUNCTION app.keep_guests_in_the_demo();

CREATE OR REPLACE FUNCTION app.forget_guests(p_created_before timestamptz) RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
  v_ids uuid[];
BEGIN
  IF to_regclass('auth.users') IS NULL THEN
    RETURN 0;
  END IF;
  -- Bounded, so one run is one short transaction however many have piled up;
  -- the next day's run takes the rest.
  SELECT array_agg(id) INTO v_ids FROM (
    SELECT id FROM auth.users
    WHERE is_anonymous AND created_at < p_created_before
    ORDER BY created_at
    LIMIT 5000
  ) stale;
  IF v_ids IS NULL THEN
    RETURN 0;
  END IF;
  DELETE FROM notification_reads WHERE user_id = ANY (v_ids);
  DELETE FROM notification_dismissals WHERE user_id = ANY (v_ids);
  DELETE FROM organization_members WHERE user_id = ANY (v_ids);
  DELETE FROM auth.users WHERE id = ANY (v_ids);
  RETURN cardinality(v_ids);
END;
$$;

REVOKE ALL ON FUNCTION app.is_guest() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.is_guest() TO authenticated;
REVOKE ALL ON FUNCTION app.keep_guests_in_the_demo() FROM PUBLIC;
REVOKE ALL ON FUNCTION app.forget_guests(timestamptz) FROM PUBLIC;
"""

DOWNGRADE_SQL = """
DROP TRIGGER IF EXISTS trg_organization_members_guests ON organization_members;
DROP FUNCTION IF EXISTS app.forget_guests(timestamptz);
DROP FUNCTION IF EXISTS app.keep_guests_in_the_demo();
DROP FUNCTION IF EXISTS app.is_guest();
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute(DOWNGRADE_SQL)
