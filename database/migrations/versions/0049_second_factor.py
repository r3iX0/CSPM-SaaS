"""Whether the caller has a verified second factor.

Revision ID: 0049
Revises: 0048

Supabase records a user's authenticator apps in ``auth.mfa_factors``, and a
token says only whether its own session passed one (the ``aal`` claim), not
whether its user has one at all. The API needs the second to refuse a session
that skipped a factor its user set up (DECISIONS.md section 213), because a
password alone gets a one-factor token from Supabase's API without ever seeing
the sign-in page's code prompt.

``app.has_verified_factor()`` answers it for the caller only: the user is read
from the verified claims, as ``app.user_id()`` reads them, never passed in. It
is SECURITY DEFINER because ``auth`` belongs to Supabase and the request role
is granted nothing there.

The table is looked up by name before it is read, so a PostgreSQL without
Supabase's ``auth`` schema answers false rather than failing every request.
On Supabase it always exists; if the owner could not read it, the function
would raise, and every one-factor request would fail loudly rather than pass.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0049"
down_revision: str | None = "0048"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UPGRADE_SQL = """
CREATE OR REPLACE FUNCTION app.has_verified_factor() RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE
  v_user uuid := app.user_id();
BEGIN
  IF v_user IS NULL OR to_regclass('auth.mfa_factors') IS NULL THEN
    RETURN false;
  END IF;
  RETURN EXISTS (
    SELECT 1 FROM auth.mfa_factors
    WHERE user_id = v_user AND status::text = 'verified'
  );
END;
$$;

REVOKE ALL ON FUNCTION app.has_verified_factor() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION app.has_verified_factor() TO authenticated;
"""

DOWNGRADE_SQL = """
DROP FUNCTION IF EXISTS app.has_verified_factor();
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute(DOWNGRADE_SQL)
