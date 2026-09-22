"""Close ``alembic_version`` to the API roles.

Alembic creates ``alembic_version`` in ``public`` before the first migration
runs, so migration 0001's ``GRANT ... ON ALL TABLES IN SCHEMA public TO
authenticated`` handed it to every signed-in user, and Supabase's default
privileges hand every new ``public`` table to ``anon`` as well. It was the one
table without row-level security, and PostgREST serves ``public``: anyone with
the project's anon key could read the schema revision, and a signed-in user
could rewrite it, which decides what the next ``alembic upgrade head`` runs.

RLS with no policy denies every row to every role that does not own the table,
and the privileges go too. Migrations run as the owner, which RLS does not
constrain, so Alembic is unaffected (DECISIONS.md §131).

Revision ID: 0040
Revises: 0039
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0040"
down_revision: str | None = "0039"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE alembic_version ENABLE ROW LEVEL SECURITY;")
    op.execute("REVOKE ALL ON alembic_version FROM anon, authenticated;")


def downgrade() -> None:
    op.execute("ALTER TABLE alembic_version DISABLE ROW LEVEL SECURITY;")
    op.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON alembic_version TO authenticated;")
