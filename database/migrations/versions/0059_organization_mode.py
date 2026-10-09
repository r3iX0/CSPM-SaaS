"""Whether an organization is one person or a team.

Revision ID: 0059
Revises: 0058

``organizations.mode`` (DECISIONS.md section 236). A solo organization is one person, so the
product leaves out what only a team needs: members and invitations, ownership rules, owners on
tasks. A team organization has all of it. Owners and admins switch between them in Settings;
the existing ``org_update`` policy already limits the write to them.

Every organization that exists is a team, so nothing anybody sees changes until they choose.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0059"
down_revision: str | None = "0058"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE organizations ADD COLUMN mode varchar(8) NOT NULL DEFAULT 'TEAM' "
        "CONSTRAINT ck_organizations_mode CHECK (mode IN ('SOLO', 'TEAM'))"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE organizations DROP COLUMN mode")
