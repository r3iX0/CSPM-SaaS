"""An audit package keeps the fixes a scan verified during its period.

Revision ID: 0061
Revises: 0060

``audit_packages.fixes`` (DECISIONS.md section 238): for every rule the sealed controls rest on,
the findings a scan observed fixed within the audit period, each with the task that tracked it,
the verification that confirmed it and the pull requests that changed its code. Sealed with the
rest of the package and hashed into manifest version 2.

NULL for every package sealed before this, which carries manifest version 1 and is hashed
without the section, so each still verifies as it was sealed. Nobody is granted UPDATE on the
table, so a column added now is written only by sealing.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0061"
down_revision: str | None = "0060"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE audit_packages ADD COLUMN fixes jsonb")


def downgrade() -> None:
    op.execute("ALTER TABLE audit_packages DROP COLUMN fixes")
