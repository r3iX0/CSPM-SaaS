"""How long an organization gives itself to fix a finding, by severity.

Revision ID: 0053
Revises: 0052

Four nullable day counts on ``organizations``, one per severity. A task's own due date wins; a
task with none is due this many days after its finding was first detected (DECISIONS.md section
225). NULL is "no deadline for this severity", which is every organization's state until an owner
or an admin sets one, so the queue reads exactly as before for everybody else.

Columns rather than a JSON document, so the database refuses a count outside 1 to 365 days
whoever writes it. The existing ``org_update`` policy already limits writes to owners and admins.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0053"
down_revision: str | None = "0052"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SEVERITIES = ("critical", "high", "medium", "low")


def upgrade() -> None:
    for severity in _SEVERITIES:
        column = f"fix_within_days_{severity}"
        op.execute(
            f"ALTER TABLE organizations ADD COLUMN {column} smallint "
            f"CONSTRAINT ck_organizations_{column} CHECK ({column} BETWEEN 1 AND 365)"
        )


def downgrade() -> None:
    for severity in _SEVERITIES:
        op.execute(f"ALTER TABLE organizations DROP COLUMN fix_within_days_{severity}")
