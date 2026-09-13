"""Where a running analysis is, inside its one durable step.

ANALYZE is a single scan step -- claimed, retried and settled as one unit -- and
it is also the longest stretch of a scan that says nothing while it runs:
persisting assets, evaluating every rule, reconciling findings and scoring
risk. The scan wizard could only draw it as one spinning node.

``phase`` is a progress mark the step writes as it passes the seams the
pipeline already had (``AnalyzePhase``). It is not a new unit of scheduling and
nothing reads it to decide what runs. Nullable, with no default: NULL is the
honest value for every COLLECT and PLAN step, and for an analysis that has not
reached its first phase.

Additive and nullable, so it is safe to apply before or after the code that
writes it is deployed.

Revision ID: 0035
Revises: 0034
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0035"
down_revision: str | None = "0034"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE scan_steps ADD COLUMN phase varchar(16);")


def downgrade() -> None:
    op.execute("ALTER TABLE scan_steps DROP COLUMN phase;")
