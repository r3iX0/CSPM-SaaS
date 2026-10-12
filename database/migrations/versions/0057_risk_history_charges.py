"""What each posture reading charged the score for, so its movement can be explained.

Revision ID: 0057
Revises: 0056

Two nullable JSON documents on ``risk_history`` (DECISIONS.md section 235). ``charges`` maps
each open finding risk the score deducted for to the band it was charged at, and
``rule_versions`` maps each rule to the version that ran. The movement between two readings is
then the risks whose charge changed, each given its cause. NULL on every row written before this
migration: those readings recorded only their totals, and a movement from one of them is said to
be unexplained rather than reconstructed.

No policy changes: the table's tenant and worker policies cover every column.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0057"
down_revision: str | None = "0056"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE risk_history ADD COLUMN charges jsonb")
    op.execute("ALTER TABLE risk_history ADD COLUMN rule_versions jsonb")


def downgrade() -> None:
    op.execute("ALTER TABLE risk_history DROP COLUMN rule_versions")
    op.execute("ALTER TABLE risk_history DROP COLUMN charges")
