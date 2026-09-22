"""Delete the risks a deleted connection or purged scan left behind.

Deleting a connection cascaded its assets, findings and every ``risk_findings``
link, but ``risks`` hangs off the organization rather than an asset, so the risk
rows stayed with no member. The risks list keeps a risk linked to nothing on
purpose, and the dashboard keeps an unresolved route, so both went on showing
risks about an estate nobody was watching any more. Purging a scan's findings
did the same. The delete paths now clear these as they go (DECISIONS.md §124);
this clears the ones already there.

Every writer of a risk links its members in the same transaction, so a risk
with no link is one of these and nothing else.

Not reversible: the rows are gone, and there is nothing to rebuild them from.

Revision ID: 0039
Revises: 0038
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0039"
down_revision: str | None = "0038"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        DELETE FROM risks r
         WHERE NOT EXISTS (SELECT 1 FROM risk_findings rf WHERE rf.risk_id = r.id);
        """
    )


def downgrade() -> None:
    pass
