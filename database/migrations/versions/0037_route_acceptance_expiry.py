"""When a route's acceptance runs out.

A finding's acceptance already carries its expiry, on the exception row. A route
has no finding of its own and so no exception row, and the API refused an
expiry on one because nothing would have acted on it. The expiry sweep now does
(DECISIONS.md §104), so the route needs somewhere to keep the date.

Nullable, with no default: NULL means "accepted with no end date", and also
every route that is not accepted at all. Additive, so it is safe to apply before
or after the code that writes it is deployed.

Revision ID: 0037
Revises: 0036
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0037"
down_revision: str | None = "0036"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE risks ADD COLUMN accepted_until timestamptz;")


def downgrade() -> None:
    op.execute("ALTER TABLE risks DROP COLUMN accepted_until;")
