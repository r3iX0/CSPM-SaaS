"""Which permissions a connection's grant left out.

Admin consent can succeed while granting nothing: Entra resolves ``/.default``
against whatever CloudGuard's app registration declares at that moment, and a
registration holding only delegated permissions produces a consent screen, a
GRANTED callback, and a service token with no roles in it. The connection page
showed "Admin consent: Granted" over exactly that, because the only thing it had
to go on was the callback.

The answer is in the token, and it is recorded here each time it is asked -- at
the consent callback and on every re-check -- so the page can state it without
fetching a token per render.

Nullable, with no default: NULL means "not checked", which is a different fact
from an empty list, and every existing row has not been. Additive, so it is safe
to apply before or after the code that writes it is deployed.

Revision ID: 0038
Revises: 0037
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0038"
down_revision: str | None = "0037"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("ALTER TABLE cloud_connections ADD COLUMN missing_permissions jsonb;")


def downgrade() -> None:
    op.execute("ALTER TABLE cloud_connections DROP COLUMN missing_permissions;")
