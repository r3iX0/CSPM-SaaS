"""Make a consent link redeemable once.

The Entra admin-consent round trip is authenticated by a signed ``state`` and
nothing else, and a signature is not a session: anyone holding the string can
present it, for as long as it has not expired. That is tolerable for a link the
customer hands to their Global Administrator -- it is meant to travel -- but it
also meant the link could be replayed, and replaying it rewrote the connection's
tenant binding.

So the token now carries a nonce, and its counterpart lives here. The callback
matches one against the other and clears the column, which is what turns
"verifiable forever" into "redeemable once".

The issue time is stored beside it so the link can be *reissued identically*
while it is still live. The setup wizard polls the connection, and minting a
fresh nonce on each read would invalidate the link the customer had already sent
on -- the administrator then follows a link that says the request expired, hours
after it was sent.

Both columns are nullable with no default: a connection that has never had a
link issued has neither, which is the correct starting state for every existing
row. Additive, so it is safe to apply before or after the code that writes it.

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
        "ALTER TABLE cloud_connections "
        "ADD COLUMN consent_nonce varchar(64), "
        "ADD COLUMN consent_nonce_issued_at timestamptz;"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE cloud_connections "
        "DROP COLUMN consent_nonce, "
        "DROP COLUMN consent_nonce_issued_at;"
    )
