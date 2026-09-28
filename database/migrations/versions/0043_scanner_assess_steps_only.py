"""The scanner may see and settle ASSESS steps, and no other kind.

Revision ID: 0043
Revises: 0042

Migration 0042 gave ``cloudguard_scanner`` its step's lease and status through
column grants, under policies that held it to the organization it declared and
nothing narrower. Within that organization it could therefore update any step:
mark a COLLECT failed, an ANALYZE succeeded, a PLAN pending again. The scanner
runs third-party code -- Prowler and several hundred of its dependencies -- so
the grant should say what the job is, and the job is ASSESS steps only.

The organization it acts for is still its own declaration
(``app.organization_id``), as it is for ``cloudguard_worker``; what the policies
narrow is what it can do once it has declared one (DECISIONS.md section 151).
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0043"
down_revision: str | None = "0042"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ORG = "app.current_org() = organization_id"
_ASSESS = f"{_ORG} AND kind = 'ASSESS'"


def _replace(clause: str) -> None:
    op.execute("DROP POLICY IF EXISTS scan_steps_scanner_select ON scan_steps;")
    op.execute("DROP POLICY IF EXISTS scan_steps_scanner_update ON scan_steps;")
    op.execute(
        "CREATE POLICY scan_steps_scanner_select ON scan_steps FOR SELECT "
        f"TO cloudguard_scanner USING ({clause});"
    )
    op.execute(
        "CREATE POLICY scan_steps_scanner_update ON scan_steps FOR UPDATE "
        f"TO cloudguard_scanner USING ({clause}) WITH CHECK ({clause});"
    )


def upgrade() -> None:
    _replace(_ASSESS)


def downgrade() -> None:
    _replace(_ORG)
