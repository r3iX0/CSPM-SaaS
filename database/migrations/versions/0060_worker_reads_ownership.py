"""The worker reads an organization's deadlines, members and ownership rules.

Revision ID: 0060
Revises: 0059

The weekly digest and the overdue escalation (DECISIONS.md section 237) are written by the
notification sweep, which runs as ``cloudguard_worker`` under one organization's claim. They need
what the queue reads on a request: the organization's deadline policy and mode, its members, and
its ownership rules. 0012 granted SELECT on ``organizations`` and ``organization_members`` but
added no policy arm for this role, so under row-level security the worker saw neither table's
rows, and 0058 gave ``ownership_rules`` no worker arm at all.

SELECT only, each arm the claim the worker declares, as every other worker arm is. Nothing here
lets a background job change who owns work or when it is due: those are a person's decisions.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0060"
down_revision: str | None = "0059"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UPGRADE_SQL = """
CREATE POLICY organizations_worker_select ON organizations FOR SELECT
  TO cloudguard_worker USING (app.current_org() = id);
CREATE POLICY organization_members_worker_select ON organization_members FOR SELECT
  TO cloudguard_worker USING (app.current_org() = organization_id);
CREATE POLICY ownership_rules_worker_select ON ownership_rules FOR SELECT
  TO cloudguard_worker USING (app.current_org() = organization_id);
GRANT SELECT ON ownership_rules TO cloudguard_worker;
"""

DOWNGRADE_SQL = """
REVOKE SELECT ON ownership_rules FROM cloudguard_worker;
DROP POLICY IF EXISTS ownership_rules_worker_select ON ownership_rules;
DROP POLICY IF EXISTS organization_members_worker_select ON organization_members;
DROP POLICY IF EXISTS organizations_worker_select ON organizations;
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute(DOWNGRADE_SQL)
