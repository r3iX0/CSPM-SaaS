"""Make the audit trail append-only, and readable by those it is for.

``audit_logs`` was created in 0001 as one more tenant table, and so inherited
the uniform policy set: any member could SELECT, INSERT, UPDATE and DELETE any
row of their organization. The API never offered an edit, but the database
would have accepted one -- from a VIEWER as readily as from an OWNER -- and an
audit trail a subject can rewrite is not evidence of anything (DECISIONS.md
section 163).

* UPDATE and DELETE are revoked from ``authenticated`` and from
  ``cloudguard_worker``, and their policies dropped. Rows still go when their
  organization does: a foreign-key cascade runs as the table's owner.
* SELECT narrows to owners and admins, plus a member's own entries. The second
  arm is not only a courtesy: an INSERT that returns its row must pass the
  SELECT policy, and a member writing their own entry must be able to.
* An index for the one way the trail is read: newest first, per organization.

Revision ID: 0045
Revises: 0044
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0045"
down_revision: str | None = "0044"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


UPGRADE_SQL = """
DROP POLICY IF EXISTS audit_logs_tenant_update ON audit_logs;
DROP POLICY IF EXISTS audit_logs_tenant_delete ON audit_logs;
DROP POLICY IF EXISTS audit_logs_worker_update ON audit_logs;
DROP POLICY IF EXISTS audit_logs_worker_delete ON audit_logs;
REVOKE UPDATE, DELETE ON audit_logs FROM authenticated;
REVOKE UPDATE, DELETE ON audit_logs FROM cloudguard_worker;

DROP POLICY IF EXISTS audit_logs_tenant_select ON audit_logs;
CREATE POLICY audit_logs_tenant_select ON audit_logs FOR SELECT
USING (
  app.has_role(organization_id, ARRAY['OWNER','ADMIN'])
  OR (user_id = app.user_id() AND app.is_member(organization_id))
);

CREATE INDEX IF NOT EXISTS ix_audit_logs_org_created
  ON audit_logs (organization_id, created_at DESC, id);
"""

DOWNGRADE_SQL = """
DROP INDEX IF EXISTS ix_audit_logs_org_created;

DROP POLICY IF EXISTS audit_logs_tenant_select ON audit_logs;
CREATE POLICY audit_logs_tenant_select ON audit_logs FOR SELECT
USING (app.is_member(organization_id));

GRANT UPDATE, DELETE ON audit_logs TO authenticated;
GRANT UPDATE, DELETE ON audit_logs TO cloudguard_worker;
CREATE POLICY audit_logs_tenant_update ON audit_logs FOR UPDATE
USING (app.is_member(organization_id)) WITH CHECK (app.is_member(organization_id));
CREATE POLICY audit_logs_tenant_delete ON audit_logs FOR DELETE
USING (app.is_member(organization_id));
CREATE POLICY audit_logs_worker_update ON audit_logs FOR UPDATE TO cloudguard_worker
USING (app.current_org() = organization_id) WITH CHECK (app.current_org() = organization_id);
CREATE POLICY audit_logs_worker_delete ON audit_logs FOR DELETE TO cloudguard_worker
USING (app.current_org() = organization_id);
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute(DOWNGRADE_SQL)
