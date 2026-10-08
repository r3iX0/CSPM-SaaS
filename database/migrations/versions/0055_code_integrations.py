"""Which GitHub App installations belong to which organization.

Revision ID: 0055
Revises: 0054

A customer installs Cleave's GitHub App on the repositories that hold their
Terraform, and links the installation to their organization (DECISIONS.md
section 231). The link is what turns a state index upload, authenticated by the
repository's own GitHub Actions token, into rows of one organization, and what
will let a pull request be opened on its repositories.

``installation_id`` is unique: an installation belongs to one organization, so a
second organization cannot claim it. Linking is proven against GitHub with the
linking person's own GitHub token, never taken from a redirect's query string.

Members read the links; owners and admins make and remove them. An installation
removed on GitHub is unlinked by the App's webhook, through the owner connection.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0055"
down_revision: str | None = "0054"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_MEMBER = "app.is_member(organization_id)"
_ADMIN = "app.has_role(organization_id, ARRAY['OWNER','ADMIN'])"

UPGRADE_SQL = f"""
CREATE TABLE code_integrations (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider        varchar(16) NOT NULL DEFAULT 'github' CHECK (provider = 'github'),
  installation_id bigint NOT NULL UNIQUE,
  account_login   varchar(100) NOT NULL,
  account_type    varchar(16) NOT NULL,
  connected_by    uuid NOT NULL,
  connected_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_code_integrations_org ON code_integrations (organization_id);

ALTER TABLE code_integrations ENABLE ROW LEVEL SECURITY;
CREATE POLICY code_integrations_member_select ON code_integrations FOR SELECT
  USING ({_MEMBER});
CREATE POLICY code_integrations_admin_insert ON code_integrations FOR INSERT
  WITH CHECK ({_ADMIN});
CREATE POLICY code_integrations_admin_delete ON code_integrations FOR DELETE
  USING ({_ADMIN});
GRANT SELECT, INSERT, DELETE ON code_integrations TO authenticated;
"""

DOWNGRADE_SQL = """
DROP TABLE IF EXISTS code_integrations;
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute(DOWNGRADE_SQL)
