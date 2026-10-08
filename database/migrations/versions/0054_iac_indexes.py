"""The customer's Terraform state index: which block defines each asset.

Revision ID: 0054
Revises: 0053

A GitHub Action in the customer's pipeline uploads, from ``terraform show -json``,
each managed azurerm resource's state address, type, instance key and Azure
Resource Manager id, and nothing else (DECISIONS.md section 229).

* ``iac_indexes`` -- one upload: a repository (GitHub's numeric id, which
  survives a rename, and its name for display), the directory Terraform ran in,
  the workspace and the commit. Replaced whole by the next upload of the same
  four, so an index never mixes two states.
* ``iac_index_entries`` -- one resource of it. ``resource_id`` is lower-cased,
  and indexed with the organization, because the question asked of it is "is
  this asset managed in code".

Members read both, which is what marks an asset managed in code on its finding.
Nobody writes them through the request role: the upload is authenticated by the
Action's own OIDC token rather than a person, and is written by the owner
connection scoped to the organization the repository's installation belongs to,
as change events are.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0054"
down_revision: str | None = "0053"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_MEMBER = "app.is_member(organization_id)"
_WORKER = "app.current_org() = organization_id"

UPGRADE_SQL = f"""
CREATE TABLE iac_indexes (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id   uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  repository_id     bigint NOT NULL,
  repository        varchar(200) NOT NULL,
  working_directory varchar(500) NOT NULL DEFAULT '',
  workspace         varchar(100) NOT NULL DEFAULT 'default',
  commit_sha        varchar(64) NOT NULL,
  uploaded_at       timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, repository_id, working_directory, workspace)
);

CREATE TABLE iac_index_entries (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  index_id        uuid NOT NULL REFERENCES iac_indexes(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  address         text NOT NULL,
  type            varchar(100) NOT NULL,
  instance_key    text,
  resource_id     text NOT NULL CHECK (resource_id = lower(resource_id)),
  UNIQUE (index_id, address)
);
CREATE INDEX ix_iac_index_entries_resource ON iac_index_entries (organization_id, resource_id);

ALTER TABLE iac_indexes ENABLE ROW LEVEL SECURITY;
CREATE POLICY iac_indexes_member_select ON iac_indexes FOR SELECT USING ({_MEMBER});
CREATE POLICY iac_indexes_worker_select ON iac_indexes FOR SELECT
  TO cloudguard_worker USING ({_WORKER});
GRANT SELECT ON iac_indexes TO authenticated;
GRANT SELECT ON iac_indexes TO cloudguard_worker;

ALTER TABLE iac_index_entries ENABLE ROW LEVEL SECURITY;
CREATE POLICY iac_index_entries_member_select ON iac_index_entries FOR SELECT
  USING ({_MEMBER});
CREATE POLICY iac_index_entries_worker_select ON iac_index_entries FOR SELECT
  TO cloudguard_worker USING ({_WORKER});
GRANT SELECT ON iac_index_entries TO authenticated;
GRANT SELECT ON iac_index_entries TO cloudguard_worker;
"""

DOWNGRADE_SQL = """
DROP TABLE IF EXISTS iac_index_entries;
DROP TABLE IF EXISTS iac_indexes;
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute(DOWNGRADE_SQL)
