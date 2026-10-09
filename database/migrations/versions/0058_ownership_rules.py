"""Who owns the work on an asset, by where it sits or how it is tagged.

Revision ID: 0058
Revises: 0057

One row per scope an organization names an owner for (DECISIONS.md section 236): its default, a
subscription, a resource group within one, or an Azure tag's key and value. A task nobody was
assigned to is owned by the most specific rule its asset matches -- a tag, then its resource group,
then its subscription, then the default -- derived when the queue is read, so a rule changed today
reroutes every unassigned task at once and never overwrites a person's choice.

One rule per scope. A tag's key is compared ignoring case, as Azure compares tag names; its value
is compared exactly. A resource group's name ignores case, as Azure's resource ids do.

Members read the rules; owners and admins make, change and remove them.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0058"
down_revision: str | None = "0057"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_MEMBER = "app.is_member(organization_id)"
_ADMIN = "app.has_role(organization_id, ARRAY['OWNER','ADMIN'])"

UPGRADE_SQL = f"""
CREATE TABLE ownership_rules (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  scope            varchar(16) NOT NULL
                   CHECK (scope IN ('DEFAULT', 'SUBSCRIPTION', 'RESOURCE_GROUP', 'TAG')),
  cloud_account_id uuid REFERENCES cloud_accounts(id) ON DELETE CASCADE,
  resource_group   varchar(90),
  tag_key          varchar(512),
  tag_value        varchar(256),
  owner_id         uuid NOT NULL,
  created_by       uuid NOT NULL,
  created_at       timestamptz NOT NULL DEFAULT now(),
  updated_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_ownership_rules_scope CHECK (
    (scope = 'DEFAULT' AND cloud_account_id IS NULL AND resource_group IS NULL
       AND tag_key IS NULL AND tag_value IS NULL)
    OR (scope = 'SUBSCRIPTION' AND cloud_account_id IS NOT NULL AND resource_group IS NULL
       AND tag_key IS NULL AND tag_value IS NULL)
    OR (scope = 'RESOURCE_GROUP' AND cloud_account_id IS NOT NULL AND resource_group IS NOT NULL
       AND tag_key IS NULL AND tag_value IS NULL)
    OR (scope = 'TAG' AND cloud_account_id IS NULL AND resource_group IS NULL
       AND tag_key IS NOT NULL AND tag_value IS NOT NULL)
  )
);
CREATE UNIQUE INDEX uq_ownership_rules_scope ON ownership_rules (
  organization_id,
  scope,
  coalesce(cloud_account_id, '00000000-0000-0000-0000-000000000000'::uuid),
  lower(coalesce(resource_group, '')),
  lower(coalesce(tag_key, '')),
  coalesce(tag_value, '')
);

ALTER TABLE ownership_rules ENABLE ROW LEVEL SECURITY;
CREATE POLICY ownership_rules_member_select ON ownership_rules FOR SELECT
  USING ({_MEMBER});
CREATE POLICY ownership_rules_admin_insert ON ownership_rules FOR INSERT
  WITH CHECK ({_ADMIN});
CREATE POLICY ownership_rules_admin_update ON ownership_rules FOR UPDATE
  USING ({_ADMIN}) WITH CHECK ({_ADMIN});
CREATE POLICY ownership_rules_admin_delete ON ownership_rules FOR DELETE
  USING ({_ADMIN});
GRANT SELECT, INSERT, UPDATE, DELETE ON ownership_rules TO authenticated;
"""

DOWNGRADE_SQL = """
DROP TABLE IF EXISTS ownership_rules;
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute(DOWNGRADE_SQL)
