"""What a customer has said about one asset: that it holds sensitive data.

Revision ID: 0064
Revises: 0063

DECISIONS.md section 251. ``context_declarations`` holds what a customer says about a
subscription; this holds what they say about one asset, from the attack-path page or the asset's
own page. One row per asset, cascading with it. Applied by the next evaluation as a floor, as a
subscription's declaration is: it can raise what the capture showed and never lower it, so the
worst a wrong declaration does is over-rank an asset, never hide a route.

Members read every row; members who may write declare and withdraw, and the application checks
the role. The worker reads them, under one organization's claim, to apply them in ANALYZE.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0064"
down_revision: str | None = "0063"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_MEMBER = "app.is_member(organization_id)"

UPGRADE_SQL = f"""
CREATE TABLE asset_declarations (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  resource_id         uuid NOT NULL REFERENCES cloud_resources(id) ON DELETE CASCADE,
  data_sensitivity    varchar(16) NOT NULL
    CONSTRAINT ck_asset_declarations_sensitivity
    CHECK (data_sensitivity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
  note                text,
  declared_by_user_id uuid,
  declared_at         timestamptz NOT NULL DEFAULT now(),
  created_at          timestamptz NOT NULL DEFAULT now(),
  updated_at          timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT uq_asset_declarations_resource_id UNIQUE (resource_id)
);
CREATE INDEX ix_asset_declarations_organization_id ON asset_declarations (organization_id);

ALTER TABLE asset_declarations ENABLE ROW LEVEL SECURITY;
CREATE POLICY asset_declarations_member_select ON asset_declarations FOR SELECT
  USING ({_MEMBER});
CREATE POLICY asset_declarations_member_insert ON asset_declarations FOR INSERT
  WITH CHECK ({_MEMBER});
CREATE POLICY asset_declarations_member_update ON asset_declarations FOR UPDATE
  USING ({_MEMBER}) WITH CHECK ({_MEMBER});
CREATE POLICY asset_declarations_member_delete ON asset_declarations FOR DELETE
  USING ({_MEMBER});
CREATE POLICY asset_declarations_worker_select ON asset_declarations FOR SELECT
  TO cloudguard_worker USING (app.current_org() = organization_id);
GRANT SELECT, INSERT, UPDATE, DELETE ON asset_declarations TO authenticated;
GRANT SELECT ON asset_declarations TO cloudguard_worker;
"""

DOWNGRADE_SQL = """
DROP TABLE IF EXISTS asset_declarations;
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute(DOWNGRADE_SQL)
