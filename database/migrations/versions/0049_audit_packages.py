"""Sealed audit packages: an assessment and the readings behind it, kept as it was.

Revision ID: 0049
Revises: 0048

An auditor asks what the estate looked like on a date, and a live assessment
cannot answer that: it reads the latest scan, and retention prunes the payloads
a citation points at (DECISIONS.md section 204).

* ``audit_packages`` -- one sealed assessment of one or more frameworks. Its
  ``controls`` are the verdicts as they were, and ``manifest_sha256`` is the
  SHA-256 of the canonical manifest built from this row and its items, so a
  package whose rows were edited no longer matches the hash it was sealed
  under.
* ``audit_package_items`` -- one row per reading the controls rest on: which
  listing, taken when, under which permissions, and the hash of the bytes. The
  hash is **not** a foreign key into ``evidence_blobs``, as in ``evidence``
  and ``finding_evidence``, because a payload may be gone; retention reads this
  table to keep the ones a package still names.

Immutable by grant rather than by convention: owners and admins may read and
insert, and nobody gets UPDATE or DELETE. A package ends only when its
organization does, through the cascade.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0049"
down_revision: str | None = "0048"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ADMIN = "app.has_role(organization_id, ARRAY['OWNER','ADMIN'])"
_WORKER = "app.current_org() = organization_id"

UPGRADE_SQL = f"""
CREATE TABLE audit_packages (
  id                uuid PRIMARY KEY,
  organization_id   uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name              varchar(120) NOT NULL,
  framework_ids     text[] NOT NULL CHECK (cardinality(framework_ids) > 0),
  frameworks        jsonb NOT NULL,
  controls          jsonb NOT NULL,
  scan_id           uuid NOT NULL,
  scan_status       varchar(16) NOT NULL,
  scan_completed_at timestamptz,
  period_start      date,
  period_end        date,
  manifest_version  integer NOT NULL,
  manifest_sha256   varchar(64) NOT NULL,
  sealed_by         uuid NOT NULL,
  sealed_at         timestamptz NOT NULL,
  CHECK (period_start IS NULL OR period_end IS NULL OR period_start <= period_end)
);
CREATE INDEX ix_audit_packages_org ON audit_packages (organization_id, sealed_at DESC);

CREATE TABLE audit_package_items (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  package_id       uuid NOT NULL REFERENCES audit_packages(id) ON DELETE CASCADE,
  organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  evidence_key     varchar(64) NOT NULL,
  cloud_account_id uuid,
  region           varchar(32),
  provider         varchar(16) NOT NULL,
  outcome          varchar(16) NOT NULL,
  item_count       integer NOT NULL,
  collected_at     timestamptz NOT NULL,
  source_scan_id   uuid,
  permissions      jsonb NOT NULL,
  endpoints        jsonb NOT NULL,
  content_hash     varchar(64),
  byte_size        integer NOT NULL
);
CREATE UNIQUE INDEX uq_audit_package_items_reading
  ON audit_package_items (package_id, evidence_key, cloud_account_id, region)
  NULLS NOT DISTINCT;
CREATE INDEX ix_audit_package_items_hash
  ON audit_package_items (organization_id, content_hash)
  WHERE content_hash IS NOT NULL;

ALTER TABLE audit_packages ENABLE ROW LEVEL SECURITY;
CREATE POLICY audit_packages_admin_select ON audit_packages FOR SELECT USING ({_ADMIN});
CREATE POLICY audit_packages_admin_insert ON audit_packages FOR INSERT WITH CHECK ({_ADMIN});
CREATE POLICY audit_packages_worker_select ON audit_packages FOR SELECT
  TO cloudguard_worker USING ({_WORKER});
GRANT SELECT, INSERT ON audit_packages TO authenticated;
GRANT SELECT ON audit_packages TO cloudguard_worker;

ALTER TABLE audit_package_items ENABLE ROW LEVEL SECURITY;
CREATE POLICY audit_package_items_admin_select ON audit_package_items FOR SELECT
  USING ({_ADMIN});
CREATE POLICY audit_package_items_admin_insert ON audit_package_items FOR INSERT
  WITH CHECK ({_ADMIN});
-- Retention runs as the worker, and must see which hashes a package still names.
CREATE POLICY audit_package_items_worker_select ON audit_package_items FOR SELECT
  TO cloudguard_worker USING ({_WORKER});
GRANT SELECT, INSERT ON audit_package_items TO authenticated;
GRANT SELECT ON audit_package_items TO cloudguard_worker;
"""

DOWNGRADE_SQL = """
DROP TABLE IF EXISTS audit_package_items;
DROP TABLE IF EXISTS audit_packages;
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute(DOWNGRADE_SQL)
