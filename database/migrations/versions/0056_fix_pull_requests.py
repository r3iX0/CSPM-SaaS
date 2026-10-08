"""Fix-as-Code pull requests: one per rule per repository, and the findings each edits.

Revision ID: 0056
Revises: 0055

A member asks for a rule's fix as a pull request; Cleave locates each failing
asset's block through the organization's state indexes, edits the blocks it can
stand behind, and opens one pull request per repository (DECISIONS.md section
232). A merge claims the fix for every finding the pull request edited, and the
next scan decides.

* ``fix_pull_requests`` -- one request for one rule in one repository, from
  ``QUEUED`` through ``OPENING`` (claimed under a lease by the worker's sweep)
  to ``OPEN``, then ``MERGED`` or ``CLOSED``; or ``DECLINED`` when no block
  could be edited, or ``FAILED`` after its attempts. At most one is in flight
  or open per organization, rule and repository.
* ``fix_pull_request_findings`` -- which findings it covers, and for each
  whether its block was edited, where, or why not.

Members read both and ask for one; the worker writes the rest through the owner
connection, scoped to the row's organization.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0056"
down_revision: str | None = "0055"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_MEMBER = "app.is_member(organization_id)"

UPGRADE_SQL = f"""
CREATE TABLE fix_pull_requests (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  rule_id         varchar(128) NOT NULL,
  repository_id   bigint NOT NULL,
  repository      varchar(200) NOT NULL,
  state           varchar(16) NOT NULL DEFAULT 'QUEUED',
  branch          varchar(200),
  pr_number       integer,
  pr_url          text,
  decline_reason  varchar(64),
  detail          text,
  requested_by    uuid NOT NULL,
  attempts        integer NOT NULL DEFAULT 0,
  claimed_until   timestamptz,
  created_at      timestamptz NOT NULL DEFAULT now(),
  updated_at      timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uq_fix_pull_requests_live
  ON fix_pull_requests (organization_id, rule_id, repository_id)
  WHERE state IN ('QUEUED', 'OPENING', 'OPEN');
CREATE INDEX ix_fix_pull_requests_due ON fix_pull_requests (created_at)
  WHERE state IN ('QUEUED', 'OPENING');
CREATE INDEX ix_fix_pull_requests_number ON fix_pull_requests (repository_id, pr_number);

CREATE TABLE fix_pull_request_findings (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  pull_request_id uuid NOT NULL REFERENCES fix_pull_requests(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  finding_id      uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  address         text NOT NULL,
  outcome         varchar(16) NOT NULL DEFAULT 'PENDING',
  reason          varchar(64),
  path            text,
  line            integer,
  UNIQUE (pull_request_id, finding_id)
);

ALTER TABLE fix_pull_requests ENABLE ROW LEVEL SECURITY;
CREATE POLICY fix_pull_requests_member_select ON fix_pull_requests FOR SELECT
  USING ({_MEMBER});
CREATE POLICY fix_pull_requests_member_insert ON fix_pull_requests FOR INSERT
  WITH CHECK ({_MEMBER});
GRANT SELECT, INSERT ON fix_pull_requests TO authenticated;

ALTER TABLE fix_pull_request_findings ENABLE ROW LEVEL SECURITY;
CREATE POLICY fix_pull_request_findings_member_select ON fix_pull_request_findings FOR SELECT
  USING ({_MEMBER});
CREATE POLICY fix_pull_request_findings_member_insert ON fix_pull_request_findings FOR INSERT
  WITH CHECK ({_MEMBER});
GRANT SELECT, INSERT ON fix_pull_request_findings TO authenticated;
"""

DOWNGRADE_SQL = """
DROP TABLE IF EXISTS fix_pull_request_findings;
DROP TABLE IF EXISTS fix_pull_requests;
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute(DOWNGRADE_SQL)
