"""A cut as a pull request: delete the role assignment blocks it removes.

Revision ID: 0065
Revises: 0064

DECISIONS.md section 258. A Fix-as-Code pull request was one rule's fix in one repository
(section 232), covering findings. A cut is a link of the attack-path graph, usually a role
assignment, and has neither a rule nor findings, so ``fix_pull_requests`` takes a second kind:

* ``kind`` -- ``RULE`` (every existing row) or ``CUT``. A rule's request names its rule; a cut's
  names no rule and carries ``cut_key`` (the link as the page names it) and ``cut`` (the link and
  its sentence, for the pull request's title and body).
* At most one cut request is in flight or open per organization, link and repository, as a rule's
  is per rule.
* ``fix_pull_request_assignments`` -- the role assignments a cut request removes, each with its
  state address and, once the worker has read the repository, whether its block was deleted, where,
  or why not.

Members read both and ask for one; the worker writes the rest through the owner connection, as it
does for a rule's request.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0065"
down_revision: str | None = "0064"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_MEMBER = "app.is_member(organization_id)"

UPGRADE_SQL = f"""
ALTER TABLE fix_pull_requests
  ADD COLUMN kind varchar(8) NOT NULL DEFAULT 'RULE'
    CONSTRAINT ck_fix_pull_requests_kind CHECK (kind IN ('RULE', 'CUT')),
  ADD COLUMN cut_key text,
  ADD COLUMN cut jsonb,
  ALTER COLUMN rule_id DROP NOT NULL;
ALTER TABLE fix_pull_requests
  ADD CONSTRAINT ck_fix_pull_requests_subject CHECK (
    (kind = 'RULE' AND rule_id IS NOT NULL AND cut_key IS NULL)
    OR (kind = 'CUT' AND rule_id IS NULL AND cut_key IS NOT NULL AND cut IS NOT NULL)
  );
CREATE UNIQUE INDEX uq_fix_pull_requests_live_cut
  ON fix_pull_requests (organization_id, cut_key, repository_id)
  WHERE kind = 'CUT' AND state IN ('QUEUED', 'OPENING', 'OPEN');

CREATE TABLE fix_pull_request_assignments (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  pull_request_id uuid NOT NULL REFERENCES fix_pull_requests(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  assignment_id   text NOT NULL,
  address         text NOT NULL,
  working_directory text NOT NULL DEFAULT '',
  outcome         varchar(16) NOT NULL DEFAULT 'PENDING'
    CONSTRAINT ck_fix_pull_request_assignments_outcome
    CHECK (outcome IN ('PENDING', 'REMOVED', 'DECLINED')),
  reason          varchar(64),
  path            text,
  line            integer,
  UNIQUE (pull_request_id, assignment_id)
);
CREATE INDEX ix_fix_pull_request_assignments_organization_id
  ON fix_pull_request_assignments (organization_id);

ALTER TABLE fix_pull_request_assignments ENABLE ROW LEVEL SECURITY;
CREATE POLICY fix_pull_request_assignments_member_select ON fix_pull_request_assignments
  FOR SELECT USING ({_MEMBER});
CREATE POLICY fix_pull_request_assignments_member_insert ON fix_pull_request_assignments
  FOR INSERT WITH CHECK ({_MEMBER});
GRANT SELECT, INSERT ON fix_pull_request_assignments TO authenticated;
"""

DOWNGRADE_SQL = """
DROP TABLE IF EXISTS fix_pull_request_assignments;
DROP INDEX IF EXISTS uq_fix_pull_requests_live_cut;
DELETE FROM fix_pull_requests WHERE kind = 'CUT';
ALTER TABLE fix_pull_requests
  DROP CONSTRAINT IF EXISTS ck_fix_pull_requests_subject,
  ALTER COLUMN rule_id SET NOT NULL,
  DROP COLUMN cut,
  DROP COLUMN cut_key,
  DROP COLUMN kind;
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute(DOWNGRADE_SQL)
