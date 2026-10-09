"""An acceptance at or above a chosen severity waits for a second person.

Revision ID: 0062
Revises: 0061

DECISIONS.md section 239. ``organizations.acceptance_approval_from`` is the lowest severity whose
acceptance needs a second approver, or NULL for none. An acceptance it covers is written to
``exceptions`` as PENDING and changes nothing until another owner or admin approves it (ACTIVE)
or rejects it (REJECTED).

``exceptions`` changes to hold a request as well as a decision:

* ``requested_by`` is who asked, backfilled from ``approved_by`` for every earlier row, where the
  two were the same person. ``approved_by`` becomes nullable: a request has no approver yet.
* ``second_approval`` marks a row the policy covered. For those, the person who decided may not be
  the person who asked, and the database refuses it (``ck_exceptions_four_eyes``) whatever the
  application does.
* ``risk_id`` lets a route or an escalation wait too. A row names a finding or a risk, never both
  and never neither. A route's acceptance, once approved, is still kept on ``risks`` (section 104).
* ``decided_by``, ``decided_at`` and ``decision_note`` record the second person's decision.
* One request waits per finding or risk at a time.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0062"
down_revision: str | None = "0061"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UPGRADE_SQL = """
ALTER TABLE organizations ADD COLUMN acceptance_approval_from varchar(8)
  CONSTRAINT ck_organizations_acceptance_approval
  CHECK (acceptance_approval_from IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'));

ALTER TABLE exceptions
  ALTER COLUMN finding_id DROP NOT NULL,
  ALTER COLUMN approved_by DROP NOT NULL,
  ADD COLUMN risk_id uuid REFERENCES risks(id) ON DELETE CASCADE,
  ADD COLUMN requested_by uuid,
  ADD COLUMN second_approval boolean NOT NULL DEFAULT false,
  ADD COLUMN decided_by uuid,
  ADD COLUMN decided_at timestamptz,
  ADD COLUMN decision_note text;

UPDATE exceptions SET requested_by = approved_by;
ALTER TABLE exceptions ALTER COLUMN requested_by SET NOT NULL;

ALTER TABLE exceptions
  ADD CONSTRAINT ck_exceptions_subject CHECK (num_nonnulls(finding_id, risk_id) = 1),
  ADD CONSTRAINT ck_exceptions_status
    CHECK (status IN ('PENDING', 'ACTIVE', 'REJECTED', 'EXPIRED', 'REVOKED')),
  ADD CONSTRAINT ck_exceptions_four_eyes
    CHECK (NOT second_approval OR decided_by IS NULL OR decided_by <> requested_by),
  ADD CONSTRAINT ck_exceptions_active_approved
    CHECK (status <> 'ACTIVE' OR approved_by IS NOT NULL);

CREATE UNIQUE INDEX uq_exceptions_pending_finding ON exceptions (finding_id)
  WHERE status = 'PENDING' AND finding_id IS NOT NULL;
CREATE UNIQUE INDEX uq_exceptions_pending_risk ON exceptions (risk_id)
  WHERE status = 'PENDING' AND risk_id IS NOT NULL;
"""

DOWNGRADE_SQL = """
DROP INDEX IF EXISTS uq_exceptions_pending_risk;
DROP INDEX IF EXISTS uq_exceptions_pending_finding;
DELETE FROM exceptions WHERE risk_id IS NOT NULL OR status IN ('PENDING', 'REJECTED');
ALTER TABLE exceptions
  DROP CONSTRAINT IF EXISTS ck_exceptions_active_approved,
  DROP CONSTRAINT IF EXISTS ck_exceptions_four_eyes,
  DROP CONSTRAINT IF EXISTS ck_exceptions_status,
  DROP CONSTRAINT IF EXISTS ck_exceptions_subject,
  DROP COLUMN decision_note,
  DROP COLUMN decided_at,
  DROP COLUMN decided_by,
  DROP COLUMN second_approval,
  DROP COLUMN requested_by,
  DROP COLUMN risk_id,
  ALTER COLUMN approved_by SET NOT NULL,
  ALTER COLUMN finding_id SET NOT NULL;
ALTER TABLE organizations DROP COLUMN acceptance_approval_from;
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute(DOWNGRADE_SQL)
