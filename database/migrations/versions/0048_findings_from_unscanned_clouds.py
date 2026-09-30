"""Findings a rule raised about a cloud the organization does not use.

Revision ID: 0048
Revises: 0047

The rule engine ran every rule over every scan, and an AGGREGATE rule reads the
scan's controls rather than its resources. AWS-IAM-004 looked for an AWS
password policy in an Azure tenant's state, found none, and failed -- so every
Azure-only organization carried an open finding about an AWS account it does
not have. A scan now runs only the rules of the clouds it read (DECISIONS.md
section 184), which stops new ones but closes none: nothing will ever pass the
rule there again, so they would stay open for ever.

They are deleted, with the risks they leave with no member -- deleted rather
than resolved, for the reason section 124 gives: nothing was fixed, the
finding was never true. Only where the organization has neither a connection
nor an account of the rule's provider, so an organization that does use AWS
keeps every AWS finding, including one this defect happened to raise first
(its own AWS scans judge that one).

The downgrade restores nothing: a finding about an account that does not exist
is not data.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0048"
down_revision: str | None = "0047"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

UNSCANNED = """
    SELECT f.id
      FROM findings f
      JOIN rules r ON r.rule_id = f.rule_id
     WHERE NOT EXISTS (
             SELECT 1 FROM cloud_connections c
              WHERE c.organization_id = f.organization_id AND c.provider = r.provider)
       AND NOT EXISTS (
             SELECT 1 FROM cloud_accounts a
              WHERE a.organization_id = f.organization_id AND a.provider = r.provider)
"""


def upgrade() -> None:
    # The risks to look at afterwards, taken before the findings go: the
    # cascade removes the links that would have named them.
    op.execute(
        f"""
        CREATE TEMPORARY TABLE _unscanned_risks ON COMMIT DROP AS
        SELECT DISTINCT rf.risk_id
          FROM risk_findings rf
         WHERE rf.finding_id IN ({UNSCANNED});
        """
    )
    op.execute(f"DELETE FROM findings WHERE id IN ({UNSCANNED});")
    op.execute(
        """
        DELETE FROM risks r
         USING _unscanned_risks u
         WHERE r.id = u.risk_id
           AND NOT EXISTS (SELECT 1 FROM risk_findings rf WHERE rf.risk_id = r.id);
        """
    )


def downgrade() -> None:
    pass
