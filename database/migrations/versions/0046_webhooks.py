"""Send notifications where a team already talks: webhooks, Slack, Teams.

The bell was the only place a notification arrived, and nobody sits watching a
CSPM tab. An endpoint is a URL an owner or admin gives, a format, and which of
the three notification kinds it wants; a delivery is one notification owed to
one endpoint, retried until it lands or is given up on (DECISIONS.md section
164).

* ``webhook_endpoints`` -- owners and admins read and write them. The worker
  reads them and records the last success and failure on them. ``secret`` signs
  a generic endpoint's deliveries; it is shown once, at creation, and the API
  never returns it again.
* ``webhook_deliveries`` -- written and advanced by the worker, read by owners
  and admins. One per endpoint and notification, so a sweep that runs twice
  owes nothing twice.

Revision ID: 0046
Revises: 0045
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0046"
down_revision: str | None = "0045"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_ADMIN = "app.has_role(organization_id, ARRAY['OWNER','ADMIN'])"
_WORKER = "app.current_org() = organization_id"

UPGRADE_SQL = f"""
CREATE TABLE webhook_endpoints (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name            varchar(120) NOT NULL,
  url             text NOT NULL CHECK (url LIKE 'https://%'),
  format          varchar(16) NOT NULL CHECK (format IN ('GENERIC','SLACK','TEAMS')),
  kinds           text[] NOT NULL,
  secret          varchar(64),
  enabled         boolean NOT NULL DEFAULT true,
  created_by      uuid NOT NULL,
  created_at      timestamptz NOT NULL DEFAULT now(),
  last_success_at timestamptz,
  last_failure_at timestamptz,
  last_error      text
);
CREATE INDEX ix_webhook_endpoints_org ON webhook_endpoints (organization_id);

CREATE TABLE webhook_deliveries (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  endpoint_id     uuid NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
  notification_id uuid NOT NULL REFERENCES notifications(id) ON DELETE CASCADE,
  status          varchar(16) NOT NULL DEFAULT 'PENDING'
                  CHECK (status IN ('PENDING','SENT','FAILED')),
  attempts        integer NOT NULL DEFAULT 0,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  last_status     integer,
  last_error      text,
  created_at      timestamptz NOT NULL DEFAULT now(),
  delivered_at    timestamptz,
  UNIQUE (endpoint_id, notification_id)
);
CREATE INDEX ix_webhook_deliveries_due
  ON webhook_deliveries (next_attempt_at) WHERE status = 'PENDING';
CREATE INDEX ix_webhook_deliveries_endpoint
  ON webhook_deliveries (endpoint_id, created_at DESC);

ALTER TABLE webhook_endpoints ENABLE ROW LEVEL SECURITY;
CREATE POLICY webhook_endpoints_admin_all ON webhook_endpoints FOR ALL
  USING ({_ADMIN}) WITH CHECK ({_ADMIN});
CREATE POLICY webhook_endpoints_worker_select ON webhook_endpoints FOR SELECT
  TO cloudguard_worker USING ({_WORKER});
CREATE POLICY webhook_endpoints_worker_update ON webhook_endpoints FOR UPDATE
  TO cloudguard_worker USING ({_WORKER}) WITH CHECK ({_WORKER});
GRANT SELECT, INSERT, UPDATE, DELETE ON webhook_endpoints TO authenticated;
GRANT SELECT, UPDATE ON webhook_endpoints TO cloudguard_worker;

ALTER TABLE webhook_deliveries ENABLE ROW LEVEL SECURITY;
CREATE POLICY webhook_deliveries_admin_select ON webhook_deliveries FOR SELECT
  USING ({_ADMIN});
CREATE POLICY webhook_deliveries_worker_select ON webhook_deliveries FOR SELECT
  TO cloudguard_worker USING ({_WORKER});
CREATE POLICY webhook_deliveries_worker_insert ON webhook_deliveries FOR INSERT
  TO cloudguard_worker WITH CHECK ({_WORKER});
CREATE POLICY webhook_deliveries_worker_update ON webhook_deliveries FOR UPDATE
  TO cloudguard_worker USING ({_WORKER}) WITH CHECK ({_WORKER});
GRANT SELECT ON webhook_deliveries TO authenticated;
GRANT SELECT, INSERT, UPDATE ON webhook_deliveries TO cloudguard_worker;
"""

DOWNGRADE_SQL = """
DROP TABLE IF EXISTS webhook_deliveries;
DROP TABLE IF EXISTS webhook_endpoints;
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute(DOWNGRADE_SQL)
