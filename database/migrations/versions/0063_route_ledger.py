"""The route ledger: which routes existed at each reading.

Revision ID: 0063
Revises: 0062

DECISIONS.md section 244. ANALYZE records every route its graph holds as an episode, from the
scan that first saw it to the scan that no longer did, and the attack-path page reads it to say
what is new, what closed and whether there are fewer routes than before.

* ``route_episodes`` -- one stretch of time one route was open. A route that closes and comes
  back opens a second row. At most one episode per route is open at a time. ``connection_id``
  cascades, so a deleted connection takes its routes' history rather than leaving them open or
  reading as closed by a fix.
* ``route_events`` -- the moments in an episode: OPENED, REROUTED (the same ends by another way
  round, with the way it used to run) and CLOSED (with why: a link removed, or an asset gone).

Scans are referenced SET NULL, as ``risk_history`` references them: pruning an execution log
must not rewrite history. Members read both tables; only the worker writes them, under one
organization's claim.

No backfill: past scans did not keep their routes, and a reconstructed history would be a guess
shown as fact.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0063"
down_revision: str | None = "0062"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_MEMBER = "app.is_member(organization_id)"
_WORKER = "app.current_org() = organization_id"

UPGRADE_SQL = f"""
CREATE TABLE route_episodes (
  id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id    uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  route_key          text NOT NULL,
  connection_id      uuid REFERENCES cloud_connections(id) ON DELETE CASCADE,
  entry_id           text NOT NULL,
  entry_name         varchar(400) NOT NULL,
  target_id          text NOT NULL,
  target_name        varchar(400) NOT NULL,
  target_sensitivity varchar(16) NOT NULL,
  hops               integer NOT NULL,
  steps              jsonb NOT NULL DEFAULT '[]'::jsonb,
  shape              jsonb NOT NULL DEFAULT '[]'::jsonb,
  opened_scan_id     uuid REFERENCES scans(id) ON DELETE SET NULL,
  opened_at          timestamptz NOT NULL,
  last_seen_scan_id  uuid REFERENCES scans(id) ON DELETE SET NULL,
  last_seen_at       timestamptz NOT NULL,
  rerouted_scan_id   uuid REFERENCES scans(id) ON DELETE SET NULL,
  rerouted_at        timestamptz,
  closed_scan_id     uuid REFERENCES scans(id) ON DELETE SET NULL,
  closed_at          timestamptz,
  close_reason       varchar(16)
    CONSTRAINT ck_route_episodes_close_reason
    CHECK (close_reason IN ('LINK_REMOVED', 'ASSET_GONE')),
  created_at         timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT ck_route_episodes_closed CHECK ((closed_at IS NULL) = (close_reason IS NULL))
);
CREATE INDEX ix_route_episodes_organization_id ON route_episodes (organization_id);
CREATE UNIQUE INDEX uq_route_episodes_open ON route_episodes (organization_id, route_key)
  WHERE closed_at IS NULL;
CREATE INDEX ix_route_episodes_timeline ON route_episodes (organization_id, closed_at, opened_at);
CREATE INDEX ix_route_episodes_connection ON route_episodes (connection_id);

CREATE TABLE route_events (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  episode_id      uuid NOT NULL REFERENCES route_episodes(id) ON DELETE CASCADE,
  scan_id         uuid REFERENCES scans(id) ON DELETE SET NULL,
  kind            varchar(16) NOT NULL
    CONSTRAINT ck_route_events_kind CHECK (kind IN ('OPENED', 'REROUTED', 'CLOSED')),
  observed_at     timestamptz NOT NULL,
  reason          varchar(16)
    CONSTRAINT ck_route_events_reason CHECK (reason IN ('LINK_REMOVED', 'ASSET_GONE')),
  steps_before    jsonb
);
CREATE INDEX ix_route_events_organization_id ON route_events (organization_id);
CREATE INDEX ix_route_events_episode ON route_events (episode_id, observed_at);

ALTER TABLE route_episodes ENABLE ROW LEVEL SECURITY;
CREATE POLICY route_episodes_member_select ON route_episodes FOR SELECT USING ({_MEMBER});
CREATE POLICY route_episodes_worker_select ON route_episodes FOR SELECT
  TO cloudguard_worker USING ({_WORKER});
CREATE POLICY route_episodes_worker_insert ON route_episodes FOR INSERT
  TO cloudguard_worker WITH CHECK ({_WORKER});
CREATE POLICY route_episodes_worker_update ON route_episodes FOR UPDATE
  TO cloudguard_worker USING ({_WORKER}) WITH CHECK ({_WORKER});
GRANT SELECT ON route_episodes TO authenticated;
GRANT SELECT, INSERT, UPDATE ON route_episodes TO cloudguard_worker;

ALTER TABLE route_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY route_events_member_select ON route_events FOR SELECT USING ({_MEMBER});
CREATE POLICY route_events_worker_select ON route_events FOR SELECT
  TO cloudguard_worker USING ({_WORKER});
CREATE POLICY route_events_worker_insert ON route_events FOR INSERT
  TO cloudguard_worker WITH CHECK ({_WORKER});
GRANT SELECT ON route_events TO authenticated;
GRANT SELECT, INSERT ON route_events TO cloudguard_worker;
"""

DOWNGRADE_SQL = """
DROP TABLE IF EXISTS route_events;
DROP TABLE IF EXISTS route_episodes;
"""


def upgrade() -> None:
    op.execute(UPGRADE_SQL)


def downgrade() -> None:
    op.execute(DOWNGRADE_SQL)
