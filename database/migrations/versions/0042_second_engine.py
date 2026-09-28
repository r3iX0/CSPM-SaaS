"""The second engine: where Prowler's runs are stored, and who may store them.

Revision ID: 0042
Revises: 0041

Four changes, all additive (DECISIONS.md section 150).

**Rule ids get longer.** A Prowler check's rule id is ``PRW-<cloud>-<check>``,
and Prowler's longest check id is 93 characters. Every column holding a rule id
goes from 32 to 128. Widening a varchar is a catalogue change in PostgreSQL --
no table rewrite, no lock beyond the instant of the ALTER.

**The rules mirror says which engine answers each rule.** ``engine`` and
``engine_version``, so a finding, a control and the rules page can say whether
a verdict is Cleave's own or Prowler's, and which Prowler release reached it.

**Two tables.** ``assessment_captures`` holds each ASSESS step's run verbatim,
one row per scope; ``engine_divergences`` holds where a native rule and its
Prowler counterpart disagreed. Both tenant-owned, both under the same two
policy arms every scan table carries.

**A role for the scanner service.** ``cloudguard_scanner`` runs third-party code
-- Prowler and several hundred of its dependencies -- with a customer's
credentials in memory. It gets the least this job needs and nothing else: read
the scope it was handed, keep its step's lease, write its capture. It cannot
read a finding, an asset, a snapshot or another tenant's anything. It learns
which organization a scan belongs to through ``app.scan_owner``, a one-column
SECURITY DEFINER lookup, because that is the one read that has to happen
before there is an organization to be held to -- the same exception the
worker's own ``service_session`` makes, narrowed to one row.

Created NOLOGIN, like ``cloudguard_worker`` in 0012: the operator gives it a
password in ``infrastructure/supabase/roles.sql`` when the scanner service is
deployed. Until then it can do nothing, which is exactly as much as the
scanner service that does not exist yet needs.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0042"
down_revision: str | None = "0041"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

RULE_ID_COLUMNS = (
    "findings",
    "rules",
    "scan_rule_results",
    "scan_evaluation_gaps",
    "remediation_verifications",
)

NEW_TABLES = ("assessment_captures", "engine_divergences")

# What the scanner may do to each table it touches, and nothing more.
SCANNER_ACTIONS = (
    ("scans", ("SELECT",)),
    ("cloud_connections", ("SELECT",)),
    ("cloud_accounts", ("SELECT",)),
    ("scan_steps", ("SELECT", "UPDATE")),
    ("assessment_captures", ("SELECT", "INSERT", "DELETE")),
)

_CLAUSES = {
    "SELECT": "USING (app.current_org() = organization_id)",
    "INSERT": "WITH CHECK (app.current_org() = organization_id)",
    "UPDATE": "USING (app.current_org() = organization_id) "
    "WITH CHECK (app.current_org() = organization_id)",
    "DELETE": "USING (app.current_org() = organization_id)",
}


def _policies(table: str) -> None:
    op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
    for action, clause in (
        ("SELECT", "USING (app.is_member(organization_id))"),
        ("INSERT", "WITH CHECK (app.is_member(organization_id))"),
        (
            "UPDATE",
            "USING (app.is_member(organization_id)) "
            "WITH CHECK (app.is_member(organization_id))",
        ),
        ("DELETE", "USING (app.is_member(organization_id))"),
    ):
        op.execute(
            f"CREATE POLICY {table}_tenant_{action.lower()} "
            f"ON {table} FOR {action} {clause};"
        )
    for action, clause in _CLAUSES.items():
        op.execute(
            f"CREATE POLICY {table}_worker_{action.lower()} "
            f"ON {table} FOR {action} TO cloudguard_worker {clause};"
        )
    # Read-only to signed-in users: both tables are written by scans alone.
    op.execute(f"GRANT SELECT ON {table} TO authenticated;")
    op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO cloudguard_worker;")


def upgrade() -> None:
    for table in RULE_ID_COLUMNS:
        op.execute(f"ALTER TABLE {table} ALTER COLUMN rule_id TYPE varchar(128);")

    op.execute(
        """
        ALTER TABLE rules
          ADD COLUMN IF NOT EXISTS engine varchar(16) NOT NULL DEFAULT 'native',
          ADD COLUMN IF NOT EXISTS engine_version varchar(32);
        """
    )

    op.execute(
        """
        CREATE TABLE assessment_captures (
          id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          organization_id    uuid NOT NULL
                               REFERENCES organizations(id) ON DELETE CASCADE,
          scan_id            uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
          -- NULL is the directory run; one scan has at most one.
          cloud_account_id   uuid REFERENCES cloud_accounts(id) ON DELETE CASCADE,
          connection_id      uuid REFERENCES cloud_connections(id) ON DELETE CASCADE,
          provider           varchar(16) NOT NULL,
          engine             varchar(16) NOT NULL DEFAULT 'prowler',
          engine_version     varchar(32) NOT NULL,
          outcome            varchar(16) NOT NULL
                               CHECK (outcome IN ('COMPLETE', 'PARTIAL', 'FAILED')),
          checks_requested   integer NOT NULL DEFAULT 0,
          checks_completed   integer NOT NULL DEFAULT 0,
          result_count       integer NOT NULL DEFAULT 0,
          errors             jsonb NOT NULL DEFAULT '{}'::jsonb,
          payload_compressed bytea,
          content_hash       varchar(64),
          byte_size          integer NOT NULL DEFAULT 0,
          stored_bytes       integer NOT NULL DEFAULT 0,
          started_at         timestamptz,
          finished_at        timestamptz,
          created_at         timestamptz NOT NULL DEFAULT now(),
          CONSTRAINT uq_assessment_captures_scan_account
            UNIQUE NULLS NOT DISTINCT (scan_id, cloud_account_id)
        );

        -- What retention reads: the newest run of each scope.
        CREATE INDEX ix_assessment_captures_scope
            ON assessment_captures (organization_id, cloud_account_id, created_at DESC);

        CREATE TABLE engine_divergences (
          id                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          organization_id      uuid NOT NULL
                                 REFERENCES organizations(id) ON DELETE CASCADE,
          scan_id              uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
          rule_id              varchar(128) NOT NULL,
          check_id             varchar(128) NOT NULL,
          resource_id          uuid REFERENCES cloud_resources(id) ON DELETE CASCADE,
          provider_resource_id text,
          native_state         varchar(16) NOT NULL,
          prowler_state        varchar(16) NOT NULL,
          kind                 varchar(24) NOT NULL,
          expected             boolean NOT NULL DEFAULT false,
          detail               text,
          created_at           timestamptz NOT NULL DEFAULT now()
        );

        CREATE INDEX ix_engine_divergences_scan
            ON engine_divergences (scan_id, rule_id);
        """
    )
    for table in NEW_TABLES:
        _policies(table)

    # ---------------------------------------------------------- the scanner
    op.execute(
        """
        DO $$
        BEGIN
          IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cloudguard_scanner') THEN
            CREATE ROLE cloudguard_scanner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
          END IF;
        END $$;
        """
    )
    op.execute("GRANT USAGE ON SCHEMA app TO cloudguard_scanner;")
    op.execute("GRANT EXECUTE ON FUNCTION app.current_org() TO cloudguard_scanner;")

    # The one read before there is an organization to be held to. One row, one
    # column; nothing else about the scan is visible through it.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION app.scan_owner(p_scan uuid) RETURNS uuid
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, public
        AS $$ SELECT organization_id FROM public.scans WHERE id = p_scan $$;
        """
    )
    op.execute("REVOKE ALL ON FUNCTION app.scan_owner(uuid) FROM PUBLIC;")
    op.execute("GRANT EXECUTE ON FUNCTION app.scan_owner(uuid) TO cloudguard_scanner;")

    # Read the scope it was handed. Column grants rather than table grants, so
    # nothing a connection or account row holds beyond what a run needs --
    # consent nonces, status prose -- is readable by third-party code.
    op.execute(
        "GRANT SELECT (id, organization_id, status, connection_id, cloud_account_id) "
        "ON scans TO cloudguard_scanner;"
    )
    op.execute(
        "GRANT SELECT (id, organization_id, provider, tenant_id, provider_ref, "
        "scope_type, scope_id) ON cloud_connections TO cloudguard_scanner;"
    )
    op.execute(
        "GRANT SELECT (id, organization_id, connection_id, provider, tenant_id, "
        "subscription_id, provider_ref, display_name, account_name) "
        "ON cloud_accounts TO cloudguard_scanner;"
    )
    # Keep its own step's lease and settle it.
    op.execute(
        "GRANT SELECT (id, organization_id, scan_id, kind, cloud_account_id, status, "
        "attempt, max_attempts, lease_until) ON scan_steps TO cloudguard_scanner;"
    )
    op.execute(
        "GRANT UPDATE (status, lease_until, worker_id, error, finished_at) "
        "ON scan_steps TO cloudguard_scanner;"
    )
    # And write its capture -- replacing its own previous attempt's, if any.
    op.execute("GRANT SELECT, INSERT, DELETE ON assessment_captures TO cloudguard_scanner;")

    for table, actions in SCANNER_ACTIONS:
        for action in actions:
            op.execute(
                f"CREATE POLICY {table}_scanner_{action.lower()} ON {table} "
                f"FOR {action} TO cloudguard_scanner {_CLAUSES[action]};"
            )


def downgrade() -> None:
    for table, actions in SCANNER_ACTIONS:
        for action in actions:
            op.execute(f"DROP POLICY IF EXISTS {table}_scanner_{action.lower()} ON {table};")
        op.execute(f"REVOKE ALL ON {table} FROM cloudguard_scanner;")
    op.execute("DROP FUNCTION IF EXISTS app.scan_owner(uuid);")
    op.execute("REVOKE ALL ON SCHEMA app FROM cloudguard_scanner;")
    op.execute("DROP TABLE IF EXISTS engine_divergences;")
    op.execute("DROP TABLE IF EXISTS assessment_captures;")
    op.execute("ALTER TABLE rules DROP COLUMN IF EXISTS engine_version;")
    op.execute("ALTER TABLE rules DROP COLUMN IF EXISTS engine;")
    # The rule ids stay 128 wide: narrowing would fail on any Prowler finding
    # already stored, and a wider column costs nothing.
