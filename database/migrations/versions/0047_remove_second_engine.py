"""The second engine is gone: its tables, its role, and whatever it left behind.

Revision ID: 0047
Revises: 0046

Prowler no longer runs beside the native rules (DECISIONS.md section 168), so
everything migrations 0042 and 0043 added for it is taken back out.

**What it wrote.** A Prowler check's rule id is ``PRW-<cloud>-<check>``. Any
finding raised under one is deleted, with the risks it leaves with no member --
deleted rather than resolved, for the reason section 124 gives: nothing was
fixed, the check simply stopped existing. Rule results, evaluation gaps and
verifications under those ids go too, and so do the mirrored ``rules`` rows,
which the startup sync would otherwise keep listing as disabled for ever.
ASSESS steps are deleted; a scan does not wait on a step kind nothing runs.

**The two tables** -- ``assessment_captures`` and ``engine_divergences`` -- are
dropped, and so are the ``rules.engine`` columns, which only ever said "native"
or "prowler".

**The role.** ``cloudguard_scanner`` loses every grant and policy 0042 and 0043
gave it, and ``app.scan_owner``, which existed only for it. The role itself is
dropped where this connection may; where it may not -- an operator granted it
something this migration cannot revoke, such as CONNECT from ``roles.sql``
under another owner -- it is left without login and without a privilege this
migration knows of, and the operator drops it by hand. A migration that failed
there would hold the API's start command back over a role nothing uses.

Rule id columns stay 128 wide: narrowing a varchar is a table rewrite, and the
width costs nothing.

The downgrade recreates the empty schema 0043 left, and the role NOLOGIN with
no grants so the earlier downgrades still run -- not the data: findings a
removed engine raised are not restored by a downgrade of the code that raised
them.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0047"
down_revision: str | None = "0046"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

PROWLER_RULES = "rule_id LIKE 'PRW-%'"

# Every policy 0042 and 0043 created for the scanner, by table and action.
SCANNER_POLICIES = (
    ("scans", ("select",)),
    ("cloud_connections", ("select",)),
    ("cloud_accounts", ("select",)),
    ("scan_steps", ("select", "update")),
)

_TENANT = {
    "SELECT": "USING (app.is_member(organization_id))",
    "INSERT": "WITH CHECK (app.is_member(organization_id))",
    "UPDATE": "USING (app.is_member(organization_id)) "
    "WITH CHECK (app.is_member(organization_id))",
    "DELETE": "USING (app.is_member(organization_id))",
}
_WORKER = {
    "SELECT": "USING (app.current_org() = organization_id)",
    "INSERT": "WITH CHECK (app.current_org() = organization_id)",
    "UPDATE": "USING (app.current_org() = organization_id) "
    "WITH CHECK (app.current_org() = organization_id)",
    "DELETE": "USING (app.current_org() = organization_id)",
}


def upgrade() -> None:
    # --------------------------------------------------------- what it wrote
    # The risks to look at afterwards, taken before the findings go: the
    # cascade removes the links that would have named them.
    op.execute(
        f"""
        CREATE TEMPORARY TABLE _prowler_risks ON COMMIT DROP AS
        SELECT DISTINCT rf.risk_id
          FROM risk_findings rf
          JOIN findings f ON f.id = rf.finding_id
         WHERE f.{PROWLER_RULES};
        """
    )
    op.execute(f"DELETE FROM findings WHERE {PROWLER_RULES};")
    op.execute(
        """
        DELETE FROM risks r
         USING _prowler_risks p
         WHERE r.id = p.risk_id
           AND NOT EXISTS (SELECT 1 FROM risk_findings rf WHERE rf.risk_id = r.id);
        """
    )
    for table in ("scan_rule_results", "scan_evaluation_gaps", "remediation_verifications"):
        op.execute(f"DELETE FROM {table} WHERE {PROWLER_RULES};")
    op.execute(f"DELETE FROM rules WHERE {PROWLER_RULES};")
    op.execute("DELETE FROM scan_steps WHERE kind = 'ASSESS';")

    # ------------------------------------------------------------ the tables
    op.execute("DROP TABLE IF EXISTS engine_divergences;")
    op.execute("DROP TABLE IF EXISTS assessment_captures;")
    op.execute("ALTER TABLE rules DROP COLUMN IF EXISTS engine_version;")
    op.execute("ALTER TABLE rules DROP COLUMN IF EXISTS engine;")

    # -------------------------------------------------------------- the role
    for table, actions in SCANNER_POLICIES:
        for action in actions:
            op.execute(f"DROP POLICY IF EXISTS {table}_scanner_{action} ON {table};")
    op.execute("DROP FUNCTION IF EXISTS app.scan_owner(uuid);")
    op.execute(
        """
        DO $$
        BEGIN
          IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cloudguard_scanner') THEN
            RETURN;
          END IF;
          -- Revoking a table's privileges revokes its column privileges too.
          REVOKE ALL ON scans, cloud_connections, cloud_accounts, scan_steps
            FROM cloudguard_scanner;
          REVOKE ALL ON FUNCTION app.current_org() FROM cloudguard_scanner;
          REVOKE ALL ON SCHEMA app FROM cloudguard_scanner;
          EXECUTE format(
            'REVOKE ALL ON DATABASE %I FROM cloudguard_scanner', current_database()
          );
          BEGIN
            DROP ROLE cloudguard_scanner;
          EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'cloudguard_scanner kept (%); drop it by hand', SQLERRM;
            BEGIN
              ALTER ROLE cloudguard_scanner NOLOGIN;
            EXCEPTION WHEN OTHERS THEN
              RAISE NOTICE 'cloudguard_scanner could not be set NOLOGIN (%)', SQLERRM;
            END;
          END;
        END $$;
        """
    )


def downgrade() -> None:
    # Without grants: only so 0043's and 0042's downgrades, which name it, run.
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
    op.execute(
        """
        ALTER TABLE rules
          ADD COLUMN IF NOT EXISTS engine varchar(16) NOT NULL DEFAULT 'native',
          ADD COLUMN IF NOT EXISTS engine_version varchar(32);

        CREATE TABLE IF NOT EXISTS assessment_captures (
          id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
          organization_id    uuid NOT NULL
                               REFERENCES organizations(id) ON DELETE CASCADE,
          scan_id            uuid NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
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
        CREATE INDEX IF NOT EXISTS ix_assessment_captures_scope
            ON assessment_captures (organization_id, cloud_account_id, created_at DESC);

        CREATE TABLE IF NOT EXISTS engine_divergences (
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
        CREATE INDEX IF NOT EXISTS ix_engine_divergences_scan
            ON engine_divergences (scan_id, rule_id);
        """
    )
    for table in ("assessment_captures", "engine_divergences"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        for action in ("SELECT", "INSERT", "UPDATE", "DELETE"):
            op.execute(
                f"CREATE POLICY {table}_tenant_{action.lower()} "
                f"ON {table} FOR {action} {_TENANT[action]};"
            )
            op.execute(
                f"CREATE POLICY {table}_worker_{action.lower()} "
                f"ON {table} FOR {action} TO cloudguard_worker {_WORKER[action]};"
            )
        op.execute(f"GRANT SELECT ON {table} TO authenticated;")
        op.execute(f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO cloudguard_worker;")
