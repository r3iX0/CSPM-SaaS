"""The scanner's side of the database: its scope, its lease, its capture.

Raw SQL over psycopg rather than the API's models, because the API's models
cannot be imported here (``cloudguard_scanner/__init__.py``). What that costs is
a second statement of the step fence, so it is stated in the same terms as
``apps/api/app/services/orchestrator.py`` and checked against it by
``apps/api/tests/unit/test_prowler_engine.py``:

* a renewal, a settle and a capture write each name the attempt the step was
  claimed at, and change nothing once the row has moved on;
* the capture is written in a transaction that holds the step row ``FOR
  SHARE`` -- the reaper and the next claim both update that row, so neither can
  land between the check and the commit.

Every transaction first declares the organization it acts for
(``app.organization_id``), which is what the ``cloudguard_scanner`` policies of
migration 0042 hold it to. The one read before that is ``app.scan_owner``: a
single column of a single row, resolved by a SECURITY DEFINER function because
there is no organization yet to be held to.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

import psycopg
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row

from cloudguard_scanner.capture import RunOutcome, encode

# Must equal ScanStep.LEASE_SECONDS in apps/api/app/models/scan.py.
LEASE_SECONDS = 600
# Must equal the step kind the API claims and routes here.
ASSESS = "ASSESS"


class LeaseLost(Exception):
    """This worker no longer holds the step: it was reclaimed, or settled."""


@dataclass(frozen=True)
class Step:
    id: UUID
    scan_id: UUID
    kind: str
    cloud_account_id: UUID | None
    status: str
    attempt: int
    max_attempts: int


@dataclass(frozen=True)
class Scope:
    """What one ASSESS step runs over, and how it authenticates.

    ``reference`` is the provider-specific half of the connection row -- on AWS
    the role ARN and external id. It holds no customer secret (the API's
    ``cloud_connection.py`` says why), and the scanner treats it the same way.
    """

    provider: str
    tenant_id: str
    subscription_id: str | None
    reference: dict[str, Any]
    directory: bool
    cloud_account_id: UUID | None
    connection_id: UUID | None


_SCHEME = re.compile(r"^postgres(?:ql)?(?:\+[a-z0-9_]+)?://", re.IGNORECASE)
# The role migration 0042 creates. Supabase's pooler names it
# ``cloudguard_scanner.<project ref>``.
SCANNER_ROLE = "cloudguard_scanner"


def connection_url(url: str) -> str:
    """``SCANNER_DATABASE_URL`` as psycopg takes it, or a refusal that names no secret.

    Three mistakes are caught before the first connection, because each fails
    badly after it (DECISIONS.md section 152):

    * the API's ``postgresql+asyncpg://`` form, which psycopg rejects -- with
      an error that quotes the whole string, password included, into the log
      of every step. The driver suffix is dropped instead;
    * a password with an unencoded ``/``, ``@`` or ``:``, which libpq does not
      reject but misreads -- the user name becomes the host;
    * any role but the scanner's. Third-party code runs in this process, and
      the owner or ``cloudguard_app`` URL would hand it every table.

    No message here includes the URL or any part of it.
    """
    url = url.strip()
    if not url:
        raise RuntimeError(
            "SCANNER_DATABASE_URL is not set. The scanner connects as "
            "cloudguard_scanner (migration 0042) and has nothing else to use."
        )
    if not _SCHEME.match(url):
        raise RuntimeError("SCANNER_DATABASE_URL is not a postgresql:// URL.")
    url = _SCHEME.sub("postgresql://", url, count=1)
    try:
        parts = conninfo_to_dict(url)
    except psycopg.Error:
        raise RuntimeError(
            "SCANNER_DATABASE_URL could not be parsed. Percent-encode any /, @, : or # "
            "in the password."
        ) from None
    user = str(parts.get("user") or "")
    if user != SCANNER_ROLE and not user.startswith(SCANNER_ROLE + "."):
        raise RuntimeError(
            "SCANNER_DATABASE_URL does not sign in as cloudguard_scanner. If the password "
            "contains /, @, : or #, percent-encode it; otherwise use the scanner's role, "
            "never the owner's or the API's."
        )
    return url


def _uuid(value: Any) -> UUID | None:
    return UUID(str(value)) if value else None


class Store:
    def __init__(self, url: str) -> None:
        self.url = connection_url(url)

    @contextmanager
    def _transaction(self, organization_id: UUID | None) -> Iterator[psycopg.Cursor[Any]]:
        with (
            psycopg.connect(self.url, row_factory=dict_row) as connection,
            connection.transaction(),
            connection.cursor() as cursor,
        ):
            if organization_id is not None:
                cursor.execute(
                    "SELECT set_config('app.organization_id', %s, true)",
                    (str(organization_id),),
                )
            yield cursor

    # ------------------------------------------------------------- reading

    def owner(self, scan_id: UUID) -> UUID | None:
        with self._transaction(None) as cursor:
            cursor.execute("SELECT app.scan_owner(%s) AS organization_id", (str(scan_id),))
            row = cursor.fetchone()
        return _uuid(row["organization_id"]) if row else None

    def step(self, organization_id: UUID, step_id: UUID) -> Step | None:
        with self._transaction(organization_id) as cursor:
            cursor.execute(
                "SELECT id, scan_id, kind, cloud_account_id, status, attempt, max_attempts "
                "FROM scan_steps WHERE id = %s",
                (str(step_id),),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        return Step(
            id=UUID(str(row["id"])),
            scan_id=UUID(str(row["scan_id"])),
            kind=str(row["kind"]),
            cloud_account_id=_uuid(row["cloud_account_id"]),
            status=str(row["status"]),
            attempt=int(row["attempt"]),
            max_attempts=int(row["max_attempts"]),
        )

    def scan_status(self, organization_id: UUID, scan_id: UUID) -> str | None:
        with self._transaction(organization_id) as cursor:
            cursor.execute("SELECT status FROM scans WHERE id = %s", (str(scan_id),))
            row = cursor.fetchone()
        return str(row["status"]) if row else None

    def scope(self, organization_id: UUID, step: Step) -> Scope | None:
        """The account (or, for the directory step, the connection) to run over."""
        with self._transaction(organization_id) as cursor:
            if step.cloud_account_id is not None:
                cursor.execute(
                    "SELECT id, connection_id, provider, tenant_id, subscription_id, "
                    "provider_ref FROM cloud_accounts WHERE id = %s",
                    (str(step.cloud_account_id),),
                )
                row = cursor.fetchone()
                if row is None:
                    return None
                return Scope(
                    provider=str(row["provider"]),
                    tenant_id=str(row["tenant_id"] or ""),
                    subscription_id=str(row["subscription_id"] or "") or None,
                    reference=dict(row["provider_ref"] or {}),
                    directory=False,
                    cloud_account_id=_uuid(row["id"]),
                    connection_id=_uuid(row["connection_id"]),
                )

            # The directory step: the connection the scan was run through,
            # directly or by way of the single account it covered.
            cursor.execute(
                "SELECT connection_id, cloud_account_id FROM scans WHERE id = %s",
                (str(step.scan_id),),
            )
            scan = cursor.fetchone()
            if scan is None:
                return None
            connection_id = scan["connection_id"]
            if connection_id is None and scan["cloud_account_id"] is not None:
                cursor.execute(
                    "SELECT connection_id FROM cloud_accounts WHERE id = %s",
                    (str(scan["cloud_account_id"]),),
                )
                account = cursor.fetchone()
                connection_id = account["connection_id"] if account else None
            if connection_id is None:
                return None
            cursor.execute(
                "SELECT id, provider, tenant_id, provider_ref FROM cloud_connections "
                "WHERE id = %s",
                (str(connection_id),),
            )
            row = cursor.fetchone()
            if row is None:
                return None
            return Scope(
                provider=str(row["provider"]),
                tenant_id=str(row["tenant_id"] or ""),
                subscription_id=None,
                reference=dict(row["provider_ref"] or {}),
                directory=True,
                cloud_account_id=None,
                connection_id=_uuid(row["id"]),
            )

    # --------------------------------------------------------------- lease

    def renew(self, organization_id: UUID, step_id: UUID, attempt: int) -> bool:
        with self._transaction(organization_id) as cursor:
            cursor.execute(
                "UPDATE scan_steps SET lease_until = now() + make_interval(secs => %s) "
                "WHERE id = %s AND status = 'RUNNING' AND attempt = %s",
                (LEASE_SECONDS, str(step_id), attempt),
            )
            return cursor.rowcount == 1

    @staticmethod
    def _hold(cursor: psycopg.Cursor[Any], step_id: UUID, attempt: int) -> None:
        cursor.execute(
            "SELECT id FROM scan_steps WHERE id = %s AND status = 'RUNNING' AND attempt = %s "
            "FOR SHARE",
            (str(step_id), attempt),
        )
        if cursor.fetchone() is None:
            raise LeaseLost(f"step {step_id} is no longer attempt {attempt}'s")

    # ------------------------------------------------------------- writing

    def write_capture(
        self,
        organization_id: UUID,
        step: Step,
        scope: Scope,
        run: RunOutcome,
        *,
        engine_version: str,
        started_at: datetime,
        finished_at: datetime,
    ) -> None:
        """Replace this scope's capture for this scan, if the step is still ours.

        Demolition then insert, in one transaction, for the reason the API's
        collection gives: a retried step starts clean rather than merging with
        what a previous attempt half wrote.
        """
        encoded = encode(run.payload())
        account = str(scope.cloud_account_id) if scope.cloud_account_id else None
        with self._transaction(organization_id) as cursor:
            self._hold(cursor, step.id, step.attempt)
            cursor.execute(
                "DELETE FROM assessment_captures "
                "WHERE scan_id = %s AND cloud_account_id IS NOT DISTINCT FROM %s",
                (str(step.scan_id), account),
            )
            cursor.execute(
                """
                INSERT INTO assessment_captures (
                  organization_id, scan_id, cloud_account_id, connection_id, provider,
                  engine, engine_version, outcome, checks_requested, checks_completed,
                  result_count, errors, payload_compressed, content_hash, byte_size,
                  stored_bytes, started_at, finished_at
                ) VALUES (
                  %s, %s, %s, %s, %s, 'prowler', %s, %s, %s, %s,
                  %s, %s::jsonb, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    str(organization_id),
                    str(step.scan_id),
                    account,
                    str(scope.connection_id) if scope.connection_id else None,
                    scope.provider,
                    engine_version,
                    run.outcome,
                    len(run.requested),
                    len(run.completed),
                    len(run.results),
                    json.dumps(run.errors),
                    encoded.compressed,
                    encoded.content_hash,
                    encoded.byte_size,
                    len(encoded.compressed),
                    started_at,
                    finished_at,
                ),
            )

    def finish(
        self,
        organization_id: UUID,
        step: Step,
        status: str,
        error: str | None = None,
    ) -> bool:
        """Settle the step, fenced on its attempt. Mirrors ``orchestrator.finish``."""
        with self._transaction(organization_id) as cursor:
            cursor.execute(
                "UPDATE scan_steps SET status = %s, error = %s, finished_at = now(), "
                "lease_until = NULL "
                "WHERE id = %s AND status = 'RUNNING' AND attempt = %s",
                (status, error[:2000] if error else None, str(step.id), step.attempt),
            )
            return cursor.rowcount == 1

    def fail_or_retry(self, organization_id: UUID, step: Step, error: str) -> str | None:
        """Back to PENDING while attempts remain, FAILED after.

        Mirrors ``orchestrator.fail_or_retry``; returns what was decided, or
        None when the step was no longer this attempt's.
        """
        if step.attempt < step.max_attempts:
            with self._transaction(organization_id) as cursor:
                cursor.execute(
                    "UPDATE scan_steps SET status = 'PENDING', error = %s, "
                    "lease_until = NULL, worker_id = NULL "
                    "WHERE id = %s AND status = 'RUNNING' AND attempt = %s",
                    (error[:2000], str(step.id), step.attempt),
                )
                return "PENDING" if cursor.rowcount == 1 else None
        return "FAILED" if self.finish(organization_id, step, "FAILED", error) else None
