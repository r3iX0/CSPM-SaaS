"""The ASSESS step, from claimed message to settled row.

The same shape as the API's ``ScanPipeline.run_step``: find the step, check it
is still this attempt's, do the work under a lease, write the result fenced on
the attempt, settle. What differs is only who does the work -- Prowler -- and
that the fence and the settle are the SQL in ``store.py`` rather than the
orchestrator, which this process cannot import.

Every outcome is decided here, not in Celery. The task never retries the
message: a retry is a step returned to PENDING with its attempt raised, which
the API's next advance hands to whichever scanner is free.
"""

from __future__ import annotations

import importlib.metadata
import logging
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from cloudguard_scanner.capture import RunOutcome
from cloudguard_scanner.catalog import ScannerCatalog, load
from cloudguard_scanner.celery_app import ADVANCE_TASK, ASSESS_TASK, DEFAULT_QUEUE, celery_app
from cloudguard_scanner.config import Settings, settings
from cloudguard_scanner.heartbeat import Heartbeat
from cloudguard_scanner.runner import ScopeNotRunnable, run
from cloudguard_scanner.store import ASSESS, LeaseLost, Store

log = logging.getLogger("cloudguard_scanner")


class ReusedProcess(RuntimeError):
    """This process has already run Prowler, and must not run it again."""


def refuse_reused_process() -> None:
    """Stop before a second step runs in a process that ran a first.

    Prowler's service clients are module globals built from the provider that
    was current when their module was first imported. In a reused process
    they are the previous tenant's. ``worker_max_tasks_per_child=1`` is what
    prevents that; this is what notices if it ever stops doing so -- a
    changed start command, a thread pool -- and refuses rather than scanning
    one customer with another's clients.
    """
    loaded = [
        name
        for name in sys.modules
        if name.startswith("prowler.providers.") and name.endswith("_client")
    ]
    if loaded:
        raise ReusedProcess(
            "Prowler service clients are already loaded in this process "
            f"({len(loaded)} modules). The scanner must run one step per child "
            "process (worker_max_tasks_per_child=1)."
        )


def installed_prowler() -> str:
    return importlib.metadata.version("prowler")


def execute(
    scan_id: UUID,
    step_id: UUID,
    *,
    store: Store,
    catalog: ScannerCatalog,
    config: Settings,
    prowler_version: str,
    attempt: int | None = None,
    runner: Callable[..., RunOutcome] = run,
    heartbeat: Callable[..., Any] = Heartbeat,
) -> str:
    """Run one ASSESS step and settle it. Returns what happened, for the log.

    Collaborators are parameters so the whole decision table below is tested
    without a database, a broker or a cloud (``tests/test_tasks.py``).
    """
    organization_id = store.owner(scan_id)
    if organization_id is None:
        return "VANISHED"
    step = store.step(organization_id, step_id)
    if step is None or step.kind != ASSESS or step.status != "RUNNING":
        # Settled, reclaimed or never ours: whoever holds it now decides.
        return "NOT_OURS"
    if attempt is not None and attempt != step.attempt:
        # A copy of the message for an attempt the reaper has given up on.
        # The step now belongs to a later attempt, whose own message is on
        # the queue; running this one too would put two Prowler runs on one
        # attempt, both passing its fence (DECISIONS.md section 151).
        return "NOT_OURS"

    if prowler_version != catalog.prowler_version:
        store.finish(
            organization_id,
            step,
            "FAILED",
            f"The scanner runs Prowler {prowler_version} but the catalogue was built "
            f"from {catalog.prowler_version}. Rebuild the image from one commit.",
        )
        return "FAILED"

    if store.scan_status(organization_id, scan_id) == "CANCELLED":
        store.finish(organization_id, step, "SKIPPED", "the scan was cancelled")
        return "SKIPPED"

    scope = store.scope(organization_id, step)
    if scope is None:
        store.finish(
            organization_id,
            step,
            "FAILED",
            "The scope this step was created for is no longer connected to Cleave.",
        )
        return "FAILED"

    checks = catalog.checks_for(scope.provider, directory=scope.directory)
    started = datetime.now(UTC)
    refused = False
    try:
        with heartbeat(store, organization_id, step.id, step.attempt) as beat:
            try:
                outcome = runner(
                    scope,
                    checks,
                    config,
                    keep_going=beat.alive,
                    deadline=started.timestamp() + config.run_budget,
                )
            except ScopeNotRunnable as refusal:
                # Recorded, so ANALYZE can say why every check here is
                # unknown -- then settled without a retry, because the
                # configuration will be the same on the next attempt.
                refused = True
                outcome = RunOutcome(requested=checks, errors={"fatal": str(refusal)})
            if not beat.alive():
                raise LeaseLost("the lease was lost before the capture was written")
            store.write_capture(
                organization_id,
                step,
                scope,
                outcome,
                engine_version=prowler_version,
                started_at=started,
                finished_at=datetime.now(UTC),
            )
    except LeaseLost:
        log.warning("scanner.step_lost step_id=%s attempt=%s", step.id, step.attempt)
        return "LOST"
    except Exception as error:
        log.exception("scanner.step_failed step_id=%s", step.id)
        decided = store.fail_or_retry(organization_id, step, f"{type(error).__name__}: {error}")
        return decided or "LOST"

    fatal = outcome.errors.get("fatal")
    if refused:
        store.finish(organization_id, step, "FAILED", str(fatal))
        return "FAILED"
    if fatal:
        # The provider would not initialise: credentials refused, a token
        # endpoint timing out. Possibly transient, so retried like any other
        # failed step; the capture written above says why in the meantime.
        return store.fail_or_retry(organization_id, step, str(fatal)) or "LOST"

    store.finish(organization_id, step, "SUCCEEDED")
    return "SUCCEEDED"


@celery_app.task(
    name=ASSESS_TASK,
    bind=True,
    max_retries=0,
    soft_time_limit=settings.soft_time_limit,
    time_limit=settings.time_limit,
)
def run_assess_step(
    self: object, scan_id: str, step_id: str, attempt: int | None = None
) -> dict[str, str]:
    refuse_reused_process()
    outcome = execute(
        UUID(scan_id),
        UUID(step_id),
        store=Store(settings.database_url),
        catalog=load(settings.catalog_path),
        config=settings,
        prowler_version=installed_prowler(),
        # None only for a message queued before the API sent attempts.
        attempt=attempt,
    )
    log.info("scanner.step_finished scan_id=%s step_id=%s outcome=%s", scan_id, step_id, outcome)
    # Always, whatever happened: a settled step may have unblocked ANALYZE, and
    # a step returned to PENDING needs an advance to be claimed again.
    celery_app.send_task(ADVANCE_TASK, args=[scan_id], queue=DEFAULT_QUEUE)
    return {"scan_id": scan_id, "step_id": step_id, "outcome": outcome}
