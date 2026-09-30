"""Everything downstream of the snapshots, in the order it has to happen.

    normalize -> persist assets -> evaluate -> coverage
              -> findings and risks -> verify fixes -> correlate routes
              -> record posture

This module is the order and nothing else. Each stage is a module of its own
(``assets``, ``coverage``, ``findings``, ``remediations``, ``correlation``,
``posture``) taking the same :class:`AnalyzeContext`, and every commit goes
through the context's :class:`ScanWriter` -- so a stage's rows are written in
bulk and only while the step is still this attempt's.
"""

from datetime import UTC, datetime, timedelta

from app.connectors.base import NormalizedState
from app.core.enums import AnalyzePhase, ScanStatus
from app.core.logging import get_logger
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection
from app.models.scan import Scan
from app.rules.base import RuleContext
from app.rules.engine import RuleEngine
from app.services.scan.assets import existing_resource_ids, group_edges, persist_resources
from app.services.scan.context import AnalyzeContext
from app.services.scan.correlation import correlate_paths
from app.services.scan.coverage import persist_coverage
from app.services.scan.findings import persist_findings, would_be_open_count
from app.services.scan.lease import PhaseReport, _no_phase
from app.services.scan.posture import record_posture
from app.services.scan.remediations import verify_remediations
from app.services.scan.writer import ScanWriter

log = get_logger(__name__)


async def evaluate(
    writer: ScanWriter,
    scan: Scan,
    engine: RuleEngine,
    account_state: list[tuple[CloudAccount, NormalizedState]],
    merged: NormalizedState,
    *,
    observed_at: datetime,
    mutate_findings: bool,
    degraded: bool,
    directory: tuple[CloudConnection, NormalizedState] | None = None,
    finalize: bool = True,
    on_phase: PhaseReport = _no_phase,
) -> None:
    """Everything downstream of the snapshots: persist, evaluate, finalize.

    Shared verbatim by a fresh scan and a replay, and the sharing is the
    point. If the two paths diverged, a replay would stop being evidence
    about the pipeline a real scan runs.

    Assets are persisted per subscription, because a resource belongs to
    one; rules are evaluated once over all of them, because a tenant is
    what the customer actually has.
    """
    # What this run is entitled to touch. Every query below that reaches
    # for existing rows is scoped by it, so the cost of a scan tracks what
    # it read rather than how large the customer has grown.
    account_ids = [account.id for account, _ in account_state]
    connection_id = directory[0].id if directory is not None else None
    # Which subscription each asset came from, taken before the merge --
    # after it, a tenant-wide scan's resources are one list and the
    # subscription that produced each is no longer recoverable from them.
    # A finding cites the readings of *its* asset's subscription, so this is
    # what keeps subscription B's storage listing from being offered as the
    # provenance of a finding in subscription A.
    account_of = {
        resource.provider_resource_id: account.id
        for account, state in account_state
        for resource in state.resources
    }
    ctx = AnalyzeContext(
        writer=writer,
        scan=scan,
        observed_at=observed_at,
        account_ids=account_ids,
        connection_id=connection_id,
        account_of=account_of,
    )

    # --- normalize ------------------------------------------------------
    await on_phase(AnalyzePhase.NORMALIZE)
    await set_status(writer, scan, ScanStatus.NORMALIZING)
    if mutate_findings:
        id_map = await persist_resources(ctx, account_state, directory=directory)
    else:
        # A superseded capture describes an environment that has since
        # moved on. Upserting from it would overwrite live criticality,
        # exposure and metadata with historical values -- the columns the
        # risk scorer reads -- and re-create resources deleted since.
        # ``evaluation_only`` means the run changes nothing, and the asset
        # inventory is part of "nothing".
        id_map = await existing_resource_ids(ctx)
    scan.resource_count = len(merged.resources)

    # Now the size of the job is known, so progress can be a count
    # rather than a phase name. Committed here so a long evaluation
    # shows a denominator immediately rather than at the end.
    scan.progress_total = len(merged.resources)
    scan.progress_done = len(merged.resources)
    await writer.commit()

    # --- evaluate -------------------------------------------------------
    await on_phase(AnalyzePhase.EVALUATE)
    await set_status(writer, scan, ScanStatus.EVALUATING)
    context = RuleContext(
        resources=merged.resources,
        relationships=group_edges(merged),
        collection_errors=merged.collection_errors,
        controls=merged.controls,
    )
    report = engine.evaluate(context)
    scan.rule_count = report.rules_run

    await persist_coverage(ctx, report, id_map)

    # --- findings and risks ---------------------------------------------
    await on_phase(AnalyzePhase.SCORE)
    await set_status(writer, scan, ScanStatus.CALCULATING_RISK)
    if mutate_findings:
        finding_count = await persist_findings(ctx, report, id_map)
        await verify_remediations(ctx, report, id_map)
        # After the findings exist, because a scenario is built out of
        # them: the worst member is the floor a route is scored from, and
        # a route assembled before its members would have nothing to stand
        # on.
        await correlate_paths(ctx, merged, id_map)
        # Last, because it is a reading of everything above it: the
        # findings this scan wrote, the risks they were scored into, and
        # the routes correlation found between them.
        await record_posture(ctx)
    else:
        # What today's rules would have raised against that capture,
        # reported as a number without being written down as fact --
        # counted the same way a real scan counts, so the two are
        # comparable in the column that shows them side by side.
        finding_count = await would_be_open_count(ctx, report, id_map)

    scan.finding_count = finding_count
    if finalize:
        # Replay owns its own ending: it is one task rather than a set of
        # steps, so nothing else is going to write this. A step-driven scan
        # passes False and the orchestrator derives the same fields from the
        # steps -- two writers for one fact is how a scan ends up COMPLETED
        # with a step still running.
        scan.completed_at = datetime.now(UTC)
        scan.status = ScanStatus.PARTIAL if degraded else ScanStatus.COMPLETED
        scan.lease_until = None
    await writer.commit()

    log.info(
        "scan.evaluated",
        scan_id=str(scan.id),
        # Not the scan's status. A step-driven scan is still running when
        # this line is written -- the orchestrator settles it afterwards --
        # so reporting ``scan.status`` here printed CALCULATING_RISK beside
        # the word "completed" and invited exactly the wrong conclusion.
        finalized=finalize,
        subscriptions=len(account_state),
        resources=scan.resource_count,
        findings=finding_count,
        coverage=round(report.coverage_ratio, 3),
        evaluation_only=scan.evaluation_only,
    )


async def set_status(writer: ScanWriter, scan: Scan, status: ScanStatus) -> None:
    scan.status = status
    # Every phase change is a sign of life, and the phases bracket the two
    # stretches that report nothing while they run: rule evaluation and
    # finding reconciliation. Extending here means the lease covers them
    # without a heartbeat task of its own.
    scan.lease_until = datetime.now(UTC) + timedelta(seconds=Scan.LEASE_SECONDS)
    await writer.commit()
