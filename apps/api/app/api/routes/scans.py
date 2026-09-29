from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import rls_session
from app.core.deps import DbSession, Tenant
from app.core.enums import ScanStatus
from app.core.errors import ConflictError, ScanNotFound, ValidationFailed
from app.core.logging import get_logger
from app.models.scan import Scan, ScanEvaluationGap, ScanRuleResult
from app.schemas.common import ERROR_RESPONSES, Envelope, NoMeta, error_responses
from app.schemas.scan import (
    CollectionStatusOut,
    CoverageGapOut,
    CoverageOut,
    ScanCreate,
    ScanDeletedOut,
    ScanDetailOut,
    ScanOut,
    ScanScopeOut,
    ScanStageOut,
    WorkerStatusOut,
)
from app.services import cloud_accounts as accounts_service
from app.services import scans as scans_service
from app.services.scan_events import stream_scan
from app.workers.celery_app import celery_app
from app.workers.scan_tasks import replay_scan, run_scan

log = get_logger(__name__)

router = APIRouter(prefix="/scans", tags=["scans"], responses=ERROR_RESPONSES)

WORKER_PING_FAILED = (
    "Could not reach the task broker, so no scan can be queued or collected. "
    "Check that the Redis service is running and that REDIS_URL points at it."
)


@router.post("", status_code=status.HTTP_202_ACCEPTED, responses=error_responses(403, 409))
async def create_scan(
    payload: ScanCreate, session: DbSession, tenant: Tenant
) -> Envelope[ScanOut, NoMeta]:
    tenant.require_write()
    account = await accounts_service.get_cloud_account(
        session, tenant, payload.cloud_account_id
    )

    if not account.is_scannable:
        raise ValidationFailed(
            "This connection is not ready to scan. Grant admin consent, assign the "
            "Reader role, then validate the connection."
        )

    # Taken before the check, released when this request's transaction ends.
    # Without it two clicks a millisecond apart both read "nothing running" and
    # both queue a scan over the same subscriptions.
    await scans_service.lock_scan_target(
        session, tenant.organization_id, account.connection_id, account.id
    )
    if await scans_service.scan_in_flight(
        session, tenant.organization_id, account.connection_id, account.id
    ):
        raise ConflictError("A scan is already running for this connection")

    scan = Scan(
        organization_id=tenant.organization_id,
        # Scoped to the whole connection when there is one: its subscriptions
        # are resolved in the worker, so one discovered between queueing and
        # running is still picked up. Falls back to the single subscription for
        # an account that predates connections.
        connection_id=account.connection_id,
        cloud_account_id=None if account.connection_id else account.id,
        status=ScanStatus.QUEUED,
        # Recorded from the authenticated user, never from the request body.
        triggered_by_user_id=tenant.user.id,
    )
    session.add(scan)
    await session.commit()

    # Only the id crosses the queue. The worker re-reads the tenant boundary
    # from the scan row rather than trusting the message.
    await scans_service.enqueue_or_fail(run_scan.delay, scan, tenant.user.id)

    return Envelope(data=ScanOut.model_validate(scan), meta=NoMeta())


@router.post(
    "/{scan_id}/replay",
    status_code=status.HTTP_202_ACCEPTED,
    responses=error_responses(403, 409),
)
async def replay_scan_endpoint(
    scan_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[ScanOut, NoMeta]:
    """Re-evaluate a finished scan's stored snapshot against today's rules.

    Costs nothing in the customer's cloud: no Azure call, no consent, no
    throttle budget. Every scan already stored the provider's own JSON before
    interpreting it, so a rule shipped after that scan ran can still be applied
    to it.

    Whether the result may change anything is decided in the pipeline, not
    here, and it turns on one question: is that snapshot still the newest one
    for the account? If it is, the replay behaves as a scan that skipped
    collection. If it is not, it reports what the rules would have found and
    writes no findings -- a capture from last month is evidence about last
    month, and resolving a finding on the strength of it would put "verified
    fixed" against something nobody looked at.
    """
    tenant.require_write()
    source = await scans_service.get_scan(session, tenant, scan_id)

    # Replaying a replay resolves to the capture underneath it. Only a scan
    # that collected owns a snapshot, so pointing at a replay would queue a run
    # guaranteed to fail with "no stored snapshot" -- which reads as data loss
    # rather than as the harmless thing it is. One hop always reaches a
    # collecting scan, because this is the only code that sets the column and
    # it never sets it to another replay.
    if source.replay_of_scan_id is not None:
        origin = await scans_service.get_scan(
            session, tenant, source.replay_of_scan_id
        )
        source = origin

    if not source.status.is_terminal:
        raise ConflictError(
            "That scan has not finished yet. Wait for it to complete before "
            "replaying its snapshot."
        )

    await scans_service.lock_scan_target(
        session, tenant.organization_id, source.connection_id, source.cloud_account_id
    )
    if await scans_service.scan_in_flight(
        session, tenant.organization_id, source.connection_id, source.cloud_account_id
    ):
        raise ConflictError("A scan is already running for this connection")

    scan = Scan(
        organization_id=tenant.organization_id,
        connection_id=source.connection_id,
        cloud_account_id=source.cloud_account_id,
        status=ScanStatus.QUEUED,
        triggered_by_user_id=tenant.user.id,
        replay_of_scan_id=source.id,
    )
    session.add(scan)
    await session.commit()

    await scans_service.enqueue_or_fail(
        replay_scan.delay, scan, tenant.user.id, noun="replay"
    )

    return Envelope(data=ScanOut.model_validate(scan), meta=NoMeta())


@router.post("/{scan_id}/cancel", responses=error_responses(403, 409))
async def cancel_scan(
    scan_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[ScanOut, NoMeta]:
    """Stop a scan that has not finished.

    Cancelling a queued scan is the common case and the reason this exists: a
    scan sits queued until a worker collects it, and if none is running it sits
    there indefinitely. The pipeline re-reads the status before it starts, so a
    task collected after cancellation stops rather than writing findings nobody
    asked for.
    """
    tenant.require_write()
    scan = (
        await session.execute(
            select(Scan).where(
                Scan.id == scan_id,
                Scan.organization_id == tenant.organization_id,
            )
        )
    ).scalar_one_or_none()
    if scan is None:
        raise ScanNotFound()

    if scan.status.is_terminal:
        raise ConflictError(f"This scan has already finished ({scan.status.value}).")

    scan.status = ScanStatus.CANCELLED
    scan.completed_at = datetime.now(UTC)
    scan.error_message = "Cancelled."
    await session.commit()
    return Envelope(data=ScanOut.model_validate(scan), meta=NoMeta())


@router.get("")
async def list_scans(
    session: DbSession, tenant: Tenant, limit: int = Query(default=25, ge=1, le=100)
) -> Envelope[list[ScanOut], NoMeta]:
    rows = (
        (
            await session.execute(
                select(Scan)
                .where(Scan.organization_id == tenant.organization_id)
                .order_by(Scan.created_at.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return Envelope(data=[ScanOut.model_validate(s) for s in rows], meta=NoMeta())


# Declared before the parameterised routes below: FastAPI matches in order,
# so `/{scan_id}` would otherwise swallow this and answer it with a 422 for
# an id that is not a UUID.

@router.get("/worker-status")
async def worker_status(tenant: Tenant) -> Envelope[WorkerStatusOut, NoMeta]:
    """Whether any Celery worker is actually listening.

    The scans page infers trouble from elapsed time, which is a guess: a scan
    queued for five minutes *probably* means no worker. This asks the broker
    instead and turns that into a fact, which matters because the failure looks
    like success from every other angle -- the worker service reports Online,
    passes health checks, and is simply running the wrong process.

    Called only when a scan already looks stuck. A broker round trip on every
    poll would be a cost paid by every healthy deployment to diagnose a rare
    broken one.
    """
    try:
        replies = celery_app.control.ping(timeout=1.0) or []
    except Exception as exc:
        # The exception goes to the log, not the response: it is written for
        # an operator and can carry the broker's address or credentials, and
        # any member may ask this (DECISIONS.md section 158).
        log.warning("scan.worker_ping_failed", error=str(exc))
        return Envelope(
            data=WorkerStatusOut(
                workers=0,
                reachable=False,
                detail=WORKER_PING_FAILED,
            ),
            meta=NoMeta(),
        )

    if not replies:
        return Envelope(
            data=WorkerStatusOut(
                workers=0,
                reachable=True,
                detail=(
                    "The task broker is reachable but no worker answered. The "
                    "Celery worker service is not running -- check that its "
                    "start command runs celery rather than the API."
                ),
            ),
            meta=NoMeta(),
        )

    return Envelope(
        data=WorkerStatusOut(
            workers=len(replies),
            reachable=True,
            detail=f"{len(replies)} worker(s) responding.",
        ),
        meta=NoMeta(),
    )


async def _detail_payload(session: AsyncSession, scan: Scan) -> ScanDetailOut:
    """What the detail endpoint returns, and what the event stream pushes.

    One builder for both, so a state delivered over the stream and one fetched
    by a poll are the same document -- the browser writes either into the same
    query and cannot tell them apart.
    """
    data = ScanDetailOut.model_validate(scan)
    data.scope = ScanScopeOut.model_validate(await scans_service.scan_context(session, scan))
    data.stages = [
        ScanStageOut.model_validate(stage)
        for stage in await scans_service.scan_stages(session, scan)
    ]
    data.findings_by_severity = await scans_service.severity_breakdown(session, scan)
    data.purgeable_finding_count = await scans_service.findings_attributable_to(
        session, scan
    )
    return data


@router.get("/{scan_id}/detail")
async def get_scan_detail(
    scan_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[ScanDetailOut, NoMeta]:
    """One scan, with its scope, identity, stages and severity breakdown."""
    scan = await scans_service.get_scan(session, tenant, scan_id)
    return Envelope(data=await _detail_payload(session, scan), meta=NoMeta())


@router.get(
    "/{scan_id}/events",
    response_class=StreamingResponse,
    responses={
        200: {
            "description": (
                "Server-sent events: ``scan`` carries the same document as "
                "``/detail`` whenever it changes; ``end``, ``gone`` and "
                "``timeout`` close the stream."
            ),
            "content": {"text/event-stream": {}},
        }
    },
)
async def scan_events(
    scan_id: UUID, request: Request, session: DbSession, tenant: Tenant
) -> StreamingResponse:
    """A running scan's detail, pushed as server-sent events whenever it changes.

    The scan is resolved once up front, on the request's session, so a scan
    this reader cannot see is a 404 before any stream opens. Every tick after
    that reads through a fresh ``rls_session`` for the same user: the request
    session is not held open for the life of a stream, and PostgreSQL applies
    the tenant boundary to each read exactly as it does to a poll.
    """
    await scans_service.get_scan(session, tenant, scan_id)
    user_id = tenant.user.id

    async def load() -> dict | None:
        async with rls_session(user_id) as tick:
            try:
                scan = await scans_service.get_scan(tick, tenant, scan_id)
            except ScanNotFound:
                return None
            return (await _detail_payload(tick, scan)).model_dump(mode="json")

    return StreamingResponse(
        stream_scan(load, is_disconnected=request.is_disconnected),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            # Proxies that buffer responses would hold every event until the
            # stream ended, which is the one thing a stream must not do.
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/{scan_id}")
async def get_scan(scan_id: UUID, session: DbSession, tenant: Tenant) -> Envelope[ScanOut, NoMeta]:
    scan = (
        await session.execute(
            select(Scan).where(
                Scan.id == scan_id, Scan.organization_id == tenant.organization_id
            )
        )
    ).scalar_one_or_none()
    if scan is None:
        raise ScanNotFound()
    return Envelope(data=ScanOut.model_validate(scan), meta=NoMeta())


@router.delete("/{scan_id}", status_code=status.HTTP_200_OK, responses=error_responses(403))
async def delete_scan(
    scan_id: UUID,
    session: DbSession,
    tenant: Tenant,
    purge_findings: bool = False,
) -> Envelope[ScanDeletedOut, NoMeta]:
    """Delete a scan record, and optionally the findings it last detected.

    ``purge_findings`` defaults to false because the two are different acts:
    deleting the record prunes an execution log, while purging also discards
    what was found. Resolved findings are never purged either way -- each one
    is the evidence that a fix was verified.
    """
    tenant.require_write()
    result = await scans_service.delete_scan(
        session, tenant, scan_id, purge_findings=purge_findings
    )
    return Envelope(data=ScanDeletedOut.model_validate(result), meta=NoMeta())


@router.get("/{scan_id}/collection")
async def scan_collection(
    scan_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[CollectionStatusOut, NoMeta]:
    """What this scan could and could not read, per subscription and per task.

    Separate from ``/coverage``, which reports what the rules concluded. The
    two were one flat map of category to a sentence, which could say a category
    was unreliable but not whether it had failed outright or merely come back
    truncated -- an outage and a very large tenant, reported identically.
    """
    scan = await scans_service.get_scan(session, tenant, scan_id)
    status = await scans_service.collection_status(session, scan)
    return Envelope(data=CollectionStatusOut.model_validate(status), meta=NoMeta())


@router.get("/{scan_id}/coverage")
async def scan_coverage(
    scan_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[CoverageOut, NoMeta]:
    """What this scan could and could not determine.

    Reported apart from the security score: a user asking "why is my score 84?"
    should not have to understand coverage maths to get an answer, and a user
    asking "what did you miss?" deserves a straight one.
    """
    totals = (
        await session.execute(
            select(
                func.coalesce(func.sum(ScanRuleResult.passed_count), 0),
                func.coalesce(func.sum(ScanRuleResult.failed_count), 0),
                func.coalesce(func.sum(ScanRuleResult.unknown_count), 0),
                func.coalesce(func.sum(ScanRuleResult.evaluated_count), 0),
            ).where(
                ScanRuleResult.scan_id == scan_id,
                ScanRuleResult.organization_id == tenant.organization_id,
            )
        )
    ).one()
    passed, failed, unknown, evaluated = (int(v) for v in totals)

    gaps = (
        (
            await session.execute(
                select(ScanEvaluationGap)
                .where(
                    ScanEvaluationGap.scan_id == scan_id,
                    ScanEvaluationGap.organization_id == tenant.organization_id,
                )
                .limit(200)
            )
        )
        .scalars()
        .all()
    )

    conclusive = passed + failed
    denominator = conclusive + unknown
    return Envelope(
        data=CoverageOut(
            coverage_ratio=round(conclusive / denominator, 4) if denominator else 1.0,
            evaluated=evaluated,
            conclusive=conclusive,
            unknown=unknown,
            gaps=[
                CoverageGapOut(rule_id=g.rule_id, resource_id=g.resource_id, reason=g.reason)
                for g in gaps
            ],
        ),
        meta=NoMeta(),
    )
