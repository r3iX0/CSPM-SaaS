from uuid import UUID

from fastapi import APIRouter, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.links import accepted
from app.core.db import rls_session
from app.core.deps import Costly, DbSession, Tenant
from app.core.errors import ScanNotFound
from app.core.logging import get_logger
from app.models.scan import Scan
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


@router.post(
    "",
    status_code=status.HTTP_202_ACCEPTED,
    responses=error_responses(403, 409),
    dependencies=[Costly],
)
async def create_scan(
    payload: ScanCreate, request: Request, response: Response, session: DbSession, tenant: Tenant
) -> Envelope[ScanOut, NoMeta]:
    """Queue a scan of an account's connection. One scan at a time per connection."""
    tenant.require_write()
    scan = await scans_service.queue_scan(session, tenant, payload.cloud_account_id)
    await session.commit()

    # Only the id crosses the queue. The worker re-reads the tenant boundary
    # from the scan row rather than trusting the message.
    await scans_service.enqueue_or_fail(run_scan.delay, scan, tenant.user.id)

    accepted(request, response, "get_scan_detail", scan_id=scan.id)
    return Envelope(data=ScanOut.model_validate(scan), meta=NoMeta())


@router.post(
    "/{scan_id}/replay",
    status_code=status.HTTP_202_ACCEPTED,
    responses=error_responses(403, 409),
    dependencies=[Costly],
)
async def replay_scan_endpoint(
    scan_id: UUID, request: Request, response: Response, session: DbSession, tenant: Tenant
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
    scan = await scans_service.queue_replay(session, tenant, scan_id)
    await session.commit()

    await scans_service.enqueue_or_fail(replay_scan.delay, scan, tenant.user.id, noun="replay")

    accepted(request, response, "get_scan_detail", scan_id=scan.id)
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
    scan = await scans_service.cancel_scan(session, tenant, scan_id)
    await session.commit()
    return Envelope(data=ScanOut.model_validate(scan), meta=NoMeta())


@router.get("")
async def list_scans(
    session: DbSession, tenant: Tenant, limit: int = Query(default=25, ge=1, le=100)
) -> Envelope[list[ScanOut], NoMeta]:
    """The most recent scans, newest first."""
    rows = await scans_service.list_scans(session, tenant, limit=limit)
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
    data.purgeable_finding_count = await scans_service.findings_attributable_to(session, scan)
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
    """One scan's record: what it covered, how it ended and how many findings it raised."""
    scan = await scans_service.get_scan(session, tenant, scan_id)
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
    passed, failed, unknown, evaluated = await scans_service.coverage_totals(
        session, tenant, scan_id
    )
    gaps = await scans_service.evaluation_gaps(session, tenant, scan_id)

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
