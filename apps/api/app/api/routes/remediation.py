from uuid import UUID

from fastapi import APIRouter, Query, Request, Response, status

from app.api.links import accepted, created
from app.core.deps import DbSession, Tenant
from app.core.enums import RemediationStatus
from app.schemas.code_integration import (
    FixPullRequestFindingOut,
    FixPullRequestIn,
    FixPullRequestOut,
    FixPullRequestsQueuedOut,
)
from app.schemas.common import ERROR_RESPONSES, Envelope, NoMeta, error_responses
from app.schemas.finding import (
    FixedFindingOut,
    FixProgressOut,
    RemediationCreate,
    RemediationOut,
    RemediationUpdate,
    RemediationUpdatedOut,
    SeverityProgressOut,
)
from app.services import pull_requests as pull_request_service
from app.services import remediation as service
from app.services.deadlines import Deadline

router = APIRouter(prefix="/remediation", tags=["remediation"], responses=ERROR_RESPONSES)


@router.post("", status_code=status.HTTP_201_CREATED, responses=error_responses(403))
async def create_task(
    payload: RemediationCreate,
    request: Request,
    response: Response,
    session: DbSession,
    tenant: Tenant,
) -> Envelope[RemediationOut, NoMeta]:
    """Open a remediation task for a finding. A finding has at most one open task."""
    tenant.require_write()
    task = await service.create_task(session, tenant, payload)
    due = await service.deadline_of(session, tenant, task)
    await session.commit()
    created(request, response, "update_task", task_id=task.id)
    return Envelope(data=_with_deadline(RemediationOut.model_validate(task), due), meta=NoMeta())


@router.get("")
async def list_tasks(session: DbSession, tenant: Tenant) -> Envelope[list[RemediationOut], NoMeta]:
    """The queue, in the order the page says it is in.

    It said "ordered by impact against effort" and was ordered by when each
    task was created. Now: open work first, then priority, then how many attack
    paths run through the finding's asset, then the finding's own score
    (DECISIONS.md section 127). ``service.queue`` holds the ordering. Each task
    says when it is due, by its own date or the organization's policy (§225).
    """
    out = []
    for task, on_routes, due in await service.queue(session, tenant):
        item = _with_deadline(RemediationOut.model_validate(task), due)
        item.on_routes = on_routes
        out.append(item)
    return Envelope(data=out, meta=NoMeta())


@router.get("/progress")
async def progress(
    session: DbSession,
    tenant: Tenant,
    days: int = Query(default=30, ge=7, le=365),
) -> Envelope[FixProgressOut, NoMeta]:
    """What a scan observed fixed in the last ``days`` days, and how it went against deadlines.

    Finished work used to leave the queue and the page with it. Counted from the findings a scan
    resolved, never from tasks marked done, since only an observation closes a finding: each
    severity's count and median days from first detection to the fix, how many met their
    deadline, and the latest few by name (DECISIONS.md §225).
    """
    result = await service.progress(session, tenant, days)
    return Envelope(
        data=FixProgressOut(
            days=days,
            fixed=result.fixed,
            on_time=result.on_time,
            late=result.late,
            by_severity=[SeverityProgressOut.model_validate(row) for row in result.by_severity],
            recent=[FixedFindingOut.model_validate(fix) for fix in result.recent],
        ),
        meta=NoMeta(),
    )


@router.post(
    "/pull-requests", status_code=status.HTTP_202_ACCEPTED, responses=error_responses(403, 404)
)
async def request_pull_requests(
    payload: FixPullRequestIn,
    request: Request,
    response: Response,
    session: DbSession,
    tenant: Tenant,
) -> Envelope[FixPullRequestsQueuedOut, NoMeta]:
    """Ask for a rule's fix as pull requests, one per repository its failing assets are in.

    Matched through the organization's state indexes; a failing asset no index
    names is counted in ``not_indexed``. Queued for the worker, which reads the
    repository, edits what it can stand behind and opens the pull request
    (DECISIONS.md §232). A request already in flight or open is answered, not
    repeated.
    """
    queued, not_indexed = await pull_request_service.request(session, tenant, payload.rule_id)
    await session.commit()
    accepted(request, response, "list_pull_requests")
    return Envelope(
        data=FixPullRequestsQueuedOut(
            pull_requests=[FixPullRequestOut.model_validate(row) for row in queued],
            not_indexed=not_indexed,
        ),
        meta=NoMeta(),
    )


@router.get("/pull-requests")
async def list_pull_requests(
    session: DbSession,
    tenant: Tenant,
    rule_id: str | None = Query(default=None, max_length=128),
) -> Envelope[list[FixPullRequestOut], NoMeta]:
    """The organization's latest fix pull requests, with each finding's outcome."""
    rows = await pull_request_service.for_rule(session, tenant, rule_id)
    return Envelope(
        data=[
            FixPullRequestOut.model_validate(pr).model_copy(
                update={"findings": [FixPullRequestFindingOut.model_validate(f) for f in findings]}
            )
            for pr, findings in rows
        ],
        meta=NoMeta(),
    )


@router.patch("/{task_id}", responses=error_responses(403))
async def update_task(
    task_id: UUID, payload: RemediationUpdate, session: DbSession, tenant: Tenant
) -> Envelope[RemediationUpdatedOut, NoMeta]:
    """Change a task. Marking it done opens a claim for the next scan to check.

    It does not close the finding: only an observation does.
    """
    tenant.require_write()
    task = await service.update_task(session, tenant, task_id, payload)
    due = await service.deadline_of(session, tenant, task)
    await session.commit()

    payload_out = _with_deadline(RemediationUpdatedOut.model_validate(task), due)
    if task.status == RemediationStatus.DONE:
        # Marking work done does not resolve the finding. Only an observation
        # does -- but the customer no longer has to remember to ask for one.
        payload_out.note = (
            "Marked done. Cleave will check the environment shortly and "
            "again after that if the change has not appeared yet, then close "
            "the finding once the check passes."
        )
    return Envelope(data=payload_out, meta=NoMeta())


def _with_deadline[OutT: RemediationOut](item: OutT, due: Deadline) -> OutT:
    item.due_on = due.due_on
    item.due_by_policy = due.by_policy
    return item
