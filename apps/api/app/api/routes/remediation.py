from uuid import UUID

from fastapi import APIRouter, Request, Response, status

from app.api.links import created
from app.core.deps import DbSession, Tenant
from app.core.enums import RemediationStatus
from app.schemas.common import ERROR_RESPONSES, Envelope, NoMeta, error_responses
from app.schemas.finding import (
    RemediationCreate,
    RemediationOut,
    RemediationUpdate,
    RemediationUpdatedOut,
)
from app.services import remediation as service

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
    await session.commit()
    created(request, response, "update_task", task_id=task.id)
    return Envelope(data=RemediationOut.model_validate(task), meta=NoMeta())


@router.get("")
async def list_tasks(session: DbSession, tenant: Tenant) -> Envelope[list[RemediationOut], NoMeta]:
    """The queue, in the order the page says it is in.

    It said "ordered by impact against effort" and was ordered by when each
    task was created. Now: open work first, then priority, then how many attack
    paths run through the finding's asset, then the finding's own score
    (DECISIONS.md section 127). ``service.queue`` holds the ordering.
    """
    out = []
    for task, on_routes in await service.queue(session, tenant):
        item = RemediationOut.model_validate(task)
        item.on_routes = on_routes
        out.append(item)
    return Envelope(data=out, meta=NoMeta())


@router.patch("/{task_id}", responses=error_responses(403))
async def update_task(
    task_id: UUID, payload: RemediationUpdate, session: DbSession, tenant: Tenant
) -> Envelope[RemediationUpdatedOut, NoMeta]:
    """Change a task. Marking it done opens a claim for the next scan to check.

    It does not close the finding: only an observation does.
    """
    tenant.require_write()
    task = await service.update_task(session, tenant, task_id, payload)
    await session.commit()

    payload_out = RemediationUpdatedOut.model_validate(task)
    if task.status == RemediationStatus.DONE:
        # Marking work done does not resolve the finding. Only an observation
        # does -- but the customer no longer has to remember to ask for one.
        payload_out.note = (
            "Marked done. Cleave will check the environment shortly and "
            "again after that if the change has not appeared yet, then close "
            "the finding once the check passes."
        )
    return Envelope(data=payload_out, meta=NoMeta())
