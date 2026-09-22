from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, status
from sqlalchemy import select

from app.core.deps import DbSession, Tenant
from app.core.enums import FindingStatus, Priority, RemediationStatus
from app.core.errors import NotFound, ValidationFailed, envelope
from app.models.finding import Finding
from app.models.remediation import RemediationTask
from app.models.resource import ResourceRecord
from app.models.rule import Rule
from app.risk.scorer import default_scorer
from app.schemas.finding import RemediationCreate, RemediationOut, RemediationUpdate
from app.services import findings as findings_service
from app.services import graph as graph_service
from app.services import verification as verification_service

router = APIRouter(prefix="/remediation", tags=["remediation"])


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_task(
    payload: RemediationCreate, session: DbSession, tenant: Tenant
) -> dict:
    tenant.require_write()
    finding = await findings_service.get_finding(session, tenant, payload.finding_id)

    existing = (
        await session.execute(
            select(RemediationTask).where(
                RemediationTask.finding_id == finding.id,
                RemediationTask.organization_id == tenant.organization_id,
                RemediationTask.status != RemediationStatus.CANCELLED,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ValidationFailed("This finding already has an open remediation task")

    rule = (
        await session.execute(select(Rule).where(Rule.rule_id == finding.rule_id))
    ).scalar_one_or_none()
    effort = rule.estimated_effort_minutes if rule else 30
    score = float(finding.risk_score) if finding.risk_score is not None else 0.0

    # The finding's own risk, not any route it happens to be part of. A
    # remediation task attached to an attack path would be a job nobody can
    # close: the route is severed by fixing one of its members.
    risk = await findings_service.own_risk(session, finding)

    task = RemediationTask(
        organization_id=tenant.organization_id,
        finding_id=finding.id,
        risk_id=risk.id if risk else None,
        assigned_to=payload.assigned_to,
        status=RemediationStatus.TODO,
        # Effort-aware, so a fifteen-minute firewall change outranks a redesign
        # of comparable raw score (RISK_ENGINE.md section 4).
        priority=default_scorer.priority(score, effort),
        due_date=payload.due_date,
        estimated_effort_minutes=effort,
        notes=payload.notes,
    )
    session.add(task)

    # Assigning work is a statement of intent -- reflect it on the finding.
    if finding.status == FindingStatus.OPEN:
        finding.status = FindingStatus.IN_PROGRESS

    await findings_service.record_audit(
        session,
        tenant,
        action="remediation.created",
        resource_type="finding",
        resource_id=finding.id,
        metadata={"assigned_to": str(payload.assigned_to) if payload.assigned_to else None},
    )
    await session.commit()
    return envelope(RemediationOut.model_validate(task).model_dump(mode="json"))


# Work still to do first, and within it the order the page promises: impact
# against effort, as the task's priority says.
_STATUS_ORDER = {
    RemediationStatus.TODO: 0,
    RemediationStatus.IN_PROGRESS: 0,
    RemediationStatus.DONE: 1,
    RemediationStatus.CANCELLED: 2,
}
_PRIORITY_ORDER = {
    Priority.CRITICAL: 0,
    Priority.HIGH: 1,
    Priority.MEDIUM: 2,
    Priority.LOW: 3,
}


@router.get("")
async def list_tasks(session: DbSession, tenant: Tenant) -> dict:
    """The queue, in the order the page says it is in.

    It said "ordered by impact against effort" and was ordered by when each
    task was created. Now: open work first; then priority, which is impact
    against effort (RISK_ENGINE.md section 4); then how many attack paths run
    through the finding's asset, so of two equally urgent fixes the one on a
    route comes first; then the finding's own score (DECISIONS.md section 127).

    The routes break ties rather than set the order. A finding on a route is
    already outranked by the route itself in the risks queue, and scoring it
    up here as well would count the route twice.
    """
    rows = (
        await session.execute(
            select(RemediationTask, Finding.risk_score, ResourceRecord.provider_resource_id)
            .join(Finding, Finding.id == RemediationTask.finding_id)
            .outerjoin(ResourceRecord, ResourceRecord.id == Finding.resource_id)
            .where(RemediationTask.organization_id == tenant.organization_id)
        )
    ).all()

    graph = await graph_service.load_graph(session, tenant.organization_id)
    through = graph_service.routes_through(graph)

    queue = []
    for task, score, provider_id in rows:
        on_routes = through.get(graph.resolve(provider_id), 0) if provider_id else 0
        queue.append((task, float(score or 0.0), on_routes))
    queue.sort(
        key=lambda item: (
            _STATUS_ORDER[item[0].status],
            _PRIORITY_ORDER[item[0].priority],
            -item[2],
            -item[1],
            -item[0].created_at.timestamp(),
        )
    )
    return envelope(
        [
            {
                **RemediationOut.model_validate(task).model_dump(mode="json"),
                "on_routes": on_routes,
            }
            for task, _, on_routes in queue
        ]
    )


@router.patch("/{task_id}")
async def update_task(
    task_id: UUID, payload: RemediationUpdate, session: DbSession, tenant: Tenant
) -> dict:
    tenant.require_write()
    task = (
        await session.execute(
            select(RemediationTask).where(
                RemediationTask.id == task_id,
                RemediationTask.organization_id == tenant.organization_id,
            )
        )
    ).scalar_one_or_none()
    if task is None:
        raise NotFound("Remediation task not found")

    if payload.status is not None:
        task.status = payload.status
        if payload.status == RemediationStatus.DONE:
            task.completed_at = datetime.now(UTC)
            # The claim, written down. Until this existed, marking work done
            # left the expectation in the customer's head: nothing recorded what
            # CloudGuard should now see, nothing looked again on its own, and
            # every way of not being verified came out as the same silence.
            finding = await findings_service.get_finding(
                session, tenant, task.finding_id
            )
            await verification_service.open_verification(
                session,
                organization_id=tenant.organization_id,
                finding=finding,
                task=task,
                claimed_by_user_id=tenant.user.id,
            )
        elif payload.status == RemediationStatus.CANCELLED:
            # Work called off is not a fix that failed to verify, and leaving
            # the question open would have the scheduler starting scans to
            # settle something nobody is waiting on.
            await verification_service.abandon(
                session,
                tenant.organization_id,
                task.finding_id,
                reason="The remediation task was cancelled.",
            )
    if payload.assigned_to is not None:
        task.assigned_to = payload.assigned_to
    if payload.due_date is not None:
        task.due_date = payload.due_date
    if payload.notes is not None:
        task.notes = payload.notes

    await findings_service.record_audit(
        session,
        tenant,
        action="remediation.updated",
        resource_type="remediation_task",
        resource_id=task.id,
        metadata={"status": task.status.value},
    )
    await session.commit()

    payload_out = RemediationOut.model_validate(task).model_dump(mode="json")
    if task.status == RemediationStatus.DONE:
        # Marking work done does not resolve the finding. Only an observation
        # does -- but the customer no longer has to remember to ask for one.
        payload_out["note"] = (
            "Marked done. CloudGuard will check the environment shortly and "
            "again after that if the change has not appeared yet, then close "
            "the finding once the check passes."
        )
    return envelope(payload_out)
