"""The remediation queue: who is fixing what, in what order, and what that claims.

The route authorizes and shapes the answer; the rules live here, where a worker could also reach
them. Every function runs in the caller's request session and never commits it: the request's
transaction carries the RLS claims, so ending it is the route's job.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import TenantContext
from app.core.enums import FindingStatus, OwnershipScope, Priority, RemediationStatus, Severity
from app.core.errors import NotFound, ValidationFailed
from app.models.finding import Finding
from app.models.organization import Organization
from app.models.remediation import RemediationTask
from app.models.resource import ResourceRecord
from app.models.rule import Rule
from app.risk.scorer import default_scorer
from app.schemas.finding import RemediationCreate, RemediationUpdate
from app.services import deadlines, ownership
from app.services import findings as findings_service
from app.services import graph as graph_service
from app.services import organizations as organizations_service
from app.services import verification as verification_service

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

#: How many of the window's fixes the progress report names.
RECENT_FIXES = 10


async def require_assignee(
    session: AsyncSession, tenant: TenantContext, assignee: UUID | None
) -> None:
    """Refuse work handed to somebody outside the organization.

    Any UUID used to be stored. A task can only be picked up by a member, so one
    assigned to anybody else -- a mistyped id, a colleague who has left, a user
    of another tenant -- would sit owned by somebody who can never see it.
    """
    if assignee is not None and not await organizations_service.is_member(
        session, tenant.organization_id, assignee
    ):
        raise ValidationFailed("The assignee is not a member of this organization")


async def create_task(
    session: AsyncSession, tenant: TenantContext, payload: RemediationCreate
) -> RemediationTask:
    """Open a task for a finding, once, and mark the finding as being worked."""
    await require_assignee(session, tenant, payload.assigned_to)
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
    # Flushed so the task has its id; the route commits, because the request's transaction is
    # the route's to end (``test_request_transaction``).
    await session.flush()
    return task


async def fix_within(session: AsyncSession, organization_id: UUID) -> deadlines.FixWithin:
    """The organization's policy on how long a fix may take, by severity (DECISIONS.md §225)."""
    org = await session.get(Organization, organization_id)
    if org is None:  # pragma: no cover -- the tenant context resolved it
        return deadlines.NO_POLICY
    return deadlines.fix_within(
        {
            Severity.CRITICAL: org.fix_within_days_critical,
            Severity.HIGH: org.fix_within_days_high,
            Severity.MEDIUM: org.fix_within_days_medium,
            Severity.LOW: org.fix_within_days_low,
        }
    )


async def deadline_of(
    session: AsyncSession, tenant: TenantContext, task: RemediationTask
) -> deadlines.Deadline:
    """When one task is due: its own date, or the policy's for its finding."""
    finding = await findings_service.get_finding(session, tenant, task.finding_id)
    return deadlines.deadline(
        task.due_date,
        finding.severity,
        finding.first_detected_at,
        await fix_within(session, tenant.organization_id),
    )


@dataclass(frozen=True)
class Owner:
    """Who has a task: the person assigned, else the rule its asset's place names (§236)."""

    owner_id: UUID | None
    #: The rule's scope where routed; ``None`` where a person assigned it, or nobody has it.
    by_rule: OwnershipScope | None = None


def owner(task: RemediationTask, routed: ownership.Routed | None) -> Owner:
    if task.assigned_to is not None:
        return Owner(task.assigned_to)
    if routed is None:
        return Owner(None)
    return Owner(routed.owner_id, routed.scope)


async def owner_of(session: AsyncSession, tenant: TenantContext, task: RemediationTask) -> Owner:
    """One task's owner, for an answer about that task alone."""
    if task.assigned_to is not None:
        return Owner(task.assigned_to)
    row = (
        await session.execute(
            select(
                ResourceRecord.cloud_account_id,
                ResourceRecord.provider_resource_id,
                ResourceRecord.resource_metadata["tags"],
            )
            .select_from(Finding)
            .outerjoin(ResourceRecord, ResourceRecord.id == Finding.resource_id)
            .where(Finding.id == task.finding_id)
        )
    ).one_or_none()
    placement = ownership.placement_of(*row) if row is not None else ownership.Placement()
    route = await ownership.router(session, tenant.organization_id)
    return owner(task, route(placement))


async def queue(
    session: AsyncSession, tenant: TenantContext
) -> list[tuple[RemediationTask, int, deadlines.Deadline, Owner]]:
    """Every task with how many attack paths run through its asset, in queue order.

    Open work first; then priority, which is impact against effort (RISK_ENGINE.md section 4);
    then how many attack paths run through the finding's asset, so of two equally urgent fixes
    the one on a route comes first; then the finding's own score (DECISIONS.md section 127).

    The routes break ties rather than set the order. A finding on a route is already outranked
    by the route itself in the risks queue, and scoring it up here as well would count the
    route twice.

    Each task comes with when it is due (§225). The deadline does not reorder the queue: a
    late fifteen-minute change and a late redesign are both late, and priority still says
    which cuts more risk first. And with who has it, assigned or routed by the organization's
    ownership rules (§236).
    """
    rows = (
        await session.execute(
            select(
                RemediationTask,
                Finding.risk_score,
                Finding.severity,
                Finding.first_detected_at,
                ResourceRecord.provider_resource_id,
                ResourceRecord.cloud_account_id,
                ResourceRecord.resource_metadata["tags"],
            )
            .join(Finding, Finding.id == RemediationTask.finding_id)
            .outerjoin(ResourceRecord, ResourceRecord.id == Finding.resource_id)
            .where(RemediationTask.organization_id == tenant.organization_id)
        )
    ).all()

    graph = await graph_service.load_graph(session, tenant.organization_id)
    through = graph_service.routes_through(graph)
    policy = await fix_within(session, tenant.organization_id)
    route = await ownership.router(session, tenant.organization_id)

    ordered = []
    for task, score, severity, first_detected_at, provider_id, account_id, tags in rows:
        on_routes = through.get(graph.resolve(provider_id), 0) if provider_id else 0
        due = deadlines.deadline(task.due_date, severity, first_detected_at, policy)
        has = owner(task, route(ownership.placement_of(account_id, provider_id, tags)))
        ordered.append((task, float(score or 0.0), on_routes, due, has))
    ordered.sort(
        key=lambda item: (
            _STATUS_ORDER[item[0].status],
            _PRIORITY_ORDER[item[0].priority],
            -item[2],
            -item[1],
            -item[0].created_at.timestamp(),
        )
    )
    return [(task, on_routes, due, has) for task, _, on_routes, due, has in ordered]


async def progress(session: AsyncSession, tenant: TenantContext, days: int) -> deadlines.Progress:
    """What a scan observed fixed in the last ``days`` days, and how it went against deadlines.

    Verified fixes only: a finding is fixed when a scan observes it passing (RULE_ENGINE.md
    section 3), never when a task is marked done, so work marked done and still failing is not
    counted. Every fix counts, tracked or not, since a fix nobody queued is still a fix. A
    finding resolved and then detected again is open, and is not counted.

    Each fix is held to its task's due date where a person set one, and otherwise to today's
    policy, counted from first detection: there is no record of what the policy was before, and
    judging against the standard the organization holds now is the useful comparison (§225).
    """
    since = datetime.now(UTC) - timedelta(days=days)
    rows = (
        await session.execute(
            select(
                Finding.id,
                Finding.title,
                Finding.rule_id,
                Finding.severity,
                Finding.first_detected_at,
                Finding.resolved_at,
                RemediationTask.due_date,
            )
            # At most one task per finding is not cancelled (``create_task``).
            .outerjoin(
                RemediationTask,
                and_(
                    RemediationTask.finding_id == Finding.id,
                    RemediationTask.status != RemediationStatus.CANCELLED,
                ),
            )
            .where(
                Finding.organization_id == tenant.organization_id,
                Finding.status == FindingStatus.RESOLVED,
                Finding.resolved_at >= since,
            )
        )
    ).all()
    policy = await fix_within(session, tenant.organization_id)
    fixes = [
        deadlines.Fix(
            finding_id=finding_id,
            title=title,
            rule_id=rule_id,
            severity=severity,
            first_detected_at=first_detected_at,
            resolved_at=resolved_at,
            due_on=deadlines.deadline(due_date, severity, first_detected_at, policy).due_on,
        )
        for finding_id, title, rule_id, severity, first_detected_at, resolved_at, due_date in rows
    ]
    return deadlines.progress(fixes, recent=RECENT_FIXES)


async def update_task(
    session: AsyncSession, tenant: TenantContext, task_id: UUID, payload: RemediationUpdate
) -> RemediationTask:
    """Change what a task says; marking it done opens the claim the scanner will check."""
    await require_assignee(session, tenant, payload.assigned_to)
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
        await _change_status(session, tenant, task, payload.status)
    # A field sent as null clears it; a field left out is left alone. Reading
    # `None` as "not sent" meant an owner or a due date, once set, could never
    # be taken off a task again (DECISIONS.md section 212).
    sent = payload.model_fields_set
    if "assigned_to" in sent:
        task.assigned_to = payload.assigned_to
    if "due_date" in sent:
        task.due_date = payload.due_date
    if "notes" in sent:
        task.notes = payload.notes

    await findings_service.record_audit(
        session,
        tenant,
        action="remediation.updated",
        resource_type="remediation_task",
        resource_id=task.id,
        metadata={
            "status": task.status.value,
            **{
                field: None if getattr(task, field) is None else str(getattr(task, field))
                for field in sent & {"assigned_to", "due_date"}
            },
        },
    )
    return task


async def _change_status(
    session: AsyncSession,
    tenant: TenantContext,
    task: RemediationTask,
    status: RemediationStatus,
) -> None:
    """Move a task, and settle what the move says about its finding.

    A cancelled task stays cancelled: the finding is tracked again with a new
    task, and reopening the old one beside it would give the finding two.
    """
    previous = task.status
    if previous == RemediationStatus.CANCELLED and status != previous:
        raise ValidationFailed("A cancelled task is not reopened; track the finding again")
    task.status = status

    if status == RemediationStatus.DONE:
        task.completed_at = datetime.now(UTC)
        # The claim, written down. Until this existed, marking work done
        # left the expectation in the customer's head: nothing recorded what
        # CloudGuard should now see, nothing looked again on its own, and
        # every way of not being verified came out as the same silence.
        finding = await findings_service.get_finding(session, tenant, task.finding_id)
        await verification_service.open_verification(
            session,
            organization_id=tenant.organization_id,
            finding=finding,
            task=task,
            claimed_by_user_id=tenant.user.id,
        )
    elif status == RemediationStatus.CANCELLED and previous != status:
        # Work called off is not a fix that failed to verify, and leaving
        # the question open would have the scheduler starting scans to
        # settle something nobody is waiting on.
        await verification_service.abandon(
            session,
            tenant.organization_id,
            task.finding_id,
            reason="The remediation task was cancelled.",
        )
        # Tracking moved the finding to IN_PROGRESS; nobody is working it now,
        # so it is open again, and offered again with the work nobody tracked.
        finding = await findings_service.get_finding(session, tenant, task.finding_id)
        if finding.status == FindingStatus.IN_PROGRESS:
            finding.status = FindingStatus.OPEN
    elif previous == RemediationStatus.DONE:
        # Reopened: the work was not finished after all, so the claim that it
        # was is withdrawn rather than left for the scheduler to keep checking.
        task.completed_at = None
        await verification_service.abandon(
            session,
            tenant.organization_id,
            task.finding_id,
            reason="The remediation task was reopened.",
        )
