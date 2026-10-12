"""Acceptances waiting for a second person, and that person's decision (DECISIONS.md §239).

An owner or an admin other than the person who asked approves or rejects. Approving makes the
acceptance take effect exactly as one made at once would -- the same timeline event, exception
and audit row, through ``findings.apply_acceptance`` -- with the approver named on it. Rejecting
leaves the finding or route as it was and tells the person who asked why.

Services flush and the route commits (§194).
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import ColumnElement, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import TenantContext
from app.core.enums import ExceptionStatus, FindingStatus, RiskStatus, Role
from app.core.errors import ConflictError, NotFound, PermissionDenied
from app.models.finding import Finding
from app.models.organization import OrganizationMember
from app.models.remediation import RiskException
from app.models.risk import Risk, RiskFinding
from app.services import approval_policy, audit
from app.services import findings as findings_service

#: Who may decide: the roles that may already set the organization's policies.
DECIDERS = (Role.OWNER, Role.ADMIN)

#: A finding in one of these can still be accepted; anything else has moved on since the request.
_ACCEPTABLE = {FindingStatus.OPEN, FindingStatus.IN_PROGRESS, FindingStatus.ACCEPTED_RISK}
_ACCEPTABLE_ROUTE = {RiskStatus.OPEN, RiskStatus.IN_PROGRESS, RiskStatus.ACCEPTED}


@dataclass(frozen=True)
class Request:
    """One acceptance as the approvals list shows it: what, who asked, and the subject's state."""

    exception: RiskException
    subject_title: str
    subject_severity: str
    #: The finding's or route's status now, so a request overtaken by a fix says so.
    subject_status: str
    requested_by_email: str | None
    decided_by_email: str | None


async def _emails(session: AsyncSession, organization_id: UUID) -> dict[UUID, str]:
    rows = await session.execute(
        select(OrganizationMember.user_id, OrganizationMember.email).where(
            OrganizationMember.organization_id == organization_id
        )
    )
    return {user_id: email for user_id, email in rows.tuples() if email}


def _text(value: object) -> str:
    """An enum's value or a plain string, and an empty string for nothing."""
    if value is None:
        return ""
    return str(getattr(value, "value", value))


async def _describe(
    session: AsyncSession,
    tenant: TenantContext,
    scope: Sequence[ColumnElement[bool]],
    *,
    limit: int,
    offset: int,
) -> list[Request]:
    rows = (
        await session.execute(
            select(
                RiskException,
                Finding.title,
                Finding.severity,
                Finding.status,
                Risk.title,
                Risk.risk_level,
                Risk.status,
            )
            .outerjoin(Finding, Finding.id == RiskException.finding_id)
            .outerjoin(Risk, Risk.id == RiskException.risk_id)
            .where(*scope)
            .order_by(RiskException.created_at.desc(), RiskException.id)
            .limit(limit)
            .offset(offset)
        )
    ).all()
    emails = await _emails(session, tenant.organization_id)
    shown = await _risk_levels(session, [row[0].finding_id for row in rows if row[0].finding_id])
    requests = []
    for exception, f_title, f_severity, f_status, r_title, r_level, r_status in rows:
        on_finding = exception.finding_id is not None
        # The level the acceptance was judged at (approval_policy.level_of_finding): what the
        # queue showed, so the request reads the same as the row it was asked from.
        level = (
            approval_policy.highest([f_severity, *shown.get(exception.finding_id, [])])
            if on_finding
            else r_level
        )
        requests.append(
            Request(
                exception=exception,
                subject_title=_text(f_title if on_finding else r_title),
                subject_severity=_text(level),
                subject_status=_text(f_status if on_finding else r_status),
                requested_by_email=emails.get(exception.requested_by),
                decided_by_email=emails.get(exception.decided_by) if exception.decided_by else None,
            )
        )
    return requests


async def _risk_levels(session: AsyncSession, finding_ids: list[UUID]) -> dict[UUID, list[str]]:
    """The scored level of every risk each of these findings belongs to."""
    if not finding_ids:
        return {}
    rows = await session.execute(
        select(RiskFinding.finding_id, Risk.risk_level)
        .join(Risk, Risk.id == RiskFinding.risk_id)
        .where(RiskFinding.finding_id.in_(finding_ids))
    )
    levels: dict[UUID, list[str]] = {}
    for finding_id, level in rows.tuples():
        levels.setdefault(finding_id, []).append(level)
    return levels


async def list_requests(
    session: AsyncSession,
    tenant: TenantContext,
    *,
    status: ExceptionStatus,
    limit: int,
    offset: int,
) -> tuple[list[Request], int]:
    """A page of this organization's acceptances that asked for a second approver, newest first.

    Members read them, as they read the findings they are about: the request is part of the
    finding's story, and the person who asked should see what became of it.
    """
    scope = (
        RiskException.organization_id == tenant.organization_id,
        RiskException.second_approval.is_(True),
        RiskException.status == status,
    )
    total = (
        await session.execute(select(func.count()).select_from(RiskException).where(*scope))
    ).scalar_one()
    return await _describe(session, tenant, scope, limit=limit, offset=offset), total


async def describe(
    session: AsyncSession, tenant: TenantContext, exception: RiskException
) -> Request:
    """One request as the list shows it, read again after a decision."""
    (request,) = await _describe(
        session,
        tenant,
        (
            RiskException.organization_id == tenant.organization_id,
            RiskException.id == exception.id,
        ),
        limit=1,
        offset=0,
    )
    return request


async def _pending(
    session: AsyncSession, tenant: TenantContext, acceptance_id: UUID
) -> RiskException:
    """The request, locked, after checking who is deciding and that it still waits."""
    tenant.require_write()
    tenant.require_role(*DECIDERS)
    exception = (
        await session.execute(
            select(RiskException)
            .where(
                RiskException.id == acceptance_id,
                RiskException.organization_id == tenant.organization_id,
                RiskException.second_approval.is_(True),
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if exception is None:
        raise NotFound("No such acceptance request")
    if exception.status is not ExceptionStatus.PENDING:
        raise ConflictError(
            f"This request was already {exception.status.value.lower()}, so it cannot be decided"
        )
    if exception.requested_by == tenant.user.id:
        raise PermissionDenied("An acceptance you asked for must be decided by somebody else")
    return exception


def _decided(exception: RiskException, tenant: TenantContext, status: ExceptionStatus) -> None:
    exception.status = status
    exception.decided_by = tenant.user.id
    exception.decided_at = datetime.now(UTC)


async def approve(
    session: AsyncSession, tenant: TenantContext, acceptance_id: UUID
) -> RiskException:
    """Approve a waiting acceptance, which then takes effect with the approver named on it.

    Refused (``409``) where the date it asked for has passed, or where the finding or route has
    moved on since -- fixed, or marked a false positive -- since approving then would accept
    something nobody asked about.
    """
    exception = await _pending(session, tenant, acceptance_id)
    if exception.expires_at is not None and exception.expires_at <= datetime.now(UTC):
        raise ConflictError("The end date this acceptance asked for has passed. Ask again.")

    if exception.finding_id is not None:
        finding = await findings_service.get_finding(session, tenant, exception.finding_id)
        if finding.status not in _ACCEPTABLE:
            raise ConflictError(
                f"The finding is {finding.status.value.lower().replace('_', ' ')} now, "
                "so there is nothing to accept"
            )
        _decided(exception, tenant, ExceptionStatus.ACTIVE)
        exception.approved_by = tenant.user.id
        await findings_service.apply_acceptance(session, tenant, finding, exception)
    else:
        risk = await session.get(Risk, exception.risk_id)
        if risk is None or risk.organization_id != tenant.organization_id:
            raise NotFound("No such acceptance request")
        if risk.status not in _ACCEPTABLE_ROUTE:
            raise ConflictError(
                f"The route is {risk.status.value.lower()} now, so there is nothing to accept"
            )
        _decided(exception, tenant, ExceptionStatus.ACTIVE)
        exception.approved_by = tenant.user.id
        # A route's running acceptance lives on the risk (§104); the request is its record.
        risk.status = RiskStatus.ACCEPTED
        risk.accepted_until = exception.expires_at
        await audit.record(
            session,
            tenant,
            "risk.status_change",
            "risk",
            risk.id,
            {
                "status": RiskStatus.ACCEPTED.value,
                "kind": risk.kind.value,
                "reason": exception.reason,
                "expires_at": exception.expires_at.isoformat() if exception.expires_at else None,
                "requested_by": str(exception.requested_by),
            },
        )
    await audit.record(
        session,
        tenant,
        "acceptance.approved",
        "acceptance",
        exception.id,
        {"requested_by": str(exception.requested_by)},
    )
    await session.flush()
    return exception


async def reject(
    session: AsyncSession, tenant: TenantContext, acceptance_id: UUID, note: str
) -> RiskException:
    """Turn a waiting acceptance down, saying why; the finding or route is left as it was."""
    exception = await _pending(session, tenant, acceptance_id)
    _decided(exception, tenant, ExceptionStatus.REJECTED)
    exception.decision_note = note
    await audit.record(
        session,
        tenant,
        "acceptance.rejected",
        "acceptance",
        exception.id,
        {"requested_by": str(exception.requested_by), "note": note},
    )
    await session.flush()
    return exception


async def pending_for_finding(session: AsyncSession, finding_id: UUID) -> RiskException | None:
    """The acceptance waiting on this finding, if one is."""
    return (
        await session.execute(
            select(RiskException).where(
                RiskException.finding_id == finding_id,
                RiskException.status == ExceptionStatus.PENDING,
            )
        )
    ).scalar_one_or_none()
