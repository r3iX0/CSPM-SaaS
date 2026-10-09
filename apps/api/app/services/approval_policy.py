"""Whether an acceptance waits for a second person, and the request it waits as (§239).

An organization may require that accepting a risk at or above a severity it chooses is approved
by a second owner or admin, so no one person can quietly decide to live with a critical finding.
An acceptance the policy covers is written as a PENDING exception and changes nothing: the
finding stays open, the route stays in the queue, until somebody else approves or rejects it
(``services/approvals.py``).

Kept apart from ``approvals`` so ``findings`` can ask it without a cycle: approving applies the
acceptance through ``findings``, and ``findings`` asks here before applying one.
"""

from collections.abc import Iterable
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import TenantContext
from app.core.enums import ExceptionStatus, OrganizationMode, Severity
from app.models.finding import Finding
from app.models.organization import Organization
from app.models.remediation import RiskException
from app.models.risk import Risk, RiskFinding
from app.services import audit

#: Lowest first, so a policy covers its own severity and every one above it.
_RANK = {Severity.LOW: 0, Severity.MEDIUM: 1, Severity.HIGH: 2, Severity.CRITICAL: 3}


def requires(policy: Severity | None, severity: Severity | str) -> bool:
    """Whether an acceptance of this severity needs a second approver under this policy.

    A severity this does not know -- a route's, written by an older scorer -- is treated as the
    highest, so an unreadable value is never the way around the policy.
    """
    if policy is None:
        return False
    try:
        rank = _RANK[Severity(severity)]
    except ValueError:
        rank = _RANK[Severity.CRITICAL]
    return rank >= _RANK[policy]


def highest(levels: Iterable[StrEnum | str]) -> Severity | None:
    """The highest severity among these, ignoring a level that is not one (UNKNOWN)."""
    known: list[Severity] = []
    for level in levels:
        try:
            known.append(Severity(str(level)))
        except ValueError:
            continue
    if not known:
        return None
    return max(known, key=lambda severity: _RANK[severity])


async def level_of_finding(session: AsyncSession, finding: Finding) -> Severity:
    """What an acceptance of this finding is judged at: what the queue shows, at the least.

    The queue ranks by a risk's scored level -- the rule's severity weighed by what the asset
    is -- so a finding the rule calls Medium can sit on a row labelled High. A reviewer who asks
    for a second approver on High expects that row to wait, so the policy judges the higher of
    the finding's own severity and the level of every risk it belongs to.
    """
    levels = (
        await session.execute(
            select(Risk.risk_level)
            .join(RiskFinding, RiskFinding.risk_id == Risk.id)
            .where(RiskFinding.finding_id == finding.id)
        )
    ).scalars()
    return highest([finding.severity, *levels]) or finding.severity


async def policy_of(session: AsyncSession, organization_id: UUID) -> Severity | None:
    """The organization's policy, or None in solo, where there is nobody else to approve."""
    org = await session.get(Organization, organization_id)
    if org is None or org.mode is OrganizationMode.SOLO:
        return None
    return org.acceptance_approval_from


async def request(
    session: AsyncSession,
    tenant: TenantContext,
    *,
    reason: str,
    expires_at: datetime | None,
    finding_id: UUID | None = None,
    risk_id: UUID | None = None,
) -> RiskException:
    """Ask for an acceptance a second person must approve, replacing any earlier request.

    One request waits per finding or route: asking again, to change the reason or the date,
    withdraws the one before rather than leaving two for an approver to choose between.
    """
    subject = (
        RiskException.finding_id == finding_id
        if finding_id is not None
        else RiskException.risk_id == risk_id
    )
    now = datetime.now(UTC)
    await session.execute(
        update(RiskException)
        .where(
            RiskException.organization_id == tenant.organization_id,
            subject,
            RiskException.status == ExceptionStatus.PENDING,
        )
        .values(status=ExceptionStatus.REVOKED, decided_at=now)
    )
    pending = RiskException(
        organization_id=tenant.organization_id,
        finding_id=finding_id,
        risk_id=risk_id,
        requested_by=tenant.user.id,
        reason=reason,
        expires_at=expires_at,
        status=ExceptionStatus.PENDING,
        second_approval=True,
        created_at=now,
    )
    session.add(pending)
    await session.flush()
    await audit.record(
        session,
        tenant,
        "acceptance.requested",
        "acceptance",
        pending.id,
        {
            "finding_id": str(finding_id) if finding_id else None,
            "risk_id": str(risk_id) if risk_id else None,
            "reason": reason,
            "expires_at": expires_at.isoformat() if expires_at else None,
        },
    )
    return pending
