"""Acceptances that have run out.

An acceptance with an end date used to be a promise nothing kept: the date was
stored on the exception row and never read again, so a risk accepted "until
the migration finishes" stayed accepted for ever (DECISIONS.md §104). This is
the half that reads it.

An expired acceptance puts the risk back in the queue as OPEN -- not in
progress, and not resolved. Nobody has decided anything about it since the
acceptance ran out, and nothing about the environment has been observed to
change; the finding stays exactly as failing as it was.
"""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import ColumnElement, and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    ExceptionStatus,
    FindingEvent,
    FindingStatus,
    RiskKind,
    RiskStatus,
)
from app.models.finding import Finding
from app.models.history import FindingEventRecord
from app.models.remediation import AuditLog, RiskException
from app.models.risk import Risk
from app.services.findings import resync_own_risk


def _due_exceptions(now: datetime) -> ColumnElement[bool]:
    return and_(
        RiskException.status == ExceptionStatus.ACTIVE,
        RiskException.expires_at.is_not(None),
        RiskException.expires_at <= now,
    )


def _due_routes(now: datetime) -> ColumnElement[bool]:
    return and_(
        Risk.kind != RiskKind.FINDING,
        Risk.status == RiskStatus.ACCEPTED,
        Risk.accepted_until.is_not(None),
        Risk.accepted_until <= now,
    )


async def organizations_due(session: AsyncSession, now: datetime) -> list[UUID]:
    """The organizations with anything to expire, asked once across every tenant.

    Called on the owner session by the sweep, which then works each
    organization inside its own tenant-scoped session: the only cross-tenant
    question is *who*, never *what*.
    """
    findings = select(RiskException.organization_id).where(_due_exceptions(now))
    routes = select(Risk.organization_id).where(_due_routes(now))
    return list((await session.execute(findings.union(routes))).scalars().all())


async def expire_due(
    session: AsyncSession, organization_id: UUID, now: datetime | None = None
) -> int:
    """Expire every acceptance in one organization whose end date has passed.

    Returns how many acceptances ran out. The caller commits.
    """
    now = now or datetime.now(UTC)
    expired = 0

    due = (
        await session.execute(
            select(RiskException, Finding)
            .join(Finding, Finding.id == RiskException.finding_id)
            .where(
                RiskException.organization_id == organization_id,
                _due_exceptions(now),
            )
        )
    ).all()

    # A finding another acceptance still covers is left alone. Accepting again
    # revokes the earlier exception, but rows written before that rule existed
    # can hold two, and the older date must not undo the newer decision.
    still_covered: set[UUID] = set()
    if due:
        still_covered = set(
            (
                await session.execute(
                    select(RiskException.finding_id).where(
                        RiskException.organization_id == organization_id,
                        RiskException.status == ExceptionStatus.ACTIVE,
                        RiskException.finding_id.in_([f.id for _, f in due]),
                        or_(
                            RiskException.expires_at.is_(None),
                            RiskException.expires_at > now,
                        ),
                    )
                )
            ).scalars()
        )

    for exception, finding in due:
        exception.status = ExceptionStatus.EXPIRED
        expired += 1
        if finding.status != FindingStatus.ACCEPTED_RISK or finding.id in still_covered:
            # Already moved on -- reopened, fixed, marked a false positive -- or
            # still accepted under a later decision. The acceptance ends on
            # paper and nothing else changes.
            continue
        session.add(
            FindingEventRecord(
                organization_id=organization_id,
                finding_id=finding.id,
                scan_id=finding.scan_id,
                # No person did this. The timeline says so by having no user,
                # exactly as it does for the transitions a scan makes.
                user_id=None,
                event=FindingEvent.STATUS_CHANGED,
                previous_status=FindingStatus.ACCEPTED_RISK,
                current_status=FindingStatus.OPEN,
                detail=(
                    f"The acceptance ran out on {_day(exception.expires_at)}, so this "
                    f"is back in the queue. It had been accepted because: "
                    f"{exception.reason}"
                ),
                observed_at=now,
            )
        )
        finding.status = FindingStatus.OPEN
        await resync_own_risk(session, finding)
        _audit(
            session,
            organization_id,
            action="finding.acceptance_expired",
            resource_type="finding",
            resource_id=finding.id,
            metadata={"rule_id": finding.rule_id, "expired_at": _iso(exception.expires_at)},
            now=now,
        )

    routes = (
        await session.execute(
            select(Risk).where(Risk.organization_id == organization_id, _due_routes(now))
        )
    ).scalars()
    for route in routes:
        _audit(
            session,
            organization_id,
            action="risk.acceptance_expired",
            resource_type="risk",
            resource_id=route.id,
            metadata={"kind": route.kind.value, "expired_at": _iso(route.accepted_until)},
            now=now,
        )
        route.status = RiskStatus.OPEN
        route.accepted_until = None
        expired += 1

    return expired


def _audit(
    session: AsyncSession,
    organization_id: UUID,
    *,
    action: str,
    resource_type: str,
    resource_id: UUID,
    metadata: dict,
    now: datetime,
) -> None:
    """An audit row with no user: the sweep acted, on a date a person chose."""
    session.add(
        AuditLog(
            organization_id=organization_id,
            user_id=None,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            audit_metadata=metadata,
            created_at=now,
        )
    )


def _day(value: datetime | None) -> str:
    if value is None:
        return "an unknown date"
    day = value.astimezone(UTC)
    return f"{day.day} {day:%B %Y}"


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None
