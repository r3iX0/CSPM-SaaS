"""The triage actions on a risk.

The risks list is where somebody decides what to do, so a decision is made on
the risk. Where it is *recorded* depends on what the risk is about (DECISIONS.md
§103):

- A finding risk writes through to its findings. The finding is what
  compliance cites and what an exception hangs off, so it stays the one place
  the decision lives; the risk's own status is read back from its members.
- A route or an escalation has no finding of its own to write to. Its status
  is its own, and accepting one says "this reach is by design", which is a
  different claim from accepting any of the findings along it.
"""

from collections.abc import Sequence
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import Select, delete, exists, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import commit_unless_externally_managed
from app.core.deps import TenantContext
from app.core.enums import FindingStatus, RiskKind, RiskStatus
from app.core.errors import NotFound, ValidationFailed
from app.models.finding import Finding
from app.models.risk import Risk, RiskFinding
from app.risk.triage import acceptance_expiry, finding_risk_status, finding_status_for
from app.services import findings as findings_service

#: The members a decision on a finding risk reaches. A resolved finding is over
#: and a false positive was never a problem; neither is re-decided by a
#: decision about the group.
_TRIAGEABLE = (FindingStatus.OPEN, FindingStatus.IN_PROGRESS, FindingStatus.ACCEPTED_RISK)


async def get_risks(
    session: AsyncSession, tenant: TenantContext, risk_ids: Sequence[UUID]
) -> list[Risk]:
    """The named risks, in the order asked for, or ``NotFound`` for any missing."""
    rows = {
        risk.id: risk
        for risk in (
            await session.execute(
                select(Risk).where(
                    Risk.id.in_(risk_ids),
                    Risk.organization_id == tenant.organization_id,
                )
            )
        ).scalars()
    }
    if any(risk_id not in rows for risk_id in risk_ids):
        raise NotFound("Risk not found")
    return [rows[risk_id] for risk_id in dict.fromkeys(risk_ids)]


async def set_status(
    session: AsyncSession,
    tenant: TenantContext,
    risks: Sequence[Risk],
    status: RiskStatus,
    *,
    reason: str | None,
    expires_at: datetime | None,
) -> list[Risk]:
    """Decide about one or more risks, all or nothing.

    Every refusal is checked before anything is written: a bulk decision that
    accepted twelve risks and then failed on the thirteenth would leave the
    queue in a state nobody chose.
    """
    if status == RiskStatus.RESOLVED:
        raise ValidationFailed(
            "Risks cannot be marked resolved by hand. Fix the issue and run a "
            "rescan — CloudGuard resolves it once a scan confirms the fix."
        )
    if status == RiskStatus.ACCEPTED and not reason:
        raise ValidationFailed("Accepting a risk needs a reason")

    if expires_at is not None and status != RiskStatus.ACCEPTED:
        raise ValidationFailed("Only an acceptance has an end date")
    try:
        expires_at = acceptance_expiry(expires_at, datetime.now(UTC))
    except ValueError as exc:
        raise ValidationFailed(str(exc)) from exc

    members = await _members(session, [r.id for r in risks if r.kind == RiskKind.FINDING])
    for risk in risks:
        if risk.kind == RiskKind.FINDING and not members.get(risk.id):
            raise ValidationFailed(f"Nothing on “{risk.title}” is open to decide about")

    for risk in risks:
        if risk.kind == RiskKind.FINDING:
            await _decide_findings(
                session, tenant, risk, members[risk.id], status, reason, expires_at
            )
        else:
            risk.status = status
            # The end date belongs to this acceptance only. Any other decision
            # clears it, so a route reopened and later accepted again without a
            # date is not reopened by the first one's (DECISIONS.md §104).
            risk.accepted_until = expires_at if status == RiskStatus.ACCEPTED else None
            await findings_service.record_audit(
                session,
                tenant,
                action="risk.status_change",
                resource_type="risk",
                resource_id=risk.id,
                metadata={
                    "status": status.value,
                    "kind": risk.kind.value,
                    "reason": reason,
                    "expires_at": expires_at.isoformat() if expires_at else None,
                },
            )

    await commit_unless_externally_managed(session)
    return list(risks)


async def _decide_findings(
    session: AsyncSession,
    tenant: TenantContext,
    risk: Risk,
    members: list[Finding],
    status: RiskStatus,
    reason: str | None,
    expires_at: datetime | None,
) -> None:
    """Write a decision to every member, through the finding's own actions.

    Through them rather than beside them, so a decision made here leaves the
    same timeline event, audit row and exception a decision on the finding page
    would -- one per finding, because each is a separate thing somebody chose
    to live with.
    """
    target = finding_status_for(status)
    for finding in members:
        # Accepting an accepted finding is not a no-op: it is how an end date
        # is extended or removed, and it replaces the running exception.
        if finding.status == target and target != FindingStatus.ACCEPTED_RISK:
            continue
        if target == FindingStatus.ACCEPTED_RISK:
            assert reason is not None  # refused by the caller otherwise
            await findings_service.accept_risk(session, tenant, finding, reason, expires_at)
        else:
            await findings_service.set_status(session, tenant, finding, target)
    risk.status = finding_risk_status((f.status for f in members), risk.status)


async def linked_to(
    session: AsyncSession,
    organization_id: UUID,
    finding_ids: Select[tuple[UUID]] | Sequence[UUID],
) -> set[UUID]:
    """The risks any of these findings is a member of.

    Read before the findings are deleted, because afterwards the links are gone
    with them and nothing says which risks they held up.
    """
    return set(
        (
            await session.execute(
                select(RiskFinding.risk_id).where(
                    RiskFinding.organization_id == organization_id,
                    RiskFinding.finding_id.in_(finding_ids),
                )
            )
        ).scalars()
    )


async def delete_emptied(
    session: AsyncSession, organization_id: UUID, risk_ids: set[UUID]
) -> int:
    """Delete those of these risks that no finding is a member of any more.

    For after a delete that took findings with it -- a connection, or a scan
    purged of what it found. ``risk_findings`` cascades from the finding and
    ``risks`` has nothing to cascade from, so the row stayed: a card with no
    evidence behind it that the risks list keeps on purpose, because it cannot
    tell such a row from one whose links went missing (DECISIONS.md §124).

    Deleted rather than resolved. Nothing was fixed; the estate it was about
    stopped being watched, and a resolved row would put a remediation in the
    history that nobody made. A risk with a member left -- a route that crosses
    into another connection -- is kept, and the next scan of what remains
    decides it.

    The caller flushes the delete first, so the cascade has already run.
    """
    if not risk_ids:
        return 0
    emptied = (
        await session.execute(
            delete(Risk)
            .where(
                Risk.organization_id == organization_id,
                Risk.id.in_(risk_ids),
                ~exists().where(RiskFinding.risk_id == Risk.id),
            )
            .returning(Risk.id)
        )
    ).scalars()
    return len(list(emptied))


async def _members(
    session: AsyncSession, risk_ids: list[UUID]
) -> dict[UUID, list[Finding]]:
    """The triageable findings of each finding risk, in one query."""
    if not risk_ids:
        return {}
    by_risk: dict[UUID, list[Finding]] = {}
    for risk_id, finding in (
        await session.execute(
            select(RiskFinding.risk_id, Finding)
            .join(Finding, Finding.id == RiskFinding.finding_id)
            .where(
                RiskFinding.risk_id.in_(risk_ids),
                Finding.status.in_(_TRIAGEABLE),
            )
            .order_by(Finding.id)
        )
    ).all():
        by_risk.setdefault(risk_id, []).append(finding)
    return by_risk
