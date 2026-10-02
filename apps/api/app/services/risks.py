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

from sqlalchemy import Select, delete, exists, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.core.db import commit_unless_externally_managed
from app.core.deps import TenantContext
from app.core.enums import ExceptionStatus, FindingStatus, Level, RiskKind, RiskStatus
from app.core.errors import NotFound, ValidationFailed
from app.models.finding import Finding
from app.models.remediation import RiskException
from app.models.risk import Risk, RiskFinding
from app.models.scan import Scan
from app.risk.triage import acceptance_expiry, finding_risk_status, finding_status_for
from app.services import findings as findings_service

#: The members a decision on a finding risk reaches. A resolved finding is over
#: and a false positive was never a problem; neither is re-decided by a
#: decision about the group.
_TRIAGEABLE = (FindingStatus.OPEN, FindingStatus.IN_PROGRESS, FindingStatus.ACCEPTED_RISK)

#: A finding that still needs somebody: what "live" means for a risk, and what a queue row counts.
_OPEN_FINDINGS = (FindingStatus.OPEN, FindingStatus.IN_PROGRESS)


async def list_risks(
    session: AsyncSession,
    tenant: TenantContext,
    *,
    level: Level | None,
    status: RiskStatus | None,
    kind: RiskKind | None,
    search: str | None,
    limit: int,
    offset: int,
) -> tuple[list[Risk], int]:
    """One page of risks, worst first, and how many match in all."""
    stmt = select(Risk).where(Risk.organization_id == tenant.organization_id)

    # Live risks only, unless a status is asked for by name.
    #
    # A risk row outlives the finding it was scored from: the finding closes,
    # the next scan supersedes it, and the row stays. Listed unfiltered, the
    # page showed every risk ever raised as though all of them were current --
    # four identical "Storage account allows public access" cards, all Open,
    # on an estate the dashboard was simultaneously reporting two open findings
    # for. The two screens disagreed because only one of them was applying the
    # product's own definition of live.
    #
    # The rule is *settled* rather than *strict*: a risk is hidden when its
    # findings say it is over, not merely when they fail to say it is current.
    # A risk linked to nothing at all stays listed — the link table is the only
    # thing that could vouch for it, and a row whose evidence is missing is
    # exactly the row a security product must not quietly drop. Hiding it would
    # trade four duplicates for an empty page, which is the worse failure.
    #
    # Asking for a status explicitly still reaches everything, which is how a
    # resolved risk is looked up rather than lost.
    if status is None:
        linked_findings = select(RiskFinding.risk_id).where(
            RiskFinding.organization_id == tenant.organization_id
        )
        live_finding_risks = (
            select(RiskFinding.risk_id)
            .join(Finding, Finding.id == RiskFinding.finding_id)
            .where(
                RiskFinding.organization_id == tenant.organization_id,
                Finding.status.in_(_OPEN_FINDINGS),
            )
        )
        stmt = stmt.where(
            or_(
                Risk.kind != RiskKind.FINDING,
                Risk.id.notin_(linked_findings),
                Risk.id.in_(live_finding_risks),
            ),
            Risk.status != RiskStatus.RESOLVED,
        )

    if level:
        stmt = stmt.where(Risk.risk_level == level)
    if status:
        stmt = stmt.where(Risk.status == status)
    # Unfiltered by default, so a scenario ranks against the findings it groups
    # rather than hiding on a page of its own. That is the whole point of
    # putting it in this table: the combination outranking its parts is only
    # visible where they are listed together.
    if kind:
        stmt = stmt.where(Risk.kind == kind)
    if search:
        # A risk is named by its own title and explained by its description; a
        # scenario's asset names live in the description rather than in a
        # column, so both are searched.
        needle = f"%{search}%"
        stmt = stmt.where(or_(Risk.title.ilike(needle), Risk.description.ilike(needle)))

    total = (await session.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (
        await session.execute(
            stmt.order_by(Risk.risk_score.desc(), Risk.id).limit(limit).offset(offset)
        )
    ).scalars()
    return list(rows.all()), total


async def member_expiries(session: AsyncSession, risk_ids: list[UUID]) -> dict[UUID, datetime]:
    """The earliest running acceptance's end date among each risk's accepted findings.

    The earliest, because that is when the risk next needs a decision: one
    member coming back is enough to put the row back in the queue.
    """
    if not risk_ids:
        return {}
    rows = (
        await session.execute(
            select(RiskFinding.risk_id, func.min(RiskException.expires_at))
            .join(Finding, Finding.id == RiskFinding.finding_id)
            .join(RiskException, RiskException.finding_id == Finding.id)
            .where(
                RiskFinding.risk_id.in_(risk_ids),
                Finding.status == FindingStatus.ACCEPTED_RISK,
                RiskException.status == ExceptionStatus.ACTIVE,
                RiskException.expires_at.is_not(None),
            )
            .group_by(RiskFinding.risk_id)
        )
    ).tuples()
    return {risk_id: until for risk_id, until in rows if until is not None}


async def open_counts(
    session: AsyncSession, risk_ids: list[UUID]
) -> tuple[dict[UUID, int], dict[UUID, int]]:
    """How many open findings each risk covers, and how many open routes it is on.

    Both for the queue, where a row has to say what deciding about it would
    decide: a grouped risk is forty accounts, and a finding on two routes is
    worth more than its own score says. A page at a time, two grouped queries.
    """
    if not risk_ids:
        return {}, {}
    findings = dict(
        (
            await session.execute(
                select(RiskFinding.risk_id, func.count(func.distinct(Finding.id)))
                .join(Finding, Finding.id == RiskFinding.finding_id)
                .where(
                    RiskFinding.risk_id.in_(risk_ids),
                    Finding.status.in_(_OPEN_FINDINGS),
                )
                .group_by(RiskFinding.risk_id)
            )
        )
        .tuples()
        .all()
    )
    # Routes that share a member finding with this risk. Counted for finding
    # risks only: a route sharing findings with another route is overlap, not
    # a fact about either of them.
    own, other = aliased(RiskFinding), aliased(RiskFinding)
    route = aliased(Risk)
    subject = aliased(Risk)
    routes = dict(
        (
            await session.execute(
                select(own.risk_id, func.count(func.distinct(route.id)))
                .join(subject, subject.id == own.risk_id)
                .join(other, other.finding_id == own.finding_id)
                .join(route, route.id == other.risk_id)
                .where(
                    own.risk_id.in_(risk_ids),
                    subject.kind == RiskKind.FINDING,
                    route.kind != RiskKind.FINDING,
                    route.status != RiskStatus.RESOLVED,
                )
                .group_by(own.risk_id)
            )
        )
        .tuples()
        .all()
    )
    return findings, routes


async def get_risk_detail(
    session: AsyncSession, tenant: TenantContext, risk_id: UUID
) -> tuple[Risk, list[Finding], datetime | None]:
    """One risk, its member findings, and when its route was last seen."""
    risk = (
        await session.execute(
            select(Risk).where(Risk.id == risk_id, Risk.organization_id == tenant.organization_id)
        )
    ).scalar_one_or_none()
    if risk is None:
        raise NotFound("Risk not found")

    # 1:1 with findings today; the join already supports many.
    findings = (
        await session.execute(
            select(Finding)
            .join(RiskFinding, RiskFinding.finding_id == Finding.id)
            .where(RiskFinding.risk_id == risk_id)
        )
    ).scalars()

    # When the route was last seen, not merely which scan saw it. A bare id is
    # not an answer a person can act on, and one extra lookup on a single-row
    # page is cheaper than a client fetching the scan itself to render a date.
    observed_at = None
    if risk.observed_scan_id is not None:
        observed_at = (
            await session.execute(
                select(Scan.completed_at).where(
                    Scan.id == risk.observed_scan_id,
                    Scan.organization_id == tenant.organization_id,
                )
            )
        ).scalar_one_or_none()
    return risk, list(findings.all()), observed_at


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
            "rescan — Cleave resolves it once a scan confirms the fix."
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


async def delete_emptied(session: AsyncSession, organization_id: UUID, risk_ids: set[UUID]) -> int:
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


async def _members(session: AsyncSession, risk_ids: list[UUID]) -> dict[UUID, list[Finding]]:
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
