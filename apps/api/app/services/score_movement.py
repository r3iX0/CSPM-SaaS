"""What the security score charges for, and why it moved since the previous scan (§235).

The score deducts once per open finding risk, by the band it is charged at
(``open_charges``). Each posture reading stores that ledger beside its total
(``risk_history.charges``), so the movement the dashboard shows is a diff of two
ledgers: the reading before the latest scan, and the charges as they stand now.
Each risk whose charge changed is given one cause from what was recorded in
between -- its findings' events, its asset's first sighting, the rule versions
that ran -- and ``risk.movement`` splits the points over the causes exactly.

A risk nothing explains is said to be unexplained, and never given the nearest
cause: a score that explains itself wrongly is worse than one that says it
cannot.
"""

from collections import defaultdict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import AssetChange, FindingEvent, FindingStatus, Level, RiskKind
from app.models.finding import Finding
from app.models.history import AssetChangeEvent, FindingEventRecord
from app.models.resource import ResourceRecord
from app.models.risk import Risk, RiskFinding, RiskHistory
from app.risk.movement import Cause, charge_changes, split, total_deduction
from app.risk.scorer import default_scorer
from app.rules.registry import enabled_rules

OPEN = (FindingStatus.OPEN, FindingStatus.IN_PROGRESS)
#: Findings named per cause; the rest are counted.
MAX_EXAMPLES = 5


async def open_charges(
    session: AsyncSession, organization_id: UUID
) -> dict[UUID, tuple[Level, Level]]:
    """Every open finding risk, to its ranked band and the band the score charges.

    Finding risks only, and each once: a scenario groups findings already
    charged here, and a risk grouping forty findings is one problem stated once.
    ``known_risk_level`` is what the score charges, coalesced so risks written
    before it existed charge as they did (RISK_ENGINE.md section 3).
    """
    rows = await session.execute(
        select(Risk.id, Risk.risk_level, func.coalesce(Risk.known_risk_level, Risk.risk_level))
        .join(RiskFinding, RiskFinding.risk_id == Risk.id)
        .join(Finding, Finding.id == RiskFinding.finding_id)
        .where(
            Risk.organization_id == organization_id,
            Risk.kind == RiskKind.FINDING,
            Finding.status.in_(OPEN),
        )
        .distinct()
    )
    return {
        risk_id: (Level(ranked), Level(known or ranked)) for risk_id, ranked, known in rows.tuples()
    }


def ledger(charges: Mapping[UUID, tuple[Level, Level]]) -> dict[str, str]:
    """The charges as a reading stores them: each risk to the band it was charged at."""
    return {str(risk_id): known.value for risk_id, (_ranked, known) in charges.items()}


def rule_versions() -> dict[str, str]:
    return {rule.rule_id: rule.version for rule in enabled_rules()}


@dataclass(frozen=True)
class Member:
    """A finding of a risk whose charge changed, as far as its cause needs it."""

    id: UUID
    rule_id: str
    resource_id: UUID | None


@dataclass
class _Share:
    rise: float = 0.0
    risks: int = 0
    examples: list[UUID] = field(default_factory=list)


async def explain(session: AsyncSession, organization_id: UUID) -> dict:
    """The dashboard's ``score_delta``, split into what caused it.

    Compared against the same reading the delta is: the one before the latest
    scan's, since the latest scan's own reading is part of the movement.
    """
    readings = list(
        (
            await session.execute(
                select(RiskHistory)
                .where(RiskHistory.organization_id == organization_id)
                .order_by(RiskHistory.observed_at.desc())
                .limit(2)
            )
        )
        .scalars()
        .all()
    )
    if len(readings) < 2:
        return _unavailable("first_reading")
    previous = readings[1]
    if previous.charges is None:
        return _unavailable("not_recorded", previous)

    config = default_scorer.config
    before = {UUID(key): Level(value) for key, value in previous.charges.items()}
    charges = await open_charges(session, organization_id)
    after = {risk_id: known for risk_id, (_ranked, known) in charges.items()}
    current = default_scorer.security_score(list(after.values()))
    target = current - previous.security_score

    rises = charge_changes(before, after, config)
    causes = await _causes(
        session,
        rises,
        moved=before.keys() & after.keys(),
        since=previous.created_at,
        versions_then=previous.rule_versions or {},
    )
    shares: dict[Cause, _Share] = defaultdict(_Share)
    for risk_id, rise in rises.items():
        cause, example = causes[risk_id]
        share = shares[cause]
        share.rise += rise
        share.risks += 1
        if example is not None and len(share.examples) < MAX_EXAMPLES:
            share.examples.append(example)

    points = split(
        {cause: share.rise for cause, share in shares.items()},
        before=total_deduction(before, config),
        after=total_deduction(after, config),
        config=config,
        target=target,
    )
    findings = await _examples(session, [f for share in shares.values() for f in share.examples])
    rows: list[dict[str, Any]] = []
    for cause, (whole, exact) in points.items():
        share = shares.get(cause, _Share())
        rows.append(
            {
                "cause": cause.value,
                "points": whole,
                "exact": round(exact, 2),
                "risks": share.risks,
                "findings": [findings[f] for f in share.examples if f in findings],
            }
        )
    rows.sort(key=lambda row: (-abs(row["exact"]), row["cause"]))
    return {
        "available": True,
        "reason": None,
        "since": previous.observed_at,
        "from_score": previous.security_score,
        "to_score": current,
        "delta": target,
        "causes": rows,
    }


def _unavailable(reason: str, previous: RiskHistory | None = None) -> dict:
    return {
        "available": False,
        "reason": reason,
        "since": previous.observed_at if previous is not None else None,
        "from_score": previous.security_score if previous is not None else None,
        "to_score": None,
        "delta": None,
        "causes": [],
    }


async def _causes(
    session: AsyncSession,
    rises: Mapping[UUID, float],
    *,
    moved: set[UUID],
    since: datetime,
    versions_then: Mapping[str, str],
) -> dict[UUID, tuple[Cause, UUID | None]]:
    """Each changed risk's cause, and the finding that decided it."""
    if not rises:
        return {}
    risk_ids = list(rises)
    existing = set((await session.execute(select(Risk.id).where(Risk.id.in_(risk_ids)))).scalars())
    members: dict[UUID, list[Member]] = defaultdict(list)
    for risk_id, finding_id, rule_id, resource_id in (
        await session.execute(
            select(RiskFinding.risk_id, Finding.id, Finding.rule_id, Finding.resource_id)
            .join(Finding, Finding.id == RiskFinding.finding_id)
            .where(RiskFinding.risk_id.in_(risk_ids))
        )
    ).tuples():
        members[risk_id].append(Member(finding_id, rule_id, resource_id))

    finding_ids = [member.id for found in members.values() for member in found]
    events: dict[UUID, list[FindingEventRecord]] = defaultdict(list)
    if finding_ids:
        for event in (
            await session.execute(
                select(FindingEventRecord)
                .where(
                    FindingEventRecord.finding_id.in_(finding_ids),
                    FindingEventRecord.created_at > since,
                )
                .order_by(FindingEventRecord.created_at)
            )
        ).scalars():
            events[event.finding_id].append(event)

    resource_ids = {m.resource_id for found in members.values() for m in found if m.resource_id}
    appeared = await _appeared(session, resource_ids, since) if resource_ids else set()
    versions_now = rule_versions()

    def rule_changed(member: Member) -> bool:
        return versions_then.get(member.rule_id) != versions_now.get(member.rule_id)

    return {
        risk_id: classify(
            rise,
            members=members.get(risk_id, []),
            events=events,
            exists=risk_id in existing,
            moved=risk_id in moved,
            rule_changed=rule_changed,
            appeared=appeared,
        )
        for risk_id, rise in rises.items()
    }


async def _appeared(session: AsyncSession, resource_ids: set[UUID], since: datetime) -> set[UUID]:
    """Assets first seen, or seen again after going, since the earlier reading."""
    first_seen = select(ResourceRecord.id).where(
        ResourceRecord.id.in_(resource_ids), ResourceRecord.first_seen_at > since
    )
    returned = select(AssetChangeEvent.resource_id).where(
        AssetChangeEvent.resource_id.in_(resource_ids),
        AssetChangeEvent.change == AssetChange.APPEARED,
        AssetChangeEvent.created_at > since,
    )
    return set((await session.execute(first_seen.union(returned))).scalars())


def classify(
    rise: float,
    *,
    members: Iterable[Member],
    events: Mapping[UUID, list[FindingEventRecord]],
    exists: bool,
    moved: bool,
    rule_changed: Callable[[Member], bool],
    appeared: set[UUID],
) -> tuple[Cause, UUID | None]:
    """One risk's cause, from what its findings did since the earlier reading.

    ``moved``: the risk was charged in both readings, at another band. A risk
    that rose is explained by the first of its findings to open; one that fell
    by the last to close, since that is what took the charge off.
    """
    found = list(members)
    if not exists:
        return Cause.ASSETS_REMOVED, None
    if moved:
        changed = next((member for member in found if rule_changed(member)), None)
        if changed is not None:
            return Cause.RULES_CHANGED, changed.id
        return Cause.CONTEXT_CHANGED, found[0].id if found else None

    by_id = {member.id: member for member in found}
    timeline = sorted(
        (event for member in found for event in events.get(member.id, [])),
        key=lambda event: event.created_at,
    )
    if rise > 0:
        opening = [
            e for e in timeline if e.current_status in OPEN and e.previous_status not in OPEN
        ]
        if not opening:
            return Cause.UNEXPLAINED, None
        event = opening[0]
        member = by_id[event.finding_id]
        if event.event == FindingEvent.STATUS_CHANGED:
            expired = event.user_id is None and event.previous_status == FindingStatus.ACCEPTED_RISK
            return (Cause.ACCEPTANCES_EXPIRED if expired else Cause.BY_HAND), member.id
        if rule_changed(member):
            return Cause.RULES_CHANGED, member.id
        if member.resource_id is not None and member.resource_id in appeared:
            return Cause.ASSETS_APPEARED, member.id
        return Cause.NEW_FAILURES, member.id

    closing = [e for e in timeline if e.previous_status in OPEN and e.current_status not in OPEN]
    if not closing:
        return Cause.UNEXPLAINED, None
    event = closing[-1]
    member = by_id[event.finding_id]
    if event.event == FindingEvent.RISK_ACCEPTED:
        return Cause.ACCEPTED, member.id
    if event.event == FindingEvent.RESOLVED and event.user_id is None:
        return (Cause.RULES_CHANGED if rule_changed(member) else Cause.FIXES_VERIFIED), member.id
    return Cause.BY_HAND, member.id


async def _examples(session: AsyncSession, finding_ids: list[UUID]) -> dict[UUID, dict]:
    if not finding_ids:
        return {}
    rows = await session.execute(
        select(Finding.id, Finding.title, Finding.severity, Finding.rule_id, Finding.status).where(
            Finding.id.in_(finding_ids)
        )
    )
    return {
        finding_id: {
            "id": finding_id,
            "title": title,
            "severity": severity,
            "rule_id": rule_id,
            "status": status,
        }
        for finding_id, title, severity, rule_id, status in rows.tuples()
    }
