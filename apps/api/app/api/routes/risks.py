from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Query
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased

from app.core.deps import DbSession, Tenant
from app.core.enums import ExceptionStatus, FindingStatus, Level, RiskKind, RiskStatus
from app.core.errors import NotFound, envelope
from app.models.finding import Finding
from app.models.remediation import RiskException
from app.models.risk import Risk, RiskFinding
from app.models.scan import Scan
from app.schemas.finding import BulkRiskStatusRequest, RiskOut, RiskStatusRequest
from app.services import risks as service

_OPEN_FINDINGS = (FindingStatus.OPEN, FindingStatus.IN_PROGRESS)

router = APIRouter(prefix="/risks", tags=["risks"])


@router.get("")
async def list_risks(
    session: DbSession,
    tenant: Tenant,
    risk_level: Level | None = None,
    risk_status: RiskStatus | None = Query(default=None, alias="status"),
    kind: RiskKind | None = None,
    search: str | None = None,
    limit: int = Query(default=100, le=500),
    offset: int = 0,
) -> dict:
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
    if risk_status is None:
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

    if risk_level:
        stmt = stmt.where(Risk.risk_level == risk_level)
    if risk_status:
        stmt = stmt.where(Risk.status == risk_status)
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
        stmt = stmt.where(
            or_(Risk.title.ilike(needle), Risk.description.ilike(needle))
        )

    total = (
        await session.execute(select(func.count()).select_from(stmt.subquery()))
    ).scalar_one()

    rows = (
        (
            await session.execute(
                stmt.order_by(Risk.risk_score.desc()).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )

    finding_counts, route_counts = await _counts(session, [r.id for r in rows])
    expiries = await _member_expiries(session, [r.id for r in rows])
    return envelope(
        [
            {
                **_risk_out(r, expiries),
                "finding_count": finding_counts.get(r.id, 0),
                "route_count": route_counts.get(r.id, 0),
            }
            for r in rows
        ],
        {"total": total, "limit": limit, "offset": offset},
    )


def _risk_out(risk: Risk, expiries: dict[UUID, datetime]) -> dict:
    """A risk as the API shows it, with a finding risk's expiry read from its members."""
    out = RiskOut.model_validate(risk)
    out.status = risk.status
    if risk.kind == RiskKind.FINDING:
        out.accepted_until = expiries.get(risk.id)
    return out.model_dump(mode="json")


async def _member_expiries(
    session: AsyncSession, risk_ids: list[UUID]
) -> dict[UUID, datetime]:
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


async def _counts(
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
        ).tuples()
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
        ).tuples()
    )
    return findings, routes


@router.post("/status")
async def set_risks_status(
    payload: BulkRiskStatusRequest, session: DbSession, tenant: Tenant
) -> dict:
    """One decision about several risks, applied to all of them or to none."""
    tenant.require_write()
    risks = await service.get_risks(session, tenant, payload.risk_ids)
    risks = await service.set_status(
        session,
        tenant,
        risks,
        payload.status,
        reason=payload.reason,
        expires_at=payload.expires_at,
    )
    return envelope([{"id": str(r.id), "status": r.status} for r in risks])


@router.post("/{risk_id}/status")
async def set_risk_status(
    risk_id: UUID, payload: RiskStatusRequest, session: DbSession, tenant: Tenant
) -> dict:
    tenant.require_write()
    risks = await service.get_risks(session, tenant, [risk_id])
    [risk] = await service.set_status(
        session,
        tenant,
        risks,
        payload.status,
        reason=payload.reason,
        expires_at=payload.expires_at,
    )
    return envelope(_risk_out(risk, await _member_expiries(session, [risk.id])))


@router.get("/{risk_id}")
async def get_risk(risk_id: UUID, session: DbSession, tenant: Tenant) -> dict:
    risk = (
        await session.execute(
            select(Risk).where(
                Risk.id == risk_id, Risk.organization_id == tenant.organization_id
            )
        )
    ).scalar_one_or_none()
    if risk is None:
        raise NotFound("Risk not found")

    # 1:1 with findings today; the join already supports many.
    findings = (
        (
            await session.execute(
                select(Finding)
                .join(RiskFinding, RiskFinding.finding_id == Finding.id)
                .where(RiskFinding.risk_id == risk_id)
            )
        )
        .scalars()
        .all()
    )

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

    return envelope(
        {
            **_risk_out(risk, await _member_expiries(session, [risk.id])),
            # ``None`` where a route predates this being tracked, or where the
            # scan that saw it has been pruned. Both mean "we cannot say when",
            # which the page must not render as "just now".
            "observed_at": observed_at.isoformat() if observed_at else None,
            "findings": [
                {
                    "id": str(f.id),
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "status": f.status,
                }
                for f in findings
            ],
        }
    )
