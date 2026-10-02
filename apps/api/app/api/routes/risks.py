from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Query

from app.core.deps import DbSession, Tenant
from app.core.enums import Level, RiskKind, RiskStatus
from app.models.risk import Risk
from app.schemas.common import ERROR_RESPONSES, Envelope, NoMeta, PageMeta, error_responses
from app.schemas.finding import (
    BulkRiskStatusRequest,
    RiskDetailOut,
    RiskListItemOut,
    RiskMemberOut,
    RiskOut,
    RiskStatusOut,
    RiskStatusRequest,
)
from app.services import risks as service

router = APIRouter(prefix="/risks", tags=["risks"], responses=ERROR_RESPONSES)


@router.get("")
async def list_risks(
    session: DbSession,
    tenant: Tenant,
    risk_level: Level | None = None,
    risk_status: RiskStatus | None = Query(default=None, alias="status"),
    kind: RiskKind | None = None,
    search: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Envelope[list[RiskListItemOut], PageMeta]:
    """The live risks, worst first; ask for a status by name to reach the settled ones.

    A risk is live unless its findings say it is over (``service.list_risks`` holds the rule and
    why it is "settled" rather than "strict").
    """
    rows, total = await service.list_risks(
        session,
        tenant,
        level=risk_level,
        status=risk_status,
        kind=kind,
        search=search,
        limit=limit,
        offset=offset,
    )

    risk_ids = [r.id for r in rows]
    finding_counts, route_counts = await service.open_counts(session, risk_ids)
    expiries = await service.member_expiries(session, risk_ids)
    return Envelope(
        data=[
            RiskListItemOut(
                **_risk_out(r, expiries).model_dump(),
                finding_count=finding_counts.get(r.id, 0),
                route_count=route_counts.get(r.id, 0),
            )
            for r in rows
        ],
        meta=PageMeta(total=total, limit=limit, offset=offset),
    )


def _risk_out(risk: Risk, expiries: dict[UUID, datetime]) -> RiskOut:
    """A risk as the API shows it, with a finding risk's expiry read from its members."""
    out = RiskOut.model_validate(risk)
    if risk.kind == RiskKind.FINDING:
        out.accepted_until = expiries.get(risk.id)
    return out


@router.post("/status", responses=error_responses(403))
async def set_risks_status(
    payload: BulkRiskStatusRequest, session: DbSession, tenant: Tenant
) -> Envelope[list[RiskStatusOut], NoMeta]:
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
    return Envelope(data=[RiskStatusOut.model_validate(r) for r in risks], meta=NoMeta())


@router.post("/{risk_id}/status", responses=error_responses(403))
async def set_risk_status(
    risk_id: UUID, payload: RiskStatusRequest, session: DbSession, tenant: Tenant
) -> Envelope[RiskOut, NoMeta]:
    """One decision about one risk: open it, start work on it, or accept it with a reason."""
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
    expiries = await service.member_expiries(session, [risk.id])
    return Envelope(data=_risk_out(risk, expiries), meta=NoMeta())


@router.get("/{risk_id}")
async def get_risk(
    risk_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[RiskDetailOut, NoMeta]:
    """One risk with the findings it covers and when its route was last seen."""
    risk, findings, observed_at = await service.get_risk_detail(session, tenant, risk_id)
    expiries = await service.member_expiries(session, [risk.id])
    return Envelope(
        data=RiskDetailOut(
            **_risk_out(risk, expiries).model_dump(),
            observed_at=observed_at,
            findings=[RiskMemberOut.model_validate(f) for f in findings],
        ),
        meta=NoMeta(),
    )
