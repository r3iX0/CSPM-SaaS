from fastapi import APIRouter

from app.core.deps import DbSession, Tenant
from app.schemas.common import ERROR_RESPONSES, Envelope, NoMeta
from app.schemas.dashboard import DashboardOut, ScoreMovementOut
from app.services import score_movement
from app.services.dashboard import build_dashboard

router = APIRouter(prefix="/dashboard", tags=["dashboard"], responses=ERROR_RESPONSES)


@router.get("")
async def get_dashboard(session: DbSession, tenant: Tenant) -> Envelope[DashboardOut, NoMeta]:
    dashboard = await build_dashboard(session, tenant.organization_id)
    return Envelope(data=DashboardOut.model_validate(dashboard), meta=NoMeta())


@router.get("/score-movement")
async def get_score_movement(
    session: DbSession, tenant: Tenant
) -> Envelope[ScoreMovementOut, NoMeta]:
    """Why the score moved since the reading before the latest scan, cause by cause.

    The causes' points sum to ``delta``, which is the dashboard's ``score_delta``.
    """
    movement = await score_movement.explain(session, tenant.organization_id)
    return Envelope(data=ScoreMovementOut.model_validate(movement), meta=NoMeta())
