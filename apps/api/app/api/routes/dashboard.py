from fastapi import APIRouter

from app.core.deps import DbSession, Tenant
from app.schemas.common import ERROR_RESPONSES, Envelope, NoMeta
from app.schemas.dashboard import DashboardOut
from app.services.dashboard import build_dashboard

router = APIRouter(prefix="/dashboard", tags=["dashboard"], responses=ERROR_RESPONSES)


@router.get("")
async def get_dashboard(session: DbSession, tenant: Tenant) -> Envelope[DashboardOut, NoMeta]:
    dashboard = await build_dashboard(session, tenant.organization_id)
    return Envelope(data=DashboardOut.model_validate(dashboard), meta=NoMeta())
