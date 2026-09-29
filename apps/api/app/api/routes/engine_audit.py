"""Where the two engines disagreed (DECISIONS.md section 150)."""

from uuid import UUID

from fastapi import APIRouter

from app.core.deps import DbSession, Tenant
from app.schemas.common import ERROR_RESPONSES, Envelope, NoMeta
from app.schemas.engine_audit import EngineAuditOut
from app.services import engine_audit as audit_service

router = APIRouter(prefix="/engine-audit", tags=["engine audit"], responses=ERROR_RESPONSES)


@router.get("")
async def get_engine_audit(
    session: DbSession, tenant: Tenant, scan_id: UUID | None = None
) -> Envelope[EngineAuditOut, NoMeta]:
    """What the extended checks ran, what they could not read, and every asset
    where a Cleave rule and the Prowler checks answering the same question
    disagreed -- for one scan, or the newest the second engine ran in."""
    audit = await audit_service.audit(session, tenant.organization_id, scan_id)
    return Envelope(data=EngineAuditOut.model_validate(audit), meta=NoMeta())
