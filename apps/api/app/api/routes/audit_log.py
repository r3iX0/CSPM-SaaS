"""Who changed what in this organization (DECISIONS.md section 163)."""

from uuid import UUID

from fastapi import APIRouter, Query

from app.core.deps import DbSession, Tenant
from app.models.remediation import AuditLog
from app.schemas.audit_log import AuditEntryOut
from app.schemas.common import ERROR_RESPONSES, Envelope, PageMeta, error_responses
from app.services import audit as service

router = APIRouter(prefix="/audit-log", tags=["audit"], responses=ERROR_RESPONSES)


def _entry(entry: AuditLog, email: str | None) -> AuditEntryOut:
    details = dict(entry.audit_metadata or {})
    # Carried on its own field, so the details are only what the change was.
    request_id = details.pop("request_id", None)
    return AuditEntryOut(
        id=entry.id,
        action=entry.action,
        resource_type=entry.resource_type,
        resource_id=entry.resource_id,
        actor_id=entry.user_id,
        actor_email=email,
        ip_address=str(entry.ip_address) if entry.ip_address is not None else None,
        request_id=request_id if isinstance(request_id, str) else None,
        details=details,
        created_at=entry.created_at,
    )


@router.get("", responses=error_responses(403))
async def list_audit_log(
    session: DbSession,
    tenant: Tenant,
    action: str | None = Query(default=None, min_length=1, max_length=64),
    actor: UUID | None = None,
    resource_type: str | None = Query(default=None, min_length=1, max_length=64),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> Envelope[list[AuditEntryOut], PageMeta]:
    """The audit trail, newest first. Owners and admins.

    ``action`` is one verb (``member.removed``) or, ending in a dot, a family
    (``member.``). Entries cannot be edited or deleted by anybody through any
    path the application has -- the database refuses it.
    """
    rows, total = await service.list_entries(
        session,
        tenant,
        action=action,
        actor=actor,
        resource_type=resource_type,
        limit=limit,
        offset=offset,
    )
    return Envelope(
        data=[_entry(entry, email) for entry, email in rows],
        meta=PageMeta(total=total, limit=limit, offset=offset),
    )
