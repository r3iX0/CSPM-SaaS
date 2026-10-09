"""Acceptances waiting for a second approver, and the decision on them (DECISIONS.md §239).

An acceptance is asked for where it always was -- ``POST /findings/{id}/accept-risk`` and the
risks triage -- and waits here when the organization's policy covers its severity. Members read
the list; an owner or an admin other than the person who asked approves or rejects. Approve and
reject are actions on the item, as accept-risk is: each is a state transition with its own rules
and audit trail, not a field somebody edits.
"""

from uuid import UUID

from fastapi import APIRouter, Query

from app.core.deps import DbSession, Tenant
from app.core.enums import ExceptionStatus
from app.schemas.acceptance import AcceptanceOut, AcceptanceReject
from app.schemas.common import ERROR_RESPONSES, Envelope, NoMeta, PageMeta, error_responses
from app.services import approvals as service

router = APIRouter(prefix="/acceptances", tags=["acceptances"], responses=ERROR_RESPONSES)


def acceptance_out(request: service.Request) -> AcceptanceOut:
    exception = request.exception
    return AcceptanceOut(
        id=exception.id,
        finding_id=exception.finding_id,
        risk_id=exception.risk_id,
        subject_title=request.subject_title,
        subject_severity=request.subject_severity,
        subject_status=request.subject_status,
        reason=exception.reason,
        expires_at=exception.expires_at,
        status=exception.status,
        requested_by=exception.requested_by,
        requested_by_email=request.requested_by_email,
        created_at=exception.created_at,
        decided_by=exception.decided_by,
        decided_by_email=request.decided_by_email,
        decided_at=exception.decided_at,
        decision_note=exception.decision_note,
    )


@router.get("")
async def list_acceptances(
    session: DbSession,
    tenant: Tenant,
    status: ExceptionStatus = Query(default=ExceptionStatus.PENDING),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> Envelope[list[AcceptanceOut], PageMeta]:
    """Acceptances that asked for a second approver, in one status, newest first."""
    requests, total = await service.list_requests(
        session, tenant, status=status, limit=limit, offset=offset
    )
    return Envelope(
        data=[acceptance_out(request) for request in requests],
        meta=PageMeta(total=total, limit=limit, offset=offset),
    )


@router.post("/{acceptance_id}/approve", responses=error_responses(403, 404, 409))
async def approve_acceptance(
    acceptance_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[AcceptanceOut, NoMeta]:
    """Approve a waiting acceptance; it takes effect with the approver named on it.

    ``403`` for the person who asked, or anyone but an owner or an admin. ``409`` once it is
    decided, its date has passed, or the finding or route has moved on since.
    """
    exception = await service.approve(session, tenant, acceptance_id)
    return Envelope(
        data=acceptance_out(await service.describe(session, tenant, exception)), meta=NoMeta()
    )


@router.post("/{acceptance_id}/reject", responses=error_responses(403, 404, 409))
async def reject_acceptance(
    acceptance_id: UUID, payload: AcceptanceReject, session: DbSession, tenant: Tenant
) -> Envelope[AcceptanceOut, NoMeta]:
    """Turn a waiting acceptance down, saying why; nothing about the finding or route changes."""
    exception = await service.reject(session, tenant, acceptance_id, payload.note)
    return Envelope(
        data=acceptance_out(await service.describe(session, tenant, exception)), meta=NoMeta()
    )
