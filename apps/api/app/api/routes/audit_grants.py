"""Grants: who may read a sealed package, made and withdrawn by owners and administrators.

A grant is one address's right to read one package until a date (DECISIONS.md section 211). It is
a collection of its own and not a sub-collection of the package, because its revoke and its events
would otherwise sit four segments deep. Nothing here reads a package for an auditor: that is
``/auditor``, through functions that check the grant on every call.

There is no ``PATCH``: a grant changes only by being revoked, and a different address or a longer
time is a new grant, which replaces the old one. ``DELETE`` revokes and keeps the row as history,
as it does for an invitation.
"""

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Query, Request, Response, status

from app.api.links import created
from app.core.deps import DbSession, Tenant
from app.models.audit_grant import AuditGrant
from app.schemas.audit_grant import (
    AuditGrantCreate,
    AuditGrantCreatedOut,
    AuditGrantEventOut,
    AuditGrantOut,
    AuditGrantRevokedOut,
)
from app.schemas.common import ERROR_RESPONSES, Envelope, NoMeta, PageMeta, error_responses
from app.services import audit_grants as service

router = APIRouter(prefix="/audit-grants", tags=["audit-grants"], responses=ERROR_RESPONSES)

ADMIN_ONLY = error_responses(403)


def _out(grant: AuditGrant) -> AuditGrantOut:
    return AuditGrantOut(
        id=grant.id,
        package_id=grant.package_id,
        email=grant.email,
        status=service.grant_status(grant, datetime.now(UTC)),
        created_by=grant.created_by,
        created_at=grant.created_at,
        expires_at=grant.expires_at,
        opened_at=grant.opened_at,
        revoked_at=grant.revoked_at,
    )


@router.post("", status_code=status.HTTP_201_CREATED, responses=ADMIN_ONLY)
async def create_audit_grant(
    payload: AuditGrantCreate,
    request: Request,
    response: Response,
    session: DbSession,
    tenant: Tenant,
) -> Envelope[AuditGrantCreatedOut, NoMeta]:
    """Let one address read one sealed package, and return the link -- this once.

    Cleave sends no email: the link is handed to whoever made the grant, to pass on however the
    team talks. It opens only for the address it was made for, after that address has signed up
    and verified it, so a link that travels further than meant reads nothing. Granting an
    address that already holds a live grant on the package replaces it.
    """
    grant, link = await service.grant(
        session, tenant, payload.package_id, str(payload.email), payload.expires_in_days
    )
    created(request, response, "get_audit_grant", grant_id=grant.id)
    return Envelope(data=AuditGrantCreatedOut(**_out(grant).model_dump(), link=link), meta=NoMeta())


@router.get("", responses=ADMIN_ONLY)
async def list_audit_grants(
    session: DbSession,
    tenant: Tenant,
    package_id: UUID | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> Envelope[list[AuditGrantOut], PageMeta]:
    """This organization's grants, newest first, ended ones included. Filter by package."""
    grants, total = await service.list_grants(
        session, tenant, package_id=package_id, limit=limit, offset=offset
    )
    return Envelope(
        data=[_out(grant) for grant in grants],
        meta=PageMeta(total=total, limit=limit, offset=offset),
    )


@router.get("/{grant_id}", responses=ADMIN_ONLY)
async def get_audit_grant(
    grant_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[AuditGrantOut, NoMeta]:
    """One grant: whom it is for, when it ends, and whether it has been opened."""
    return Envelope(data=_out(await service.get_grant(session, tenant, grant_id)), meta=NoMeta())


@router.delete("/{grant_id}", responses=error_responses(403, 409))
async def revoke_audit_grant(
    grant_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[AuditGrantRevokedOut, NoMeta]:
    """End a grant now, so its auditor reads nothing more. Kept as history; cannot be undone.

    Takes effect on the auditor's next request. A download that has already started finishes.
    ``409`` for a grant already revoked.
    """
    await service.revoke(session, tenant, grant_id)
    return Envelope(data=AuditGrantRevokedOut(revoked=grant_id), meta=NoMeta())


@router.get("/{grant_id}/events", responses=ADMIN_ONLY)
async def list_audit_grant_events(
    grant_id: UUID,
    session: DbSession,
    tenant: Tenant,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> Envelope[list[AuditGrantEventOut], PageMeta]:
    """What was done through a grant: when it was opened and when its archive was taken.

    The only trail of an auditor's reading. They have no tenant, so their reads are not in the
    organization's audit log. A refused attempt leaves no event, and is in the server's log.
    """
    events, total = await service.list_events(session, tenant, grant_id, limit=limit, offset=offset)
    return Envelope(
        # Validated, not constructed: the table's check allows the two names the model does, and
        # a third would fail here and not be drawn.
        data=[AuditGrantEventOut.model_validate(event, from_attributes=True) for event in events],
        meta=PageMeta(total=total, limit=limit, offset=offset),
    )
