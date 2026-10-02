"""Members of the current organization, and invitations into it (DECISIONS.md section 162)."""

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Request, Response, status

from app.api.links import created
from app.core.deps import CurrentUser, DbSession, Tenant
from app.models.organization import OrganizationInvitation, OrganizationMember
from app.schemas.common import ERROR_RESPONSES, Envelope, NoMeta, error_responses
from app.schemas.organization import OrganizationMembershipOut, OrganizationOut
from app.schemas.team import (
    InvitationCreate,
    InvitationCreatedOut,
    InvitationOut,
    InvitationPreviewOut,
    InvitationRevokedOut,
    InvitationToken,
    MemberOut,
    MemberRemovedOut,
    MemberUpdate,
)
from app.services import team as service

router = APIRouter(tags=["team"], responses=ERROR_RESPONSES)

WRITE = error_responses(403, 409)


def _member(member: OrganizationMember, you: UUID) -> MemberOut:
    return MemberOut(
        id=member.id,
        user_id=member.user_id,
        email=member.email,
        role=member.role,
        joined_at=member.created_at,
        is_you=member.user_id == you,
    )


def _invitation(invitation: OrganizationInvitation) -> InvitationOut:
    return InvitationOut(
        id=invitation.id,
        email=invitation.email,
        role=invitation.role,
        status=service.invitation_status(invitation, datetime.now(UTC)),
        invited_by=invitation.invited_by,
        created_at=invitation.created_at,
        expires_at=invitation.expires_at,
    )


@router.get("/members")
async def list_members(session: DbSession, tenant: Tenant) -> Envelope[list[MemberOut], NoMeta]:
    """Everyone in this organization. Any member may ask."""
    members = await service.list_members(session, tenant)
    return Envelope(data=[_member(m, tenant.user.id) for m in members], meta=NoMeta())


@router.patch("/members/{member_id}", responses=WRITE)
async def change_member_role(
    member_id: UUID, payload: MemberUpdate, session: DbSession, tenant: Tenant
) -> Envelope[MemberOut, NoMeta]:
    """Change what a member may do. Owners and admins; only an owner touches an owner."""
    member = await service.change_role(session, tenant, member_id, payload.role)
    return Envelope(data=_member(member, tenant.user.id), meta=NoMeta())


@router.delete("/members/{member_id}", responses=WRITE)
async def remove_member(
    member_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[MemberRemovedOut, NoMeta]:
    """Take somebody out of this organization. The last owner cannot be removed."""
    await service.remove_member(session, tenant, member_id)
    return Envelope(data=MemberRemovedOut(removed=member_id), meta=NoMeta())


@router.get("/invitations", responses=error_responses(403))
async def list_invitations(
    session: DbSession, tenant: Tenant
) -> Envelope[list[InvitationOut], NoMeta]:
    """Invitations waiting to be used, expired ones included. Owners and admins."""
    invitations = await service.list_invitations(session, tenant)
    return Envelope(data=[_invitation(i) for i in invitations], meta=NoMeta())


@router.post("/invitations", status_code=status.HTTP_201_CREATED, responses=WRITE)
async def create_invitation(
    payload: InvitationCreate,
    request: Request,
    response: Response,
    session: DbSession,
    tenant: Tenant,
) -> Envelope[InvitationCreatedOut, NoMeta]:
    """Invite an address, and return the link -- this once.

    CloudGuard sends no email: the link is handed to whoever invited, to pass on
    however their team talks. It works only for the invited address, so a link
    that travels further than meant joins nobody.
    """
    invitation, link = await service.invite(session, tenant, str(payload.email), payload.role)
    created(request, response, "revoke_invitation", invitation_id=invitation.id)
    return Envelope(
        data=InvitationCreatedOut(**_invitation(invitation).model_dump(), link=link),
        meta=NoMeta(),
    )


@router.delete("/invitations/{invitation_id}", responses=WRITE)
async def revoke_invitation(
    invitation_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[InvitationRevokedOut, NoMeta]:
    """Withdraw an invitation, so its link stops working. Kept as history."""
    await service.revoke(session, tenant, invitation_id)
    return Envelope(data=InvitationRevokedOut(revoked=invitation_id), meta=NoMeta())


# The two below act for somebody who is not a member yet, so they take the
# signed-in user rather than a tenant: there is no organization to resolve.


@router.post("/invitations/preview")
async def preview_invitation(
    payload: InvitationToken, user: CurrentUser, session: DbSession
) -> Envelope[InvitationPreviewOut, NoMeta]:
    """What an invitation link offers, before it is used."""
    return Envelope(
        data=InvitationPreviewOut(**await service.preview(session, user, payload.token)),
        meta=NoMeta(),
    )


@router.post("/invitations/accept", responses=error_responses(403, 409))
async def accept_invitation(
    payload: InvitationToken, user: CurrentUser, session: DbSession
) -> Envelope[OrganizationMembershipOut, NoMeta]:
    """Join the organization an invitation names, as the invited address."""
    organization, role = await service.accept(session, user, payload.token)
    return Envelope(
        data=OrganizationMembershipOut(
            **OrganizationOut.model_validate(organization).model_dump(), role=role
        ),
        meta=NoMeta(),
    )
