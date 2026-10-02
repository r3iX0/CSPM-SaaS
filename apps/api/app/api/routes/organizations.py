from uuid import UUID

from fastapi import APIRouter, Request, Response, status

from app.api.links import created
from app.core.deps import CurrentUser, DbSession, Tenant
from app.core.enums import Role
from app.core.errors import OrganizationNotFound
from app.models.organization import Organization
from app.schemas.common import Envelope, NoMeta, error_responses
from app.schemas.organization import (
    LeftDemoOut,
    OrganizationCreate,
    OrganizationDeletedOut,
    OrganizationMembershipOut,
    OrganizationOut,
    OrganizationUpdate,
)
from app.services import organizations as service

# Most of these act on the caller rather than on an organization they are in,
# so a missing membership is a 404 only where a route looks one up.
router = APIRouter(
    prefix="/organizations", tags=["organizations"], responses=error_responses(401, 422)
)


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_organization(
    payload: OrganizationCreate,
    request: Request,
    response: Response,
    user: CurrentUser,
    session: DbSession,
) -> Envelope[OrganizationOut, NoMeta]:
    org = await service.create_organization(session, user, payload)
    created(request, response, "get_organization", organization_id=org.id)
    return Envelope(data=OrganizationOut.model_validate(org), meta=NoMeta())


@router.post("/demo/join", responses=error_responses(404))
async def join_demo(
    user: CurrentUser, session: DbSession
) -> Envelope[OrganizationMembershipOut, NoMeta]:
    """Open the shared demo organization, read-only.

    A recorded estate run through the real pipeline, so a new customer sees
    what CloudGuard does before connecting anything. The caller becomes a
    VIEWER, and every write in the demo is refused whatever the role.
    """
    org = await service.join_demo(session, user)
    return Envelope(data=_membership(org, Role.VIEWER), meta=NoMeta())


@router.post("/demo/leave")
async def leave_demo(user: CurrentUser, session: DbSession) -> Envelope[LeftDemoOut, NoMeta]:
    """Take the demo out of the caller's organization list."""
    await service.leave_demo(session)
    return Envelope(data=LeftDemoOut(left=True), meta=NoMeta())


@router.get("")
async def list_organizations(
    user: CurrentUser, session: DbSession
) -> Envelope[list[OrganizationMembershipOut], NoMeta]:
    memberships = await service.list_memberships(session, user)
    return Envelope(data=[_membership(org, role) for org, role in memberships], meta=NoMeta())


def _membership(org: Organization, role: Role) -> OrganizationMembershipOut:
    return OrganizationMembershipOut(**OrganizationOut.model_validate(org).model_dump(), role=role)


@router.get("/{organization_id}", responses=error_responses(404))
async def get_organization(
    organization_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[OrganizationOut, NoMeta]:
    # RLS would hide another tenant's row anyway; this returns the honest 404
    # rather than letting a NULL propagate.
    org = await session.get(Organization, organization_id)
    if org is None:
        raise OrganizationNotFound()
    return Envelope(data=OrganizationOut.model_validate(org), meta=NoMeta())


@router.patch("", responses=error_responses(403, 404))
async def update_organization(
    payload: OrganizationUpdate, session: DbSession, tenant: Tenant
) -> Envelope[OrganizationOut, NoMeta]:
    """Correct how this organization describes itself.

    No id in the path, unlike DELETE. Deleting a different organization from
    the one on screen is a real thing to want; editing one is not, and taking
    the target from the tenant context means the membership check has already
    happened rather than being repeated here.
    """
    org = await service.update_organization(session, tenant, payload)
    return Envelope(data=OrganizationOut.model_validate(org), meta=NoMeta())


@router.delete(
    "/{organization_id}", status_code=status.HTTP_200_OK, responses=error_responses(403, 404)
)
async def delete_organization(
    organization_id: UUID, user: CurrentUser, session: DbSession
) -> Envelope[OrganizationDeletedOut, NoMeta]:
    """Delete an organization and everything under it.

    Takes the id from the path rather than the tenant header: this is the one
    operation whose target is not "the organization I am currently working in",
    and resolving it from the header would make deleting a *different* one
    impossible from a single screen.
    """
    await service.delete_organization(session, user, organization_id)
    return Envelope(data=OrganizationDeletedOut(deleted=organization_id), meta=NoMeta())
