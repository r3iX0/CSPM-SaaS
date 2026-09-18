"""Organization creation and membership."""

import re
import secrets
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import commit_unless_externally_managed
from app.core.deps import TenantContext
from app.core.enums import Role
from app.core.errors import OrganizationNotFound, PermissionDenied
from app.core.security import AuthenticatedUser
from app.models.organization import Organization, OrganizationMember
from app.schemas.organization import OrganizationCreate, OrganizationUpdate

_SLUG_STRIP = re.compile(r"[^a-z0-9]+")


def slugify(name: str) -> str:
    base = _SLUG_STRIP.sub("-", name.lower()).strip("-")[:40] or "org"
    # A short random suffix keeps slugs unique without a retry loop, and without
    # leaking how many organizations exist.
    return f"{base}-{secrets.token_hex(3)}"


async def create_organization(
    session: AsyncSession, user: AuthenticatedUser, payload: OrganizationCreate
) -> Organization:
    """Create an org and the caller's OWNER membership, atomically.

    Delegated to ``app.create_organization`` in the database because the creator
    is not yet a member and therefore cannot satisfy any membership-based RLS
    policy. Doing it in one SECURITY DEFINER function avoids widening the
    policies to a hole big enough to drive a tenant through.
    """
    result = await session.execute(
        text("SELECT app.create_organization(:name, :slug, :industry, :country) AS id"),
        {
            "name": payload.name,
            "slug": slugify(payload.name),
            "industry": payload.industry,
            "country": payload.country,
        },
    )
    org_id = result.scalar_one()
    await session.flush()

    org = await session.get(Organization, org_id)
    if org is None:  # pragma: no cover -- would mean the function lied to us
        raise OrganizationNotFound("Organization creation failed")
    return org


async def list_memberships(
    session: AsyncSession, user: AuthenticatedUser
) -> list[tuple[Organization, Role]]:
    stmt = (
        select(Organization, OrganizationMember.role)
        .join(OrganizationMember, OrganizationMember.organization_id == Organization.id)
        .where(OrganizationMember.user_id == user.id)
        # Own organizations first: the client defaults to the first one, and
        # the demo is somewhere to look, not somewhere to land.
        .order_by(Organization.is_demo, Organization.created_at)
    )
    rows = (await session.execute(stmt)).all()
    return [(org, Role(role)) for org, role in rows]


async def update_organization(
    session: AsyncSession,
    tenant: TenantContext,
    payload: OrganizationUpdate,
) -> Organization:
    """Correct how an organization describes itself. Owners and admins.

    Scoped to the organization the request is already acting in rather than an
    id in the path: unlike deletion, there is no reason to edit a *different*
    organization from the one on screen, and taking the id from the tenant
    context means the membership check has already happened.

    Only the fields present in the payload are written. ``model_dump`` with
    ``exclude_unset`` is what makes that true -- without it, a form that submits
    a name would post ``country: null`` and clear a value nobody edited.
    """
    tenant.require_role(Role.OWNER, Role.ADMIN)

    org = await session.get(Organization, tenant.organization_id)
    if org is None:  # pragma: no cover -- the tenant context resolved it
        raise OrganizationNotFound()

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(org, field, value)

    # Not ``session.commit()``. On the API path this session is inside
    # ``rls_session``'s ``session.begin()``, and committing there tears down the
    # transaction-scoped ``SET LOCAL ROLE authenticated`` that RLS depends on.
    await commit_unless_externally_managed(session)
    return org


async def delete_organization(
    session: AsyncSession, user: AuthenticatedUser, organization_id: UUID
) -> None:
    """Delete an organization and everything under it. Owners only.

    The membership check here is not a duplicate of the RLS policy, it is the
    part that can *speak*. RLS filters rows rather than raising: a member who is
    not an owner issues a DELETE that matches nothing and gets a cheerful 200
    while the organization stands. Checking first turns that into a 403 that
    says why.

    Everything below an organization is removed with it -- connections,
    discovered subscriptions, assets, scans, findings, risks and audit history,
    fourteen tables in all, by ``ON DELETE CASCADE``. There is no soft delete
    and no undo.
    """
    membership = (
        await session.execute(
            select(OrganizationMember).where(
                OrganizationMember.organization_id == organization_id,
                OrganizationMember.user_id == user.id,
            )
        )
    ).scalar_one_or_none()

    # Indistinguishable from "does not exist", deliberately: a non-member
    # learning that an organization exists is a small leak, but a free one.
    if membership is None:
        raise OrganizationNotFound()

    if Role(membership.role) != Role.OWNER:
        raise PermissionDenied("Only an owner can delete an organization")

    organization = await session.get(Organization, organization_id)
    if organization is None:  # pragma: no cover -- membership implies existence
        raise OrganizationNotFound()
    # Nobody owns the demo, but this is the one path that checks a role without
    # going through the tenant context, so it says so itself.
    if organization.is_demo:
        raise PermissionDenied("The demo organization cannot be deleted. Leave it instead.")

    await session.delete(organization)
    await commit_unless_externally_managed(session)


async def join_demo(session: AsyncSession, user: AuthenticatedUser) -> Organization:
    """Add the caller to the shared demo organization, as VIEWER.

    Through ``app.join_demo_organization``, for the reason creation goes through
    its own function: the caller is not a member yet, so no membership policy
    lets them insert themselves -- correctly, for every other organization. The
    role is fixed inside the function, so nothing the client sends can make
    somebody more than a viewer of the demo. Joining twice is a no-op.
    """
    try:
        org_id = (
            await session.execute(text("SELECT app.join_demo_organization() AS id"))
        ).scalar_one()
    except DBAPIError as exc:
        if "no demo organization" in str(exc.orig):
            raise OrganizationNotFound(
                "The demo is not available on this deployment yet."
            ) from exc
        raise
    await commit_unless_externally_managed(session)

    org = await session.get(Organization, org_id)
    if org is None:  # pragma: no cover -- the function just granted visibility
        raise OrganizationNotFound()
    return org


async def leave_demo(session: AsyncSession) -> None:
    """Remove the caller's own demo membership, and nothing else."""
    await session.execute(text("SELECT app.leave_demo_organization()"))
    await commit_unless_externally_managed(session)
