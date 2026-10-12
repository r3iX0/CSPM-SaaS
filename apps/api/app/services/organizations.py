"""Organization creation and membership."""

import re
import secrets
from uuid import UUID

from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import commit_unless_externally_managed
from app.core.deps import TenantContext
from app.core.enums import OrganizationMode, Role
from app.core.errors import ConflictError, OrganizationNotFound, PermissionDenied
from app.core.security import AuthenticatedUser
from app.models.organization import Organization, OrganizationInvitation, OrganizationMember
from app.schemas.organization import FixWithinDays, OrganizationCreate, OrganizationUpdate
from app.services import audit

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


async def is_member(session: AsyncSession, organization_id: UUID, user_id: UUID) -> bool:
    """Whether ``user_id`` belongs to this organization.

    Read under the caller's row-level security, which shows a member everyone
    else in their own organizations -- except the demo, where a visitor sees only
    themselves, and nothing is written there anyway.
    """
    found = (
        await session.execute(
            select(OrganizationMember.id).where(
                OrganizationMember.organization_id == organization_id,
                OrganizationMember.user_id == user_id,
            )
        )
    ).scalar_one_or_none()
    return found is not None


async def get_organization(session: AsyncSession, organization_id: UUID) -> Organization:
    """An organization the caller belongs to.

    Row-level security hides any other tenant's row, so a missing one reads the same whether it
    does not exist or is somebody else's: both are the honest ``404`` rather than a ``None``
    that propagates.
    """
    org = await session.get(Organization, organization_id)
    if org is None:
        raise OrganizationNotFound()
    return org


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

    changes = payload.model_dump(exclude_unset=True)
    if changes.get("mode") == OrganizationMode.SOLO and org.mode != OrganizationMode.SOLO:
        await _require_alone(session, org.id)
    solo = changes.get("mode", org.mode) == OrganizationMode.SOLO
    if changes.get("acceptance_approval_from") is not None and solo:
        raise ConflictError("A second approver needs a second person; switch to a team first")
    if "fix_within_days" in changes:
        # The policy is sent whole: a severity left out is cleared, null clears them all, and the
        # audit row records the policy that resulted rather than the keys that were sent (§225).
        changes["fix_within_days"] = (payload.fix_within_days or FixWithinDays()).model_dump()
    for field, value in changes.items():
        if field == "fix_within_days":
            for severity, days in value.items():
                setattr(org, f"fix_within_days_{severity}", days)
        else:
            setattr(org, field, value)
    await audit.record(
        session, tenant, "organization.updated", "organization", org.id, {"changed": changes}
    )

    # Not ``session.commit()``. On the API path this session is inside
    # ``rls_session``'s ``session.begin()``, and committing there tears down the
    # transaction-scoped ``SET LOCAL ROLE authenticated`` that RLS depends on.
    await commit_unless_externally_managed(session)
    return org


async def _require_alone(session: AsyncSession, organization_id: UUID) -> None:
    """Refuse solo while anybody else is in the organization or invited to it (§236).

    Solo hides members and invitations, so switching with somebody else there would leave a
    colleague nobody can see or remove, and an open invitation that would bring one in.
    """
    others = (
        await session.execute(
            select(func.count())
            .select_from(OrganizationMember)
            .where(OrganizationMember.organization_id == organization_id)
        )
    ).scalar_one()
    invited = (
        await session.execute(
            select(func.count())
            .select_from(OrganizationInvitation)
            .where(
                OrganizationInvitation.organization_id == organization_id,
                OrganizationInvitation.accepted_at.is_(None),
                OrganizationInvitation.revoked_at.is_(None),
                OrganizationInvitation.expires_at > func.now(),
            )
        )
    ).scalar_one()
    if others > 1 or invited:
        raise ConflictError(
            "Solo is for one person: remove the other members and withdraw open invitations first"
        )


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
            raise OrganizationNotFound("The demo is not available on this deployment yet.") from exc
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
