"""Who is in an organization, how they got there, and what they may do.

Two halves. Members: listed to every member, changed and removed by owners and
admins, under two rules the database's policies cannot express and this module
enforces -- only an owner makes or unmakes an owner, and the last owner stays.
Invitations: made by owners and admins, accepted by the invited address through
``app.accept_invitation`` (DECISIONS.md section 162).
"""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import commit_unless_externally_managed
from app.core.deps import TenantContext
from app.core.enums import Role
from app.core.errors import ConflictError, NotFound, PermissionDenied
from app.core.security import AuthenticatedUser
from app.models.organization import Organization, OrganizationInvitation, OrganizationMember
from app.schemas.team import InvitationStatus
from app.services import audit

# Long enough for somebody back from a week away, short enough that a link
# sitting in an old thread stops working on its own.
INVITATION_LIFETIME = timedelta(days=7)

# Where the link lands. A fragment rather than a path or a query, so the token
# is never sent to any server -- not in a Referer, not in an access log, not to
# the frontend's host -- and only the page's own script reads it.
INVITATION_PATH = "/invite#"


def token_hash(token: str) -> str:
    """What is stored and looked up. The token itself is never kept."""
    return hashlib.sha256(token.encode()).hexdigest()


def invitation_status(invitation: OrganizationInvitation, now: datetime) -> InvitationStatus:
    if invitation.accepted_at is not None:
        return "ACCEPTED"
    if invitation.revoked_at is not None:
        return "REVOKED"
    if invitation.expires_at <= now:
        return "EXPIRED"
    return "OPEN"


# ------------------------------------------------------------------- members


def check_role_change(actor: Role, current: Role, wanted: Role | None, owners: int) -> None:
    """Refuse a change to a member the actor may not make. ``wanted=None`` is removal.

    Pure, so the whole matrix is tested without a database. The caller has
    already required OWNER or ADMIN, and counted the owners under a lock.
    """
    touches_owner = current is Role.OWNER or wanted is Role.OWNER
    if touches_owner and actor is not Role.OWNER:
        raise PermissionDenied("Only an owner can make somebody an owner, or change one")
    if current is Role.OWNER and wanted is not Role.OWNER and owners <= 1:
        raise ConflictError("An organization needs an owner. Make somebody else an owner first.")


async def list_members(session: AsyncSession, tenant: TenantContext) -> list[OrganizationMember]:
    """Everyone in the organization, owners first, then by when they joined.

    Row-level security decides who is visible, and in the demo a visitor sees
    only themselves -- the other members there are strangers.
    """
    return list(
        (
            await session.execute(
                select(OrganizationMember)
                .where(OrganizationMember.organization_id == tenant.organization_id)
                .order_by(
                    OrganizationMember.role != Role.OWNER,
                    OrganizationMember.created_at,
                    OrganizationMember.id,
                )
            )
        )
        .scalars()
        .all()
    )


async def _locked_member(
    session: AsyncSession, tenant: TenantContext, member_id: UUID
) -> OrganizationMember:
    member = (
        await session.execute(
            select(OrganizationMember)
            .where(
                OrganizationMember.id == member_id,
                OrganizationMember.organization_id == tenant.organization_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if member is None:
        raise NotFound("No such member in this organization")
    return member


async def _owner_count(session: AsyncSession, tenant: TenantContext) -> int:
    """Owners, counted with their rows locked.

    Locked so two owners demoting each other at once cannot both see the other
    still standing: the second waits for the first, then re-reads and finds
    one owner left.
    """
    owners = (
        await session.execute(
            select(OrganizationMember.id)
            .where(
                OrganizationMember.organization_id == tenant.organization_id,
                OrganizationMember.role == Role.OWNER,
            )
            .with_for_update()
        )
    ).all()
    return len(owners)


async def change_role(
    session: AsyncSession, tenant: TenantContext, member_id: UUID, role: Role
) -> OrganizationMember:
    tenant.require_role(Role.OWNER, Role.ADMIN)
    member = await _locked_member(session, tenant, member_id)
    previous = Role(member.role)
    if previous is role:
        return member

    owners = await _owner_count(session, tenant) if previous is Role.OWNER else 0
    check_role_change(tenant.role, previous, role, owners)

    member.role = role
    await audit.record(
        session,
        tenant,
        "member.role_changed",
        "member",
        member.id,
        {"email": member.email, "from": previous.value, "to": role.value},
    )
    await commit_unless_externally_managed(session)
    return member


async def remove_member(session: AsyncSession, tenant: TenantContext, member_id: UUID) -> None:
    tenant.require_role(Role.OWNER, Role.ADMIN)
    member = await _locked_member(session, tenant, member_id)
    previous = Role(member.role)
    owners = await _owner_count(session, tenant) if previous is Role.OWNER else 0
    check_role_change(tenant.role, previous, None, owners)

    await audit.record(
        session,
        tenant,
        "member.removed",
        "member",
        member.id,
        {"email": member.email, "role": previous.value, "user_id": str(member.user_id)},
    )
    await session.delete(member)
    await commit_unless_externally_managed(session)


# --------------------------------------------------------------- invitations


async def invite(
    session: AsyncSession, tenant: TenantContext, email: str, role: Role
) -> tuple[OrganizationInvitation, str]:
    """Make an invitation and return it with its link, which is not stored.

    Inviting an address that already has an open invitation replaces it: the
    old link stops working and the new one is the only one. An address that is
    already a member is refused rather than invited into a role it would not
    get -- accepting never changes an existing member's role.
    """
    tenant.require_role(Role.OWNER, Role.ADMIN)
    if role is Role.OWNER:  # pragma: no cover -- the schema refuses it first
        raise PermissionDenied("Invite as another role, then make them an owner")
    email = email.strip().lower()
    now = datetime.now(UTC)

    already = (
        await session.execute(
            select(OrganizationMember.id).where(
                OrganizationMember.organization_id == tenant.organization_id,
                func.lower(OrganizationMember.email) == email,
            )
        )
    ).first()
    if already is not None:
        raise ConflictError(f"{email} is already a member of this organization")

    superseded = (
        (
            await session.execute(
                select(OrganizationInvitation)
                .where(
                    OrganizationInvitation.organization_id == tenant.organization_id,
                    OrganizationInvitation.email == email,
                    OrganizationInvitation.accepted_at.is_(None),
                    OrganizationInvitation.revoked_at.is_(None),
                )
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    for old in superseded:
        old.revoked_at = now
    # Before the insert: the one-open-invitation index would refuse the new
    # row while the old one still counts as open.
    await session.flush()

    token = secrets.token_urlsafe(32)
    invitation = OrganizationInvitation(
        organization_id=tenant.organization_id,
        email=email,
        role=role,
        token_hash=token_hash(token),
        invited_by=tenant.user.id,
        created_at=now,
        expires_at=now + INVITATION_LIFETIME,
    )
    session.add(invitation)
    await session.flush()
    await audit.record(
        session,
        tenant,
        "invitation.created",
        "invitation",
        invitation.id,
        {"email": email, "role": role.value, "replaced": len(superseded)},
    )
    await commit_unless_externally_managed(session)
    return invitation, f"{settings.app_url.rstrip('/')}{INVITATION_PATH}{token}"


async def list_invitations(
    session: AsyncSession, tenant: TenantContext
) -> list[OrganizationInvitation]:
    """Invitations not yet used or withdrawn, newest first -- expired ones included.

    Expired ones stay listed so an admin can see why somebody never arrived,
    and send a fresh link from the same row.
    """
    tenant.require_role(Role.OWNER, Role.ADMIN)
    return list(
        (
            await session.execute(
                select(OrganizationInvitation)
                .where(
                    OrganizationInvitation.organization_id == tenant.organization_id,
                    OrganizationInvitation.accepted_at.is_(None),
                    OrganizationInvitation.revoked_at.is_(None),
                )
                .order_by(OrganizationInvitation.created_at.desc(), OrganizationInvitation.id)
                .limit(200)
            )
        )
        .scalars()
        .all()
    )


async def revoke(session: AsyncSession, tenant: TenantContext, invitation_id: UUID) -> None:
    tenant.require_role(Role.OWNER, Role.ADMIN)
    invitation = (
        await session.execute(
            select(OrganizationInvitation)
            .where(
                OrganizationInvitation.id == invitation_id,
                OrganizationInvitation.organization_id == tenant.organization_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if invitation is None:
        raise NotFound("No such invitation in this organization")
    if invitation.accepted_at is not None or invitation.revoked_at is not None:
        raise ConflictError("This invitation has already been used or withdrawn")

    invitation.revoked_at = datetime.now(UTC)
    await audit.record(
        session,
        tenant,
        "invitation.revoked",
        "invitation",
        invitation.id,
        {"email": invitation.email, "role": Role(invitation.role).value},
    )
    await commit_unless_externally_managed(session)


async def preview(session: AsyncSession, user: AuthenticatedUser, token: str) -> dict[str, Any]:
    row = (
        (
            await session.execute(
                text("SELECT * FROM app.peek_invitation(:hash)"), {"hash": token_hash(token)}
            )
        )
        .mappings()
        .first()
    )
    if row is None:
        raise NotFound("This invitation link is not valid")
    return {
        "organization_name": row["organization_name"],
        "role": Role(row["role"]),
        "email": row["email"],
        "status": row["status"],
        "email_matches": bool(user.email) and (user.email or "").lower() == row["email"],
    }


# What ``app.accept_invitation`` raises, and what the caller is told.
_REFUSALS: tuple[tuple[str, type[Exception], str], ...] = (
    ("invitation not found", NotFound, "This invitation link is not valid"),
    (
        "invitation not open",
        ConflictError,
        "This invitation has already been used or was withdrawn. Ask for a new one.",
    ),
    ("invitation expired", ConflictError, "This invitation has expired. Ask for a new one."),
    (
        "invitation is for another address",
        PermissionDenied,
        "This invitation was sent to a different email address. "
        "Sign in with that address to accept it.",
    ),
)


async def accept(
    session: AsyncSession, user: AuthenticatedUser, token: str
) -> tuple[Organization, Role]:
    """Join the organization an invitation names, as the role it names.

    The checks are all inside ``app.accept_invitation`` -- open, unexpired, and
    addressed to the email on the caller's own verified token -- because the
    caller is not a member yet and nothing outside a SECURITY DEFINER function
    may add them.
    """
    try:
        organization_id = (
            await session.execute(
                text("SELECT app.accept_invitation(:hash)"), {"hash": token_hash(token)}
            )
        ).scalar_one()
    except DBAPIError as exc:
        reason = str(exc.orig)
        for fragment, error, message in _REFUSALS:
            if fragment in reason:
                raise error(message) from exc
        raise

    membership = (
        await session.execute(
            select(OrganizationMember).where(
                OrganizationMember.organization_id == organization_id,
                OrganizationMember.user_id == user.id,
            )
        )
    ).scalar_one()
    role = Role(membership.role)
    organization = await session.get(Organization, organization_id)
    if organization is None:  # pragma: no cover -- the function just joined it
        raise NotFound("Organization not found")

    tenant = TenantContext(user=user, organization_id=organization_id, role=role)
    await audit.record(
        session,
        tenant,
        "invitation.accepted",
        "member",
        membership.id,
        {"email": membership.email, "role": role.value},
    )
    await commit_unless_externally_managed(session)
    return organization, role
