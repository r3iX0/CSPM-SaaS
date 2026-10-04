"""Giving an auditor the right to read one sealed package, and taking it back.

Owners and administrators grant, list and revoke (DECISIONS.md section 211). A grant is bound to one
package and one address and ends on its own. Its link is made here, once: the token is 32 random
bytes, only its SHA-256 is stored, and the link carries it in the URL fragment, which no server
sees (section 162). Nothing here reads a package for an auditor. That is ``services/auditor``,
through functions that check the grant, and none of its writes happen in this module.

Services flush and the route commits, because the row-level-security claims live in the request's
transaction (section 194). Each entry in the audit trail is written in that transaction, so a
grant that does not commit leaves no entry claiming it exists.
"""

import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.deps import TenantContext
from app.core.enums import Role
from app.core.errors import ConflictError, NotFound
from app.models.audit_grant import AuditGrant, AuditGrantEvent
from app.models.audit_package import AuditPackage
from app.schemas.audit_grant import GrantStatus
from app.services import audit
from app.services.team import token_hash

# Where the link lands: a fragment, so the token is never sent to any server (section 162).
AUDITOR_PATH = "/auditor#"


def grant_status(grant: AuditGrant, now: datetime) -> GrantStatus:
    """Where a grant stands. A revoke wins over an expiry, and either ends an opened grant."""
    if grant.revoked_at is not None:
        return "REVOKED"
    if grant.expires_at <= now:
        return "EXPIRED"
    return "OPENED" if grant.opened_at is not None else "PENDING"


def _require_owner_or_admin(tenant: TenantContext) -> None:
    tenant.require_role(Role.OWNER, Role.ADMIN)


async def grant(
    session: AsyncSession,
    tenant: TenantContext,
    package_id: UUID,
    email: str,
    expires_in_days: int,
) -> tuple[AuditGrant, str]:
    """Make a grant and return it with its link, which is not stored.

    Granting an address that already holds a live grant on the package replaces it: the old link
    stops working and the new one is the only one, as for an invitation (section 162). ``NotFound``
    for a package this organization does not hold, whoever it belongs to.
    """
    _require_owner_or_admin(tenant)
    held = (
        await session.execute(
            select(AuditPackage.id).where(
                AuditPackage.id == package_id,
                AuditPackage.organization_id == tenant.organization_id,
            )
        )
    ).first()
    if held is None:
        raise NotFound("No such audit package")

    address = email.strip().lower()
    superseded = (
        (
            await session.execute(
                select(AuditGrant)
                .where(
                    AuditGrant.package_id == package_id,
                    AuditGrant.organization_id == tenant.organization_id,
                    AuditGrant.email == address,
                    AuditGrant.revoked_at.is_(None),
                )
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    now = datetime.now(UTC)
    for old in superseded:
        old.revoked_at = now
        old.revoked_by = tenant.user.id
    # Before the insert: the one-live-grant index would refuse the new row while the old one
    # still counts.
    await session.flush()

    token = secrets.token_urlsafe(32)
    # The expiry is the database's time plus the days asked for, so the table's ceiling of 90
    # days is measured against the same instant ``created_at`` is.
    new = AuditGrant(
        organization_id=tenant.organization_id,
        package_id=package_id,
        email=address,
        token_hash=token_hash(token),
        created_by=tenant.user.id,
        expires_at=func.now() + timedelta(days=expires_in_days),
    )
    session.add(new)
    await session.flush()
    await session.refresh(new)
    await audit.record(
        session,
        tenant,
        "audit_grant.created",
        "audit_grant",
        new.id,
        {
            "package_id": str(package_id),
            "email": address,
            "expires_at": new.expires_at.isoformat(),
            "replaced": len(superseded),
        },
    )
    return new, f"{settings.app_url.rstrip('/')}{AUDITOR_PATH}{token}"


async def list_grants(
    session: AsyncSession,
    tenant: TenantContext,
    *,
    package_id: UUID | None,
    limit: int,
    offset: int,
) -> tuple[list[AuditGrant], int]:
    """A page of this organization's grants, newest first, and how many there are.

    Ended grants stay listed: an owner asks who could read a package, and who could once.
    """
    _require_owner_or_admin(tenant)
    scope = [AuditGrant.organization_id == tenant.organization_id]
    if package_id is not None:
        scope.append(AuditGrant.package_id == package_id)
    total = (
        await session.execute(select(func.count()).select_from(AuditGrant).where(*scope))
    ).scalar_one()
    rows = await session.execute(
        select(AuditGrant)
        .where(*scope)
        .order_by(AuditGrant.created_at.desc(), AuditGrant.id)
        .limit(limit)
        .offset(offset)
    )
    return list(rows.scalars().all()), total


async def get_grant(session: AsyncSession, tenant: TenantContext, grant_id: UUID) -> AuditGrant:
    """A grant of this organization, or ``NotFound`` for one it does not hold."""
    _require_owner_or_admin(tenant)
    found = (
        await session.execute(
            select(AuditGrant).where(
                AuditGrant.id == grant_id,
                AuditGrant.organization_id == tenant.organization_id,
            )
        )
    ).scalar_one_or_none()
    if found is None:
        raise NotFound("No such grant in this organization")
    return found


async def revoke(session: AsyncSession, tenant: TenantContext, grant_id: UUID) -> None:
    """End a grant now. It is kept as history, and a revoke cannot be taken back.

    Takes effect on the auditor's next request: every read checks the grant again. A download
    already streaming finishes.
    """
    found = await get_grant(session, tenant, grant_id)
    if found.revoked_at is not None:
        raise ConflictError("This grant has already been revoked")
    # Locked only now, and only while live: the update policy hides a revoked row from a locking
    # read, so locking first would answer a second revoke with "not found". A row that has gone
    # between the two reads was revoked by somebody else in that moment.
    live = (
        await session.execute(
            select(AuditGrant)
            .where(
                AuditGrant.id == grant_id,
                AuditGrant.organization_id == tenant.organization_id,
                AuditGrant.revoked_at.is_(None),
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if live is None:
        raise ConflictError("This grant has already been revoked")
    found = live

    found.revoked_at = datetime.now(UTC)
    found.revoked_by = tenant.user.id
    await audit.record(
        session,
        tenant,
        "audit_grant.revoked",
        "audit_grant",
        found.id,
        {"package_id": str(found.package_id), "email": found.email},
    )
    await session.flush()


async def list_events(
    session: AsyncSession,
    tenant: TenantContext,
    grant_id: UUID,
    *,
    limit: int,
    offset: int,
) -> tuple[list[AuditGrantEvent], int]:
    """What was done through a grant, newest first: when it was opened, when it was downloaded."""
    await get_grant(session, tenant, grant_id)
    scope = (
        AuditGrantEvent.grant_id == grant_id,
        AuditGrantEvent.organization_id == tenant.organization_id,
    )
    total = (
        await session.execute(select(func.count()).select_from(AuditGrantEvent).where(*scope))
    ).scalar_one()
    rows = await session.execute(
        select(AuditGrantEvent)
        .where(*scope)
        .order_by(AuditGrantEvent.at.desc(), AuditGrantEvent.id)
        .limit(limit)
        .offset(offset)
    )
    return list(rows.scalars().all()), total
