"""The audit trail: who changed what, from where, in which request.

One writer for every change a person makes through the API, so every row
carries the same four facts beside the change itself -- the organization, the
user, the address the request came from, and the request's id, which finds the
request's log lines (DECISIONS.md sections 161-163).

The table is append-only for the application role. Nothing here updates or
deletes a row, and the database refuses to if anything tries.
"""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import TenantContext
from app.core.enums import Role
from app.core.errors import PermissionDenied
from app.core.request_context import current_client_ip, current_request_id
from app.models.organization import OrganizationMember
from app.models.remediation import AuditLog


async def record(
    session: AsyncSession,
    tenant: TenantContext,
    action: str,
    resource_type: str,
    resource_id: UUID | None,
    metadata: dict[str, Any] | None = None,
) -> None:
    """Add one entry to the trail, in the caller's transaction.

    In the caller's transaction on purpose: a change that rolls back leaves no
    entry claiming it happened, and one that commits cannot lose its entry.
    """
    details = dict(metadata or {})
    if (request_id := current_request_id()) is not None:
        details["request_id"] = request_id
    session.add(
        AuditLog(
            organization_id=tenant.organization_id,
            user_id=tenant.user.id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            audit_metadata=details,
            ip_address=current_client_ip(),
            created_at=datetime.now(UTC),
        )
    )


async def list_entries(
    session: AsyncSession,
    tenant: TenantContext,
    *,
    action: str | None,
    actor: UUID | None,
    resource_type: str | None,
    limit: int,
    offset: int,
) -> tuple[list[tuple[AuditLog, str | None]], int]:
    """The trail, newest first, each entry with the address of who made it.

    Owners and admins. Asked directly rather than through ``require_role``,
    which also refuses the demo: reading is not writing, and the answer there
    is the same refusal for a different reason -- nobody in the demo is either.

    ``action`` ending in a dot is a family (``member.`` is every change to a
    member), so a reader can ask about a kind of change without knowing every
    verb in it. The address is joined from the membership as it is now, so an
    entry by somebody since removed shows none; their id stays on the entry.
    """
    if tenant.role not in (Role.OWNER, Role.ADMIN):
        raise PermissionDenied("The audit trail is for owners and admins")

    conditions = [AuditLog.organization_id == tenant.organization_id]
    if action:
        conditions.append(
            AuditLog.action.startswith(action, autoescape=True)
            if action.endswith(".")
            else AuditLog.action == action
        )
    if actor:
        conditions.append(AuditLog.user_id == actor)
    if resource_type:
        conditions.append(AuditLog.resource_type == resource_type)

    total = (
        await session.execute(select(func.count()).select_from(AuditLog).where(*conditions))
    ).scalar_one()
    rows = (
        await session.execute(
            select(AuditLog, OrganizationMember.email)
            .outerjoin(
                OrganizationMember,
                and_(
                    OrganizationMember.organization_id == AuditLog.organization_id,
                    OrganizationMember.user_id == AuditLog.user_id,
                ),
            )
            .where(*conditions)
            .order_by(AuditLog.created_at.desc(), AuditLog.id)
            .limit(limit)
            .offset(offset)
        )
    ).all()
    return [(row[0], row[1]) for row in rows], int(total)
