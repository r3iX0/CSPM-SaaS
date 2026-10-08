"""The customer's Terraform state index: storing an upload, and reading where an asset lives.

An upload arrives from the customer's own pipeline, authenticated by the Action's
OIDC token rather than by a person, so it is written through the owner session
scoped explicitly to the organization the repository's installation belongs to,
as change events are (DECISIONS.md §229). Reading is a member's, under RLS.
"""

from collections.abc import Sequence
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import TenantContext
from app.models.iac import IacIndex, IacIndexEntry
from app.models.resource import ResourceRecord
from app.remediation.iac.index import IndexEntry


async def replace_index(
    session: AsyncSession,
    organization_id: UUID,
    *,
    repository_id: int,
    repository: str,
    working_directory: str,
    workspace: str,
    commit_sha: str,
    entries: Sequence[IndexEntry],
) -> IacIndex:
    """Store one state's index in place of the last one from the same place.

    Whole, never merged: a resource removed from the code must stop being
    called managed in code, and only the upload that no longer lists it says so.
    The caller has already checked the entries (``entries_from_upload``) and
    proved which organization the repository belongs to; ``session`` is the
    owner's, so every statement here names the organization itself.
    """
    await session.execute(
        delete(IacIndex).where(
            IacIndex.organization_id == organization_id,
            IacIndex.repository_id == repository_id,
            IacIndex.working_directory == working_directory,
            IacIndex.workspace == workspace,
        )
    )
    index = IacIndex(
        organization_id=organization_id,
        repository_id=repository_id,
        repository=repository,
        working_directory=working_directory,
        workspace=workspace,
        commit_sha=commit_sha,
    )
    session.add(index)
    await session.flush()
    session.add_all(
        IacIndexEntry(
            organization_id=organization_id,
            index_id=index.id,
            address=entry.address,
            type=entry.type,
            instance_key=entry.index,
            resource_id=entry.resource_id,
        )
        for entry in entries
    )
    await session.flush()
    return index


async def managed_in_code(
    session: AsyncSession, tenant: TenantContext, resource: ResourceRecord | None
) -> list[tuple[IacIndex, IacIndexEntry]]:
    """Where the customer's state says an asset is defined; empty if no index names it.

    Usually one place. Two roots managing one resource is a mistake in the
    customer's code, and both are said rather than one chosen.
    """
    if resource is None or not resource.provider_resource_id:
        return []
    rows = await session.execute(
        select(IacIndex, IacIndexEntry)
        .join(IacIndexEntry, IacIndexEntry.index_id == IacIndex.id)
        .where(
            IacIndexEntry.organization_id == tenant.organization_id,
            IacIndexEntry.resource_id == resource.provider_resource_id.lower(),
        )
        .order_by(IacIndex.repository, IacIndexEntry.address)
    )
    return [(index, entry) for index, entry in rows.tuples()]
