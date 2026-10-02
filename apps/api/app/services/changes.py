"""The change feed: what moved in the environment, newest first."""

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import TenantContext
from app.core.enums import AssetChange
from app.models.history import AssetChangeEvent
from app.models.resource import ResourceRecord


async def list_changes(
    session: AsyncSession,
    tenant: TenantContext,
    *,
    days: int,
    change: AssetChange | None,
    limit: int,
    offset: int,
) -> list[tuple[AssetChangeEvent, ResourceRecord]]:
    """Asset changes in the last ``days`` days, each joined to its asset.

    Joined so a row is readable on its own: a feed of resource ids would be technically
    complete and would make the reader look up every line to find out whether it mattered.
    Ordered by when it was seen, then by id, so a page boundary never lands on the same row twice.
    """
    since = datetime.now(UTC) - timedelta(days=days)

    stmt = (
        select(AssetChangeEvent, ResourceRecord)
        .join(ResourceRecord, ResourceRecord.id == AssetChangeEvent.resource_id)
        .where(
            AssetChangeEvent.organization_id == tenant.organization_id,
            AssetChangeEvent.observed_at >= since,
        )
    )
    if change is not None:
        stmt = stmt.where(AssetChangeEvent.change == change)

    rows = await session.execute(
        stmt.order_by(AssetChangeEvent.observed_at.desc(), AssetChangeEvent.id)
        .limit(limit)
        .offset(offset)
    )
    return [(event, resource) for event, resource in rows.all()]
