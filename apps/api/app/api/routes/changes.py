"""What moved in the environment, rather than what is true in it now.

The first question after a week of somebody else's deployments, and until the
change events existed it was answerable only by diffing snapshot blobs by hand.

Deliberately a feed of *transitions*, not a diff of two scans. A scan that finds
nothing different contributes nothing here, so an empty week reads as an empty
week rather than as a wall of rows saying everything is still where it was.
"""

from fastapi import APIRouter, Query

from app.core.deps import DbSession, Tenant
from app.core.enums import AssetChange
from app.schemas.change import ChangedAssetOut, ChangeOut, ChangesMeta
from app.schemas.common import ERROR_RESPONSES, Envelope
from app.services import changes as service

router = APIRouter(prefix="/changes", tags=["changes"], responses=ERROR_RESPONSES)

# How far back the feed looks when nobody says. A week, because that is the
# span the question is usually asked over -- "what changed while I was away".
DEFAULT_WINDOW_DAYS = 7


@router.get("")
async def list_changes(
    session: DbSession,
    tenant: Tenant,
    days: int = Query(default=DEFAULT_WINDOW_DAYS, ge=1, le=90),
    change: AssetChange | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Envelope[list[ChangeOut], ChangesMeta]:
    """Asset changes, newest first.

    Joined to the asset so a row is readable on its own. A feed of resource ids
    would be technically complete and would make the reader look up every line
    to find out whether it mattered.
    """
    rows = await service.list_changes(
        session, tenant, days=days, change=change, limit=limit, offset=offset
    )

    return Envelope(
        data=[
            ChangeOut(
                id=event.id,
                change=event.change,
                previous_value=event.previous_value,
                current_value=event.current_value,
                observed_at=event.observed_at,
                scan_id=event.scan_id,
                asset=ChangedAssetOut(
                    id=resource.id,
                    name=resource.name,
                    resource_type=resource.resource_type,
                    environment=resource.environment,
                    # Whether it is currently missing, which is what turns a
                    # DISAPPEARED row from history into something to act on.
                    absent_since=resource.absent_since,
                ),
            )
            for event, resource in rows
        ],
        meta=ChangesMeta(days=days, limit=limit, offset=offset),
    )
