"""Where each asset sits: its subscription, or the directory, and its group.

Read the same way everywhere it is asked -- the hierarchy view, the list's
scope filter, and the estate map -- so a box on the map and the list it opens
into always name the same assets.
"""

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.graph.estate import DIRECTORY_SCOPE, Placement
from app.models.cloud_account import CloudAccount
from app.models.resource import ResourceRecord

__all__ = ["DIRECTORY_SCOPE", "RESOURCE_GROUP", "Placements", "load_placements"]

# The resource group, read out of the provider's own identifier.
#
# An ARM id spells out where the resource sits -- ``/subscriptions/{id}/
# resourceGroups/{name}/providers/...`` -- so the fifth segment *is* the group
# and nothing needs storing or asking. Positional rather than pattern-matched
# on the segment name, because ARM treats `/resourcegroups/` and
# `/resourceGroups/` as the same path and an estate whose ids arrive in the
# other casing would otherwise report every asset as ungrouped.
#
# The guard matters: a directory asset (`/principals/...`) has no fifth segment
# to mean anything, and slicing one anyway would invent a resource group out of
# a principal id.
RESOURCE_GROUP = case(
    (
        ResourceRecord.provider_resource_id.ilike("/subscriptions/%/resourcegroups/%"),
        func.split_part(ResourceRecord.provider_resource_id, "/", 5),
    ),
    else_=None,
)


@dataclass(frozen=True)
class Placements:
    """Every present asset's place, its row id, and what each scope is called."""

    of: dict[str, Placement]
    row_ids: dict[str, UUID]
    scope_names: dict[str, str]
    scope_providers: dict[str, str]


async def load_placements(session: AsyncSession, organization_id: UUID) -> Placements:
    """One query for the whole estate, keyed by provider id as the graph is.

    Present assets only, as the graph holds. A provider id held under two
    accounts -- which the graph already collapses into one vertex -- is placed
    by the first in a fixed order, so the same estate draws the same map.
    """
    rows = await session.execute(
        select(
            ResourceRecord.provider_resource_id,
            ResourceRecord.id,
            CloudAccount.subscription_id,
            CloudAccount.display_name,
            ResourceRecord.provider,
            RESOURCE_GROUP,
        )
        .outerjoin(CloudAccount, CloudAccount.id == ResourceRecord.cloud_account_id)
        .where(
            ResourceRecord.organization_id == organization_id,
            ResourceRecord.absent_since.is_(None),
        )
        .order_by(ResourceRecord.provider_resource_id, CloudAccount.subscription_id)
    )

    of: dict[str, Placement] = {}
    row_ids: dict[str, UUID] = {}
    names: dict[str, str] = {}
    providers: dict[str, str] = {}
    for provider_id, row_id, subscription_id, display_name, provider, group in rows.tuples():
        if provider_id in of:
            continue
        # An account row with no subscription id is not a scope anybody can
        # open, so it falls to the directory -- as it does in the hierarchy.
        scope = subscription_id or DIRECTORY_SCOPE
        of[provider_id] = Placement(scope, group or None)
        row_ids[provider_id] = row_id
        names.setdefault(
            scope, "Directory" if scope == DIRECTORY_SCOPE else display_name or scope
        )
        providers.setdefault(scope, provider.value)
    return Placements(of, row_ids, names, providers)
