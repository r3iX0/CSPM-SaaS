"""The asset inventory: the list and its facets, the estate's shape, and one asset in full.

Everything here is counted, filtered and ordered in the database. A page that did it over the
rows it held would search one page of an estate and report "nothing matches" for the rest.
"""

from collections.abc import Collection
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from sqlalchemy import ColumnElement, false, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import InstrumentedAttribute

from app.core.deps import TenantContext
from app.core.enums import FindingStatus, Level, ResourceType
from app.core.errors import NotFound
from app.graph.model import ENTRY_EXPOSURE, SENSITIVE_DATA
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection
from app.models.finding import Finding
from app.models.resource import ResourceRecord
from app.services import graph as graph_service
from app.services.placement import (
    DIRECTORY_SCOPE,
    NO_REGION,
    REGION,
    RESOURCE_GROUP,
    region_key,
)

_OPEN_FINDINGS = [FindingStatus.OPEN, FindingStatus.IN_PROGRESS]


@dataclass(frozen=True)
class AssetFilters:
    """What narrows the inventory. Every field is optional and they combine."""

    resource_type: str | None = None
    environment: str | None = None
    criticality: Level | None = None
    exposure: Level | None = None
    search: str | None = None
    # The three things the graph marks an asset with, so the list can be
    # narrowed to what the estate map draws a globe, a cylinder or a route on.
    # The first two are the graph's own predicates over two columns; the third
    # is membership of a route, which only the graph can say.
    entry_point: bool = False
    sensitive: bool = False
    on_attack_path: bool = False
    # Where the asset sits, which is how the hierarchy view drills into it.
    # `subscription_id="directory"` is the tenant-scoped set -- users, service
    # principals -- which belongs to no subscription at all and would otherwise
    # be unreachable from a tree keyed by one.
    subscription_id: str | None = None
    resource_group: str | None = None
    # The region it runs in, which is how the dashboard's region map drills in.
    # `none` is the assets tied to no region -- the directory, and anything ARM
    # calls `global` -- which a query string cannot spell as NULL.
    region: str | None = None


@dataclass(frozen=True)
class AssetPage:
    """One page of assets, and what the whole filtered set looks like."""

    #: Each asset with how many findings are open on it.
    rows: list[tuple[ResourceRecord, int]]
    total: int
    #: How many of the filtered set CloudGuard has no rule for.
    unchecked: int
    #: The filter menus: counts per type, per environment and per region.
    facets: dict[str, dict[str, int]]
    #: Provider ids of the assets on at least one attack path.
    on_route: Collection[str]


@dataclass(frozen=True)
class AssetDetail:
    """One asset with the context the page needs around it."""

    asset: ResourceRecord
    account: CloudAccount | None
    connection: CloudConnection | None
    resource_group: str | None
    findings: list[Finding]


async def list_assets(
    session: AsyncSession,
    tenant: TenantContext,
    filters: AssetFilters,
    *,
    limit: int,
    offset: int,
) -> AssetPage:
    """The inventory, a page at a time, most open findings first."""
    # Open findings per asset, counted in the database rather than by loading
    # every finding into Python.
    finding_counts = (
        select(Finding.resource_id, func.count().label("open_findings"))
        .where(
            Finding.organization_id == tenant.organization_id,
            Finding.status.in_(_OPEN_FINDINGS),
        )
        .group_by(Finding.resource_id)
        .subquery()
    )
    open_findings = func.coalesce(finding_counts.c.open_findings, 0)

    # Each filter keyed by what it narrows, so a facet can be counted under
    # every filter except its own (below).
    conditions: dict[str, ColumnElement[bool]] = {
        "tenant": ResourceRecord.organization_id == tenant.organization_id,
    }
    if filters.resource_type:
        conditions["resource_type"] = ResourceRecord.resource_type == filters.resource_type
    if filters.environment:
        conditions["environment"] = ResourceRecord.environment == filters.environment
    if filters.criticality:
        conditions["criticality"] = ResourceRecord.criticality == filters.criticality
    if filters.exposure:
        conditions["exposure"] = ResourceRecord.public_exposure == filters.exposure
    if filters.search:
        conditions["search"] = ResourceRecord.name.ilike(f"%{filters.search}%")
    if filters.entry_point:
        conditions["entry_point"] = ResourceRecord.public_exposure.in_(ENTRY_EXPOSURE)
    if filters.sensitive:
        conditions["sensitive"] = ResourceRecord.data_sensitivity.in_(SENSITIVE_DATA)

    # Cached per tenant against the data's version, with its routes worked out
    # once, so asking on every list request costs a version check.
    graph = await graph_service.load_graph(session, tenant.organization_id)
    on_route = graph.route_members()
    if filters.on_attack_path:
        conditions["on_attack_path"] = (
            ResourceRecord.provider_resource_id.in_(sorted(on_route)) if on_route else false()
        )
    if filters.subscription_id == DIRECTORY_SCOPE:
        conditions["subscription"] = ResourceRecord.cloud_account_id.is_(None)
    elif filters.subscription_id:
        conditions["subscription"] = ResourceRecord.cloud_account_id.in_(
            select(CloudAccount.id).where(
                CloudAccount.organization_id == tenant.organization_id,
                CloudAccount.subscription_id == filters.subscription_id,
            )
        )
    if filters.resource_group:
        # Compared case-insensitively because ARM is: a group named `Prod` and
        # a link that says `prod` name the same place.
        conditions["resource_group"] = func.lower(RESOURCE_GROUP) == filters.resource_group.lower()
    if filters.region:
        # Not-distinct, so `none` -- and `global`, which is spelled as none --
        # finds the NULLs rather than nothing.
        key = None if filters.region == NO_REGION else region_key(filters.region)
        conditions["region"] = REGION.is_not_distinct_from(key)

    stmt = (
        select(ResourceRecord, open_findings)
        .outerjoin(finding_counts, finding_counts.c.resource_id == ResourceRecord.id)
        .where(*conditions.values())
    )

    scoped = stmt.subquery()
    total = (await session.execute(select(func.count()).select_from(scoped))).scalar_one()
    # How many of those CloudGuard has no rule for. Counted over the filtered
    # set rather than the page, because the honest sentence is about the estate
    # the customer is looking at: "CloudGuard checks 12 of these 47" is a fact
    # about their subscription, and the same number computed over one page of a
    # hundred would be a fact about the pagination.
    #
    # These exist at all because the inventory reading is now read. Before it,
    # the asset list showed the ten-odd types the connector models and silently
    # omitted everything else -- which read as coverage rather than as an
    # inventory of what CloudGuard happens to understand.
    unchecked_total = (
        await session.execute(
            select(func.count())
            .select_from(scoped)
            .where(scoped.c.resource_type == ResourceType.UNKNOWN)
        )
    ).scalar_one()

    # The options the filters can offer, counted over the whole filtered set
    # rather than read off the page. Each dimension is counted under every
    # filter except its own, so choosing a type still offers the other types
    # instead of collapsing the menu to the one already chosen. The page used
    # to build these menus from the fifty rows it held, so a type that sorted
    # onto page two could not be filtered to at all.
    async def facet(column: InstrumentedAttribute[Any], own: str) -> dict[str, int]:
        others = [c for key, c in conditions.items() if key != own]
        counted = await session.execute(
            select(column, func.count()).where(*others).group_by(column)
        )
        return {str(value): int(n) for value, n in counted.all() if value is not None}

    # Regions are counted with the unplaced ones kept, under the name a link
    # uses for them, so the menu can offer "not tied to a region" when the
    # dashboard has sent somebody there.
    region_rows = await session.execute(
        select(REGION, func.count())
        .where(*[c for key, c in conditions.items() if key != "region"])
        .group_by(REGION)
    )
    facets = {
        "resource_type": await facet(ResourceRecord.resource_type, "resource_type"),
        "environment": await facet(ResourceRecord.environment, "environment"),
        "region": {
            (value if value is not None else NO_REGION): int(n) for value, n in region_rows.all()
        },
    }

    # A queue, not a directory: the asset with the most open findings comes
    # first across the whole set. Ordered here rather than by the client,
    # which could only re-sort the page it held -- an asset with twenty
    # findings on page five never reached the top. The id breaks ties so an
    # offset lands on the same row every time it is asked for.
    rows = (
        await session.execute(
            stmt.order_by(open_findings.desc(), ResourceRecord.name, ResourceRecord.id)
            .limit(limit)
            .offset(offset)
        )
    ).all()

    return AssetPage(
        rows=[(asset, int(count)) for asset, count in rows],
        total=total,
        unchecked=int(unchecked_total),
        facets=facets,
        on_route=on_route,
    )


async def hierarchy(session: AsyncSession, tenant: TenantContext) -> list[dict[str, Any]]:
    """The estate as it is organised: subscriptions, then groups, worst first at both levels.

    Counted in the database and returned whole. The list view pages, and a tree built from one
    page of it would be a lie of the worst kind: a resource group whose assets straddled two
    pages would appear twice, each time with a fraction of its findings.
    """
    open_findings = (
        select(Finding.resource_id, func.count().label("open"))
        .where(
            Finding.organization_id == tenant.organization_id,
            Finding.status.in_(_OPEN_FINDINGS),
        )
        .group_by(Finding.resource_id)
        .subquery()
    )

    rows = (
        await session.execute(
            select(
                ResourceRecord.cloud_account_id,
                RESOURCE_GROUP.label("resource_group"),
                func.count(ResourceRecord.id),
                func.coalesce(func.sum(open_findings.c.open), 0),
            )
            .outerjoin(open_findings, open_findings.c.resource_id == ResourceRecord.id)
            .where(ResourceRecord.organization_id == tenant.organization_id)
            .group_by(ResourceRecord.cloud_account_id, RESOURCE_GROUP)
        )
    ).all()

    accounts = {
        account.id: account
        for account in (
            await session.execute(
                select(CloudAccount).where(CloudAccount.organization_id == tenant.organization_id)
            )
        )
        .scalars()
        .all()
    }

    scopes: dict[str, dict[str, Any]] = {}
    for account_id, group, asset_count, finding_count in rows:
        account = accounts.get(account_id) if account_id else None
        # A subscription row with no subscription id is not a scope anybody can
        # drill into, so it falls back to the directory bucket rather than
        # keying the tree on null.
        key = (account.subscription_id if account else None) or DIRECTORY_SCOPE
        scope = scopes.setdefault(
            key,
            {
                "id": key,
                "name": (
                    account.display_name or account.subscription_id if account else "Directory"
                ),
                # Named rather than inferred from a null id: a directory asset
                # is not an asset whose subscription is unknown, it is one that
                # belongs to the tenant instead.
                "kind": "SUBSCRIPTION" if account else "DIRECTORY",
                "asset_count": 0,
                "open_findings": 0,
                "groups": [],
            },
        )
        scope["asset_count"] += int(asset_count)
        scope["open_findings"] += int(finding_count)
        scope["groups"].append(
            {
                # Null where the asset sits directly in the subscription rather
                # than in a group. Left null rather than called "Ungrouped",
                # which would read as somebody's oversight.
                "name": group,
                "asset_count": int(asset_count),
                "open_findings": int(finding_count),
            }
        )

    # Worst first at both levels, so the tree opens on the part of the estate
    # with the most to answer for rather than on whichever came back first.
    ordered = sorted(
        scopes.values(),
        key=lambda scope: (-scope["open_findings"], -scope["asset_count"], scope["name"]),
    )
    for scope in ordered:
        scope["groups"].sort(
            key=lambda group: (
                -group["open_findings"],
                -group["asset_count"],
                group["name"] or "",
            )
        )
    return ordered


async def resolve(session: AsyncSession, tenant: TenantContext, provider_resource_id: str) -> UUID:
    """The row id behind a provider id, among present assets only.

    Present only, like the graph: a route through something a later scan no longer found should
    not open a page describing it as current.
    """
    asset_id = (
        await session.execute(
            select(ResourceRecord.id)
            .where(
                ResourceRecord.organization_id == tenant.organization_id,
                ResourceRecord.provider_resource_id == provider_resource_id,
                ResourceRecord.absent_since.is_(None),
            )
            .limit(1)
        )
    ).scalar_one_or_none()
    if asset_id is None:
        raise NotFound("No such asset in this organization")
    return asset_id


async def get_asset_detail(
    session: AsyncSession, tenant: TenantContext, asset_id: UUID
) -> AssetDetail:
    """One asset, where it sits, and every finding raised on it, worst first."""
    asset = (
        await session.execute(
            select(ResourceRecord).where(
                ResourceRecord.id == asset_id,
                ResourceRecord.organization_id == tenant.organization_id,
            )
        )
    ).scalar_one_or_none()
    if asset is None:
        raise NotFound("Asset not found")

    # Where it sits, for the page's trail into the estate map: the same
    # subscription id and resource group the map's lens and the list's scope
    # filter take, read the same way (``services/placement.py``).
    account = (
        await session.get(CloudAccount, asset.cloud_account_id) if asset.cloud_account_id else None
    )
    connection = (
        await session.get(CloudConnection, asset.connection_id) if asset.connection_id else None
    )
    group = (
        await session.execute(select(RESOURCE_GROUP).where(ResourceRecord.id == asset.id))
    ).scalar_one_or_none()

    findings = (
        await session.execute(
            select(Finding)
            .where(
                Finding.organization_id == tenant.organization_id,
                Finding.resource_id == asset_id,
            )
            .order_by(Finding.risk_score.desc().nullslast())
        )
    ).scalars()
    return AssetDetail(
        asset=asset,
        account=account,
        connection=connection,
        resource_group=group,
        findings=list(findings.all()),
    )
