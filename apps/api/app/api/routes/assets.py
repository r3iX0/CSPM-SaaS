from typing import Any
from uuid import UUID

from fastapi import APIRouter, Query
from sqlalchemy import ColumnElement, func, select
from sqlalchemy.orm import InstrumentedAttribute

from app.core.deps import DbSession, Tenant
from app.core.enums import ContextSource, FindingStatus, Level, ResourceType
from app.core.errors import NotFound, envelope
from app.models.cloud_account import CloudAccount
from app.models.finding import Finding
from app.models.resource import ResourceRecord
from app.services.placement import DIRECTORY_SCOPE, RESOURCE_GROUP

router = APIRouter(prefix="/assets", tags=["assets"])


def _fact(value: object, source: ContextSource) -> dict:
    """One context value with where it came from and how much to trust it.

    Shown rather than kept internal because the value alone cannot be argued
    with. "CRITICAL" invites the question "says who?", and until now the honest
    answer -- a tag, a guess at the name, or a person here saying so -- existed
    nowhere the customer could reach.
    """
    return {
        "value": value,
        "source": source.value,
        "confidence": source.confidence,
    }


@router.get("")
async def list_assets(
    session: DbSession,
    tenant: Tenant,
    resource_type: str | None = None,
    environment: str | None = None,
    criticality: Level | None = None,
    exposure: Level | None = None,
    search: str | None = None,
    # Where the asset sits, which is how the hierarchy view drills into it.
    # `subscription_id="directory"` is the tenant-scoped set -- users, service
    # principals -- which belongs to no subscription at all and would otherwise
    # be unreachable from a tree keyed by one.
    subscription_id: str | None = None,
    resource_group: str | None = None,
    limit: int = Query(default=100, le=500),
    offset: int = 0,
) -> dict:
    # Open findings per asset, counted in the database rather than by loading
    # every finding into Python.
    finding_counts = (
        select(Finding.resource_id, func.count().label("open_findings"))
        .where(
            Finding.organization_id == tenant.organization_id,
            Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_PROGRESS]),
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
    if resource_type:
        conditions["resource_type"] = ResourceRecord.resource_type == resource_type
    if environment:
        conditions["environment"] = ResourceRecord.environment == environment
    if criticality:
        conditions["criticality"] = ResourceRecord.criticality == criticality
    if exposure:
        conditions["exposure"] = ResourceRecord.public_exposure == exposure
    if search:
        conditions["search"] = ResourceRecord.name.ilike(f"%{search}%")
    if subscription_id == DIRECTORY_SCOPE:
        conditions["subscription"] = ResourceRecord.cloud_account_id.is_(None)
    elif subscription_id:
        conditions["subscription"] = ResourceRecord.cloud_account_id.in_(
            select(CloudAccount.id).where(
                CloudAccount.organization_id == tenant.organization_id,
                CloudAccount.subscription_id == subscription_id,
            )
        )
    if resource_group:
        # Compared case-insensitively because ARM is: a group named `Prod` and
        # a link that says `prod` name the same place.
        conditions["resource_group"] = func.lower(RESOURCE_GROUP) == resource_group.lower()

    stmt = (
        select(ResourceRecord, open_findings)
        .outerjoin(finding_counts, finding_counts.c.resource_id == ResourceRecord.id)
        .where(*conditions.values())
    )

    scoped = stmt.subquery()
    total = (
        await session.execute(select(func.count()).select_from(scoped))
    ).scalar_one()
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

    facets = {
        "resource_type": await facet(ResourceRecord.resource_type, "resource_type"),
        "environment": await facet(ResourceRecord.environment, "environment"),
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

    return envelope(
        [
            {
                "id": str(r.id),
                "name": r.name,
                # The provider's own id, which the row id names nothing in.
                # Returned here as well as on the detail because it is the only
                # thing that spells out where an asset *sits*: an ARM id states
                # its own subscription and resource group, so a client can group
                # an inventory by scope without a second request per row.
                "provider_resource_id": r.provider_resource_id,
                "resource_type": r.resource_type,
                # What it actually is, for the ones CloudGuard does not model.
                # A list row reading "Unknown" would be a worse answer than the
                # omission it replaced: the point of showing these is that the
                # customer can see *what* is unchecked, not merely how many.
                "azure_type": (r.resource_metadata or {}).get("azure_type"),
                "region": r.region,
                "environment": r.environment,
                "criticality": r.criticality,
                "data_sensitivity": r.data_sensitivity,
                "public_exposure": r.public_exposure,
                "open_findings": int(count),
                "first_seen_at": r.first_seen_at.isoformat(),
                "last_seen_at": r.last_seen_at.isoformat(),
            }
            for r, count in rows
        ],
        {
            "total": total,
            "unchecked": int(unchecked_total),
            "facets": facets,
            "limit": limit,
            "offset": offset,
        },
    )


@router.get("/hierarchy")
async def asset_hierarchy(session: DbSession, tenant: Tenant) -> dict:
    """The estate as it is actually organised: subscriptions, then groups.

    A flat inventory answers "what do I have"; it cannot answer "which part of
    my estate is the problem", and that is the question with an owner attached
    -- a resource group usually has one, and a subscription almost always does.

    Counted in the database and returned whole. The list view pages, and a tree
    built from one page of it would be a lie of the worst kind: a resource group
    whose assets straddled two pages would appear twice, each time with a
    fraction of its findings.
    """
    open_findings = (
        select(Finding.resource_id, func.count().label("open"))
        .where(
            Finding.organization_id == tenant.organization_id,
            Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_PROGRESS]),
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
                select(CloudAccount).where(
                    CloudAccount.organization_id == tenant.organization_id
                )
            )
        )
        .scalars()
        .all()
    }

    scopes: dict[str, dict] = {}
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
                    account.display_name or account.subscription_id
                    if account
                    else "Directory"
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

    return envelope(
        ordered,
        {
            "total_assets": sum(scope["asset_count"] for scope in ordered),
            "total_open_findings": sum(scope["open_findings"] for scope in ordered),
        },
    )


@router.get("/resolve")
async def resolve_asset(
    session: DbSession,
    tenant: Tenant,
    provider_resource_id: str = Query(min_length=1, max_length=2048),
) -> dict:
    """The row id behind a provider id, for opening that asset's page.

    Routes and graphs are statements about provider ids -- the cloud's own
    names -- and the asset page is addressed by row id. A page holding only a
    provider id asks here once, when somebody follows it, rather than every
    route list carrying a surrogate key it rarely needs.

    Present assets only, like the graph: a route through something a later
    scan no longer found should not open a page describing it as current.
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
    return envelope({"id": str(asset_id)})


@router.get("/{asset_id}")
async def get_asset(asset_id: UUID, session: DbSession, tenant: Tenant) -> dict:
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

    findings = (
        (
            await session.execute(
                select(Finding)
                .where(
                    Finding.organization_id == tenant.organization_id,
                    Finding.resource_id == asset_id,
                )
                .order_by(Finding.risk_score.desc().nullslast())
            )
        )
        .scalars()
        .all()
    )

    return envelope(
        {
            "id": str(asset.id),
            "name": asset.name,
            "resource_type": asset.resource_type,
            "provider": asset.provider,
            "provider_resource_id": asset.provider_resource_id,
            "region": asset.region,
            "environment": asset.environment,
            "criticality": asset.criticality,
            "data_sensitivity": asset.data_sensitivity,
            "public_exposure": asset.public_exposure,
            # The same three values again, with their provenance. Kept beside
            # the flat fields rather than replacing them: the flat ones are what
            # every list view and filter reads, and changing their shape to
            # serve one detail page would be the tail wagging the dog.
            #
            # Exposure is absent here on purpose. It is read off the
            # configuration in the capture -- a public IP is attached or it is
            # not -- so there is no source to name and nothing for a customer
            # to declare.
            "context": {
                "criticality": _fact(asset.criticality, asset.criticality_source),
                "data_sensitivity": _fact(
                    asset.data_sensitivity, asset.data_sensitivity_source
                ),
                "environment": _fact(asset.environment, asset.environment_source),
            },
            "metadata": asset.resource_metadata,
            "first_seen_at": asset.first_seen_at.isoformat(),
            "last_seen_at": asset.last_seen_at.isoformat(),
            "findings": [
                {
                    "id": str(f.id),
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "severity": f.severity,
                    "status": f.status,
                    "risk_score": float(f.risk_score) if f.risk_score is not None else None,
                }
                for f in findings
            ],
        }
    )
