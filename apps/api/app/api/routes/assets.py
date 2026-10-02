from uuid import UUID

from fastapi import APIRouter, Query

from app.core.deps import DbSession, Tenant
from app.core.enums import ContextSource, Level
from app.schemas.asset import (
    AssetContextOut,
    AssetDetailOut,
    AssetFacetsOut,
    AssetFindingOut,
    AssetRowOut,
    AssetsMeta,
    ContextFactOut,
    HierarchyMeta,
    HierarchyScopeOut,
    PlacementOut,
    ResolvedAssetOut,
)
from app.schemas.common import ERROR_RESPONSES, Envelope, NoMeta
from app.services import assets as service
from app.services.placement import DIRECTORY_SCOPE

router = APIRouter(prefix="/assets", tags=["assets"], responses=ERROR_RESPONSES)


def _fact(value: str | None, source: ContextSource) -> ContextFactOut:
    """One context value with where it came from and how much to trust it.

    Shown rather than kept internal because the value alone cannot be argued
    with. "CRITICAL" invites the question "says who?", and until now the honest
    answer -- a tag, a guess at the name, or a person here saying so -- existed
    nowhere the customer could reach.
    """
    return ContextFactOut(value=value, source=source, confidence=source.confidence)


@router.get("")
async def list_assets(
    session: DbSession,
    tenant: Tenant,
    resource_type: str | None = None,
    environment: str | None = None,
    criticality: Level | None = None,
    exposure: Level | None = None,
    search: str | None = None,
    entry_point: bool = False,
    sensitive: bool = False,
    on_attack_path: bool = False,
    subscription_id: str | None = None,
    resource_group: str | None = None,
    region: str | None = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Envelope[list[AssetRowOut], AssetsMeta]:
    """The inventory, with the asset carrying the most open findings first.

    ``entry_point``, ``sensitive`` and ``on_attack_path`` narrow it to what the estate map marks;
    ``subscription_id`` (``directory`` for the tenant-scoped assets), ``resource_group`` and
    ``region`` (``none`` for unplaced ones) are how the hierarchy and the region map drill in.
    ``meta.facets`` counts each filter's options over the whole filtered set.
    """
    page = await service.list_assets(
        session,
        tenant,
        service.AssetFilters(
            resource_type=resource_type,
            environment=environment,
            criticality=criticality,
            exposure=exposure,
            search=search,
            entry_point=entry_point,
            sensitive=sensitive,
            on_attack_path=on_attack_path,
            subscription_id=subscription_id,
            resource_group=resource_group,
            region=region,
        ),
        limit=limit,
        offset=offset,
    )

    return Envelope(
        data=[
            AssetRowOut(
                id=r.id,
                name=r.name,
                # The provider's own id, which the row id names nothing in.
                # Returned here as well as on the detail because it is the only
                # thing that spells out where an asset *sits*: an ARM id states
                # its own subscription and resource group, so a client can group
                # an inventory by scope without a second request per row.
                provider_resource_id=r.provider_resource_id,
                resource_type=r.resource_type,
                # What it actually is, for the ones CloudGuard does not model.
                # A list row reading "Unknown" would be a worse answer than the
                # omission it replaced: the point of showing these is that the
                # customer can see *what* is unchecked, not merely how many.
                azure_type=(r.resource_metadata or {}).get("azure_type"),
                region=r.region,
                environment=r.environment,
                criticality=r.criticality,
                data_sensitivity=r.data_sensitivity,
                public_exposure=r.public_exposure,
                open_findings=count,
                # On at least one attack path, as the graph finds them now. An
                # asset the last scan no longer found is on none: the graph
                # holds only what is still there.
                on_attack_path=r.absent_since is None and r.provider_resource_id in page.on_route,
                first_seen_at=r.first_seen_at,
                last_seen_at=r.last_seen_at,
            )
            for r, count in page.rows
        ],
        meta=AssetsMeta(
            total=page.total,
            unchecked=page.unchecked,
            facets=AssetFacetsOut(**page.facets),
            limit=limit,
            offset=offset,
        ),
    )


@router.get("/hierarchy")
async def asset_hierarchy(
    session: DbSession, tenant: Tenant
) -> Envelope[list[HierarchyScopeOut], HierarchyMeta]:
    """The estate as it is actually organised: subscriptions, then groups.

    A flat inventory answers "what do I have"; it cannot answer "which part of
    my estate is the problem", and that is the question with an owner attached
    -- a resource group usually has one, and a subscription almost always does.
    """
    ordered = await service.hierarchy(session, tenant)
    return Envelope(
        data=[HierarchyScopeOut.model_validate(scope) for scope in ordered],
        meta=HierarchyMeta(
            total_assets=sum(scope["asset_count"] for scope in ordered),
            total_open_findings=sum(scope["open_findings"] for scope in ordered),
        ),
    )


@router.get("/resolve")
async def resolve_asset(
    session: DbSession,
    tenant: Tenant,
    provider_resource_id: str = Query(min_length=1, max_length=2048),
) -> Envelope[ResolvedAssetOut, NoMeta]:
    """The row id behind a provider id, for opening that asset's page.

    Routes and graphs are statements about provider ids -- the cloud's own
    names -- and the asset page is addressed by row id. A page holding only a
    provider id asks here once, when somebody follows it, rather than every
    route list carrying a surrogate key it rarely needs.
    """
    asset_id = await service.resolve(session, tenant, provider_resource_id)
    return Envelope(data=ResolvedAssetOut(id=asset_id), meta=NoMeta())


@router.get("/{asset_id}")
async def get_asset(
    asset_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[AssetDetailOut, NoMeta]:
    """One asset: its context and where each value came from, its place, and its findings."""
    detail = await service.get_asset_detail(session, tenant, asset_id)
    asset, account, connection, findings = (
        detail.asset,
        detail.account,
        detail.connection,
        detail.findings,
    )
    scope_id = account.subscription_id if account and account.subscription_id else None

    return Envelope(
        data=AssetDetailOut(
            id=asset.id,
            name=asset.name,
            resource_type=asset.resource_type,
            provider=asset.provider,
            provider_resource_id=asset.provider_resource_id,
            region=asset.region,
            environment=asset.environment,
            criticality=asset.criticality,
            data_sensitivity=asset.data_sensitivity,
            public_exposure=asset.public_exposure,
            # The same three values again, with their provenance. Kept beside
            # the flat fields rather than replacing them: the flat ones are what
            # every list view and filter reads, and changing their shape to
            # serve one detail page would be the tail wagging the dog.
            #
            # Exposure is absent here on purpose. It is read off the
            # configuration in the capture -- a public IP is attached or it is
            # not -- so there is no source to name and nothing for a customer
            # to declare.
            context=AssetContextOut(
                criticality=_fact(asset.criticality, asset.criticality_source),
                data_sensitivity=_fact(asset.data_sensitivity, asset.data_sensitivity_source),
                environment=_fact(asset.environment, asset.environment_source),
            ),
            metadata=asset.resource_metadata or {},
            first_seen_at=asset.first_seen_at,
            last_seen_at=asset.last_seen_at,
            # Set when a later scan looked for the asset and did not find it.
            # The row stays so its findings stay history; the page has to say
            # the asset is gone rather than present it as live.
            absent_since=asset.absent_since,
            placement=PlacementOut(
                scope_id=scope_id or DIRECTORY_SCOPE,
                scope_name=(
                    (account.display_name or account.account_name or scope_id)
                    if account and scope_id
                    else "Directory"
                ),
                resource_group=detail.resource_group or None,
            ),
            # The directory the asset lives in. A portal link without it opens
            # in the viewer's default directory, where a resource in any other
            # tenant -- every one an MSP manages -- reads as "not found".
            tenant_id=(account.tenant_id if account else None)
            or (connection.tenant_id if connection else None),
            # Counted here so no client has to decide which statuses are open.
            open_findings=sum(1 for f in findings if f.status.is_open),
            findings=[
                AssetFindingOut(
                    id=f.id,
                    rule_id=f.rule_id,
                    title=f.title,
                    severity=f.severity,
                    status=f.status,
                    risk_score=float(f.risk_score) if f.risk_score is not None else None,
                )
                for f in findings
            ],
        ),
        meta=NoMeta(),
    )
