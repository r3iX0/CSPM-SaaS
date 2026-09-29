from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel

from app.core.enums import ContextSource, FindingStatus, Level, Provider, ResourceType, Severity
from app.schemas.common import ClosedModel, PageMeta


class AssetRowOut(BaseModel):
    """One row of the inventory, ordered as a queue: most open findings first."""

    id: UUID
    name: str
    #: The provider's own id, which spells out where the asset sits.
    provider_resource_id: str
    resource_type: ResourceType
    #: What it actually is, for an asset CloudGuard does not model.
    azure_type: str | None
    region: str | None
    environment: str | None
    criticality: Level
    data_sensitivity: Level
    public_exposure: Level
    open_findings: int
    #: On at least one attack path as the graph finds them now; never for an
    #: asset the last scan no longer found.
    on_attack_path: bool
    first_seen_at: datetime
    last_seen_at: datetime


class AssetFacetsOut(BaseModel):
    """What the list's filters can offer, counted over the whole filtered set,
    each dimension under every filter except its own."""

    resource_type: dict[str, int]
    environment: dict[str, int]
    #: ``none`` for the assets tied to no region.
    region: dict[str, int]


class AssetsMeta(PageMeta):
    #: How many of the filtered set CloudGuard has no rule for.
    unchecked: int
    facets: AssetFacetsOut


class HierarchyGroupOut(ClosedModel):
    #: ``None`` for what sits directly in the subscription.
    name: str | None
    asset_count: int
    open_findings: int


class HierarchyScopeOut(ClosedModel):
    """A subscription, or the directory, and its groups -- worst first."""

    #: The subscription id, or ``directory``.
    id: str
    name: str | None
    kind: Literal["SUBSCRIPTION", "DIRECTORY"]
    asset_count: int
    open_findings: int
    groups: list[HierarchyGroupOut]


class HierarchyMeta(BaseModel):
    total_assets: int
    total_open_findings: int


class ResolvedAssetOut(BaseModel):
    """The row id behind a provider id."""

    id: UUID


class ContextFactOut(BaseModel):
    """One context value, with where it came from and how much to trust it."""

    value: str | None
    source: ContextSource
    #: On 0..1, derived from the source.
    confidence: float


class AssetContextOut(BaseModel):
    """Criticality, sensitivity and environment with their provenance. Exposure
    is absent on purpose: it is read off the configuration, so there is no
    source to name and nothing to declare."""

    criticality: ContextFactOut
    data_sensitivity: ContextFactOut
    environment: ContextFactOut


class PlacementOut(BaseModel):
    """Where the asset sits, read the way the estate map's lens reads it."""

    #: The subscription id, or ``directory``.
    scope_id: str
    scope_name: str
    resource_group: str | None


class AssetFindingOut(BaseModel):
    id: UUID
    rule_id: str
    title: str
    severity: Severity
    status: FindingStatus
    risk_score: float | None


class AssetDetailOut(BaseModel):
    id: UUID
    name: str
    resource_type: ResourceType
    provider: Provider
    provider_resource_id: str
    region: str | None
    environment: str | None
    criticality: Level
    data_sensitivity: Level
    public_exposure: Level
    context: AssetContextOut
    #: What the provider said about it, as normalized.
    metadata: dict[str, Any]
    first_seen_at: datetime
    last_seen_at: datetime
    #: Set when a later scan looked for the asset and did not find it.
    absent_since: datetime | None
    placement: PlacementOut
    #: The directory the asset lives in, for a portal link that opens there.
    tenant_id: str | None
    open_findings: int
    findings: list[AssetFindingOut]
