from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, Field

from app.core.enums import (
    AccessKind,
    Level,
    Provider,
    RelationshipType,
    ResourceType,
    Severity,
)
from app.graph.model import DeadEndReason
from app.graph.patterns import PatternKind

#: Links one simulation may remove. Each is weighed against the rest by
#: rebuilding the estate without it, so the cost grows with the plan -- and a
#: plan longer than this is a project, not a what-if.
MAX_SIMULATED_CUTS = 10


class SimulatedLink(BaseModel):
    """One link, named the way a drawn edge names it."""

    source: str = Field(min_length=1, max_length=2048)
    relationship: RelationshipType
    target: str = Field(min_length=1, max_length=2048)


class SimulationRequest(BaseModel):
    """Links to remove together. A body rather than a query string, because
    ten Azure ids three times over do not fit in a URL every proxy accepts."""

    cuts: list[SimulatedLink] = Field(min_length=1, max_length=MAX_SIMULATED_CUTS)


class PathEntryOut(BaseModel):
    """Where a route starts: somewhere an attacker could be."""

    id: str
    name: str
    resource_type: ResourceType
    public_exposure: Level


class PathTargetOut(BaseModel):
    """What a route ends on: something worth taking."""

    id: str
    name: str
    resource_type: ResourceType
    data_sensitivity: Level


class PathStepOut(BaseModel):
    """One hop, in plain language and by id."""

    source: str
    source_id: str
    relationship: RelationshipType
    target: str
    target_id: str
    description: str
    # The role, the network, the kind of identity -- what the hop is beyond its
    # kind, read off the two assets (DECISIONS.md section 121).
    facts: list[str]
    detail: str


class PathBreakOut(BaseModel):
    """Where to cut a route: always a capability hop, never containment."""

    description: str
    detail: str
    relationship: RelationshipType
    source_id: str
    target_id: str


class AttackPathOut(BaseModel):
    """One route, as ``services.graph.serialize_path`` writes it."""

    entry: PathEntryOut
    target: PathTargetOut
    hops: int
    steps: list[PathStepOut]
    cheapest_break: PathBreakOut | None


# -- What every drawing shares ------------------------------------------------


class FindingTallyOut(BaseModel):
    """Open findings on an asset or a box, and the worst of them."""

    open: int
    worst: Severity | None


class AssetRefOut(BaseModel):
    """An asset named the way every list on the access view names one: its
    provider id, and its row id where CloudGuard holds one to link to."""

    id: str
    asset_id: UUID | None
    name: str
    resource_type: ResourceType


class GraphEdgeOut(BaseModel):
    source: str
    target: str
    relationship: RelationshipType
    #: The relationship as a verb, for the line's label.
    label: str


class ReachCountsMeta(BaseModel):
    """The honest denominator for an empty answer. No routes because nothing is
    exposed is a different thing from no routes because nothing was classified
    as sensitive -- and what they are, because every directory account is an
    entry point and every administrator a sensitive one (DECISIONS.md section
    119)."""

    entry_points: int
    sensitive_targets: int
    entry_point_types: dict[str, int]
    sensitive_target_types: dict[str, int]


# -- The list, and where each way in stops ------------------------------------


class DeadEndOut(BaseModel):
    """One way in with no route out, and where it stops."""

    id: str
    asset_id: UUID | None
    name: str
    resource_type: ResourceType
    public_exposure: Level
    reason: DeadEndReason
    reached: int


class AttackPathsMeta(ReachCountsMeta):
    total: int
    #: Where each way in stops, up to a cap, and how many there are. Worked out
    #: only when there is no route -- the one time the page has nothing else
    #: to say -- and ``None`` otherwise.
    dead_ends: list[DeadEndOut] | None = None
    dead_ends_total: int | None = None


# -- Choke points and cuts -----------------------------------------------------


class LinkEndOut(BaseModel):
    id: str
    name: str
    resource_type: ResourceType


class ClosedRouteOut(BaseModel):
    """A route that closes, named by its ends."""

    entry: str
    target: str
    hops: int
    data_sensitivity: Level


class ChokePointOut(BaseModel):
    """One link, what closes with it, and the honest denominator.

    ``on_routes`` beside ``severs``, because the gap between them is a way
    round: a link on twenty routes that closes three.
    """

    description: str
    detail: str
    facts: list[str]
    relationship: RelationshipType
    source: LinkEndOut
    target: LinkEndOut
    severs: int
    on_routes: int
    total_routes: int
    closes: list[ClosedRouteOut]


class ChokePointsMeta(BaseModel):
    total_routes: int


class RouteEndOut(BaseModel):
    id: str
    name: str


class RouteTargetEndOut(RouteEndOut):
    data_sensitivity: Level


class WhatIfClosedOut(BaseModel):
    entry: RouteEndOut
    target: RouteTargetEndOut
    hops: int


class WhatIfOut(BaseModel):
    """What closes if one link is removed, across the organization."""

    description: str
    relationship: RelationshipType
    source_id: str
    target_id: str
    closes: list[WhatIfClosedOut]
    before: int
    after: int


class LinkOut(BaseModel):
    source: str
    relationship: RelationshipType
    target: str


class SimulatedRouteOut(BaseModel):
    """A route a plan closes, by the key the route map carries."""

    key: str
    entry: str
    target: str
    hops: int
    data_sensitivity: Level


class RemainingRouteOut(BaseModel):
    """A route still open with the plan made, and how long it now runs."""

    key: str
    hops: int


class SimulatedCutOut(BaseModel):
    source: str
    relationship: RelationshipType
    target: str
    description: str
    detail: str
    #: Routes this cut closes on its own.
    alone: int
    #: Routes that stay open if this cut is taken out of the plan.
    needed_for: int


class SimulationOut(BaseModel):
    """A plan of cuts, what it closes together, and what is left."""

    before: int
    after: int
    closed: list[SimulatedRouteOut]
    #: Closed only because the cuts were made together.
    together: list[str]
    remaining: list[RemainingRouteOut]
    cuts: list[SimulatedCutOut]
    #: Links in the plan the estate does not have.
    missing: list[LinkOut]
    #: What to cut next, ranked over the estate with the plan made.
    next: list[ChokePointOut]


class SimulationMeta(BaseModel):
    max_cuts: int


# -- Blast radius and access ---------------------------------------------------


class BlastAssetOut(BaseModel):
    id: str
    asset_id: UUID | None
    name: str
    resource_type: ResourceType
    data_sensitivity: Level


class AccessHolderOut(BaseModel):
    """A principal holding a role over the asset."""

    principal: AssetRefOut
    role: str
    at: AssetRefOut
    inherited_from: str | None
    kinds: list[AccessKind]
    controls: bool
    conditional: bool
    resolved: bool
    runs_on: list[AssetRefOut]
    #: A group's members, capped. ``None`` when the holder is not a group or its
    #: membership was not read, which is not the same as nobody.
    members: list[AssetRefOut] | None
    unlisted_members: list[str]
    members_total: int | None
    through_directory: bool
    eligible: bool


class AccessByTypeOut(BaseModel):
    resource_type: ResourceType
    kinds: list[AccessKind]


class AccessGrantOut(BaseModel):
    """A role the identity holds, and what it controls."""

    role: str
    at: AssetRefOut | None
    scope: str
    inherited_from: str | None
    conditional: bool
    resolved: bool
    grants_access: bool
    access: list[AccessByTypeOut]
    #: Capped for the payload; ``controlled_total`` is the count.
    controlled: list[AssetRefOut]
    controlled_total: int
    #: The group the role is held through, when it is not the identity's own.
    via: AssetRefOut | None
    through_directory: bool
    eligible: bool


class AccessOut(BaseModel):
    """Who holds access to an asset, and what an identity holds. Both halves
    every time, either possibly empty."""

    holders: list[AccessHolderOut]
    grants: list[AccessGrantOut]


class AccessMeta(BaseModel):
    holders_total: int
    grants_total: int
    controlling: int
    controlled_limit: int
    members_limit: int


# -- The neighbourhood ---------------------------------------------------------


class NeighborNodeOut(BaseModel):
    id: str
    asset_id: UUID | None
    name: str
    resource_type: ResourceType
    provider: Provider
    #: Hops from the focus: negative upstream, positive downstream.
    layer: int
    public_exposure: Level
    data_sensitivity: Level
    #: The graph's own predicates, so a box marked as a way in is exactly an
    #: asset a route may start from.
    entry: bool
    sensitive: bool
    findings: FindingTallyOut


class FoldedGroupOut(BaseModel):
    """Neighbours past the fan-out, counted rather than drawn."""

    id: str
    parent: str
    relationship: RelationshipType
    layer: int
    count: int
    by_type: dict[str, int]


class NeighborhoodOut(BaseModel):
    focus: str
    nodes: list[NeighborNodeOut]
    groups: list[FoldedGroupOut]
    edges: list[GraphEdgeOut]
    routes: list[AttackPathOut]


class NeighborhoodMeta(BaseModel):
    routes_total: int
    depth: int
    truncated: bool
    max_nodes: int
    fan_out: int


# -- The estate map ------------------------------------------------------------


class EstateBoxBase(BaseModel):
    """What every box carries, whatever it holds, so a subscription and a
    single machine are read the same way."""

    id: str
    inside: bool
    scope_id: str
    scope_name: str
    provider: str | None
    group: str | None
    assets: int
    entry: int
    sensitive: int
    findings: FindingTallyOut
    routes: int


class ScopeBoxOut(EstateBoxBase):
    kind: Literal["scope"]
    name: str


class GroupBoxOut(EstateBoxBase):
    kind: Literal["group"]
    #: ``None`` for what sits directly in the scope.
    name: str | None


class AssetBoxOut(EstateBoxBase):
    kind: Literal["asset"]
    name: str
    provider_resource_id: str
    asset_id: UUID | None
    resource_type: ResourceType
    public_exposure: Level
    data_sensitivity: Level


class FoldBoxOut(EstateBoxBase):
    """Every asset past the cap, in one box."""

    kind: Literal["fold"]
    name: None
    by_type: dict[str, int]
    #: Folded although they carry reach; their links end at the fold.
    with_reach: int


EstateBoxOut = Annotated[
    ScopeBoxOut | GroupBoxOut | AssetBoxOut | FoldBoxOut, Field(discriminator="kind")
]


class EstateLinkOut(BaseModel):
    relationship: RelationshipType
    count: int
    label: str


class EstateEdgeOut(BaseModel):
    source: str
    target: str
    links: list[EstateLinkOut]


class EstateLensOut(BaseModel):
    scope_id: str | None
    group: str | None


class EstateOut(BaseModel):
    lens: EstateLensOut
    boxes: list[EstateBoxOut]
    edges: list[EstateEdgeOut]


class EstateMeta(BaseModel):
    routes_total: int
    max_assets: int
    folded_with_reach: int


# -- The route map -------------------------------------------------------------


class RouteMapNodeOut(BaseModel):
    id: str
    asset_id: UUID | None
    name: str
    resource_type: ResourceType
    provider: Provider
    scope_id: str
    scope_name: str
    group: str | None
    #: The fewest hops from any way in: the axis the canvas lays out along.
    column: int
    public_exposure: Level
    data_sensitivity: Level
    entry: bool
    sensitive: bool
    routes: int
    findings: FindingTallyOut


class RouteMapEdgeOut(BaseModel):
    """A drawn link and what removing it removes."""

    source: str
    relationship: RelationshipType
    target: str
    label: str
    facts: list[str]
    detail: str
    severs: int
    #: The routes that close, by key.
    closes: list[str]
    on_routes: int
    #: Whether some route through here has a way round.
    alternate: bool


class MappedRouteOut(AttackPathOut):
    key: str
    #: The pattern it belongs to; ``None`` for a route in none.
    pattern: str | None


class PatternEndOut(BaseModel):
    """The end that varies across a pattern, named."""

    id: str
    name: str
    route: str


class RoutePatternOut(BaseModel):
    """Routes that differ at one end only (DECISIONS.md section 123)."""

    id: str
    kind: PatternKind
    description: str
    size: int
    hops: int
    exemplar: str
    routes: list[str]
    varies: list[PatternEndOut]


class RouteMapOut(BaseModel):
    nodes: list[RouteMapNodeOut]
    edges: list[RouteMapEdgeOut]
    routes: list[MappedRouteOut]
    patterns: list[RoutePatternOut]
    #: Routes in no pattern. With the patterns, these are every route.
    loose: list[str]
    choke_points: list[ChokePointOut]


class RouteMapMeta(ReachCountsMeta):
    total: int
    #: What the drawing holds, said rather than implied.
    drawn: int
