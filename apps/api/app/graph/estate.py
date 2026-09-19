"""The estate drawn as its containers, and the reach that crosses them.

The neighbourhood (DECISIONS.md section 101) answers "what is around this
asset", and refuses to draw the whole tenant because a canvas of every asset is
the picture nobody can read. That refusal leaves a question unanswered: "how is
my estate wired together" -- which subscription's identities can act over which
other subscription, and where the directory's principals land. This answers it
by drawing containers rather than assets (section 111).

A *lens* picks what is opened: nothing (the estate: one box per subscription and
one for the directory), one subscription (its resource groups, and the assets
that sit directly in it), or one resource group (its assets). Whatever lies
outside the lens is drawn only where reach crosses into it or out of it, and
then as the coarsest box that names it -- another subscription, or another group
in this one.

Pure: the placements come from the database, the graph from the cache, and this
module only groups them.
"""

from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from app.core.enums import RelationshipType
from app.domain.resource import CloudResource
from app.graph.model import ENTRY_EXPOSURE, SENSITIVE_DATA, AssetGraph, Path

# The scope an asset belongs to when it belongs to no subscription: the
# directory, which outlives every subscription under it. The same key the
# hierarchy view and the list's scope filter use, so a box and a filter that
# name the directory name the same set.
DIRECTORY_SCOPE = "directory"

# Asset boxes one lens may draw. The rest are folded into one counted box --
# never dropped -- and past this a group's canvas stops being read. Lower than
# the neighbourhood's cap, because every box here sits in a column of its own
# kind rather than spread along a walk.
ESTATE_MAX_ASSETS = 40

# The id of the box holding the assets a lens did not draw. One per lens: what
# is in it is listed by the same filter the lens is, so it needs no identity of
# its own.
FOLD_BOX = "fold"


@dataclass(frozen=True)
class Placement:
    """Where one asset sits: a scope, and a resource group inside it or none."""

    scope: str
    group: str | None = None


@dataclass(frozen=True)
class Lens:
    """What is opened. Nothing, one scope, or one resource group in a scope."""

    scope: str | None = None
    group: str | None = None


@dataclass(frozen=True)
class EstateBox:
    """One box on the map: a scope, a group, a single asset, or the fold."""

    id: str
    kind: str
    #: Whether the box is part of what the lens opened, or a neighbour it
    #: reaches or is reached by.
    inside: bool
    scope: str
    group: str | None
    members: tuple[CloudResource, ...]


@dataclass(frozen=True)
class EstateEdge:
    """Every link between two boxes, counted by relationship."""

    source: str
    target: str
    links: tuple[tuple[RelationshipType, int], ...]
    #: Whether any of the links is a hop on an attack path.
    on_route: bool


@dataclass(frozen=True)
class EstateMap:
    lens: Lens
    boxes: tuple[EstateBox, ...]
    edges: tuple[EstateEdge, ...]
    #: Attack paths passing through each drawn box.
    routes: dict[str, int]
    #: Attack paths that touch what the lens opened.
    routes_total: int
    #: Assets folded although they carry reach; their links end at the fold.
    folded_with_reach: int


def scope_box(scope: str) -> str:
    return f"scope:{scope}"


def group_box(scope: str, group: str | None) -> str:
    """A resource group's box; ``None`` is what sits directly in the scope.

    Lowercased because ARM is case-insensitive about group names: `Prod` and
    `prod` are one group, and two boxes for it would split its reach in half.
    """
    return f"group:{scope}:{(group or '').lower()}"


def asset_box(provider_id: str) -> str:
    return f"asset:{provider_id}"


def box_kind(box: str) -> str:
    return FOLD_BOX if box == FOLD_BOX else box.split(":", 1)[0]


def _same_group(a: str | None, b: str | None) -> bool:
    return (a or "").lower() == (b or "").lower()


def _crosses(relationship: RelationshipType) -> bool:
    """Links drawn between boxes: what an identity may do, not where things live."""
    return relationship.is_capability and relationship is not RelationshipType.CONTAINS


def estate_map(
    graph: AssetGraph,
    placements: dict[str, Placement],
    lens: Lens,
    paths: Iterable[Path] = (),
    *,
    max_assets: int = ESTATE_MAX_ASSETS,
) -> EstateMap | None:
    """The estate through one lens, or None when the lens names nothing.

    Only reach is drawn between boxes, and only reach that crosses them: a
    role over a subscription held by a directory principal is an edge from the
    directory to the subscription, while a link between two assets in one group
    is inside a box and is not. Containment is what the boxes *are*, so it is
    drawn only where an attack path runs along it -- otherwise a subscription
    would carry an edge to every group it holds, and the one route through them
    would be lost among forty statements of where things live.
    """
    placed = {
        node_id: placements.get(node_id, Placement(DIRECTORY_SCOPE)) for node_id in graph.nodes
    }

    if lens.scope is None and lens.group is not None:
        return None
    if lens.scope is not None and not any(p.scope == lens.scope for p in placed.values()):
        return None
    if lens.group is not None and not any(
        p.scope == lens.scope and _same_group(p.group, lens.group) for p in placed.values()
    ):
        return None

    def inside(node_id: str) -> bool:
        p = placed[node_id]
        if lens.scope is None:
            return True
        if p.scope != lens.scope:
            return False
        return lens.group is None or _same_group(p.group, lens.group)

    def coarse(node_id: str) -> str:
        """The box an asset lands in before any are folded."""
        p = placed[node_id]
        if lens.scope is None or p.scope != lens.scope:
            return scope_box(p.scope)
        if lens.group is None:
            # Opening a subscription: its groups are boxes, and what sits
            # directly in it -- the subscription itself, above all, which is
            # what a role over the subscription lands on -- is drawn as itself.
            return group_box(p.scope, p.group) if p.group else asset_box(node_id)
        if _same_group(p.group, lens.group):
            return asset_box(node_id)
        return group_box(p.scope, p.group)

    reach: dict[str, int] = defaultdict(int)
    for source, relationship, target in graph.links():
        if _crosses(relationship) and source != target:
            reach[source] += 1
            reach[target] += 1

    def notable(node_id: str) -> bool:
        node = graph.nodes[node_id]
        return node.public_exposure in ENTRY_EXPOSURE or node.data_sensitivity in SENSITIVE_DATA

    routes = list(paths)
    on_route: set[tuple[str, RelationshipType, str]] = {
        (step.source.provider_resource_id, step.relationship, step.target.provider_resource_id)
        for path in routes
        for step in path.steps
    }
    routed_nodes = {node_id for path in routes for node_id in path.node_ids()}

    # Assets drawn as themselves, and the ones folded. First whatever can matter
    # on a route -- a way in, sensitive data -- then whatever a route runs
    # through, then by how much reach it carries. An asset with none of those
    # is inventory, which the list answers better, so it is always folded.
    candidates = [n for n in placed if inside(n) and coarse(n) == asset_box(n)]
    drawable = sorted(
        (n for n in candidates if notable(n) or n in routed_nodes or reach[n] > 0),
        key=lambda n: (
            not notable(n),
            n not in routed_nodes,
            -reach[n],
            graph.nodes[n].resource_type.value,
            graph.nodes[n].name,
            n,
        ),
    )
    drawn = set(drawable[:max_assets])
    folded = [n for n in candidates if n not in drawn]

    box_of: dict[str, str] = {}
    for node_id in placed:
        box = coarse(node_id)
        box_of[node_id] = FOLD_BOX if box_kind(box) == "asset" and node_id not in drawn else box
    route_boxes = [{box_of[n] for n in path.node_ids() if n in box_of} for path in routes]

    members: dict[str, list[CloudResource]] = defaultdict(list)
    for node_id, box in box_of.items():
        members[box].append(graph.nodes[node_id])
    opened = {box_of[node_id] for node_id in placed if inside(node_id)}

    counted: dict[tuple[str, str], dict[RelationshipType, int]] = defaultdict(
        lambda: defaultdict(int)
    )
    routed: set[tuple[str, str]] = set()
    for source, relationship, target in graph.links():
        a, b = box_of[source], box_of[target]
        if a == b or (a not in opened and b not in opened):
            continue
        hop = (source, relationship, target) in on_route
        if not _crosses(relationship) and not (relationship is RelationshipType.CONTAINS and hop):
            continue
        counted[(a, b)][relationship] += 1
        if hop:
            routed.add((a, b))

    shown = opened | {box for pair in counted for box in pair}

    boxes = []
    for box in shown:
        held = sorted(members[box], key=lambda r: r.provider_resource_id)
        first = placed[held[0].provider_resource_id]
        boxes.append(
            EstateBox(
                id=box,
                kind=box_kind(box),
                inside=box in opened,
                scope=first.scope,
                group=None if box_kind(box) == "scope" else first.group,
                members=tuple(held),
            )
        )
    boxes.sort(key=lambda b: (not b.inside, b.kind, b.id))

    edges = tuple(
        EstateEdge(
            source=a,
            target=b,
            links=tuple(sorted(by.items(), key=lambda item: item[0].value)),
            on_route=(a, b) in routed,
        )
        for (a, b), by in sorted(counted.items())
    )

    # A route counts here when it passes through what the lens opened. One
    # that only runs between two neighbours is about somewhere else.
    touching = [on for on in route_boxes if on & opened]
    through = {box: sum(1 for on in touching if box in on) for box in shown}
    return EstateMap(
        lens=lens,
        boxes=tuple(boxes),
        edges=edges,
        routes={box: count for box, count in through.items() if count},
        routes_total=len(touching),
        folded_with_reach=sum(1 for n in folded if reach[n] > 0),
    )
