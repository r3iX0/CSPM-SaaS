"""Rebuilding the asset graph from what the last scan stored.

Computed on read rather than persisted, and that is a deliberate limit rather
than a shortcut. Attack paths are a pure function of the assets and edges
already in the database, so storing them would mean keeping a derived table in
step with its inputs -- and a stale path is worse than no path, because it
describes a route somebody may already have closed.

What is genuinely lost is history: "did a new attack path appear this week" is
a question about change over time, and this cannot answer it. That wants an
``attack_paths`` table written per scan, which is worth building once paths are
being acted on rather than looked at (ARCHITECTURE_REVIEW.md section 8).

**Assets that are still there.** An asset a scan looked for and did not find
keeps its row -- deliberately, so its findings stay history and so an asset that
vanishes for a week and returns is one asset rather than two -- and the graph
must not keep it. A route through something that no longer exists is not a
weaker claim than a real one, it is a false one, and it was being served on the
attack-paths page while the scanner's own graph, built from one scan's state,
never contained it. Two views of one tenant disagreeing, with the wrong one
facing the customer.
"""

from collections import OrderedDict
from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import FindingStatus, RelationshipType, Severity
from app.domain.resource import CloudResource
from app.graph import AssetGraph, ChokePoint, DeadEnd, Neighborhood, Path
from app.graph.access import AccessGrant, AccessHolder
from app.graph.estate import EstateMap
from app.graph.model import ENTRY_EXPOSURE, RELATIONSHIP_VERBS, SENSITIVE_DATA
from app.graph.patterns import PatternKind, route_patterns
from app.models.finding import Finding
from app.models.resource import ResourceRecord, ResourceRelationship
from app.services.placement import Placements

# Graphs held in memory, keyed by tenant, each remembered with the version of
# the data it was built from.
#
# Six callers build this and four of them are request handlers: the attack-path
# list, choke points, blast radius, and a finding's routes. Every one of them
# read the whole tenant -- every present asset and every edge -- and a person
# clicking between those screens paid for it each time, on the one page where a
# tenant large enough to have interesting paths is also large enough to be slow.
#
# Small on purpose. This is a read cache in a process that serves many tenants,
# and holding a graph per tenant indefinitely trades a latency problem for a
# memory one.
_MAX_CACHED = 8
_GraphVersion = tuple[datetime | None, datetime | None, int, int]
_cache: "OrderedDict[UUID, tuple[_GraphVersion, AssetGraph]]" = OrderedDict()


async def graph_version(
    session: AsyncSession, organization_id: UUID
) -> tuple[datetime | None, datetime | None, int, int]:
    """What the graph would be built from, cheaply enough to ask every time.

    Keyed on the data rather than on the scan that wrote it. A scan is the only
    thing that rewrites assets and edges today, but keying on "the newest scan"
    would be an inference about *which processes write*, and the day something
    else does -- a context declaration applied in place, a manual asset edit --
    the cache would go stale silently and serve routes through an estate that
    has moved.

    A newest time and a count for each of the two, because either can change by
    something being taken away, and a removal moves no timestamp: the rows that
    remain were not touched, and the one that went is not there to carry a
    time. The asset count catches a machine leaving the estate; the edge count
    catches a scan whose only change was to cut a link -- an NSG unbound, a
    role revoked -- which is exactly the moment somebody opens this page to
    confirm the route is gone.
    """
    assets = (
        await session.execute(
            select(
                func.max(ResourceRecord.updated_at),
                func.count(ResourceRecord.id),
            ).where(
                ResourceRecord.organization_id == organization_id,
                ResourceRecord.absent_since.is_(None),
            )
        )
    ).one()
    edges = (
        await session.execute(
            select(
                func.max(ResourceRelationship.created_at),
                func.count(ResourceRelationship.id),
            ).where(ResourceRelationship.organization_id == organization_id)
        )
    ).one()
    return (assets[0], edges[0], int(assets[1] or 0), int(edges[1] or 0))


async def load_graph(session: AsyncSession, organization_id: UUID) -> AssetGraph:
    """Every asset this organization holds, and the edges between them.

    Two queries whatever the size of the tenant, and a third small one first to
    ask whether they are needed at all. The edges are stored by database id and
    the graph works in provider ids -- the ones a customer can paste into a
    portal -- so the mapping happens here rather than leaking a surrogate key
    into something a person reads.

    **Cached against the version of the data, not against a clock.** A TTL would
    make the page briefly wrong after every scan, which on this page means
    showing a route somebody has already closed -- and a stale path is worse
    than no path. Keyed on the data's own version, a scan invalidates it by
    happening, and a tenant nobody has scanned pays for the traversal once.
    """
    version = await graph_version(session, organization_id)
    cached = _cache.get(organization_id)
    if cached is not None and cached[0] == version:
        _cache.move_to_end(organization_id)
        return cached[1]

    graph = await _build_graph(session, organization_id)
    _cache[organization_id] = (version, graph)
    _cache.move_to_end(organization_id)
    while len(_cache) > _MAX_CACHED:
        _cache.popitem(last=False)
    return graph


def forget_cached_graphs() -> None:
    """Drop everything held. For tests, and for a worker that has just written.

    Not called by the scan pipeline: it builds its graph from the normalized
    state in hand rather than from the database, so it never reads this cache
    and cannot leave it stale for its own process.
    """
    _cache.clear()


async def _build_graph(session: AsyncSession, organization_id: UUID) -> AssetGraph:
    records = list(
        (
            await session.execute(
                select(ResourceRecord).where(
                    ResourceRecord.organization_id == organization_id,
                    # Present, as of the last scan that covered it.
                    ResourceRecord.absent_since.is_(None),
                )
            )
        )
        .scalars()
        .all()
    )

    by_id = {record.id: record.provider_resource_id for record in records}
    edges = (
        (
            await session.execute(
                select(ResourceRelationship).where(
                    ResourceRelationship.organization_id == organization_id
                )
            )
        )
        .scalars()
        .all()
    )

    resources = [
        CloudResource(
            provider_resource_id=record.provider_resource_id,
            resource_type=record.resource_type,
            name=record.name,
            provider=record.provider,
            region=record.region,
            environment=record.environment,
            criticality=record.criticality,
            data_sensitivity=record.data_sensitivity,
            public_exposure=record.public_exposure,
            metadata=record.resource_metadata or {},
        )
        for record in records
    ]

    relationships = [
        (
            by_id[edge.source_resource_id],
            RelationshipType(edge.relationship_type),
            by_id[edge.target_resource_id],
        )
        for edge in edges
        # An edge whose endpoints are not both still present -- because the
        # resource was deleted outright and the edge outlived it, or because it
        # is absent and was filtered above. Following one would describe a route
        # through something that is gone.
        if edge.source_resource_id in by_id and edge.target_resource_id in by_id
    ]

    return AssetGraph.build(resources, relationships)


def serialize_choke_point(choke: ChokePoint, total_routes: int) -> dict:
    """One link, what closes with it, and the honest denominator.

    ``on_routes`` is carried beside ``severs`` rather than dropped, because the
    gap between them is the useful part: a link sitting on twenty routes that
    closes three is a link with a way round, and a customer who cut it expecting
    twenty would rightly stop trusting the number.
    """
    return {
        "description": choke.describe(),
        # The same link with its evidence in it. Carried beside the plain
        # sentence rather than replacing it, because the plain one is what the
        # rest of the product calls this link.
        "detail": choke.step.detail(),
        "facts": list(choke.step.facts),
        "relationship": choke.step.relationship.value,
        "source": {
            "id": choke.step.source.provider_resource_id,
            "name": choke.step.source.name,
            "resource_type": choke.step.source.resource_type.value,
        },
        "target": {
            "id": choke.step.target.provider_resource_id,
            "name": choke.step.target.name,
            "resource_type": choke.step.target.resource_type.value,
        },
        "severs": choke.severs,
        "on_routes": choke.on_routes,
        "total_routes": total_routes,
        # What actually closes, named. A count is a claim; these are the claim's
        # working, and they are what a customer checks it against.
        "closes": [
            {
                "entry": path.entry.name,
                "target": path.target.name,
                "hops": path.hops,
                "data_sensitivity": path.target.data_sensitivity.value,
            }
            for path in choke.severed
        ],
    }


def serialize_path(path: Path) -> dict:
    step = path.cheapest_break()
    return {
        "entry": {
            "id": path.entry.provider_resource_id,
            "name": path.entry.name,
            "resource_type": path.entry.resource_type.value,
            "public_exposure": path.entry.public_exposure.value,
        },
        "target": {
            "id": path.target.provider_resource_id,
            "name": path.target.name,
            "resource_type": path.target.resource_type.value,
            "data_sensitivity": path.target.data_sensitivity.value,
        },
        "hops": path.hops,
        # The route in plain language, hop by hop. A path that only named its
        # endpoints would be an alarm; naming the route is what makes it a
        # thing somebody can go and cut.
        "steps": [
            {
                "source": s.source.name,
                "source_id": s.source.provider_resource_id,
                "relationship": s.relationship.value,
                "target": s.target.name,
                "target_id": s.target.provider_resource_id,
                "description": s.describe(),
                # What the hop is, beyond its kind: the role held over the
                # scope, the network two machines share. "can act over" names
                # nothing anybody can go and change; "Contributor" does.
                "facts": list(s.facts),
                "detail": s.detail(),
            }
            for s in path.steps
        ],
        # Where to cut it. Containment cannot be removed -- a storage account
        # has to live somewhere -- so this is always a capability hop, and the
        # earliest one closes the way in rather than containing what somebody
        # reaches once inside.
        "cheapest_break": (
            {
                "description": step.describe(),
                "detail": step.detail(),
                "relationship": step.relationship.value,
                "source_id": step.source.provider_resource_id,
                "target_id": step.target.provider_resource_id,
            }
            if step
            else None
        ),
    }


def _asset_ref(resource: CloudResource, ids: dict[str, UUID]) -> dict:
    """An asset named the way every list on the access view names one."""
    asset_id = ids.get(resource.provider_resource_id)
    return {
        "id": resource.provider_resource_id,
        "asset_id": str(asset_id) if asset_id else None,
        "name": resource.name,
        "resource_type": resource.resource_type.value,
    }


def access_asset_ids(holders: list[AccessHolder], grants: list[AccessGrant]) -> list[str]:
    """Every provider id the access view links to, for one row-id lookup."""
    wanted: set[str] = set()
    for holder in holders:
        wanted.add(holder.principal.provider_resource_id)
        wanted.add(holder.at.provider_resource_id)
        wanted.update(workload.provider_resource_id for workload in holder.runs_on)
        wanted.update(member.provider_resource_id for member in holder.members or ())
    for grant in grants:
        if grant.at is not None:
            wanted.add(grant.at.provider_resource_id)
        wanted.update(asset.provider_resource_id for asset in grant.controlled)
        if grant.via is not None:
            wanted.add(grant.via.provider_resource_id)
    return sorted(wanted)


def serialize_access(
    holders: list[AccessHolder],
    grants: list[AccessGrant],
    ids: dict[str, UUID],
    *,
    controlled_limit: int,
    members_limit: int,
) -> dict:
    """Who holds access to an asset, and what an identity holds.

    Both halves every time, either possibly empty: an asset is held by
    principals, an identity holds roles, and a managed identity's own page is
    both. The controlled assets under a grant are capped for the payload and
    counted in full, so "controls 412" is never drawn as the twelve listed.
    """
    return {
        "holders": [
            {
                "principal": _asset_ref(holder.principal, ids),
                "role": holder.role,
                "at": _asset_ref(holder.at, ids),
                "inherited_from": holder.inherited_from,
                "kinds": [kind.value for kind in holder.kinds],
                "controls": holder.controls,
                "conditional": holder.conditional,
                "resolved": holder.resolved,
                "runs_on": [_asset_ref(workload, ids) for workload in holder.runs_on],
                # A group's members: null when the holder is not a group or its
                # membership was not read, which is not the same as nobody.
                "members": (
                    None
                    if holder.members is None
                    else [_asset_ref(member, ids) for member in holder.members[:members_limit]]
                ),
                "unlisted_members": list(holder.unlisted_members[:members_limit]),
                "members_total": (
                    None
                    if holder.members is None
                    else len(holder.members) + len(holder.unlisted_members)
                ),
                "through_directory": holder.through_directory,
                "eligible": holder.eligible,
            }
            for holder in holders
        ],
        "grants": [
            {
                "role": grant.role,
                "at": _asset_ref(grant.at, ids) if grant.at is not None else None,
                "scope": grant.scope,
                "inherited_from": grant.inherited_from,
                "conditional": grant.conditional,
                "resolved": grant.resolved,
                "grants_access": grant.grants_access,
                "access": [
                    {
                        "resource_type": resource_type.value,
                        "kinds": [kind.value for kind in kinds],
                    }
                    for resource_type, kinds in grant.access
                ],
                "controlled": [
                    _asset_ref(asset, ids) for asset in grant.controlled[:controlled_limit]
                ],
                "controlled_total": len(grant.controlled),
                "via": _asset_ref(grant.via, ids) if grant.via is not None else None,
                "through_directory": grant.through_directory,
                "eligible": grant.eligible,
            }
            for grant in grants
        ],
    }


def routes_through(graph: AssetGraph) -> dict[str, int]:
    """How many attack paths each asset is on, wherever on them it sits.

    The same count :meth:`AssetGraph.paths_through` gives one asset at a time,
    for every asset in one pass -- a queue asking per row would walk the route
    list once per task.
    """
    through: dict[str, int] = {}
    for path in graph.attack_paths():
        for node_id in path.node_ids():
            through[node_id] = through.get(node_id, 0) + 1
    return through


def serialize_dead_end(end: DeadEnd, ids: dict[str, UUID]) -> dict:
    """One way in with no route out, and where it stops."""
    entry = end.entry
    return {
        "id": entry.provider_resource_id,
        "asset_id": (
            str(ids[entry.provider_resource_id])
            if entry.provider_resource_id in ids
            else None
        ),
        "name": entry.name,
        "resource_type": entry.resource_type.value,
        "public_exposure": entry.public_exposure.value,
        "reason": end.reason.value,
        "reached": end.reached,
    }


async def asset_ids(
    session: AsyncSession, organization_id: UUID, provider_ids: list[str]
) -> dict[str, UUID]:
    """The row id behind each provider id, for linking a vertex to its page.

    The graph works in provider ids and the asset page is addressed by row id,
    so a canvas whose boxes open their assets needs the mapping. One query for
    the handful drawn, rather than carrying a surrogate key through the graph.
    """
    if not provider_ids:
        return {}
    rows = await session.execute(
        select(ResourceRecord.provider_resource_id, ResourceRecord.id).where(
            ResourceRecord.organization_id == organization_id,
            ResourceRecord.absent_since.is_(None),
            ResourceRecord.provider_resource_id.in_(provider_ids),
        )
    )
    return dict(rows.tuples().all())


# Worst first, for naming the most severe open finding on an asset.
_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


async def open_findings(
    session: AsyncSession, organization_id: UUID, row_ids: list[UUID] | None
) -> dict[UUID, dict]:
    """How many open findings each drawn asset carries, and the worst of them.

    One grouped query for the assets on the canvas, or for every asset when
    ``row_ids`` is None -- the estate map counts the whole tenant, and naming
    every row in an ``IN`` list would be the same answer at a far higher price.
    Open means what it means on the security score -- OPEN or IN_PROGRESS -- so
    the number on a box and the number on the asset's own page never disagree.
    """
    if row_ids is not None and not row_ids:
        return {}
    scoped = [Finding.resource_id.in_(row_ids)] if row_ids is not None else []
    rows = await session.execute(
        select(Finding.resource_id, Finding.severity, func.count(Finding.id))
        .where(
            Finding.organization_id == organization_id,
            *scoped,
            Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_PROGRESS]),
        )
        .group_by(Finding.resource_id, Finding.severity)
    )
    found: dict[UUID, dict] = {}
    for resource_id, severity, count in rows.tuples().all():
        if resource_id is None:
            continue
        entry = found.setdefault(resource_id, {"open": 0, "worst": None})
        entry["open"] += int(count)
        worst = entry["worst"]
        if worst is None or _SEVERITY_RANK[severity] < _SEVERITY_RANK[Severity(worst)]:
            entry["worst"] = severity.value
    return found


def fold_id(parent: str, relationship: RelationshipType, layer: int) -> str:
    """A folded group's id, which is also how the page asks to open it.

    Built from the fold's own identity rather than numbered, so it survives a
    refetch at another depth and means the same thing on the next request.
    The parent goes last because it is the only part that may contain ``:``.
    """
    return f"group:{layer}:{relationship.value}:{parent}"


def parse_fold_id(value: str) -> tuple[str, RelationshipType, int] | None:
    """The fold a page asked to open, or None for anything that is not one.

    None rather than an error: an id from a stale page names a fold that may
    no longer exist, and drawing the graph without opening it is the right
    answer to that, not a 422.
    """
    parts = value.split(":", 3)
    if len(parts) != 4 or parts[0] != "group":
        return None
    try:
        return parts[3], RelationshipType(parts[2]), int(parts[1])
    except ValueError:
        return None


def serialize_neighborhood(
    graph: AssetGraph,
    around: Neighborhood,
    ids: dict[str, UUID],
    findings: dict[UUID, dict] | None = None,
    routes: list[Path] | None = None,
) -> dict:
    """Vertices, folded groups, the edges between them, and the routes through
    the focus, ready to draw.

    Group edges are emitted beside the real ones, pointing the way reach runs,
    so the canvas draws one list of edges and never has to know that a group is
    not an asset.

    ``entry`` and ``sensitive`` are the graph's own predicates, sent rather than
    re-derived from the levels in the browser, so a box marked as a way in is
    exactly an asset a route may start from. UNKNOWN exposure is never an entry
    point: a gap in collection is not a door.
    """
    findings = findings or {}
    nodes = []
    for node_id, layer in sorted(around.layers.items(), key=lambda item: (item[1], item[0])):
        resource = graph.nodes[node_id]
        asset_id = ids.get(node_id)
        nodes.append(
            {
                "id": node_id,
                "asset_id": str(asset_id) if asset_id else None,
                "name": resource.name,
                "resource_type": resource.resource_type.value,
                "provider": resource.provider.value,
                "layer": layer,
                "public_exposure": resource.public_exposure.value,
                "data_sensitivity": resource.data_sensitivity.value,
                "entry": resource.public_exposure in ENTRY_EXPOSURE,
                "sensitive": resource.data_sensitivity in SENSITIVE_DATA,
                "findings": (findings.get(asset_id) if asset_id else None)
                or {"open": 0, "worst": None},
            }
        )

    edges = [
        {
            "source": source,
            "target": target,
            "relationship": relationship.value,
            "label": RELATIONSHIP_VERBS.get(relationship, relationship.value),
        }
        for source, relationship, target in around.edges
    ]

    groups = []
    for group in around.groups:
        group_id = fold_id(group.parent, group.relationship, group.layer)
        by_type: dict[str, int] = {}
        for member in group.members:
            by_type[member.resource_type.value] = by_type.get(member.resource_type.value, 0) + 1
        groups.append(
            {
                "id": group_id,
                "parent": group.parent,
                "relationship": group.relationship.value,
                "layer": group.layer,
                "count": len(group.members),
                "by_type": dict(sorted(by_type.items(), key=lambda item: (-item[1], item[0]))),
            }
        )
        downstream = group.layer > 0
        edges.append(
            {
                "source": group.parent if downstream else group_id,
                "target": group_id if downstream else group.parent,
                "relationship": group.relationship.value,
                "label": RELATIONSHIP_VERBS.get(group.relationship, group.relationship.value),
            }
        )

    return {
        "focus": around.focus,
        "nodes": nodes,
        "groups": groups,
        "edges": edges,
        "routes": [serialize_path(path) for path in routes or []],
    }


def serialize_estate(
    estate: EstateMap,
    placements: Placements,
    findings: dict[UUID, dict],
) -> dict:
    """Boxes and the counted links between them, ready to draw.

    Every box carries the same counts whatever it holds -- assets, ways in,
    sensitive assets, open findings and the worst of them, and the attack paths
    through it -- so a subscription and a single virtual machine are read the
    same way. ``entry`` and ``sensitive`` are counted with the graph's own
    predicates, as the neighbourhood's markers are, so "3 ways in" on a box is
    exactly three assets a route may start from.
    """
    boxes = []
    for box in estate.boxes:
        open_count = 0
        worst: Severity | None = None
        by_type: dict[str, int] = {}
        for member in box.members:
            by_type[member.resource_type.value] = by_type.get(member.resource_type.value, 0) + 1
            row = placements.row_ids.get(member.provider_resource_id)
            found = findings.get(row) if row else None
            if not found:
                continue
            open_count += found["open"]
            severity = Severity(found["worst"]) if found["worst"] else None
            if severity and (worst is None or _SEVERITY_RANK[severity] < _SEVERITY_RANK[worst]):
                worst = severity

        entry: dict = {
            "id": box.id,
            "kind": box.kind,
            "inside": box.inside,
            "scope_id": box.scope,
            "scope_name": placements.scope_names.get(box.scope, box.scope),
            "provider": placements.scope_providers.get(box.scope),
            "group": box.group,
            "assets": len(box.members),
            "entry": sum(1 for m in box.members if m.public_exposure in ENTRY_EXPOSURE),
            "sensitive": sum(1 for m in box.members if m.data_sensitivity in SENSITIVE_DATA),
            "findings": {"open": open_count, "worst": worst.value if worst else None},
            "routes": estate.routes.get(box.id, 0),
        }
        if box.kind == "asset":
            resource = box.members[0]
            row = placements.row_ids.get(resource.provider_resource_id)
            entry.update(
                {
                    "name": resource.name,
                    "provider_resource_id": resource.provider_resource_id,
                    "asset_id": str(row) if row else None,
                    "resource_type": resource.resource_type.value,
                    "public_exposure": resource.public_exposure.value,
                    "data_sensitivity": resource.data_sensitivity.value,
                }
            )
        elif box.kind == "scope":
            entry["name"] = entry["scope_name"]
        elif box.kind == "group":
            # Null for what sits directly in the scope; the page names that
            # rather than inventing a group called "Ungrouped".
            entry["name"] = box.group
        else:
            entry["name"] = None
            entry["by_type"] = dict(sorted(by_type.items(), key=lambda item: (-item[1], item[0])))
            entry["with_reach"] = estate.folded_with_reach
        boxes.append(entry)

    edges = [
        {
            "source": edge.source,
            "target": edge.target,
            "links": [
                {
                    "relationship": relationship.value,
                    "count": count,
                    "label": RELATIONSHIP_VERBS.get(relationship, relationship.value),
                }
                for relationship, count in edge.links
            ],
            "on_route": edge.on_route,
        }
        for edge in estate.edges
    ]

    return {
        "lens": {"scope_id": estate.lens.scope, "group": estate.lens.group},
        "boxes": boxes,
        "edges": edges,
    }


def route_key(path: Path) -> str:
    """One route, named by its ends.

    The same name the browser builds (``routeKeys.ts``) and the same pair a
    risk is keyed by (``correlation.py``), so a route is one thing across the
    three places that talk about it. The route drawn is the shortest from its
    entry to its target, so the pair names it uniquely.
    """
    return f"{path.entry.provider_resource_id}|{path.target.provider_resource_id}"


def serialize_route_map(
    graph: AssetGraph,
    paths: list[Path],
    ids: dict[str, UUID],
    findings: dict[UUID, dict],
    *,
    total_routes: int,
    choke_limit: int = 5,
) -> dict:
    """Every route in the estate as one drawable graph, with what each link holds up.

    The list of routes and this are the same facts read two ways, and both are
    sent together deliberately: the list ranks, and only the drawing shows that
    forty routes pass through one identity. Splitting them across requests made
    the page draw a shape before it knew which parts of it mattered.

    **Only the routes, not the estate.** A node is here because a route runs
    through it. The neighbourhood draws what surrounds one asset and the estate
    map draws the containers; this draws the thing the page is named after, and
    drawing anything else on it would be inviting the reader to look for the
    answer somewhere it cannot be.

    ``column`` is the fewest hops from any way in -- the axis the canvas lays
    out along, and a fact rather than a drawing decision: a target two hops from
    the internet is a different problem from one five hops away, and the reader
    should be able to see which without counting lines.
    """
    columns: dict[str, int] = {}
    through: dict[str, int] = {}
    for path in paths:
        walked = [path.entry.provider_resource_id] + [
            step.target.provider_resource_id for step in path.steps
        ]
        for hop, node_id in enumerate(walked):
            settled = columns.get(node_id)
            columns[node_id] = hop if settled is None else min(settled, hop)
        for node_id in dict.fromkeys(walked):
            through[node_id] = through.get(node_id, 0) + 1

    nodes = []
    for node_id, column in sorted(columns.items(), key=lambda item: (item[1], item[0])):
        resource = graph.nodes[node_id]
        asset_id = ids.get(node_id)
        nodes.append(
            {
                "id": node_id,
                "asset_id": str(asset_id) if asset_id else None,
                "name": resource.name,
                "resource_type": resource.resource_type.value,
                "provider": resource.provider.value,
                "column": column,
                "public_exposure": resource.public_exposure.value,
                "data_sensitivity": resource.data_sensitivity.value,
                # The graph's own predicates rather than a re-reading of the
                # levels in the browser, so a box drawn as a way in is exactly
                # an asset a route may start from.
                "entry": resource.public_exposure in ENTRY_EXPOSURE,
                "sensitive": resource.data_sensitivity in SENSITIVE_DATA,
                "routes": through.get(node_id, 0),
                "findings": (findings.get(asset_id) if asset_id else None)
                or {"open": 0, "worst": None},
            }
        )

    severance = graph.link_severance()
    on_routes = graph.links_on_routes()
    steps = {step.key(): step for path in paths for step in path.steps}
    edges = []
    for link, step in sorted(steps.items()):
        # Each drawn line answers for what removing it removes -- for an
        # escalation line, the role assignment it comes from (section 127).
        removal = graph.removal_key(link[0], step.relationship, link[2])
        severed = severance.get(removal, ())
        on = on_routes.get(removal, 0)
        edges.append(
            {
                "source": link[0],
                "relationship": link[1],
                "target": link[2],
                "label": RELATIONSHIP_VERBS.get(step.relationship, step.relationship.value),
                "facts": list(step.facts),
                "detail": step.detail(),
                # What cutting this one link would do, for every link rather
                # than for a shortlist. Zero is a real answer and is drawn as
                # one: it means every route through here has another way round.
                "severs": len(severed),
                # Named, not just counted. A count is a claim, and these are
                # its working -- they are what lets the drawing grey out
                # exactly what would go, without asking the server a second
                # question whose answer might not match the first.
                "closes": [route_key(path) for path in severed],
                "on_routes": on,
                # And whether that is the case, said plainly. The gap between
                # the two numbers is the part a customer needs before they
                # spend an afternoon removing a role assignment.
                "alternate": on > len(severed),
            }
        )

    patterns, loose = route_patterns(paths)
    of_pattern: dict[str, str] = {}
    shapes = []
    for index, pattern in enumerate(patterns):
        pattern_id = f"pattern-{index + 1}"
        for member in pattern.members:
            of_pattern[route_key(member)] = pattern_id
        shapes.append(
            {
                "id": pattern_id,
                "kind": pattern.kind.value,
                "description": pattern.describe(),
                "size": pattern.size,
                "hops": pattern.exemplar.hops,
                "exemplar": route_key(pattern.exemplar),
                "routes": [route_key(member) for member in pattern.members],
                # The end that varies, named, so the group can list what it
                # collapsed without the reader opening every member.
                "varies": [
                    {
                        "id": (
                            member.entry.provider_resource_id
                            if pattern.kind is PatternKind.MANY_ENTRIES
                            else member.target.provider_resource_id
                        ),
                        "name": (
                            member.entry.name
                            if pattern.kind is PatternKind.MANY_ENTRIES
                            else member.target.name
                        ),
                        "route": route_key(member),
                    }
                    for member in pattern.members
                ],
            }
        )

    return {
        "nodes": nodes,
        "edges": edges,
        "routes": [
            {
                **serialize_path(path),
                "key": route_key(path),
                "pattern": of_pattern.get(route_key(path)),
            }
            for path in paths
        ],
        "patterns": shapes,
        "loose": [route_key(path) for path in loose],
        "choke_points": [
            # Against every route the estate has, never against the subset
            # drawn. A link's severance is computed over all of them, and the
            # dedicated endpoint says "4 of 240"; a map capped at 200 saying
            # "4 of 200" would be the same claim with two denominators, in two
            # places one person reads in one sitting.
            serialize_choke_point(choke, total_routes)
            for choke in graph.choke_points(limit=choke_limit)
        ],
    }
