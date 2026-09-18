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
from app.graph import AssetGraph, ChokePoint, Neighborhood, Path
from app.graph.model import ENTRY_EXPOSURE, RELATIONSHIP_VERBS, SENSITIVE_DATA
from app.models.finding import Finding
from app.models.resource import ResourceRecord, ResourceRelationship

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
_cache: "OrderedDict[UUID, tuple[tuple[datetime | None, datetime | None, int], AssetGraph]]" = (
    OrderedDict()
)


async def graph_version(
    session: AsyncSession, organization_id: UUID
) -> tuple[datetime | None, datetime | None, int]:
    """What the graph would be built from, cheaply enough to ask every time.

    Keyed on the data rather than on the scan that wrote it. A scan is the only
    thing that rewrites assets and edges today, but keying on "the newest scan"
    would be an inference about *which processes write*, and the day something
    else does -- a context declaration applied in place, a manual asset edit --
    the cache would go stale silently and serve routes through an estate that
    has moved.

    Three aggregates rather than one: assets change by being written, and edges
    change by being replaced, and a scan that only removed an edge would move
    neither timestamp on its own. The count is what catches that.
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
            select(func.max(ResourceRelationship.created_at)).where(
                ResourceRelationship.organization_id == organization_id
            )
        )
    ).scalar_one_or_none()
    return (assets[0], edges, int(assets[1] or 0))


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
                "relationship": step.relationship.value,
                "source_id": step.source.provider_resource_id,
                "target_id": step.target.provider_resource_id,
            }
            if step
            else None
        ),
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
    session: AsyncSession, organization_id: UUID, row_ids: list[UUID]
) -> dict[UUID, dict]:
    """How many open findings each drawn asset carries, and the worst of them.

    One grouped query for the assets on the canvas. Open means what it means
    on the security score -- OPEN or IN_PROGRESS -- so the number on a box and
    the number on the asset's own page never disagree.
    """
    if not row_ids:
        return {}
    rows = await session.execute(
        select(Finding.resource_id, Finding.severity, func.count(Finding.id))
        .where(
            Finding.organization_id == organization_id,
            Finding.resource_id.in_(row_ids),
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
        group_id = f"group:{group.layer}:{group.relationship.value}:{group.parent}"
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
