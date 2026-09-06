"""Routes from somewhere an attacker could start to something worth taking.

The findings list answers "what is wrong". This answers "what is wrong
*together*" -- and the two are different questions with different first
actions. Five findings across a jump box, an identity and a storage account
rank by severity and get worked top-down; the same five as one path rank by how
few hops separate the internet from customer data, and name the one change that
severs it.
"""

from fastapi import APIRouter, Query

from app.core.deps import DbSession, Tenant
from app.core.errors import NotFound, envelope
from app.domain.resource import CloudResource
from app.graph.model import ENTRY_EXPOSURE
from app.services import graph as graph_service
from app.services.graph import serialize_path

router = APIRouter(prefix="/attack-paths", tags=["attack-paths"])


@router.get("")
async def list_attack_paths(
    session: DbSession,
    tenant: Tenant,
    limit: int = Query(default=50, le=200),
) -> dict:
    """Every route from an exposed asset to a sensitive one, shortest first.

    Built from the assets and edges the last scan stored rather than from a
    table of its own: a path is a pure function of those, and a stored one
    could describe a route the customer has already closed.
    """
    graph = await graph_service.load_graph(session, tenant.organization_id)
    paths = graph.attack_paths()

    return envelope(
        [serialize_path(path) for path in paths[:limit]],
        {
            "total": len(paths),
            # Both counts are the honest denominator for an empty answer. No
            # paths because nothing is exposed is a different thing from no
            # paths because nothing was classified as sensitive, and a customer
            # reading "0" deserves to know which.
            "entry_points": len(graph.entry_points()),
            "sensitive_targets": len(graph.sensitive_targets()),
        },
    )


@router.get("/exposure-map")
async def exposure_map(
    session: DbSession,
    tenant: Tenant,
    limit: int = Query(default=14, le=40),
) -> dict:
    """The shape of the estate's exposure: what is reachable, and through what.

    The overview used to carry an attack-path panel that is empty for most
    tenants, because a route needs something classified as sensitive at the far
    end and a new customer has classified nothing. This answers a question that
    always has an answer -- *what does the internet touch, and what does that
    touch* -- from the same graph, and it is what the overview draws instead
    (docs/UI_REDESIGN.md §4.1).

    Not an attack path and deliberately not scored: an edge here says one asset
    can act on another, which is a fact about how the estate is wired. Whether
    that reaches anything worth taking is the attack-paths page's question, and
    conflating the two would let a diagram imply a route CloudGuard never
    traced.

    Bounded on purpose. A tenant with four hundred assets has a graph nothing
    can usefully draw, so this walks out from the internet-facing assets and
    stops -- and says how many nodes it left out rather than silently drawing a
    fraction of the estate as though it were all of it.
    """
    graph = await graph_service.load_graph(session, tenant.organization_id)
    entries = graph.entry_points()

    kept: dict[str, CloudResource] = {}
    edges: list[tuple[str, str, str]] = []
    seen_edges: set[tuple[str, str, str]] = set()

    def keep(node_id: str) -> bool:
        node = graph.nodes.get(node_id)
        if node is None:
            return False
        kept.setdefault(node_id, node)
        return True

    for entry in entries:
        if not keep(entry.provider_resource_id):
            continue
        for target, path in graph.reachable_from(
            entry.provider_resource_id, max_depth=3
        ).items():
            if not keep(target):
                continue
            for step in path.steps:
                edge = (
                    step.source.provider_resource_id,
                    step.relationship.value,
                    step.target.provider_resource_id,
                )
                if edge in seen_edges:
                    continue
                # Both ends have to be nodes the map is drawing, or the line
                # would arrive from nowhere.
                if keep(edge[0]) and keep(edge[2]):
                    seen_edges.add(edge)
                    edges.append(edge)

    total = len(kept)
    drawn = dict(list(kept.items())[:limit])
    drawable = set(drawn)

    return envelope(
        {
            "nodes": [
                {
                    "id": node_id,
                    "name": node.name,
                    "resource_type": node.resource_type,
                    "public_exposure": node.public_exposure,
                    "data_sensitivity": node.data_sensitivity,
                    "criticality": node.criticality,
                    "is_entry": node.public_exposure in ENTRY_EXPOSURE,
                }
                for node_id, node in drawn.items()
            ],
            "edges": [
                {"source": source, "relationship": relationship, "target": target}
                for source, relationship, target in edges
                if source in drawable and target in drawable
            ],
        },
        {
            "entry_points": len(entries),
            "nodes": total,
            # What the map is not showing. A diagram that quietly truncates is
            # a diagram of a smaller, tidier estate than the customer has.
            "omitted": max(total - len(drawn), 0),
        },
    )


@router.get("/choke-points")
async def list_choke_points(
    session: DbSession,
    tenant: Tenant,
    limit: int = Query(default=5, le=20),
) -> dict:
    """The links worth cutting first, ranked by how many routes close with them.

    A separate endpoint rather than a field on the list above, because it costs
    a re-traversal per candidate and the list is read far more often than the
    question is asked. A page that wants both asks for both.
    """
    graph = await graph_service.load_graph(session, tenant.organization_id)
    total = len(graph.attack_paths())
    chokes = graph.choke_points(limit=limit)

    return envelope(
        [graph_service.serialize_choke_point(choke, total) for choke in chokes],
        {"total_routes": total},
    )


@router.get("/blast-radius/{resource_id:path}")
async def blast_radius(
    resource_id: str, session: DbSession, tenant: Tenant
) -> dict:
    """What one identity or asset can act on.

    The question a customer actually asks about an over-privileged principal:
    never "is this role too broad" in the abstract, but "what would go with it".
    """
    graph = await graph_service.load_graph(session, tenant.organization_id)
    if resource_id not in graph.nodes:
        raise NotFound("No such asset in this organization")

    reached = graph.blast_radius(resource_id)
    return envelope(
        [
            {
                "id": resource.provider_resource_id,
                "name": resource.name,
                "resource_type": resource.resource_type.value,
                "data_sensitivity": resource.data_sensitivity.value,
            }
            for resource in reached
        ],
        {"total": len(reached)},
    )
