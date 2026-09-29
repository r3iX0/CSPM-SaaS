"""Routes from somewhere an attacker could start to something worth taking.

The findings list answers "what is wrong". This answers "what is wrong
*together*" -- and the two are different questions with different first
actions. Five findings across a jump box, an identity and a storage account
rank by severity and get worked top-down; the same five as one path rank by how
few hops separate the internet from customer data, and name the one change that
severs it.
"""

from collections import Counter

from fastapi import APIRouter, Query

from app.core.deps import Costly, DbSession, Tenant
from app.core.enums import RelationshipType
from app.core.errors import NotFound
from app.domain.resource import CloudResource
from app.graph import AssetGraph
from app.graph.estate import ESTATE_MAX_ASSETS, Lens, estate_map
from app.graph.model import NEIGHBOURHOOD_FAN_OUT, NEIGHBOURHOOD_MAX_NODES
from app.schemas.attack_path import (
    MAX_SIMULATED_CUTS,
    AccessMeta,
    AccessOut,
    AttackPathOut,
    AttackPathsMeta,
    BlastAssetOut,
    ChokePointOut,
    ChokePointsMeta,
    EstateMeta,
    EstateOut,
    NeighborhoodMeta,
    NeighborhoodOut,
    ReachCountsMeta,
    RouteEndOut,
    RouteMapMeta,
    RouteMapOut,
    RouteTargetEndOut,
    SimulationMeta,
    SimulationOut,
    SimulationRequest,
    WhatIfClosedOut,
    WhatIfOut,
)
from app.schemas.common import ERROR_RESPONSES, Envelope, NoMeta, TotalMeta
from app.services import graph as graph_service
from app.services.graph import serialize_path
from app.services.placement import load_placements

router = APIRouter(prefix="/attack-paths", tags=["attack-paths"], responses=ERROR_RESPONSES)

# Routes returned with a neighbourhood. Each is a line in a list beside the
# canvas, and past this many the list stops being read.
ROUTE_LIMIT = 20

# Ways in explained on an empty page. Past this many the rest are counted: an
# estate's accounts are all entry points, and the machines sort first.
DEAD_END_LIMIT = 25

# Routes one drawing may hold. Past this the canvas stops being something a
# person reads, and the count in ``meta`` says how many were left off rather
# than letting the picture pass for the whole estate.
ROUTE_MAP_LIMIT = 200

# Assets listed under one role on the access view. Past this they are counted:
# Owner over a subscription controls everything in it, and the count is the
# answer while the list is only a sample of it.
ACCESS_CONTROLLED_LIMIT = 25
# Members listed under one group holder, for the same reason: "Everyone in
# Engineering" is a count, and the list beside it is who to look at first.
ACCESS_MEMBERS_LIMIT = 50

# Folds one request may ask to open. Each is an id of a few hundred characters
# in the query string, and the node cap bounds the drawing long before this.
EXPAND_LIMIT = 20


def _reach_counts(graph: AssetGraph) -> ReachCountsMeta:
    """The ways in and the sensitive targets, counted and by type."""
    entries = graph.entry_points()
    targets = graph.sensitive_targets()
    return ReachCountsMeta(
        entry_points=len(entries),
        sensitive_targets=len(targets),
        entry_point_types=_by_type(entries),
        sensitive_target_types=_by_type(targets),
    )


def _by_type(resources: list[CloudResource]) -> dict[str, int]:
    return dict(Counter(r.resource_type.value for r in resources))


@router.get("")
async def list_attack_paths(
    session: DbSession,
    tenant: Tenant,
    limit: int = Query(default=50, ge=1, le=200),
) -> Envelope[list[AttackPathOut], AttackPathsMeta]:
    """Every route from an exposed asset to a sensitive one, shortest first.

    Built from the assets and edges the last scan stored rather than from a
    table of its own: a path is a pure function of those, and a stored one
    could describe a route the customer has already closed.
    """
    graph = await graph_service.load_graph(session, tenant.organization_id)
    paths = graph.attack_paths()
    # Both counts are the honest denominator for an empty answer, and what
    # they are: every directory account is an entry point and every
    # administrator a sensitive one, so a tenant with one admin showed both
    # counts above zero -- and "CloudGuard found exposed and sensitive assets"
    # read as a statement about the machines when it was about the people
    # (DECISIONS.md section 119).
    meta = AttackPathsMeta(**_reach_counts(graph).model_dump(), total=len(paths))
    if not paths and meta.entry_points and meta.sensitive_targets:
        # Where each way in stops. Only when there is no route, which is the
        # one time the page has nothing else to say.
        ends = await graph_service.off_loop(graph.dead_ends)
        ids = await graph_service.asset_ids(
            session,
            tenant.organization_id,
            [end.entry.provider_resource_id for end in ends[:DEAD_END_LIMIT]],
        )
        meta.dead_ends = [
            graph_service.serialize_dead_end(end, ids) for end in ends[:DEAD_END_LIMIT]
        ]
        meta.dead_ends_total = len(ends)

    return Envelope(data=[serialize_path(path) for path in paths[:limit]], meta=meta)


@router.get("/graph")
async def route_graph(
    session: DbSession,
    tenant: Tenant,
    limit: int = Query(default=ROUTE_MAP_LIMIT, ge=1, le=ROUTE_MAP_LIMIT),
) -> Envelope[RouteMapOut, RouteMapMeta]:
    """Every route in the estate, as one graph, with what each link holds up.

    The list above ranks routes, which is the right order for reading them and
    the wrong one for acting: forty routes through one identity are forty rows
    that never say "one identity". The drawing says it in one look, and the
    numbers on its links say what closes if that identity's role goes -- for
    every link, not for a shortlist, because they are all read off one analysis
    (``graph/severance.py``).

    One request rather than three. The page used to ask for routes, then for
    choke points, then for the outcome of a cut, and drew a shape in between
    that it had to revise twice.
    """
    graph = await graph_service.load_graph(session, tenant.organization_id)
    paths = graph.attack_paths()
    drawn = paths[:limit]

    node_ids = sorted({node for path in drawn for node in path.node_ids()})
    ids = await graph_service.asset_ids(session, tenant.organization_id, node_ids)
    findings = await graph_service.open_findings(
        session, tenant.organization_id, list(ids.values())
    )
    # Where each node sits, so a hop names its subscription and group and the
    # page can narrow to one (section 138).
    placements = await load_placements(session, tenant.organization_id)

    # Off the loop: drawing the map reads what every link holds up, which is
    # the one analysis on this page that is not memoized until it is first asked.
    route_map = await graph_service.off_loop(
        lambda: graph_service.serialize_route_map(
            graph, drawn, ids, findings, total_routes=len(paths), placements=placements
        )
    )
    return Envelope(
        data=route_map,
        meta=RouteMapMeta(
            **_reach_counts(graph).model_dump(),
            total=len(paths),
            # What the drawing leaves out, said rather than implied. A canvas
            # that silently stopped at two hundred routes would be a picture of
            # part of the estate presented as the whole of it.
            drawn=len(drawn),
        ),
    )


@router.get("/choke-points")
async def list_choke_points(
    session: DbSession,
    tenant: Tenant,
    limit: int = Query(default=5, ge=1, le=20),
) -> Envelope[list[ChokePointOut], ChokePointsMeta]:
    """The links worth cutting first, ranked by how many routes close with them.

    A separate endpoint rather than a field on the list above, because it costs
    a re-traversal per candidate and the list is read far more often than the
    question is asked. A page that wants both asks for both.
    """
    graph = await graph_service.load_graph(session, tenant.organization_id)
    total = len(graph.attack_paths())
    chokes = await graph_service.off_loop(lambda: graph.choke_points(limit=limit))

    return Envelope(
        data=[graph_service.serialize_choke_point(choke, total) for choke in chokes],
        meta=ChokePointsMeta(total_routes=total),
    )


@router.get("/blast-radius/{resource_id:path}")
async def blast_radius(
    resource_id: str, session: DbSession, tenant: Tenant
) -> Envelope[list[BlastAssetOut], TotalMeta]:
    """What one identity or asset can act on.

    The question a customer actually asks about an over-privileged principal:
    never "is this role too broad" in the abstract, but "what would go with it".
    """
    graph = await graph_service.load_graph(session, tenant.organization_id)
    if graph.resolve(resource_id) not in graph.nodes:
        raise NotFound("No such asset in this organization")

    reached = await graph_service.off_loop(lambda: graph.blast_radius(resource_id))
    # The row id behind each, so the list can open what it names.
    ids = await graph_service.asset_ids(
        session,
        tenant.organization_id,
        [resource.provider_resource_id for resource in reached],
    )
    return Envelope(
        data=[
            BlastAssetOut(
                id=resource.provider_resource_id,
                asset_id=ids.get(resource.provider_resource_id),
                name=resource.name,
                resource_type=resource.resource_type,
                data_sensitivity=resource.data_sensitivity,
            )
            for resource in reached
        ],
        meta=TotalMeta(total=len(reached)),
    )


@router.get("/access/{resource_id:path}")
async def access(
    resource_id: str, session: DbSession, tenant: Tenant
) -> Envelope[AccessOut, AccessMeta]:
    """Who holds access to one asset, and what one identity holds.

    Whether or not anything exposed leads there -- the half of the question a
    route cannot answer, because a route needs a way in. Read from the same
    per-role evaluation the routes are walked with, so a principal listed here
    as controlling an asset is exactly one a route may pass through
    (DECISIONS.md section 125).
    """
    graph = await graph_service.load_graph(session, tenant.organization_id)
    if graph.resolve(resource_id) not in graph.nodes:
        raise NotFound("No such asset in this organization")

    holders, grants = await graph_service.off_loop(
        lambda: (graph.access_to(resource_id), graph.access_of(resource_id))
    )
    ids = await graph_service.asset_ids(
        session,
        tenant.organization_id,
        graph_service.access_asset_ids(holders, grants),
    )
    return Envelope(
        data=graph_service.serialize_access(
            holders,
            grants,
            ids,
            controlled_limit=ACCESS_CONTROLLED_LIMIT,
            members_limit=ACCESS_MEMBERS_LIMIT,
        ),
        meta=AccessMeta(
            holders_total=len(holders),
            grants_total=len(grants),
            controlling=sum(1 for holder in holders if holder.controls),
            controlled_limit=ACCESS_CONTROLLED_LIMIT,
            members_limit=ACCESS_MEMBERS_LIMIT,
        ),
    )


@router.get("/neighborhood/{resource_id:path}")
async def neighborhood(
    resource_id: str,
    session: DbSession,
    tenant: Tenant,
    depth: int = Query(default=2, ge=1, le=3),
    expand: list[str] = Query(default=[], max_length=EXPAND_LIMIT),
) -> Envelope[NeighborhoodOut, NeighborhoodMeta]:
    """The assets around one, what reaches it and what it reaches.

    For the graph view on an asset's page. The route list stays the answer to
    "which link do I cut"; this is for looking around (DECISIONS.md section 101).
    Capped at three hops: every route this graph can express is three or four
    hops end to end, and a neighbourhood that deep either way already spans it.
    """
    graph = await graph_service.load_graph(session, tenant.organization_id)
    opened = frozenset(
        fold for fold in map(graph_service.parse_fold_id, expand) if fold is not None
    )
    around = await graph_service.off_loop(
        lambda: graph.neighborhood(resource_id, depth, expand=opened)
    )
    if around is None:
        raise NotFound("No such asset in this organization")

    ids = await graph_service.asset_ids(
        session, tenant.organization_id, list(around.layers)
    )
    findings = await graph_service.open_findings(
        session, tenant.organization_id, list(ids.values())
    )
    # Every route the asset is on, wherever on it it sits -- the same question
    # the finding page asks. Capped for the payload, counted in full.
    routes = graph.paths_through(resource_id)
    return Envelope(
        data=graph_service.serialize_neighborhood(
            graph, around, ids, findings, routes[:ROUTE_LIMIT]
        ),
        meta=NeighborhoodMeta(
            routes_total=len(routes),
            depth=depth,
            truncated=around.truncated,
            max_nodes=NEIGHBOURHOOD_MAX_NODES,
            fan_out=NEIGHBOURHOOD_FAN_OUT,
        ),
    )


@router.get("/estate")
async def estate(
    session: DbSession,
    tenant: Tenant,
    subscription_id: str | None = Query(default=None, min_length=1, max_length=256),
    resource_group: str | None = Query(default=None, min_length=1, max_length=256),
) -> Envelope[EstateOut, EstateMeta]:
    """The estate as boxes -- subscriptions, groups, assets -- and the reach
    between them.

    For the graph view on the assets page. The neighbourhood draws one asset's
    surroundings and never the whole tenant; this draws the whole tenant by
    drawing its containers, and opens one at a time (DECISIONS.md section 111).
    The lens is the same pair the list filters by, so a box and the list it
    opens into hold the same assets.
    """
    graph = await graph_service.load_graph(session, tenant.organization_id)
    placements = await load_placements(session, tenant.organization_id)
    routes = graph.attack_paths()
    mapped = await graph_service.off_loop(
        lambda: estate_map(graph, placements.of, Lens(subscription_id, resource_group), routes)
    )
    if mapped is None:
        raise NotFound("Nothing Cleave holds sits there")

    findings = await graph_service.open_findings(session, tenant.organization_id, None)
    return Envelope(
        data=graph_service.serialize_estate(mapped, placements, findings),
        meta=EstateMeta(
            routes_total=mapped.routes_total,
            max_assets=ESTATE_MAX_ASSETS,
            folded_with_reach=mapped.folded_with_reach,
        ),
    )


@router.get("/what-if", dependencies=[Costly])
async def what_if(
    session: DbSession,
    tenant: Tenant,
    source: str = Query(min_length=1, max_length=2048),
    relationship: RelationshipType = Query(),
    target: str = Query(min_length=1, max_length=2048),
) -> Envelope[WhatIfOut, NoMeta]:
    """What closes if one link is removed, across the organization.

    For the graph view's traced route: pick a hop, see what cutting it would
    do before anybody changes a role assignment. A full re-traversal, the same
    cost as one choke-point check, so it is asked per link rather than for
    every link on every route.
    """
    graph = await graph_service.load_graph(session, tenant.organization_id)
    outcome = await graph_service.off_loop(lambda: graph.cut(source, relationship, target))
    if outcome is None:
        raise NotFound("No link here that can be removed")

    return Envelope(
        data=WhatIfOut(
            description=outcome.step.describe(),
            relationship=outcome.step.relationship,
            source_id=source,
            target_id=target,
            # Named, because a count is a claim and these are its working.
            closes=[
                WhatIfClosedOut(
                    entry=RouteEndOut(id=p.entry.provider_resource_id, name=p.entry.name),
                    target=RouteTargetEndOut(
                        id=p.target.provider_resource_id,
                        name=p.target.name,
                        data_sensitivity=p.target.data_sensitivity,
                    ),
                    hops=p.hops,
                )
                for p in outcome.closed
            ],
            before=outcome.before,
            after=outcome.after,
        ),
        meta=NoMeta(),
    )


@router.post("/simulate", dependencies=[Costly])
async def simulate(
    payload: SimulationRequest, session: DbSession, tenant: Tenant
) -> Envelope[SimulationOut, SimulationMeta]:
    """What closes if several links are removed together, across the organization.

    A POST because the plan is a body, not because anything is written: this
    changes nothing, in CloudGuard or in the cloud, and a demo visitor may ask
    it like any other question. The answer is exact for the plan as a whole --
    never the sum of what each link closes alone, which is the one number a
    plan of several changes cannot be read off (``AssetGraph.simulate``).
    """
    graph = await graph_service.load_graph(session, tenant.organization_id)
    cuts = [(link.source, link.relationship, link.target) for link in payload.cuts]
    outcome = await graph_service.off_loop(lambda: graph.simulate(cuts))
    return Envelope(
        data=graph_service.serialize_simulation(outcome),
        meta=SimulationMeta(max_cuts=MAX_SIMULATED_CUTS),
    )
