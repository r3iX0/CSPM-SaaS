"""The neighbourhood of one asset, as the graph view draws it.

The route list answers "which link do I cut"; this answers "what is around
here". The failure modes worth pinning are the ones a picture hides: an edge
that is not reach drawn as if it were, a node count that silently stops, and a
layout that moves because the database returned rows in another order.

Pure tests over a hand-built graph. No database.
"""

import random
import uuid

from app.core.enums import Level, RelationshipType, ResourceType
from app.domain.resource import CloudResource
from app.graph import AssetGraph
from app.services.graph import serialize_neighborhood

SUB = "/subscriptions/sub-1"
GROUP = f"{SUB}/resourceGroups/prod"
VM = f"{GROUP}/providers/Microsoft.Compute/virtualMachines/jump-01"
NSG = f"{GROUP}/providers/Microsoft.Network/networkSecurityGroups/jump-nsg"
IDENTITY = "/principals/mi-jump-01"
STORAGE = f"{GROUP}/providers/Microsoft.Storage/storageAccounts/customerdata"
ADMIN = "/principals/admin"


def node(
    resource_id: str,
    kind: ResourceType,
    *,
    exposure: Level = Level.LOW,
    sensitivity: Level = Level.LOW,
) -> CloudResource:
    return CloudResource(
        provider_resource_id=resource_id,
        resource_type=kind,
        name=resource_id.rsplit("/", 1)[-1],
        public_exposure=exposure,
        data_sensitivity=sensitivity,
    )


def environment() -> AssetGraph:
    """A jump box, its identity with a role over the subscription, the
    customer data beside it, and an admin over the group."""
    return AssetGraph.build(
        [
            node(SUB, ResourceType.SUBSCRIPTION),
            node(GROUP, ResourceType.RESOURCE_GROUP),
            node(VM, ResourceType.VIRTUAL_MACHINE, exposure=Level.CRITICAL),
            node(NSG, ResourceType.NETWORK_SECURITY_GROUP),
            node(IDENTITY, ResourceType.SERVICE_PRINCIPAL),
            node(STORAGE, ResourceType.STORAGE_ACCOUNT, sensitivity=Level.HIGH),
            node(ADMIN, ResourceType.USER),
        ],
        [
            (SUB, RelationshipType.CONTAINS, GROUP),
            (GROUP, RelationshipType.CONTAINS, VM),
            (GROUP, RelationshipType.CONTAINS, STORAGE),
            (GROUP, RelationshipType.CONTAINS, NSG),
            (NSG, RelationshipType.PROTECTS, VM),
            (VM, RelationshipType.HAS_IDENTITY, IDENTITY),
            (IDENTITY, RelationshipType.GRANTS_ROLE, SUB),
            (ADMIN, RelationshipType.GRANTS_ROLE, GROUP),
        ],
    )


def wide_subscription(groups: int) -> AssetGraph:
    """An admin over a subscription holding many groups, one of them sensitive."""
    resources = [node(SUB, ResourceType.SUBSCRIPTION), node(ADMIN, ResourceType.USER)]
    edges = [(ADMIN, RelationshipType.GRANTS_ROLE, SUB)]
    for index in range(groups):
        group = f"{SUB}/resourceGroups/rg-{index:03d}"
        resources.append(
            node(
                group,
                ResourceType.RESOURCE_GROUP,
                sensitivity=Level.CRITICAL if index == 7 else Level.LOW,
            )
        )
        edges.append((SUB, RelationshipType.CONTAINS, group))
    return AssetGraph.build(resources, edges)


# ------------------------------------------------------------------ placement
def test_an_unknown_asset_has_no_neighbourhood() -> None:
    assert environment().neighborhood("/nowhere") is None


def test_reach_runs_right_and_what_reaches_runs_left() -> None:
    around = environment().neighborhood(VM, depth=1)

    assert around is not None
    assert around.layers == {VM: 0, IDENTITY: 1, GROUP: -1}


def test_an_asset_on_both_sides_sits_downstream_on_a_tie() -> None:
    """The subscription is two hops either way: the VM's identity holds a role
    over it, and it contains the VM's group. It is drawn once, on the side the
    canvas is opened to ask about."""
    around = environment().neighborhood(VM, depth=2)

    assert around is not None
    assert around.layers[SUB] == 2


def test_an_asset_sits_at_its_shortest_distance() -> None:
    """From the storage account nothing is reached forward, so everything that
    reaches it sits to the left at the hop it was found."""
    around = environment().neighborhood(STORAGE, depth=2)

    assert around is not None
    assert around.layers == {STORAGE: 0, GROUP: -1, SUB: -2, ADMIN: -2}


# ---------------------------------------------------------------------- edges
def test_configuration_edges_are_not_drawn_as_reach() -> None:
    """An NSG protecting a VM is configuration, not a way to get anywhere."""
    around = environment().neighborhood(VM, depth=3)

    assert around is not None
    assert all(rel.is_capability for _, rel, _ in around.edges)
    assert (NSG, RelationshipType.PROTECTS, VM) not in around.edges


def test_edges_join_only_drawn_assets_and_keep_their_direction() -> None:
    around = environment().neighborhood(VM, depth=1)

    assert around is not None
    assert set(around.edges) == {
        (GROUP, RelationshipType.CONTAINS, VM),
        (VM, RelationshipType.HAS_IDENTITY, IDENTITY),
    }


# -------------------------------------------------------------------- folding
def test_a_wide_fan_out_is_folded_and_counted_not_dropped() -> None:
    around = wide_subscription(40).neighborhood(ADMIN, depth=2)

    assert around is not None
    drawn = [n for n in around.layers if n.startswith(f"{SUB}/")]
    assert len(drawn) + sum(len(g.members) for g in around.groups) == 40
    assert [(g.parent, g.relationship, g.layer) for g in around.groups] == [
        (SUB, RelationshipType.CONTAINS, 2)
    ]
    assert not around.truncated


def test_a_fold_still_draws_what_matters() -> None:
    """"40 resource groups" would hide the one holding sensitive data."""
    around = wide_subscription(40).neighborhood(ADMIN, depth=2)

    assert around is not None
    assert f"{SUB}/resourceGroups/rg-007" in around.layers


def test_a_folded_neighbour_drawn_anyway_is_not_counted_twice() -> None:
    around = wide_subscription(40).neighborhood(ADMIN, depth=2)

    assert around is not None
    members = {m.provider_resource_id for g in around.groups for m in g.members}
    assert members.isdisjoint(around.layers)


def test_a_narrow_fan_out_is_drawn_in_full() -> None:
    around = wide_subscription(5).neighborhood(ADMIN, depth=2)

    assert around is not None
    assert around.groups == ()
    assert len(around.layers) == 7


def test_the_node_cap_folds_the_rest_and_says_so() -> None:
    graph = environment()
    around = graph.neighborhood(VM, depth=3, max_nodes=3)

    assert around is not None
    assert len(around.layers) == 3
    assert around.truncated
    # Nothing went missing in the direction each drawn node was walked: every
    # neighbour is drawn or counted. A node left of the focus is walked leftward
    # only -- its siblings are not part of the question.
    folded = {m.provider_resource_id for g in around.groups for m in g.members}
    for current, layer in around.layers.items():
        walked = []
        if layer >= 0:
            walked += graph._out.get(current, [])
        if layer <= 0:
            walked += graph._in.get(current, [])
        for rel, other in walked:
            if rel.is_capability:
                assert other in around.layers or other in folded


# ---------------------------------------------------------------- determinism
def test_the_same_estate_draws_the_same_neighbourhood_whatever_the_row_order() -> None:
    """The database promises no row order. The canvas must not rearrange
    itself because the rows came back differently."""
    base = wide_subscription(40)
    expected = base.neighborhood(ADMIN, depth=2)
    resources = list(base.nodes.values())
    edges = [(s, rel, t) for s, out in base._out.items() for rel, t in out]

    for seed in range(5):
        rng = random.Random(seed)
        rng.shuffle(resources)
        rng.shuffle(edges)
        assert AssetGraph.build(resources, edges).neighborhood(ADMIN, depth=2) == expected


# -------------------------------------------------------------------- payload
def test_group_edges_point_the_way_reach_runs() -> None:
    """Upstream, the members reach the parent. A group edge drawn backwards
    would invert the claim the canvas makes."""
    graph = wide_subscription(40)
    upstream = graph.neighborhood(f"{SUB}/resourceGroups/rg-001", depth=2, fan_out=0)
    assert upstream is not None
    assert upstream.groups

    payload = serialize_neighborhood(graph, upstream, {})
    by_id = {g["id"]: g for g in payload["groups"]}
    group_edges = [e for e in payload["edges"] if e["source"] in by_id]
    assert len(group_edges) == len(by_id)
    for edge in group_edges:
        group = by_id[edge["source"]]
        assert group["layer"] < 0
        assert edge["target"] == group["parent"]


def test_the_payload_words_a_hop_the_way_a_route_does() -> None:
    graph = environment()
    around = graph.neighborhood(VM, depth=1)
    assert around is not None

    payload = serialize_neighborhood(graph, around, {})
    labels = {(e["source"], e["target"]): e["label"] for e in payload["edges"]}
    assert labels[(VM, IDENTITY)] == "runs as"
    assert payload["focus"] == VM
    assert all(n["asset_id"] is None for n in payload["nodes"])


def test_a_box_is_marked_as_a_way_in_only_on_the_graphs_own_terms() -> None:
    """UNKNOWN exposure is a gap in collection, not a door."""
    graph = AssetGraph.build(
        [
            node(VM, ResourceType.VIRTUAL_MACHINE, exposure=Level.CRITICAL),
            node(IDENTITY, ResourceType.SERVICE_PRINCIPAL, exposure=Level.UNKNOWN),
            node(STORAGE, ResourceType.STORAGE_ACCOUNT, sensitivity=Level.HIGH),
        ],
        [
            (VM, RelationshipType.HAS_IDENTITY, IDENTITY),
            (IDENTITY, RelationshipType.GRANTS_ROLE, STORAGE),
        ],
    )
    around = graph.neighborhood(IDENTITY, depth=1)
    assert around is not None

    by_id = {n["id"]: n for n in serialize_neighborhood(graph, around, {})["nodes"]}
    assert by_id[VM]["entry"] is True
    assert by_id[IDENTITY]["entry"] is False
    assert by_id[STORAGE]["sensitive"] is True
    assert by_id[VM]["sensitive"] is False


def test_open_findings_ride_on_the_box_they_belong_to() -> None:
    graph = environment()
    around = graph.neighborhood(VM, depth=1)
    assert around is not None
    vm_row, identity_row = uuid.uuid4(), uuid.uuid4()

    payload = serialize_neighborhood(
        graph,
        around,
        {VM: vm_row, IDENTITY: identity_row},
        {vm_row: {"open": 3, "worst": "HIGH"}},
    )
    by_id = {n["id"]: n for n in payload["nodes"]}
    assert by_id[VM]["findings"] == {"open": 3, "worst": "HIGH"}
    # No findings is zero, not absent: the box says "nothing open" rather
    # than leaving the reader to guess whether anything was asked.
    assert by_id[IDENTITY]["findings"] == {"open": 0, "worst": None}
    assert by_id[GROUP]["findings"] == {"open": 0, "worst": None}


def test_the_routes_through_the_focus_travel_with_it() -> None:
    graph = environment()
    around = graph.neighborhood(VM, depth=2)
    assert around is not None

    payload = serialize_neighborhood(graph, around, {}, routes=graph.paths_through(VM))
    assert payload["routes"], "the jump box is on the route to the customer data"
    route = payload["routes"][0]
    assert route["entry"]["id"] == VM
    assert route["target"]["id"] == STORAGE
    # The cut is a capability hop, never containment.
    assert route["cheapest_break"]["relationship"] == "has_identity"
