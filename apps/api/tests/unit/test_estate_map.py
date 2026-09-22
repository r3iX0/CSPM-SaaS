"""The estate map: containers as boxes, and the reach that crosses them.

What is worth pinning is what a grouped picture can hide: reach inside a box
drawn as though it crossed one, containment drawn everywhere so the route is
lost, a box that silently stops at the cap, and a map that changes because
rows came back in another order.

Pure tests over a hand-built graph. No database.
"""

import random
import uuid

from app.core.enums import Level, RelationshipType, ResourceType, Severity
from app.domain.resource import CloudResource
from app.graph import AssetGraph
from app.graph.estate import (
    DIRECTORY_SCOPE,
    FOLD_BOX,
    EstateMap,
    Lens,
    Placement,
    asset_box,
    estate_map,
    group_box,
    scope_box,
)
from app.services.graph import serialize_estate
from app.services.placement import Placements

SUB_A = "/subscriptions/sub-a"
SUB_B = "/subscriptions/sub-b"
WEB_RG = f"{SUB_A}/resourceGroups/web"
VM = f"{WEB_RG}/providers/Microsoft.Compute/virtualMachines/jump-01"
DATA_RG = f"{SUB_B}/resourceGroups/Data"
STORAGE = f"{DATA_RG}/providers/Microsoft.Storage/storageAccounts/customerdata"
EMPTY_RG = f"{SUB_B}/resourceGroups/empty"
IDENTITY = "/principals/mi-jump-01"
ADMIN = "/principals/admin"

PLACEMENTS = {
    SUB_A: Placement("sub-a"),
    WEB_RG: Placement("sub-a", "web"),
    VM: Placement("sub-a", "web"),
    SUB_B: Placement("sub-b"),
    DATA_RG: Placement("sub-b", "Data"),
    STORAGE: Placement("sub-b", "Data"),
    EMPTY_RG: Placement("sub-b", "empty"),
    IDENTITY: Placement(DIRECTORY_SCOPE),
    ADMIN: Placement(DIRECTORY_SCOPE),
}


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


RESOURCES = [
    node(SUB_A, ResourceType.SUBSCRIPTION),
    node(WEB_RG, ResourceType.RESOURCE_GROUP),
    node(VM, ResourceType.VIRTUAL_MACHINE, exposure=Level.CRITICAL),
    node(SUB_B, ResourceType.SUBSCRIPTION),
    node(DATA_RG, ResourceType.RESOURCE_GROUP),
    node(STORAGE, ResourceType.STORAGE_ACCOUNT, sensitivity=Level.HIGH),
    node(EMPTY_RG, ResourceType.RESOURCE_GROUP),
    node(IDENTITY, ResourceType.SERVICE_PRINCIPAL),
    node(ADMIN, ResourceType.USER),
]

EDGES = [
    (SUB_A, RelationshipType.CONTAINS, WEB_RG),
    (WEB_RG, RelationshipType.CONTAINS, VM),
    (SUB_B, RelationshipType.CONTAINS, DATA_RG),
    (SUB_B, RelationshipType.CONTAINS, EMPTY_RG),
    (DATA_RG, RelationshipType.CONTAINS, STORAGE),
    # An exposed VM in one subscription runs as an identity holding a role
    # over the other: the cross-subscription route the map exists to show.
    (VM, RelationshipType.HAS_IDENTITY, IDENTITY),
    (IDENTITY, RelationshipType.GRANTS_ROLE, SUB_B),
    (ADMIN, RelationshipType.GRANTS_ROLE, SUB_A),
]


def environment() -> AssetGraph:
    return AssetGraph.build(RESOURCES, EDGES)


def draw(
    lens: Lens,
    graph: AssetGraph | None = None,
    placements: dict[str, Placement] | None = None,
    max_assets: int = 40,
) -> EstateMap:
    graph = graph or environment()
    placed = PLACEMENTS if placements is None else placements
    mapped = estate_map(graph, placed, lens, graph.attack_paths(), max_assets=max_assets)
    assert mapped is not None
    return mapped


def edge_map(mapped: EstateMap) -> dict[tuple[str, str], dict[str, int]]:
    return {
        (edge.source, edge.target): {rel.value: count for rel, count in edge.links}
        for edge in mapped.edges
    }


# ------------------------------------------------------------------ the estate
def test_estate_draws_one_box_per_scope_and_the_reach_between_them() -> None:
    mapped = draw(Lens())

    assert {box.id for box in mapped.boxes} == {
        scope_box("sub-a"),
        scope_box("sub-b"),
        scope_box(DIRECTORY_SCOPE),
    }
    assert all(box.inside for box in mapped.boxes)
    assert edge_map(mapped) == {
        (scope_box("sub-a"), scope_box(DIRECTORY_SCOPE)): {"has_identity": 1},
        (scope_box(DIRECTORY_SCOPE), scope_box("sub-a")): {"grants_role": 1},
        (scope_box(DIRECTORY_SCOPE), scope_box("sub-b")): {"grants_role": 1},
    }


def test_reach_inside_one_box_is_not_drawn_as_crossing_it() -> None:
    # Everything in one subscription: the reach is real, but it never leaves
    # the box, so the estate has nothing to draw between boxes.
    graph = AssetGraph.build(
        [
            node(SUB_A, ResourceType.SUBSCRIPTION),
            node(VM, ResourceType.VIRTUAL_MACHINE),
            node(WEB_RG, ResourceType.RESOURCE_GROUP),
        ],
        [(VM, RelationshipType.GRANTS_ROLE, SUB_A), (SUB_A, RelationshipType.CONTAINS, WEB_RG)],
    )
    assert draw(Lens(), graph).edges == ()


def test_the_edges_on_a_route_are_marked_and_the_boxes_count_it() -> None:
    mapped = draw(Lens())
    routed = {(e.source, e.target) for e in mapped.edges if e.on_route}

    assert routed == {
        (scope_box("sub-a"), scope_box(DIRECTORY_SCOPE)),
        (scope_box(DIRECTORY_SCOPE), scope_box("sub-b")),
    }
    assert mapped.routes_total == 1
    assert mapped.routes == {
        scope_box("sub-a"): 1,
        scope_box("sub-b"): 1,
        scope_box(DIRECTORY_SCOPE): 1,
    }


# ------------------------------------------------------------ one subscription
def test_opening_a_subscription_draws_its_groups_and_what_sits_directly_in_it() -> None:
    mapped = draw(Lens("sub-b"))
    inside = {box.id for box in mapped.boxes if box.inside}
    outside = {box.id for box in mapped.boxes if not box.inside}

    assert inside == {
        asset_box(SUB_B),
        group_box("sub-b", "Data"),
        group_box("sub-b", "empty"),
    }
    # Only the neighbour whose reach crosses in: sub-a reaches sub-b through
    # the directory, not directly, so it is not drawn.
    assert outside == {scope_box(DIRECTORY_SCOPE)}


def test_containment_is_drawn_only_where_a_route_runs_along_it() -> None:
    edges = edge_map(draw(Lens("sub-b")))

    assert edges[(scope_box(DIRECTORY_SCOPE), asset_box(SUB_B))] == {"grants_role": 1}
    assert edges[(asset_box(SUB_B), group_box("sub-b", "Data"))] == {"contains": 1}
    # The subscription holds the empty group too, and no route goes there.
    assert (asset_box(SUB_B), group_box("sub-b", "empty")) not in edges


def test_links_between_two_neighbours_are_about_somewhere_else() -> None:
    edges = edge_map(draw(Lens("sub-a")))
    # The directory's identity reaching sub-b is outside-to-outside here.
    assert all(scope_box("sub-b") not in pair for pair in edges)


# ------------------------------------------------------------ one group
def test_opening_a_group_draws_its_assets_and_names_the_rest_coarsely() -> None:
    mapped = draw(Lens("sub-b", "data"))
    by_id = {box.id: box for box in mapped.boxes}

    # Case-insensitive, as ARM is: `data` opens `Data`.
    assert by_id[asset_box(STORAGE)].inside
    assert by_id[asset_box(STORAGE)].group == "Data"
    # The subscription the route arrives through sits directly in sub-b, so it
    # is drawn as sub-b's "directly in" box rather than as an asset.
    assert not by_id[group_box("sub-b", None)].inside
    # The group itself is drawn because the route runs through it, and the
    # route's containment reads on from the subscription down to the data.
    edges = edge_map(mapped)
    assert edges[(group_box("sub-b", None), asset_box(DATA_RG))] == {"contains": 1}
    assert edges[(asset_box(DATA_RG), asset_box(STORAGE))] == {"contains": 1}


def test_a_lens_that_names_nothing_is_none() -> None:
    graph = environment()
    assert estate_map(graph, PLACEMENTS, Lens("sub-z")) is None
    assert estate_map(graph, PLACEMENTS, Lens("sub-b", "nowhere")) is None
    assert estate_map(graph, PLACEMENTS, Lens(None, "Data")) is None


# ------------------------------------------------------------ folding
def crowded_directory(principals: int) -> tuple[AssetGraph, dict[str, Placement]]:
    resources = [node(SUB_A, ResourceType.SUBSCRIPTION)]
    placements = {SUB_A: Placement("sub-a")}
    edges = []
    for index in range(principals):
        principal = f"/principals/user-{index:03d}"
        resources.append(node(principal, ResourceType.USER))
        placements[principal] = Placement(DIRECTORY_SCOPE)
        # Every third holds a role; the rest are inventory.
        if index % 3 == 0:
            edges.append((principal, RelationshipType.GRANTS_ROLE, SUB_A))
    return AssetGraph.build(resources, edges), placements


def test_assets_past_the_cap_are_folded_and_their_reach_ends_at_the_fold() -> None:
    graph, placements = crowded_directory(30)
    mapped = draw(Lens(DIRECTORY_SCOPE), graph, placements, max_assets=4)
    by_id = {box.id: box for box in mapped.boxes}
    drawn = [box for box in mapped.boxes if box.kind == "asset"]

    assert len(drawn) == 4
    # Folded, never dropped: the fold holds every other directory asset.
    assert len(by_id[FOLD_BOX].members) == 26
    # Ten hold a role, four are drawn: six with reach are folded, and their
    # links are counted from the fold rather than vanishing with them.
    assert mapped.folded_with_reach == 6
    assert edge_map(mapped)[(FOLD_BOX, scope_box("sub-a"))] == {"grants_role": 6}


def test_assets_with_no_reach_and_nothing_to_mark_are_always_folded() -> None:
    graph, placements = crowded_directory(6)
    mapped = draw(Lens(DIRECTORY_SCOPE), graph, placements)
    drawn = {box.id for box in mapped.boxes if box.kind == "asset"}

    assert drawn == {asset_box("/principals/user-000"), asset_box("/principals/user-003")}
    assert mapped.folded_with_reach == 0


def test_an_asset_with_no_placement_belongs_to_the_directory() -> None:
    mapped = draw(Lens(), placements={})
    assert {box.id for box in mapped.boxes} == {scope_box(DIRECTORY_SCOPE)}


# ------------------------------------------------------------ stability
def test_the_same_estate_draws_the_same_map_whatever_order_it_arrives_in() -> None:
    expected = draw(Lens("sub-b"))
    for seed in range(5):
        rng = random.Random(seed)
        resources, edges = RESOURCES[:], EDGES[:]
        rng.shuffle(resources)
        rng.shuffle(edges)
        assert draw(Lens("sub-b"), AssetGraph.build(resources, edges)) == expected


# ------------------------------------------------------------ serialization
def test_serialized_boxes_carry_the_same_counts_whatever_they_hold() -> None:
    mapped = draw(Lens())
    rows = {pid: uuid.uuid4() for pid in PLACEMENTS}
    placements = Placements(
        of=PLACEMENTS,
        row_ids=rows,
        scope_names={"sub-a": "Web", "sub-b": "Data", DIRECTORY_SCOPE: "Directory"},
        scope_providers={"sub-a": "AZURE", "sub-b": "AZURE", DIRECTORY_SCOPE: "AZURE"},
    )
    findings = {
        rows[VM]: {"open": 2, "worst": Severity.MEDIUM.value},
        rows[WEB_RG]: {"open": 1, "worst": Severity.CRITICAL.value},
    }
    body = serialize_estate(mapped, placements, findings)
    boxes = {box["id"]: box for box in body["boxes"]}

    web = boxes[scope_box("sub-a")]
    assert web["name"] == "Web"
    assert web["kind"] == "scope"
    assert web["entry"] == 1
    assert web["findings"] == {"open": 3, "worst": "CRITICAL"}
    assert boxes[scope_box("sub-b")]["sensitive"] == 1
    assert boxes[scope_box("sub-b")]["routes"] == 1

    into_b = next(e for e in body["edges"] if e["target"] == scope_box("sub-b"))
    assert into_b["source"] == scope_box(DIRECTORY_SCOPE)
    assert into_b["on_route"] is True
    assert into_b["links"] == [
        {"relationship": "grants_role", "count": 1, "label": "can act over"}
    ]


def test_serialized_asset_boxes_link_to_their_page() -> None:
    mapped = draw(Lens("sub-b", "Data"))
    row = uuid.uuid4()
    placements = Placements(
        of=PLACEMENTS,
        row_ids={STORAGE: row},
        scope_names={"sub-b": "Data"},
        scope_providers={"sub-b": "AZURE"},
    )
    body = serialize_estate(mapped, placements, {})
    storage = next(box for box in body["boxes"] if box["id"] == asset_box(STORAGE))

    assert storage["asset_id"] == str(row)
    assert storage["provider_resource_id"] == STORAGE
    assert storage["resource_type"] == "storage_account"
    assert storage["sensitive"] == 1
    assert body["lens"] == {"scope_id": "sub-b", "group": "Data"}


# ------------------------------------------------------------ routes, traced
def test_each_route_through_the_lens_is_placed_on_the_boxes_drawn() -> None:
    mapped = draw(Lens())

    assert len(mapped.traced) == mapped.routes_total == 1
    route = mapped.traced[0]
    # Entry, then each step's target: the exposed VM's subscription, the
    # directory its identity lives in, then sub-b and down to the storage.
    assert route.boxes == (
        scope_box("sub-a"),
        scope_box(DIRECTORY_SCOPE),
        scope_box("sub-b"),
        scope_box("sub-b"),
        scope_box("sub-b"),
    )
    assert len(route.boxes) == route.path.hops + 1


def test_a_route_leaving_the_lens_names_no_box_where_none_is_drawn() -> None:
    # Opened on sub-a, the identity's role over sub-b is between two
    # neighbours, so sub-b is not drawn -- and the route must not claim it is.
    mapped = draw(Lens("sub-a"))
    drawn = {box.id for box in mapped.boxes}
    route = mapped.traced[0]

    assert route.boxes[:2] == (group_box("sub-a", "web"), scope_box(DIRECTORY_SCOPE))
    assert route.boxes[2:] == (None, None, None)
    assert all(box is None or box in drawn for box in route.boxes)


def test_routes_past_the_cap_are_counted_but_not_traced() -> None:
    graph = environment()
    mapped = estate_map(graph, PLACEMENTS, Lens(), graph.attack_paths(), max_routes=0)
    assert mapped is not None
    assert mapped.routes_total == 1
    assert mapped.traced == ()


def test_serialized_routes_carry_their_boxes_and_patterns() -> None:
    mapped = draw(Lens())
    placements = Placements(
        of=PLACEMENTS,
        row_ids={},
        scope_names={"sub-a": "Web", "sub-b": "Data"},
        scope_providers={},
    )
    body = serialize_estate(mapped, placements, {})

    (route,) = body["routes"]
    assert route["key"] == f"{VM}|{STORAGE}"
    assert route["boxes"][0] == scope_box("sub-a")
    assert len(route["boxes"]) == len(route["steps"]) + 1
    assert route["pattern"] is None
    assert body["patterns"] == []
    assert body["loose"] == [route["key"]]


def test_a_route_named_to_be_walked_is_traced_past_the_cap() -> None:
    graph = environment()
    mapped = estate_map(
        graph, PLACEMENTS, Lens(), graph.attack_paths(), max_routes=0, keep=f"{VM}|{STORAGE}"
    )
    assert mapped is not None
    assert [route.path.target.provider_resource_id for route in mapped.traced] == [STORAGE]
