"""What the overview draws, over a graph built by hand.

The endpoint is a traversal with a budget, and every interesting thing about it
is decided before the database is involved: which nodes it keeps, that both
ends of every edge are nodes it kept, and that it says how much of the estate it
left out. Those are unit-testable, and the integration test beside them then
only has to prove the query end works at all.

Worth pinning here rather than only in CI: a bounded diagram that quietly drops
half an estate is a diagram of a smaller, tidier environment than the customer
has, and the failure is silent by construction.
"""

import uuid
from unittest.mock import AsyncMock, patch

import pytest

from app.api.routes.attack_paths import exposure_map
from app.core.enums import Level, Provider, RelationshipType, ResourceType
from app.domain.resource import CloudResource
from app.graph import AssetGraph


def resource(
    provider_resource_id: str,
    name: str,
    kind: ResourceType,
    *,
    exposure: Level = Level.UNKNOWN,
    sensitivity: Level = Level.UNKNOWN,
) -> CloudResource:
    return CloudResource(
        provider_resource_id=provider_resource_id,
        resource_type=kind,
        name=name,
        provider=Provider.AZURE,
        public_exposure=exposure,
        data_sensitivity=sensitivity,
    )


VM = resource(
    "/vm/jump-01", "jump-01", ResourceType.VIRTUAL_MACHINE, exposure=Level.CRITICAL
)
IDENTITY = resource("/principals/mi-1", "mi-jump-01", ResourceType.SERVICE_PRINCIPAL)
SUB = resource(
    "/subscriptions/sub-1",
    "Production",
    ResourceType.SUBSCRIPTION,
    sensitivity=Level.HIGH,
)
UNRELATED = resource("/vm/isolated", "isolated", ResourceType.VIRTUAL_MACHINE)


def wired() -> AssetGraph:
    """An exposed VM, the identity it runs as, the scope that identity holds a
    role over -- and one machine nothing can reach."""
    return AssetGraph.build(
        [VM, IDENTITY, SUB, UNRELATED],
        [
            (
                VM.provider_resource_id,
                RelationshipType.HAS_IDENTITY,
                IDENTITY.provider_resource_id,
            ),
            (
                IDENTITY.provider_resource_id,
                RelationshipType.GRANTS_ROLE,
                SUB.provider_resource_id,
            ),
        ],
    )


async def call(graph: AssetGraph, limit: int = 14) -> dict:
    tenant = type("T", (), {"organization_id": uuid.uuid4()})()
    with patch(
        "app.api.routes.attack_paths.graph_service.load_graph",
        new=AsyncMock(return_value=graph),
    ):
        return await exposure_map(session=None, tenant=tenant, limit=limit)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_draws_outward_from_what_the_internet_can_touch() -> None:
    body = await call(wired())

    names = {node["name"] for node in body["data"]["nodes"]}
    assert names == {"jump-01", "mi-jump-01", "Production"}
    # The machine nothing reaches is not on the map: this answers "what does
    # the internet touch", not "what exists".
    assert "isolated" not in names

    entry = next(n for n in body["data"]["nodes"] if n["name"] == "jump-01")
    assert entry["is_entry"] is True
    assert body["meta"]["entry_points"] == 1


@pytest.mark.asyncio
async def test_no_edge_arrives_from_a_node_that_is_not_drawn() -> None:
    body = await call(wired())

    drawn = {node["id"] for node in body["data"]["nodes"]}
    assert body["data"]["edges"]
    for edge in body["data"]["edges"]:
        assert edge["source"] in drawn
        assert edge["target"] in drawn


@pytest.mark.asyncio
async def test_says_how_many_nodes_it_left_out() -> None:
    body = await call(wired(), limit=1)

    assert len(body["data"]["nodes"]) == 1
    assert body["meta"]["nodes"] == 3
    assert body["meta"]["omitted"] == 2
    # And it draws no line it cannot land: an edge to a node the budget cut
    # would point at empty space.
    drawn = {node["id"] for node in body["data"]["nodes"]}
    for edge in body["data"]["edges"]:
        assert edge["source"] in drawn
        assert edge["target"] in drawn


@pytest.mark.asyncio
async def test_an_estate_nothing_can_reach_draws_nothing() -> None:
    """Not an error. An estate the internet cannot touch has no map, and that
    is the answer rather than a failure to produce one."""
    body = await call(AssetGraph.build([UNRELATED], []))

    assert body["data"]["nodes"] == []
    assert body["data"]["edges"] == []
    assert body["meta"]["entry_points"] == 0
    assert body["meta"]["omitted"] == 0
