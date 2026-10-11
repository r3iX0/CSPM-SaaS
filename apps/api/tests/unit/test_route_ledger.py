"""The route ledger's rules, without a database (DECISIONS.md section 244).

Which routes open, carry or close an episode, when a route counts as rerouted,
why a route closed, and how the page reads it back. The scan-driven form -- a
real ANALYZE writing episodes and a rescan closing them -- is in the integration
suite, because it needs the scope the database holds.
"""

import uuid
from datetime import UTC, date, datetime

from app.core.enums import Level, RelationshipType, ResourceType, RouteCloseReason
from app.domain.resource import CloudResource
from app.graph import AssetGraph, Path
from app.graph.model import PathStep
from app.models.route_ledger import RouteEpisode
from app.services.graph import route_key
from app.services.route_ledger import ledger_status, open_each_day
from app.services.scan.ledger import (
    SeenRoute,
    close_reason,
    episode_nodes,
    is_rerouted,
    plan_ledger,
    route_shape,
    stored_steps,
)


def node(resource_id: str, kind: ResourceType, **levels: Level) -> CloudResource:
    return CloudResource(
        provider_resource_id=resource_id,
        resource_type=kind,
        name=resource_id,
        public_exposure=levels.get("exposure", Level.LOW),
        data_sensitivity=levels.get("sensitivity", Level.LOW),
    )


HOST = node("host", ResourceType.VIRTUAL_MACHINE, exposure=Level.HIGH)
IDENTITY = node("identity", ResourceType.SERVICE_PRINCIPAL)
STORE = node("store", ResourceType.STORAGE_ACCOUNT, sensitivity=Level.HIGH)

ROUTE = Path(
    entry=HOST,
    target=STORE,
    steps=(
        PathStep(HOST, RelationshipType.HAS_IDENTITY, IDENTITY),
        PathStep(IDENTITY, RelationshipType.GRANTS_ROLE, STORE),
    ),
)
SHAPE = [
    ["host", "has_identity", "identity"],
    ["identity", "grants_role", "store"],
]
ROUNDABOUT = [["host", "network_access", "jump"], ["jump", "grants_role", "store"]]


def seen(shape: list[list[str]] | None = None) -> SeenRoute:
    return SeenRoute(key=route_key(ROUTE), path=ROUTE, shape=shape or SHAPE)


def episode(key: str = "host|store", **values: object) -> RouteEpisode:
    fields: dict[str, object] = {
        "id": uuid.uuid4(),
        "route_key": key,
        "entry_id": "host",
        "target_id": "store",
        "steps": stored_steps(ROUTE),
        "shape": SHAPE,
        "opened_at": datetime(2026, 10, 1, tzinfo=UTC),
        "last_seen_at": datetime(2026, 10, 1, tzinfo=UTC),
    }
    fields.update(values)
    return RouteEpisode(**fields)


# --------------------------------------------------------------------- planning
def test_a_route_with_no_open_episode_opens_one() -> None:
    plan = plan_ledger({}, [seen()])
    assert [route.key for route in plan.opened] == ["host|store"]
    assert plan.seen_again == ()
    assert plan.unseen == ()


def test_a_route_seen_again_keeps_its_episode() -> None:
    open_one = episode()
    plan = plan_ledger({"host|store": open_one}, [seen()])
    assert plan.opened == ()
    assert [pair[0] for pair in plan.seen_again] == [open_one]


def test_a_route_not_seen_is_a_candidate_to_close() -> None:
    open_one = episode("elsewhere|store")
    plan = plan_ledger({"elsewhere|store": open_one}, [seen()])
    assert plan.unseen == (open_one,)
    assert [route.key for route in plan.opened] == ["host|store"]


def test_the_ledger_keys_a_route_as_the_page_does() -> None:
    """One route is one thing on the page, in the risks queue and in the ledger."""
    assert seen().key == "host|store"


# --------------------------------------------------------------------- rerouting
def test_another_way_round_is_a_reroute() -> None:
    assert is_rerouted(episode(last_seen_scan_id=uuid.uuid4()), seen(ROUNDABOUT), uuid.uuid4())


def test_the_same_way_round_is_not_a_reroute() -> None:
    assert not is_rerouted(episode(last_seen_scan_id=uuid.uuid4()), seen(), uuid.uuid4())


def test_a_retry_never_reroutes_against_its_own_shape() -> None:
    """A retried ANALYZE reads back the shape its first attempt wrote."""
    scan = uuid.uuid4()
    assert not is_rerouted(episode(last_seen_scan_id=scan), seen(ROUNDABOUT), scan)


def test_an_escalation_line_is_keyed_as_its_role_assignment() -> None:
    """Two lines that are one assignment are one link, so crossing the other of
    them does not read as a reroute (section 127)."""
    owner = node("owner", ResourceType.SERVICE_PRINCIPAL)
    group = node("rg", ResourceType.RESOURCE_GROUP, sensitivity=Level.HIGH)
    graph = AssetGraph.build(
        [owner, group],
        [
            ("owner", RelationshipType.GRANTS_ROLE, "rg"),
            ("owner", RelationshipType.CAN_GRANT_ROLES, "rg"),
        ],
        derive=False,
    )
    escalation = Path(
        entry=owner,
        target=group,
        steps=(PathStep(owner, RelationshipType.CAN_GRANT_ROLES, group),),
    )
    assert route_shape(graph, escalation) == [["owner", "grants_role", "rg"]]


# ----------------------------------------------------------------------- closing
def test_a_stored_route_names_every_asset_on_it() -> None:
    assert episode_nodes(episode()) == {"host", "identity", "store"}


def test_a_route_through_a_gone_asset_closed_because_it_went() -> None:
    """A deleted asset must never read as a fix."""
    assert close_reason({"host", "store"}, {"store"}) is RouteCloseReason.ASSET_GONE


def test_a_route_with_every_asset_left_closed_because_a_link_went() -> None:
    assert close_reason({"host", "store"}, set()) is RouteCloseReason.LINK_REMOVED


# ----------------------------------------------------------------------- reading
def test_an_episode_opened_by_the_scan_that_last_saw_it_is_new() -> None:
    scan = uuid.uuid4()
    assert ledger_status(episode(opened_scan_id=scan, last_seen_scan_id=scan)) == "NEW"


def test_an_episode_seen_again_since_is_open() -> None:
    seen_since = episode(opened_scan_id=uuid.uuid4(), last_seen_scan_id=uuid.uuid4())
    assert ledger_status(seen_since) == "OPEN"


def test_a_closed_episode_is_closed() -> None:
    closed = episode(
        closed_at=datetime(2026, 10, 3, tzinfo=UTC), close_reason=RouteCloseReason.LINK_REMOVED
    )
    assert ledger_status(closed) == "CLOSED"


def test_the_trend_counts_routes_open_at_the_end_of_each_day() -> None:
    episodes = [
        episode(opened_at=datetime(2026, 10, 1, 9, tzinfo=UTC)),
        episode(
            opened_at=datetime(2026, 10, 1, 9, tzinfo=UTC),
            closed_at=datetime(2026, 10, 2, 15, tzinfo=UTC),
        ),
        episode(opened_at=datetime(2026, 10, 3, 9, tzinfo=UTC)),
    ]
    points = open_each_day(episodes, date(2026, 10, 1), date(2026, 10, 3))
    assert [(point.day.day, point.open) for point in points] == [(1, 2), (2, 1), (3, 2)]
