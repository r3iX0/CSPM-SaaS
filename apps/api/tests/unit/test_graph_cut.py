"""What cutting one link would do, before anybody cuts it.

The graph view offers this on a traced route. The promise it must keep is the
one choke points keep: a route counts as closed only when no way round is left,
because a customer who removes a role assignment expecting five routes to close
and finds two still open will stop trusting every number on the page.
"""

from app.core.enums import Level, RelationshipType, ResourceType
from app.domain.resource import CloudResource
from app.graph import AssetGraph

VM = "/vm/jump"
APP = "/app/portal"
VM_ID = "/principals/vm"
APP_ID = "/principals/app"
GROUP = "/subscriptions/s/resourceGroups/data"
RECORDS = f"{GROUP}/providers/storage/records"
LEDGER = "/storage/ledger"


def node(resource_id: str, kind: ResourceType, **levels: Level) -> CloudResource:
    return CloudResource(
        provider_resource_id=resource_id,
        resource_type=kind,
        name=resource_id.rsplit("/", 1)[-1],
        **levels,
    )


def estate() -> AssetGraph:
    """Two ways in. Both reach the records; only the app reaches the ledger.

    The VM reaches the records two ways -- its own identity's role, and through
    the app's identity it can also act as -- so cutting one of them leaves the
    other.
    """
    return AssetGraph.build(
        [
            node(VM, ResourceType.VIRTUAL_MACHINE, public_exposure=Level.HIGH),
            node(APP, ResourceType.APP_SERVICE, public_exposure=Level.HIGH),
            node(VM_ID, ResourceType.SERVICE_PRINCIPAL),
            node(APP_ID, ResourceType.SERVICE_PRINCIPAL),
            node(GROUP, ResourceType.RESOURCE_GROUP),
            node(RECORDS, ResourceType.STORAGE_ACCOUNT, data_sensitivity=Level.CRITICAL),
            node(LEDGER, ResourceType.STORAGE_ACCOUNT, data_sensitivity=Level.HIGH),
        ],
        [
            (VM, RelationshipType.HAS_IDENTITY, VM_ID),
            (VM_ID, RelationshipType.GRANTS_ROLE, GROUP),
            (VM, RelationshipType.HAS_IDENTITY, APP_ID),
            (APP, RelationshipType.HAS_IDENTITY, APP_ID),
            (APP_ID, RelationshipType.GRANTS_ROLE, GROUP),
            (APP_ID, RelationshipType.GRANTS_ROLE, LEDGER),
            (GROUP, RelationshipType.CONTAINS, RECORDS),
        ],
    )


def pairs(outcome) -> set[tuple[str, str]]:  # type: ignore[no-untyped-def]
    return {(p.entry.name, p.target.name) for p in outcome.closed}


def test_a_link_with_no_way_round_closes_what_it_held() -> None:
    outcome = estate().cut(APP, RelationshipType.HAS_IDENTITY, APP_ID)

    assert outcome is not None
    assert pairs(outcome) == {("portal", "records"), ("portal", "ledger")}
    assert outcome.before - outcome.after == 2


def test_a_link_with_a_way_round_closes_nothing_and_says_so() -> None:
    """The VM still reaches the records through the app's identity."""
    outcome = estate().cut(VM_ID, RelationshipType.GRANTS_ROLE, GROUP)

    assert outcome is not None
    assert outcome.closed == ()
    assert outcome.before == outcome.after


def test_the_shared_link_closes_every_route_that_needs_it() -> None:
    outcome = estate().cut(APP_ID, RelationshipType.GRANTS_ROLE, GROUP)

    assert outcome is not None
    assert pairs(outcome) == {("portal", "records")}, "the VM keeps its own role"


def test_containment_is_not_offered_as_a_cut() -> None:
    assert estate().cut(GROUP, RelationshipType.CONTAINS, RECORDS) is None


def test_a_link_that_is_not_there_cannot_be_cut() -> None:
    assert estate().cut(VM_ID, RelationshipType.GRANTS_ROLE, LEDGER) is None
    assert estate().cut("/nowhere", RelationshipType.HAS_IDENTITY, VM_ID) is None


def test_asking_does_not_change_the_graph() -> None:
    graph = estate()
    before = graph.attack_paths()
    graph.cut(APP, RelationshipType.HAS_IDENTITY, APP_ID)

    assert graph.attack_paths() == before
