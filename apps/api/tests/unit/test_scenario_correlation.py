"""Turning a route into a risk: which findings it groups, and which routes a
scan may close.

Pure where the pipeline allows it. The end-to-end form -- a rescan of one
subscription leaving another's routes open -- is in the integration suite,
because it needs the database the scope is read from.
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from app.core.enums import Level, RelationshipType, ResourceType
from app.domain.resource import CloudResource
from app.graph import Path
from app.graph.model import PathStep
from app.models.finding import Finding
from app.models.risk import Risk
from app.models.scan import Scan
from app.services.scan.context import AnalyzeContext
from app.services.scan.correlation import _members_on, _outside_scope, _route_nodes
from app.services.scan.writer import ScanWriter


def node(resource_id: str, kind: ResourceType) -> CloudResource:
    return CloudResource(
        provider_resource_id=resource_id,
        resource_type=kind,
        name=resource_id,
        public_exposure=Level.HIGH,
        data_sensitivity=Level.HIGH,
    )


HOST = node("host", ResourceType.VIRTUAL_MACHINE)
IDENTITY = node("identity", ResourceType.SERVICE_PRINCIPAL)
STORE = node("store", ResourceType.STORAGE_ACCOUNT)

ROUTE = Path(
    entry=HOST,
    target=STORE,
    steps=(
        PathStep(HOST, RelationshipType.HAS_IDENTITY, IDENTITY),
        PathStep(IDENTITY, RelationshipType.GRANTS_ROLE, STORE),
    ),
)


def finding(resource_id: uuid.UUID, rule_id: str) -> Finding:
    return Finding(id=uuid.uuid4(), resource_id=resource_id, rule_id=rule_id)


# -------------------------------------------------------------------- members
def test_every_open_finding_on_an_asset_is_a_member() -> None:
    """A host with three failing checks contributes three members. Keeping one
    scored the route from whichever row the database returned last."""
    host_id, store_id = uuid.uuid4(), uuid.uuid4()
    on_host = [finding(host_id, f"rule-{n}") for n in range(3)]
    on_store = [finding(store_id, "rule-store")]

    members = _members_on(
        ROUTE,
        {host_id: on_host, store_id: on_store},
        {"host": host_id, "store": store_id},
    )

    assert {m.id for m in members} == {f.id for f in on_host + on_store}


def test_an_asset_with_no_open_findings_adds_none() -> None:
    members = _members_on(
        ROUTE, {}, {"host": uuid.uuid4(), "identity": uuid.uuid4()}
    )
    assert members == []


# ---------------------------------------------------------------------- scope
def test_a_stored_route_names_every_asset_on_it() -> None:
    risk = Risk(
        path=[
            {"source_id": "host", "target_id": "identity"},
            {"source_id": "identity", "target_id": "store"},
        ]
    )
    assert _route_nodes(risk) == {"host", "identity", "store"}


class _Rows:
    def __init__(self, rows: list[tuple[str, bool]]) -> None:
        self._rows = rows

    def all(self) -> list[tuple[str, bool]]:
        return self._rows


class _Session:
    """Answers the one scope query with the rows it was given."""

    def __init__(self, rows: list[tuple[str, bool]]) -> None:
        self.rows = rows

    async def execute(self, _statement: Any) -> _Rows:
        return _Rows(self.rows)


def scoped(session: _Session, account_ids: list[uuid.UUID]) -> AnalyzeContext:
    """An analysis covering these subscriptions, over the fake session."""
    organization_id = uuid.uuid4()
    return AnalyzeContext(
        writer=ScanWriter(session, organization_id),  # type: ignore[arg-type]
        scan=Scan(organization_id=organization_id),
        observed_at=datetime.now(UTC),
        account_ids=account_ids,
    )


async def outside(rows: list[tuple[str, bool]], nodes: set[str]) -> set[str] | None:
    return await _outside_scope(scoped(_Session(rows), [uuid.uuid4()]), nodes)


async def test_an_asset_in_another_subscription_is_outside() -> None:
    """The route through it is not this scan's to close: the graph never held
    that part of the estate."""
    assert await outside([("host", True), ("store", False)], {"host", "store"}) == {
        "store"
    }


async def test_an_asset_with_no_row_left_is_inside() -> None:
    """Gone entirely -- so is every route through it, whoever scans next."""
    assert await outside([("host", True)], {"host", "deleted"}) == set()


async def test_a_scan_that_covers_nothing_closes_nothing() -> None:
    result = await _outside_scope(scoped(_Session([]), []), {"host"})
    assert result is None
