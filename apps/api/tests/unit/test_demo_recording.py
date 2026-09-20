"""The Azure recording the demo organization is seeded from.

The demo is where most people first see the graph, so the recording has to
hold the shapes the graph view exists to show: routes, an escalation, a fold,
and choke points that are not all the same answer. These pin those, and that
the recording is still the mixed one underneath -- every asset and every
finding the demo showed before is still there, so the ``--fix`` replay still
closes what it used to.

Pure: normalizer, rules and graph over the committed JSON. No database.
"""

import importlib.util
import json
import pathlib
from types import ModuleType

from app.connectors.azure.normalizer import AzureNormalizer
from app.connectors.base import NormalizedState, RawSnapshot
from app.core.enums import Provider, ResourceType
from app.graph import AssetGraph
from app.rules.base import RuleContext
from app.rules.engine import RuleEngine

RAW = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "azure_raw"
SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"


def load(module_name: str, path: pathlib.Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(module_name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def normalized(name: str) -> NormalizedState:
    raw = json.loads((RAW / f"{name}.json").read_text())
    return AzureNormalizer().normalize(
        RawSnapshot(
            provider=Provider(raw["provider"]),
            tenant_id=raw["tenant_id"],
            subscription_id=raw["subscription_id"],
            version=raw["version"],
            data=raw["data"],
            errors=raw["errors"],
        )
    )


def graph(name: str = "snapshot_demo") -> AssetGraph:
    state = normalized(name)
    return AssetGraph.build(state.resources, state.relationships)


def report(name: str):  # type: ignore[no-untyped-def]
    state = normalized(name)
    relationships: dict[tuple[str, str], list[str]] = {}
    for source, kind, target in state.relationships:
        relationships.setdefault((source, kind.value), []).append(target)
    return RuleEngine().evaluate(
        RuleContext(
            resources=state.resources,
            relationships=relationships,
            controls=state.controls,
            collection_errors=state.collection_errors,
        )
    )


def test_the_committed_recording_is_what_its_script_builds() -> None:
    """Edit the script, not the JSON: a hand edit would drift unnoticed."""
    builder = load("build_snapshot_demo", RAW / "build_snapshot_demo.py")
    assert (RAW / "snapshot_demo.json").read_text() == builder.render()


def test_every_asset_of_the_mixed_recording_is_still_there() -> None:
    before = {r.provider_resource_id for r in normalized("snapshot_mixed").resources}
    after = {r.provider_resource_id for r in normalized("snapshot_demo").resources}
    assert before <= after


def test_every_finding_the_demo_showed_is_still_raised() -> None:
    def failing(name: str) -> set[str]:
        return {finding.rule.rule_id for finding in report(name).failures}

    assert failing("snapshot_mixed") <= failing("snapshot_demo")


def test_the_new_estate_adds_no_check_that_cannot_reach_a_verdict() -> None:
    def unknown(name: str) -> set[str]:
        return {
            rule_id
            for rule_id, coverage in report(name).coverage.items()
            if rule_id.startswith("AZ-") and coverage.unknown_count
        }

    assert unknown("snapshot_demo") <= unknown("snapshot_mixed")


def test_there_are_routes_from_more_than_one_way_in() -> None:
    paths = graph().attack_paths()
    entries = {p.entry.name for p in paths}

    assert len(paths) >= 10
    assert {"vm-jumpbox", "vm-build-agent", "app-payments-api"} <= entries


def test_the_build_agent_can_grant_itself_roles() -> None:
    chains = graph().escalation_chains()
    assert any(c.entry.name == "vm-build-agent" and c.target.name == "rg-payments" for c in chains)


def test_identities_on_a_route_can_be_told_apart() -> None:
    """Three identities named "ServicePrincipal" would make every route read alike."""
    names = {
        step.target.name
        for path in graph().attack_paths()
        for step in path.steps
        if step.target.resource_type == ResourceType.SERVICE_PRINCIPAL
    }
    assert len(names) == 3
    assert all(name.endswith("(managed identity)") for name in names)


def test_the_data_group_folds_with_the_sensitive_account_drawn() -> None:
    around = graph().neighborhood(f"{SUB}/resourceGroups/rg-data", depth=1)

    assert around is not None
    assert around.groups and len(around.groups[0].members) >= 16
    drawn = {graph().nodes[node].name for node in around.layers}
    assert "stcustomerrecords" in drawn


def test_no_single_cut_closes_every_route_to_the_customer_records() -> None:
    estate = graph()
    records = next(n for n in estate.nodes.values() if n.name == "stcustomerrecords")
    choke_points = estate.choke_points()

    assert len({c.severs for c in choke_points}) > 1, "the cuts should not all be equal"
    for choke in choke_points:
        step = choke.step
        outcome = estate.cut(
            step.source.provider_resource_id,
            step.relationship,
            step.target.provider_resource_id,
        )
        assert outcome is not None
        closed = {id(path) for path in outcome.closed}
        assert any(
            path.target == records and id(path) not in closed
            for path in estate.attack_paths()
        )


def test_the_seed_replays_this_recording_and_its_fixes_still_apply() -> None:
    seed = load(
        "demo_environment",
        pathlib.Path(__file__).resolve().parents[4] / "database" / "seed" / "demo_environment.py",
    )
    assert seed.SNAPSHOTS[Provider.AZURE].name == "snapshot_demo.json"

    payload = json.loads((RAW / "snapshot_demo.json").read_text())
    fixed = seed.apply_fixes(payload)
    assert fixed != payload
    assert all(
        server["properties"]["publicNetworkAccess"] == "Disabled"
        for server in fixed["data"]["sql_servers"]
    )


async def test_the_seed_replay_answers_the_pipeline_and_its_capture_adds_back_up() -> None:
    """The seed's replay must survive what the pipeline actually asks of it.

    It drifted once: the pipeline began passing a collection plan and storing a
    capture as a manifest of payload hashes, the replay took no plan and
    produced no payloads, and the shared demo was analyzed as an empty estate --
    score 100, no findings. So this calls it the way ``collection.py`` does and
    rebuilds the capture the way ANALYZE does.
    """
    from types import SimpleNamespace

    from app.connectors.azure.connector import AzureConnector
    from app.core.payloads import digest
    from app.services.scan.capture import manifest, rebuild_capture

    seed = load(
        "demo_environment",
        pathlib.Path(__file__).resolve().parents[4] / "database" / "seed" / "demo_environment.py",
    )
    payload = json.loads((RAW / "snapshot_demo.json").read_text())
    replay = seed.ReplayConnector(payload)

    assert replay.baseline_evidence() == AzureConnector.baseline_evidence()

    async def heartbeat(done: int, total: int) -> None:
        return None

    rebuilt: dict = {}
    for snapshot in (
        await replay.collect(heartbeat, None),
        await replay.collect_directory(heartbeat, None),
    ):
        held = {digest(p)[0]: p for p in snapshot.payloads.values()}
        row = SimpleNamespace(manifest=manifest(snapshot), data=None)
        capture = await rebuild_capture(None, None, row, held)  # type: ignore[arg-type]
        assert capture["data"] == snapshot.data
        assert set(snapshot.coverage) <= set(snapshot.payloads)
        rebuilt.update(capture["data"])

    assert rebuilt == payload["data"]
