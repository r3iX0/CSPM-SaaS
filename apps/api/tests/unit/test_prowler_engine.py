"""The second engine, as the API sees it: catalogue, rules, ingest, audit.

Everything here runs without Prowler, a database or a cloud. What the scanner
service stores is a JSON document; these tests build that document by hand and
check what the pipeline makes of it -- above all, that silence is never read as
a pass (DECISIONS.md section 150).

The last section holds the scanner service to the API: the task and queue
names it answers to, the columns it writes, the bytes it encodes. The two
share no code, so these are the only thing that notices when one side moves.
"""

import ast
import inspect
import json
import pathlib
import re
from uuid import uuid4

import pytest

from app.connectors.base import NormalizedState
from app.core.enums import Provider, ResourceType, RuleEngineKind, RuleState
from app.domain.resource import CloudResource
from app.prowler import ingest
from app.prowler.catalog import load
from app.prowler.ingest import AssetResolver, StoredAssessment
from app.prowler.rules import (
    compliance_mappings_for,
    inherited_mappings,
    prowler_rules,
    rule_for_check,
)
from app.rules.engine import EvaluatedResult, EvaluationReport
from app.rules.registry import RULE_REGISTRY, catalogue_rules, get_rule

ROOT = pathlib.Path(__file__).resolve().parents[4]
VERSION = load().prowler_version

STORAGE = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/data"
VAULT = "/subscriptions/s1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv"
CLUSTER = (
    "/subscriptions/s1/resourceGroups/rg/providers/"
    "Microsoft.ContainerService/managedClusters/aks"
)

# An account check no native rule answers, and one AZ-STO-001 answers.
UNCOVERED = "storage_ensure_file_shares_soft_delete_is_enabled"
COVERED = "storage_blob_public_access_level_is_disabled"


def _storage() -> CloudResource:
    return CloudResource(
        provider_resource_id=STORAGE,
        resource_type=ResourceType.STORAGE_ACCOUNT,
        name="data",
        provider=Provider.AZURE,
    )


def _assessment(
    results: list[dict],
    *,
    requested: list[str] | None = None,
    completed: list[str] | None = None,
    errors: dict | None = None,
    version: str = VERSION,
    account=None,
) -> StoredAssessment:
    requested = requested if requested is not None else [UNCOVERED, COVERED]
    return StoredAssessment(
        cloud_account_id=account,
        provider=Provider.AZURE,
        engine_version=version,
        outcome="COMPLETE",
        errors=errors or {},
        content={
            "requested": requested,
            "completed": completed if completed is not None else requested,
            "results": results,
        },
        scope_label="subscription Data",
    )


def _result(check: str, status: str, uid: str = STORAGE) -> dict:
    return {
        "check_id": check,
        "status": status,
        "status_extended": f"{check} said {status}",
        "resource_uid": uid,
        "resource_name": uid.rsplit("/", 1)[-1],
        "region": "westeurope",
    }


def _states(account, resources):
    state = NormalizedState(resources=list(resources))
    merged = NormalizedState(resources=list(resources))
    return {account: state}, state, merged


# --------------------------------------------------------------- catalogue


def test_the_catalogue_is_built_from_the_pinned_release() -> None:
    pinned = json.loads((ROOT / "tools/prowler/curation.json").read_text())["prowler_version"]
    assert pinned == VERSION
    assert f'"prowler=={pinned}"' in (ROOT / "apps/scanner/pyproject.toml").read_text()
    dockerfile = (ROOT / "infrastructure/docker/scanner.Dockerfile").read_text()
    assert f'"prowler=={pinned}"' in dockerfile


def test_every_rule_id_fits_and_none_collides() -> None:
    ids = [rule.rule_id for rule in catalogue_rules()]
    assert len(ids) == len(set(ids))
    assert max(len(rule_id) for rule_id in ids) <= 128


def test_excluded_and_covered_checks_raise_no_finding_of_their_own() -> None:
    registered = {rule.check.check_id for rule in prowler_rules()}
    for check in load().checks.values():
        if not check.enabled or check.covered_by:
            assert check.check_id not in registered, check.check_id
    # The ones that read secret material or call a third party are excluded,
    # never merely filtered: the scanner is not asked to run them at all.
    assert not load().checks["ec2_instance_secrets_user_data"].enabled
    assert not load().checks["network_public_ip_shodan"].enabled


def test_prowler_rules_are_never_evaluated_by_the_native_engine() -> None:
    assert all(rule.engine is RuleEngineKind.NATIVE for rule in RULE_REGISTRY)
    rule = rule_for_check(UNCOVERED)
    assert rule is not None and rule.engine is RuleEngineKind.PROWLER
    assert not rule.matches(_storage())
    assert rule.evaluate(_storage(), None).state is RuleState.UNKNOWN  # type: ignore[arg-type]


def test_every_mapping_names_a_control_the_catalogue_lists() -> None:
    from app.compliance.catalog import FRAMEWORKS

    known = {f.id: {c.id for c in f.controls} for f in FRAMEWORKS}
    for rule in catalogue_rules():
        for framework_id, controls in compliance_mappings_for(rule).items():
            assert framework_id in known, (rule.rule_id, framework_id)
            assert set(controls) <= known[framework_id], (rule.rule_id, framework_id)


def test_exploitability_stays_on_the_scale() -> None:
    assert all(0 <= rule.exploitability <= 5 for rule in prowler_rules())


def test_a_native_rule_inherits_new_frameworks_but_never_overrides_its_own() -> None:
    rule = get_rule("AZ-STO-005")
    assert rule is not None
    mappings = compliance_mappings_for(rule)
    # Its own, hand-written CIS 2.0 mapping stands...
    assert mappings["CIS_AZURE_2.0"] == rule.compliance_mappings["CIS_AZURE_2.0"]
    # ...and a framework it never mapped is inherited from its counterpart.
    assert "CIS_AZURE_6.0" in mappings


def test_a_pair_that_disagrees_by_design_passes_nothing_on() -> None:
    assert "AZ-ID-005" in load().divergence_notes
    assert "AZ-ID-005" not in inherited_mappings()


# ----------------------------------------------------------------- resolver


def test_ids_join_case_blind_through_parents_and_by_tail() -> None:
    vault = CloudResource(VAULT, ResourceType.KEY_VAULT, "kv")
    instance = CloudResource("i-0abc", ResourceType.VIRTUAL_MACHINE, "web", Provider.AWS)
    resolver = AssetResolver([_storage(), vault, instance])

    assert resolver.resolve(STORAGE.upper()) is not None
    key = resolver.resolve(f"{VAULT}/keys/signing")
    assert key is vault
    assert resolver.resolve("arn:aws:ec2:eu-west-1:1:instance/i-0abc") is instance
    assert resolver.resolve("/subscriptions/s1/other") is None


def test_an_ambiguous_tail_joins_nothing() -> None:
    one = CloudResource("sg-1/default", ResourceType.NETWORK_SECURITY_GROUP, "default")
    two = CloudResource("sg-2/default", ResourceType.NETWORK_SECURITY_GROUP, "default")
    assert AssetResolver([one, two]).resolve("arn:aws:ec2:x:1:security-group/default") is None


# ------------------------------------------------------------------- reading


def test_a_failure_lands_on_the_asset_it_names() -> None:
    account = uuid4()
    states, _state, merged = _states(account, [_storage()])
    reading = ingest.read(
        [_assessment([_result(UNCOVERED, "FAIL")], account=account)], states, merged
    )
    [verdict] = [v for v in reading.verdicts if v.check.check_id == UNCOVERED]
    assert verdict.state is RuleState.FAIL
    assert verdict.resource is not None
    assert verdict.resource.provider_resource_id == STORAGE
    assert verdict.evidence["engine"] == "prowler"


def test_silence_after_a_service_error_is_unknown_never_a_pass() -> None:
    """The failure mode this engine exists to refuse: Prowler could not list
    storage, so its storage checks said nothing about an account Cleave knows
    exists."""
    account = uuid4()
    states, _state, merged = _states(account, [_storage()])
    reading = ingest.read(
        [
            _assessment(
                [],
                requested=[UNCOVERED],
                errors={"services": {"storage": ["AuthorizationFailed"]}},
                account=account,
            )
        ],
        states,
        merged,
    )
    seen = {
        (v.state, v.resource.provider_resource_id if v.resource else None)
        for v in reading.verdicts
    }
    assert (RuleState.UNKNOWN, STORAGE) in seen
    assert (RuleState.UNKNOWN, None) in seen
    assert all(v.state is not RuleState.PASS for v in reading.verdicts)


def test_silence_with_no_error_is_nothing_to_judge() -> None:
    """A check that ran cleanly and reported nothing had nothing to evaluate.
    It ran -- so it is not 'never assessed' -- and it raises no verdict."""
    account = uuid4()
    states, _state, merged = _states(account, [])
    reading = ingest.read(
        [_assessment([], requested=[UNCOVERED], account=account)], states, merged
    )
    assert UNCOVERED in reading.ran
    assert reading.verdicts == []


def test_a_check_that_raised_is_unknown() -> None:
    account = uuid4()
    states, _state, merged = _states(account, [_storage()])
    reading = ingest.read(
        [
            _assessment(
                [],
                requested=[UNCOVERED],
                errors={"checks": {UNCOVERED: f"{UNCOVERED} -- KeyError"}},
                account=account,
            )
        ],
        states,
        merged,
    )
    assert [v.state for v in reading.verdicts] == [RuleState.UNKNOWN]


def _subscription(sub: str) -> CloudResource:
    return CloudResource(
        provider_resource_id=f"/subscriptions/{sub}",
        resource_type=ResourceType.SUBSCRIPTION,
        name=sub,
        provider=Provider.AZURE,
    )


def test_a_verdict_about_an_account_lands_on_that_accounts_asset() -> None:
    """Two subscriptions in one scan, each with a scope-level verdict. Keyed on
    no asset they would be one finding, and one's PASS would resolve the
    other's FAIL (DECISIONS.md section 151)."""
    first, second = uuid4(), uuid4()
    s1, s2 = _subscription("s1"), _subscription("s2")
    states = {
        first: NormalizedState(resources=[s1]),
        second: NormalizedState(resources=[s2]),
    }
    merged = NormalizedState(resources=[s1, s2])
    reading = ingest.read(
        [
            _assessment(
                [_result(UNCOVERED, "FAIL", uid="tenant-level label")],
                requested=[UNCOVERED],
                account=first,
            ),
            _assessment(
                [_result(UNCOVERED, "PASS", uid="tenant-level label")],
                requested=[UNCOVERED],
                account=second,
            ),
        ],
        states,
        merged,
    )
    placed = {
        (v.state, v.resource.provider_resource_id if v.resource else None)
        for v in reading.verdicts
    }
    assert placed == {(RuleState.FAIL, "/subscriptions/s1"), (RuleState.PASS, "/subscriptions/s2")}


def test_an_account_pass_with_nowhere_to_go_proves_nothing() -> None:
    """The subscription's collection failed, so there is no account asset for a
    scope-level result. A PASS on no asset would resolve a finding anywhere in
    the tenant; it is unknown instead. A FAIL is still an observation."""
    account = uuid4()
    reading = ingest.read(
        [
            _assessment(
                [
                    _result(UNCOVERED, "PASS", uid="label"),
                    _result(COVERED, "FAIL", uid="label"),
                ],
                account=account,
            )
        ],
        {},
        NormalizedState(resources=[]),
    )
    by_check = {v.check.check_id: v for v in reading.verdicts}
    assert by_check[UNCOVERED].state is RuleState.UNKNOWN
    assert by_check[UNCOVERED].resource is None
    assert by_check[COVERED].state is RuleState.FAIL


def test_one_verdict_per_check_and_asset_whatever_went_wrong() -> None:
    """A service that half-failed: the check failed one asset and said nothing
    of the scope. The FAIL stands, the scope is unknown, and neither asset gets
    two verdicts that would be two findings or a finding and a gap."""
    account = uuid4()
    subscription = _subscription("s1")
    states, _state, merged = _states(account, [subscription, _storage()])
    reading = ingest.read(
        [
            _assessment(
                [_result(UNCOVERED, "FAIL")],
                requested=[UNCOVERED],
                errors={"services": {"storage": ["AuthorizationFailed"]}},
                account=account,
            )
        ],
        states,
        merged,
    )
    keys = [
        (v.check.check_id, v.resource.provider_resource_id if v.resource else None)
        for v in reading.verdicts
    ]
    assert len(keys) == len(set(keys))
    placed = {key[1]: v.state for key, v in zip(keys, reading.verdicts, strict=True)}
    assert placed[STORAGE] is RuleState.FAIL
    assert placed["/subscriptions/s1"] is RuleState.UNKNOWN


def test_what_a_check_said_about_the_scope_stands_beside_a_service_error() -> None:
    account = uuid4()
    subscription = _subscription("s1")
    states, _state, merged = _states(account, [subscription])
    reading = ingest.read(
        [
            _assessment(
                [_result(UNCOVERED, "PASS", uid="/subscriptions/s1")],
                requested=[UNCOVERED],
                errors={"services": {"storage": ["AuthorizationFailed"]}},
                account=account,
            )
        ],
        states,
        merged,
    )
    assert [(v.state, v.resource) for v in reading.verdicts] == [(RuleState.PASS, subscription)]


def test_a_run_stopped_at_its_budget_says_so_for_what_it_never_reached() -> None:
    account = uuid4()
    states, _state, merged = _states(account, [_subscription("s1")])
    reading = ingest.read(
        [
            _assessment(
                [],
                requested=[UNCOVERED],
                completed=[],
                errors={"stopped": "The run reached its time budget and stopped."},
                account=account,
            )
        ],
        states,
        merged,
    )
    (verdict,) = reading.verdicts
    assert verdict.state is RuleState.UNKNOWN
    assert "time budget" in verdict.message


def test_manual_is_unknown() -> None:
    account = uuid4()
    states, _state, merged = _states(account, [_storage()])
    reading = ingest.read(
        [_assessment([_result(UNCOVERED, "MANUAL")], account=account)], states, merged
    )
    assert reading.verdicts[0].state is RuleState.UNKNOWN
    assert "cannot assess" in reading.verdicts[0].message


def test_a_run_from_another_prowler_release_is_not_interpreted() -> None:
    account = uuid4()
    states, _state, merged = _states(account, [_storage()])
    reading = ingest.read(
        [_assessment([_result(UNCOVERED, "PASS")], version="0.0.1", account=account)],
        states,
        merged,
    )
    assert reading.verdicts
    assert all(v.state is RuleState.UNKNOWN for v in reading.verdicts)


def test_a_run_that_could_not_start_leaves_every_check_unknown() -> None:
    account = uuid4()
    states, _state, merged = _states(account, [_storage()])
    reading = ingest.read(
        [_assessment([], errors={"fatal": "AADSTS7000215"}, account=account)], states, merged
    )
    assert {v.check.check_id for v in reading.verdicts} == {UNCOVERED, COVERED}
    assert all("AADSTS7000215" in v.message for v in reading.verdicts)


def test_an_asset_only_prowler_saw_joins_the_inventory_as_unknown_type() -> None:
    account = uuid4()
    states, state, merged = _states(account, [])
    check = "aks_cluster_rbac_enabled"
    reading = ingest.read(
        [_assessment([_result(check, "FAIL", uid=CLUSTER)], requested=[check], account=account)],
        states,
        merged,
    )
    [added] = reading.added
    assert added.resource_type is ResourceType.UNKNOWN
    assert added in state.resources and added in merged.resources
    # No native rule can evaluate it -- it carries none of the metadata they read.
    assert not [rule for rule in RULE_REGISTRY if rule.matches(added)]


def test_the_worst_of_several_results_on_one_asset_wins() -> None:
    account = uuid4()
    vault = CloudResource(VAULT, ResourceType.KEY_VAULT, "kv")
    states, _state, merged = _states(account, [vault])
    check = "keyvault_rbac_key_expiration_set"
    reading = ingest.read(
        [
            _assessment(
                [
                    _result(check, "PASS", uid=f"{VAULT}/keys/a"),
                    _result(check, "FAIL", uid=f"{VAULT}/keys/b"),
                ],
                requested=[check],
                account=account,
            )
        ],
        states,
        merged,
    )
    [verdict] = reading.verdicts
    assert verdict.state is RuleState.FAIL
    assert verdict.evidence["result_count"] == 1


# ------------------------------------------------------------------- merging


def _native_report(state: RuleState) -> EvaluationReport:
    rule = get_rule("AZ-STO-001")
    assert rule is not None
    report = EvaluationReport(rules_run=1)
    if state is RuleState.PASS:
        report.passes.append((rule.rule_id, STORAGE))
    else:
        report.failures.append(
            EvaluatedResult(rule=rule, result=None, resource=_storage())  # type: ignore[arg-type]
        )
    return report


def test_merge_turns_uncovered_verdicts_into_findings_and_coverage() -> None:
    account = uuid4()
    states, _state, merged = _states(account, [_storage()])
    reading = ingest.read(
        [_assessment([_result(UNCOVERED, "FAIL"), _result(COVERED, "PASS")], account=account)],
        states,
        merged,
    )
    report = _native_report(RuleState.PASS)
    ingest.merge(report, reading)

    rule = rule_for_check(UNCOVERED)
    assert rule is not None
    assert [f.rule.rule_id for f in report.failures] == [rule.rule_id]
    assert report.coverage[rule.rule_id].failed_count == 1
    # The covered check is evidence about AZ-STO-001, not a finding of its own.
    assert rule_for_check(COVERED) is None
    assert report.rules_run == 2


def test_disagreement_is_recorded_in_both_directions() -> None:
    account = uuid4()

    states, _state, merged = _states(account, [_storage()])
    reading = ingest.read(
        [_assessment([_result(COVERED, "FAIL")], account=account)], states, merged
    )
    [divergence] = ingest.merge(_native_report(RuleState.PASS), reading)
    assert divergence.kind == "NATIVE_MISSED"
    assert divergence.rule_id == "AZ-STO-001"
    assert divergence.check_id == COVERED
    assert not divergence.expected

    states, _state, merged = _states(account, [_storage()])
    reading = ingest.read(
        [_assessment([_result(COVERED, "PASS")], account=account)], states, merged
    )
    [divergence] = ingest.merge(_native_report(RuleState.FAIL), reading)
    assert divergence.kind == "PROWLER_MISSED"


def test_agreement_records_nothing() -> None:
    account = uuid4()
    states, _state, merged = _states(account, [_storage()])
    reading = ingest.read(
        [_assessment([_result(COVERED, "PASS")], account=account)], states, merged
    )
    assert ingest.merge(_native_report(RuleState.PASS), reading) == []


# ----------------------------------------------------- seams and contracts


def test_the_api_never_imports_prowler() -> None:
    """Prowler's pins cannot share this process (DECISIONS.md section 150).
    ``app.prowler`` is this codebase's own package; ``prowler`` is not."""
    offenders = []
    for path in (ROOT / "apps/api/app").rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            if any(name == "prowler" or name.startswith("prowler.") for name in names):
                offenders.append(str(path))
    assert offenders == []


@pytest.fixture
def scanner(monkeypatch):
    monkeypatch.syspath_prepend(str(ROOT / "apps/scanner"))
    import cloudguard_scanner.capture as capture
    import cloudguard_scanner.celery_app as celery_app
    import cloudguard_scanner.store as store

    return capture, celery_app, store


def test_the_scanner_answers_to_the_names_the_api_sends(scanner) -> None:
    _capture, scanner_celery, scanner_store = scanner
    from app.core.enums import ScanStepKind
    from app.models.scan import ScanStep
    from app.workers import celery_app

    assert scanner_celery.ASSESS_TASK == celery_app.ASSESS_TASK
    assert scanner_celery.ASSESS_QUEUE == celery_app.ASSESS_QUEUE
    assert scanner_celery.DEFAULT_QUEUE == celery_app.DEFAULT_QUEUE
    assert scanner_celery.ADVANCE_TASK == "cloudguard.advance_scan"
    assert ScanStepKind.ASSESS.value == scanner_store.ASSESS
    assert scanner_store.LEASE_SECONDS == ScanStep.LEASE_SECONDS


def test_the_scanner_takes_the_attempt_the_api_sends(scanner) -> None:
    """``advance_scan`` sends ``[scan_id, step_id, attempt]``; the scanner's
    task must read the third as the attempt, or a stale message runs beside
    the attempt that replaced it (DECISIONS.md section 151)."""
    from cloudguard_scanner.tasks import run_assess_step

    from app.workers import scan_tasks

    parameters = list(inspect.signature(run_assess_step.run).parameters)
    assert parameters[:3] == ["scan_id", "step_id", "attempt"]
    source = inspect.getsource(scan_tasks.advance_scan)
    assert "args=[scan_id, str(step_id), attempt]" in source


def test_the_scanner_writes_columns_the_model_has(scanner) -> None:
    _capture, _celery, scanner_store = scanner
    from app.models.assessment import AssessmentCapture

    source = inspect.getsource(scanner_store.Store.write_capture)
    written = re.search(r"INSERT INTO assessment_captures \((.*?)\)", source, re.S)
    assert written is not None
    columns = {name.strip() for name in written.group(1).split(",")}
    assert columns <= set(AssessmentCapture.__table__.columns.keys())


def test_the_scanner_encodes_what_the_api_decodes(scanner) -> None:
    capture, _celery, _store = scanner
    from app.core.payloads import canonical, decompress

    payload = {"requested": ["a"], "completed": ["a"], "results": [{"b": 1, "a": None}]}
    assert capture.canonical(payload) == canonical(payload)
    assert decompress(capture.encode(payload).compressed) == payload
