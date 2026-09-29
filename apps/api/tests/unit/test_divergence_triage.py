"""Divergence case files: the deterministic half of engine triage (DECISIONS.md section 167).

Everything here runs without Prowler, a database, a cloud or a model. The
fixture ``tests/fixtures/prowler/azure_mixed_run.json`` is a hand-written
Prowler run over ``snapshot_mixed.json``, each result chosen to produce one
kind of divergence:

* ``network_rdp_internet_access_restricted`` FAIL -- agrees with AZ-NET-001;
* ``storage_blob_public_access_level_is_disabled`` PASS -- PROWLER_MISSED on
  AZ-STO-001, whose capture says anonymous blob access is allowed;
* ``storage_ensure_minimum_tls_version_12`` FAIL -- NATIVE_MISSED on
  AZ-STO-003, whose capture says TLS 1.2;
* ``sqlserver_azuread_administrator_enabled`` MANUAL -- PROWLER_UNKNOWN on
  AZ-DB-008;
* ``storage_account_key_access_disabled`` FAIL -- NATIVE_MISSED on AZ-STO-002,
  which ``curation.json`` records as disagreeing by design.
"""

import copy
import importlib.util
import json
import pathlib

import pytest

from app.prowler import triage

FIXTURES = pathlib.Path(__file__).resolve().parents[1] / "fixtures"
SNAPSHOT = FIXTURES / "azure_raw" / "snapshot_mixed.json"
RUN = FIXTURES / "prowler" / "azure_mixed_run.json"
SCRIPT = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "triage_divergences.py"
API = pathlib.Path(__file__).resolve().parents[2]


def _snapshot() -> dict:
    return json.loads(SNAPSHOT.read_text())


def _runs() -> list[dict]:
    return json.loads(RUN.read_text())["runs"]


@pytest.fixture(scope="module")
def replayed() -> triage.Replay:
    return triage.replay(_snapshot(), _runs())


def _by_rule(cases: list[triage.DivergenceCase]) -> dict[str, triage.DivergenceCase]:
    return {case.rule["rule_id"]: case for case in cases}


# ------------------------------------------------------------------ replay


def test_replay_finds_exactly_the_divergences_the_fixture_was_written_for(replayed) -> None:
    found = {(d.rule_id, d.check_id, d.kind, d.expected) for d in replayed.divergences}
    assert found == {
        ("AZ-STO-001", "storage_blob_public_access_level_is_disabled", "PROWLER_MISSED", False),
        ("AZ-STO-003", "storage_ensure_minimum_tls_version_12", "NATIVE_MISSED", False),
        ("AZ-DB-008", "sqlserver_azuread_administrator_enabled", "PROWLER_UNKNOWN", False),
        ("AZ-STO-002", "storage_account_key_access_disabled", "NATIVE_MISSED", True),
    }


def test_agreement_is_not_a_case(replayed) -> None:
    assert "AZ-NET-001" not in {d.rule_id for d in replayed.divergences}


def test_the_summary_counts_what_a_caller_gates_on(replayed) -> None:
    summary = triage.summary(replayed)
    assert summary["unexpected"] == 3
    assert summary["expected"] == 1
    assert summary["by_kind"] == {"NATIVE_MISSED": 1, "PROWLER_MISSED": 1, "PROWLER_UNKNOWN": 1}


def test_a_fix_is_verified_by_replaying_it() -> None:
    """The loop the skill runs: change one side, replay, the case is gone."""
    runs = copy.deepcopy(_runs())
    for result in runs[0]["content"]["results"]:
        if result["check_id"] == "storage_ensure_minimum_tls_version_12":
            result["status"] = "PASS"
    after = triage.replay(_snapshot(), runs)
    assert "AZ-STO-003" not in {d.rule_id for d in after.divergences}
    assert triage.summary(after)["unexpected"] == 2


# ------------------------------------------------------------------- cases


def test_expected_pairs_are_left_out_unless_asked_for(replayed) -> None:
    default = triage.build_cases(replayed)
    everything = triage.build_cases(replayed, include_expected=True)
    assert "AZ-STO-002" not in _by_rule(default)
    assert "AZ-STO-002" in _by_rule(everything)
    # Unexpected first: those are the ones that are someone's bug.
    assert [case.expected for case in everything] == sorted(case.expected for case in everything)


def test_a_case_carries_both_engines_and_the_asset_they_disagree_about(replayed) -> None:
    case = _by_rule(triage.build_cases(replayed))["AZ-STO-001"]
    assert case.asset is not None and case.asset["name"] == "stgpublic"
    [native] = case.native
    assert native["state"] == "FAIL"
    [prowler] = case.prowler
    assert prowler["state"] == "PASS"
    assert prowler["check_id"] == "storage_blob_public_access_level_is_disabled"
    assert prowler["description"], "the check's own claim is what the triage weighs"
    assert case.hypotheses == list(triage.HYPOTHESES["PROWLER_MISSED"])


def test_a_pass_keeps_its_evidence_even_though_the_report_holds_only_ids(replayed) -> None:
    """``report.passes`` stores ids; the case re-derives the evidence behind one."""
    case = _by_rule(triage.build_cases(replayed))["AZ-STO-003"]
    [native] = case.native
    assert native["state"] == "PASS"
    assert native["evidence"], "a PASS with no evidence cannot be weighed against a FAIL"


def test_the_rule_is_located_in_source(replayed) -> None:
    case = _by_rule(triage.build_cases(replayed))["AZ-STO-003"]
    path, line = case.rule["source"].rsplit(":", 1)
    source = (API / path).read_text().splitlines()
    assert any("AZ-STO-003" in text for text in source[int(line) - 1 : int(line) + 10])
    assert "storage_ensure_minimum_tls_version_12" in case.rule["covered_by_checks"]


def test_case_ids_are_stable_across_replays(replayed) -> None:
    again = triage.replay(_snapshot(), _runs())
    first = sorted(case.case_id for case in triage.build_cases(replayed))
    second = sorted(case.case_id for case in triage.build_cases(again))
    assert first == second


def test_the_markdown_offers_every_verdict(replayed) -> None:
    case = triage.build_cases(replayed)[0]
    page = triage.render_markdown(case)
    assert case.case_id in page
    for verdict in triage.TRIAGE_VERDICTS:
        assert verdict in page


# --------------------------------------------------------------- redaction


def test_secret_strings_are_redacted_and_settings_are_kept() -> None:
    redacted = triage.redact(
        {
            "allow_shared_key_access": True,
            "connection_string": "Server=tcp:x;Password=hunter2",
            "tags": {"note": "DefaultEndpointsProtocol=https;AccountKey=abc123=="},
            "client_secret": "s3cr3t",
            "minimum_tls_version": "TLS1_2",
            "keys": [{"value": "https://x.blob.core.windows.net/c?sv=1&sig=abcdef"}],
        }
    )
    assert redacted["allow_shared_key_access"] is True
    assert redacted["minimum_tls_version"] == "TLS1_2"
    assert redacted["connection_string"] == triage.REDACTED
    assert redacted["client_secret"] == triage.REDACTED
    assert redacted["tags"]["note"] == triage.REDACTED
    assert redacted["keys"][0]["value"] == triage.REDACTED


def test_a_secret_in_the_capture_never_reaches_a_case() -> None:
    snapshot = _snapshot()
    account = snapshot["data"]["storage_accounts"][0]
    account.setdefault("tags", {})["backup"] = (
        "DefaultEndpointsProtocol=https;AccountName=stgpublic;AccountKey=Zm9vYmFy=="
    )
    cases = triage.build_cases(triage.replay(snapshot, _runs()), include_expected=True)
    assert "Zm9vYmFy" not in json.dumps([case.to_dict() for case in cases], default=str)


# --------------------------------------------------------------------- CLI


def _cli():
    spec = importlib.util.spec_from_file_location("triage_divergences", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_cli_exits_on_what_is_left_to_settle(tmp_path, capsys) -> None:
    cli = _cli()
    base = ["--snapshot", str(SNAPSHOT), "--prowler", str(RUN)]
    assert cli.main(base) == 1
    # Only the pair curation.json expects to differ: nothing left to settle.
    assert cli.main([*base, "--rule", "AZ-STO-002", "--include-expected"]) == 0
    assert cli.main(["--snapshot", str(tmp_path / "missing.json"), "--prowler", str(RUN)]) == 2
    capsys.readouterr()


def test_the_cli_writes_one_file_per_case(tmp_path) -> None:
    cli = _cli()
    out = tmp_path / "cases"
    cli.main(["--snapshot", str(SNAPSHOT), "--prowler", str(RUN), "--out", str(out)])
    summary = json.loads((out / "summary.json").read_text())
    assert summary["shown"] == 3
    assert len(list(out.glob("*.md"))) == 3
    assert len(list(out.glob("*.json"))) == 4  # three cases and the summary
