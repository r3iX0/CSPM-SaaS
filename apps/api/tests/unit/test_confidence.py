"""How sure Cleave is of a finding or a route (DECISIONS.md §262)."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.core.enums import (
    Confidence,
    ConfidenceReason,
    ContextSource,
    Freshness,
    Level,
    TaskOutcome,
)
from app.models.finding import Finding
from app.remediation import Comparison
from app.risk.confidence import (
    AssetContext,
    assess,
    assess_finding,
    assess_route,
    evidence_window,
)
from app.rules.registry import enabled_rules
from app.services.findings import condition_of, limitations_of
from app.services.graph import NodeReading, serialize_route_map
from tests.unit.test_route_analysis import RECORDS, WEB, diamond

NOW = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)

KNOWN = AssetContext(
    criticality=Level.HIGH,
    criticality_source=ContextSource.CUSTOMER,
    data_sensitivity=Level.CRITICAL,
    data_sensitivity_source=ContextSource.PROVIDER_TAG,
)


def ago(**delta: float) -> datetime:
    return NOW - timedelta(**delta)


# -- The window ----------------------------------------------------------------


def test_a_connection_scanned_by_hand_is_held_to_a_day() -> None:
    window = evidence_window(NOW, None)
    assert window.fresh_until == NOW + timedelta(hours=36)
    assert window.stale_at == NOW + timedelta(days=7)


def test_a_week_is_the_floor_for_stale_however_often_a_connection_is_read() -> None:
    window = evidence_window(NOW, 1)
    assert window.fresh_until == NOW + timedelta(minutes=90)
    assert window.stale_at == NOW + timedelta(days=7)


def test_a_weekly_connection_goes_stale_after_three_weeks() -> None:
    window = evidence_window(NOW, 168)
    assert window.stale_at == NOW + timedelta(weeks=3)


@pytest.mark.parametrize(
    ("observed", "expected"),
    [
        (ago(hours=35), Freshness.FRESH),
        (ago(hours=36), Freshness.AGING),
        (ago(days=6, hours=23), Freshness.AGING),
        (ago(days=7), Freshness.STALE),
    ],
)
def test_freshness_turns_at_the_window_edges(observed: datetime, expected: Freshness) -> None:
    assert evidence_window(observed, None).freshness(NOW) is expected


# -- A finding -------------------------------------------------------------------


def test_fresh_evidence_on_known_context_is_high_and_says_nothing() -> None:
    assessment = assess_finding(ago(hours=2), 24, KNOWN, NOW)
    assert assessment.level is Confidence.HIGH
    assert assessment.reasons == ()


def test_ageing_evidence_is_medium() -> None:
    assessment = assess_finding(ago(days=2), 24, KNOWN, NOW)
    assert assessment.level is Confidence.MEDIUM
    assert [reason.code for reason in assessment.reasons] == [ConfidenceReason.EVIDENCE_AGING]


def test_stale_evidence_is_low_whatever_the_context() -> None:
    assessment = assess_finding(ago(days=8), 24, KNOWN, NOW)
    assert assessment.level is Confidence.LOW
    assert [reason.code for reason in assessment.reasons] == [ConfidenceReason.EVIDENCE_STALE]


def test_unknown_context_names_each_field_and_never_goes_below_medium() -> None:
    context = AssetContext(
        criticality=Level.UNKNOWN,
        criticality_source=ContextSource.NONE,
        data_sensitivity=Level.UNKNOWN,
        data_sensitivity_source=ContextSource.NONE,
    )
    assessment = assess_finding(ago(hours=1), 24, context, NOW)
    assert assessment.level is Confidence.MEDIUM
    (reason,) = assessment.reasons
    assert reason.code is ConfidenceReason.CONTEXT_UNKNOWN
    assert reason.fields == ("criticality", "data_sensitivity")


def test_a_guess_from_a_name_is_a_reason_and_a_type_floor_is_not() -> None:
    guessed = AssetContext(
        criticality=Level.HIGH,
        criticality_source=ContextSource.INFERRED,
        data_sensitivity=Level.HIGH,
        data_sensitivity_source=ContextSource.TYPE_FLOOR,
    )
    assessment = assess_finding(ago(hours=1), 24, guessed, NOW)
    assert assessment.level is Confidence.MEDIUM
    (reason,) = assessment.reasons
    assert (reason.code, reason.fields) == (ConfidenceReason.CONTEXT_INFERRED, ("criticality",))


def test_evidence_reasons_come_before_context_reasons() -> None:
    window = evidence_window(ago(days=10), 24)
    assessment = assess(window, NOW, unknown=("criticality",), inferred=("data_sensitivity",))
    assert [reason.code for reason in assessment.reasons] == [
        ConfidenceReason.EVIDENCE_STALE,
        ConfidenceReason.CONTEXT_UNKNOWN,
        ConfidenceReason.CONTEXT_INFERRED,
    ]


def test_a_tenant_wide_finding_is_judged_on_its_evidence_alone() -> None:
    assert assess_finding(ago(hours=1), 24, None, NOW).level is Confidence.HIGH


# -- A route ---------------------------------------------------------------------


def test_a_route_is_as_current_as_its_oldest_hop() -> None:
    windows = [evidence_window(ago(hours=1), 24), evidence_window(ago(days=9), 24)]
    assessment = assess_route(windows, Level.CRITICAL, ContextSource.CUSTOMER, NOW)
    assert assessment is not None
    assert assessment.level is Confidence.LOW
    assert assessment.window.observed_at == ago(days=9)


def test_a_route_to_a_target_guessed_sensitive_is_provisional() -> None:
    windows = [evidence_window(ago(hours=1), 24)]
    assessment = assess_route(windows, Level.HIGH, ContextSource.INFERRED, NOW)
    assert assessment is not None
    assert assessment.level is Confidence.MEDIUM
    assert assessment.reasons[0].fields == ("data_sensitivity",)


def test_a_route_with_no_reading_has_no_confidence() -> None:
    assert assess_route([], Level.CRITICAL, ContextSource.CUSTOMER, NOW) is None


def test_the_route_map_dates_its_nodes_and_weighs_each_route() -> None:
    graph = diamond()
    paths = graph.attack_paths()
    ids = {node_id: uuid4() for path in paths for node_id in path.node_ids()}
    readings = {
        asset: NodeReading(ago(hours=1), 24, ContextSource.CUSTOMER) for asset in ids.values()
    }
    # The way in was last seen ten days ago: every route through it is stale.
    readings[ids[WEB]] = NodeReading(ago(days=10), 24, ContextSource.NONE)

    payload = serialize_route_map(
        graph, paths, ids, {}, total_routes=len(paths), readings=readings, now=NOW
    ).model_dump(mode="json")

    by_id = {node["id"]: node for node in payload["nodes"]}
    assert by_id[RECORDS]["observed_at"] is not None
    assert all(route["confidence"]["level"] == "LOW" for route in payload["routes"])


def test_without_readings_the_route_map_dates_nothing() -> None:
    graph = diamond()
    paths = graph.attack_paths()
    payload = serialize_route_map(graph, paths, {}, {}, total_routes=len(paths)).model_dump()
    assert all(route["confidence"] is None for route in payload["routes"])
    assert all(node["observed_at"] is None for node in payload["nodes"])


# -- The condition and the record --------------------------------------------------


def _equals_rule() -> tuple[str, str, object, str]:
    """A registered rule that declares an EQUALS expectation: id, field, value, version."""
    for rule in enabled_rules():
        spec = rule.remediation_spec
        for state in spec.expected if spec else ():
            if state.comparison is Comparison.EQUALS:
                return rule.rule_id, state.field, state.equals, rule.version
    raise AssertionError("No rule declares an EQUALS expectation")


def finding(rule_id: str, version: str, evidence: dict) -> Finding:
    return Finding(
        id=uuid4(),
        rule_id=rule_id,
        rule_version=version,
        evidence=evidence,
        remediation="",
        first_detected_at=NOW,
        last_detected_at=NOW,
    )


def test_the_condition_puts_what_was_seen_beside_what_is_expected() -> None:
    rule_id, field, expected, version = _equals_rule()
    (condition, *_rest) = condition_of(finding(rule_id, version, {field: "observed-value"}))
    assert condition.field == field
    assert condition.expected == expected
    assert condition.observed == "observed-value"
    assert condition.observed_recorded is True


def test_a_field_the_excerpt_does_not_carry_is_unrecorded_not_null() -> None:
    rule_id, _field, _expected, version = _equals_rule()
    (condition, *_rest) = condition_of(finding(rule_id, version, {}))
    assert condition.observed is None
    assert condition.observed_recorded is False


def test_a_finding_whose_rule_has_left_says_so() -> None:
    raised = finding("XX-GONE-001", "1.0", {})
    assert condition_of(raised) == []
    codes = [limit.code for limit in limitations_of(raised, None, [])]
    assert codes == ["NOT_CITED", "RULE_RETIRED"]


def test_a_changed_rule_and_a_thin_record_are_each_named() -> None:
    rule_id, field, _expected, version = _equals_rule()
    raised = finding(rule_id, f"{version}-old", {field: True})
    citations = [
        {"evidence_key": "storage_accounts", "payload_available": False, "outcome": None},
        {
            "evidence_key": "network_rules",
            "payload_available": True,
            "outcome": TaskOutcome.PARTIAL,
        },
    ]
    codes = [limit.code for limit in limitations_of(raised, citations, condition_of(raised))]
    assert codes == ["PAYLOAD_PRUNED", "READING_INCOMPLETE", "RULE_CHANGED"]
