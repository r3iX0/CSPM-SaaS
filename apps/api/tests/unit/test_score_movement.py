"""Why the score moved: causes whose points add up to the delta shown (§235).

The split is made in the score curve's own terms, so it is exact and the same
whichever order the causes happened in. Each changed risk gets one cause from
what its findings did, and one nothing explains is said to be unexplained.
"""

import math
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from app.core.enums import FindingEvent, FindingStatus, Level
from app.models.history import FindingEventRecord
from app.risk.config import DEFAULT_RISK_CONFIG as CONFIG
from app.risk.movement import Cause, charge_changes, split, total_deduction
from app.risk.scorer import default_scorer
from app.services.score_movement import Member, classify

A, B, C, D = (uuid4() for _ in range(4))


def _score(levels: dict[UUID, Level]) -> int:
    return default_scorer.security_score(list(levels.values()))


def _split(
    before: dict[UUID, Level], after: dict[UUID, Level], causes: dict[UUID, Cause]
) -> dict[Cause, tuple[int, float]]:
    rises: dict[Cause, float] = {}
    for key, rise in charge_changes(before, after, CONFIG).items():
        rises[causes[key]] = rises.get(causes[key], 0.0) + rise
    return split(
        rises,
        before=total_deduction(before, CONFIG),
        after=total_deduction(after, CONFIG),
        config=CONFIG,
        target=_score(after) - _score(before),
    )


# ------------------------------------------------------------------ the split
def test_only_risks_whose_charge_changed_are_counted() -> None:
    before = {A: Level.CRITICAL, B: Level.HIGH, C: Level.LOW}
    after = {A: Level.CRITICAL, B: Level.MEDIUM, D: Level.HIGH}
    assert charge_changes(before, after, CONFIG) == {B: -5.0, C: -1.0, D: 8.0}


def test_the_causes_add_up_to_the_delta_shown() -> None:
    before = {A: Level.CRITICAL, B: Level.CRITICAL, C: Level.HIGH}
    after = {C: Level.HIGH, D: Level.MEDIUM}
    parts = _split(
        before, after, {A: Cause.FIXES_VERIFIED, B: Cause.ACCEPTED, D: Cause.NEW_FAILURES}
    )
    assert sum(points for points, _ in parts.values()) == _score(after) - _score(before)
    assert parts[Cause.FIXES_VERIFIED][0] > 0 > parts[Cause.NEW_FAILURES][0]


def test_two_equal_causes_take_equal_shares_whatever_their_order() -> None:
    parts = _split(
        {A: Level.CRITICAL, B: Level.CRITICAL}, {}, {A: Cause.FIXES_VERIFIED, B: Cause.ACCEPTED}
    )
    assert parts[Cause.FIXES_VERIFIED][1] == pytest.approx(parts[Cause.ACCEPTED][1])


def test_the_exact_shares_sum_to_the_exact_change() -> None:
    before = {A: Level.CRITICAL, B: Level.LOW}
    after = {B: Level.HIGH, C: Level.CRITICAL}
    parts = _split(
        before,
        after,
        {A: Cause.FIXES_VERIFIED, B: Cause.CONTEXT_CHANGED, C: Cause.NEW_FAILURES},
    )
    k = CONFIG.score_decay
    exact = 100 * math.exp(-total_deduction(after, CONFIG) / k) - 100 * math.exp(
        -total_deduction(before, CONFIG) / k
    )
    assert sum(share for _, share in parts.values()) == pytest.approx(exact)


def test_offsetting_causes_are_both_shown_when_the_score_stands_still() -> None:
    parts = _split(
        {A: Level.HIGH}, {B: Level.HIGH}, {A: Cause.FIXES_VERIFIED, B: Cause.NEW_FAILURES}
    )
    assert parts[Cause.FIXES_VERIFIED][0] == -parts[Cause.NEW_FAILURES][0] != 0


def test_a_scoring_change_beyond_rounding_is_unexplained() -> None:
    # Ten points with no risk changed: only a change of scoring does that.
    parts = split({}, before=20.0, after=20.0, config=CONFIG, target=10)
    assert parts == {Cause.UNEXPLAINED: (10, 10.0)}


def test_nothing_moved_explains_nothing() -> None:
    assert split({}, before=20.0, after=20.0, config=CONFIG, target=0) == {}


# --------------------------------------------------------------------- causes
SINCE = datetime(2026, 10, 1, tzinfo=UTC)
OPENED, IP, RES = FindingStatus.OPEN, FindingStatus.IN_PROGRESS, FindingStatus.RESOLVED
FP = FindingStatus.FALSE_POSITIVE


def _event(
    finding: UUID,
    event: FindingEvent,
    previous: FindingStatus | None,
    current: FindingStatus,
    *,
    user: UUID | None = None,
    hours: int = 1,
) -> FindingEventRecord:
    return FindingEventRecord(
        finding_id=finding,
        event=event,
        previous_status=previous,
        current_status=current,
        user_id=user,
        created_at=SINCE + timedelta(hours=hours),
    )


def _classify(
    rise: float,
    *events: FindingEventRecord,
    exists: bool = True,
    moved: bool = False,
    rule_changed: bool = False,
    appeared: set[UUID] | None = None,
) -> Cause:
    grouped: dict[UUID, list[FindingEventRecord]] = {}
    for event in events:
        grouped.setdefault(event.finding_id, []).append(event)
    cause, _finding = classify(
        rise,
        members=[Member(A, "AZ-STO-002", B)],
        events=grouped,
        exists=exists,
        moved=moved,
        rule_changed=lambda _member: rule_changed,
        appeared=appeared or set(),
    )
    return cause


def test_a_detection_is_a_new_failure() -> None:
    assert _classify(8, _event(A, FindingEvent.DETECTED, None, OPENED)) is Cause.NEW_FAILURES


def test_a_regression_is_a_new_failure() -> None:
    assert _classify(8, _event(A, FindingEvent.REOPENED, RES, OPENED)) is Cause.NEW_FAILURES


def test_a_detection_on_an_asset_first_seen_is_the_asset() -> None:
    cause = _classify(8, _event(A, FindingEvent.DETECTED, None, OPENED), appeared={B})
    assert cause is Cause.ASSETS_APPEARED


def test_a_detection_by_a_rule_added_or_changed_is_the_rule() -> None:
    cause = _classify(8, _event(A, FindingEvent.DETECTED, None, OPENED), rule_changed=True)
    assert cause is Cause.RULES_CHANGED


def test_an_acceptance_that_ran_out_is_named() -> None:
    event = _event(A, FindingEvent.STATUS_CHANGED, FindingStatus.ACCEPTED_RISK, OPENED)
    assert _classify(8, event) is Cause.ACCEPTANCES_EXPIRED


def test_a_person_reopening_is_by_hand() -> None:
    event = _event(A, FindingEvent.STATUS_CHANGED, FP, OPENED, user=uuid4())
    assert _classify(8, event) is Cause.BY_HAND


def test_a_scan_resolving_is_a_verified_fix() -> None:
    assert _classify(-8, _event(A, FindingEvent.RESOLVED, IP, RES)) is Cause.FIXES_VERIFIED


def test_a_scan_resolving_under_a_changed_rule_is_the_rule() -> None:
    event = _event(A, FindingEvent.RESOLVED, OPENED, RES)
    assert _classify(-8, event, rule_changed=True) is Cause.RULES_CHANGED


def test_an_acceptance_is_named() -> None:
    event = _event(A, FindingEvent.RISK_ACCEPTED, OPENED, FindingStatus.ACCEPTED_RISK, user=uuid4())
    assert _classify(-8, event) is Cause.ACCEPTED


def test_a_false_positive_is_by_hand() -> None:
    event = _event(A, FindingEvent.STATUS_CHANGED, OPENED, FP, user=uuid4())
    assert _classify(-8, event) is Cause.BY_HAND


def test_a_risk_deleted_with_its_connection_is_an_asset_removed() -> None:
    assert _classify(-8, exists=False) is Cause.ASSETS_REMOVED


def test_a_risk_charged_at_another_band_is_its_context() -> None:
    assert _classify(5, moved=True) is Cause.CONTEXT_CHANGED


def test_a_risk_charged_at_another_band_by_a_new_rule_version_is_the_rule() -> None:
    assert _classify(5, moved=True, rule_changed=True) is Cause.RULES_CHANGED


def test_a_change_nothing_recorded_explains_is_unexplained() -> None:
    assert _classify(8) is Cause.UNEXPLAINED
    started = _event(A, FindingEvent.STATUS_CHANGED, OPENED, IP, user=uuid4())
    assert _classify(-8, started) is Cause.UNEXPLAINED


def test_a_grouped_risk_that_closed_is_explained_by_its_last_member_to_close() -> None:
    events = {
        A: [_event(A, FindingEvent.RESOLVED, OPENED, RES, hours=1)],
        C: [_event(C, FindingEvent.RISK_ACCEPTED, OPENED, FindingStatus.ACCEPTED_RISK, hours=2)],
    }
    cause, finding = classify(
        -20,
        members=[Member(A, "AZ-IAM-001", None), Member(C, "AZ-IAM-001", None)],
        events=events,
        exists=True,
        moved=False,
        rule_changed=lambda _member: False,
        appeared=set(),
    )
    assert (cause, finding) == (Cause.ACCEPTED, C)
