"""What a risk's triage status is (DECISIONS.md §103)."""

from datetime import UTC, datetime, timedelta, timezone

import pytest

from app.core.enums import FindingStatus, RiskStatus
from app.risk.triage import (
    acceptance_expiry,
    finding_risk_status,
    finding_status_for,
    route_status_on_observation,
)

F = FindingStatus
R = RiskStatus
NOW = datetime(2026, 9, 19, 12, 0, tzinfo=UTC)


def test_one_open_member_keeps_a_group_in_the_queue() -> None:
    # Thirty-nine accepted and one nobody has looked at is not an accepted risk.
    members = [F.ACCEPTED_RISK] * 39 + [F.OPEN]
    assert finding_risk_status(members, R.ACCEPTED) == R.OPEN


def test_work_under_way_outranks_a_decision_to_live_with_it() -> None:
    assert finding_risk_status([F.ACCEPTED_RISK, F.IN_PROGRESS], R.OPEN) == R.IN_PROGRESS


def test_every_member_accepted_accepts_the_risk() -> None:
    assert finding_risk_status([F.ACCEPTED_RISK, F.ACCEPTED_RISK], R.OPEN) == R.ACCEPTED


def test_an_in_progress_finding_is_not_put_back_in_the_queue() -> None:
    # The scanner used to write OPEN whenever a member was open *or in
    # progress*, so a risk somebody had picked up was untriaged by morning.
    assert finding_risk_status([F.IN_PROGRESS], R.IN_PROGRESS) == R.IN_PROGRESS


def test_settled_members_have_no_say() -> None:
    assert (
        finding_risk_status([F.RESOLVED, F.FALSE_POSITIVE, F.ACCEPTED_RISK], R.OPEN)
        == R.ACCEPTED
    )


def test_with_nothing_live_the_status_stands() -> None:
    assert finding_risk_status([F.RESOLVED], R.IN_PROGRESS) == R.IN_PROGRESS
    assert finding_risk_status([], R.OPEN) == R.OPEN


@pytest.mark.parametrize("decided", [R.ACCEPTED, R.IN_PROGRESS, R.OPEN])
def test_a_route_seen_again_keeps_its_decision(decided: RiskStatus) -> None:
    assert route_status_on_observation(decided) == decided


def test_a_route_that_closed_and_came_back_is_open() -> None:
    assert route_status_on_observation(R.RESOLVED) == R.OPEN


def test_decisions_map_onto_finding_statuses() -> None:
    assert finding_status_for(R.OPEN) == F.OPEN
    assert finding_status_for(R.IN_PROGRESS) == F.IN_PROGRESS
    assert finding_status_for(R.ACCEPTED) == F.ACCEPTED_RISK


def test_nothing_is_resolved_by_hand() -> None:
    with pytest.raises(KeyError):
        finding_status_for(R.RESOLVED)


def test_an_acceptance_without_an_end_date_has_none() -> None:
    assert acceptance_expiry(None, NOW) is None


def test_an_end_date_already_past_is_refused() -> None:
    # The sweep would reopen it within minutes, and the person accepting it
    # would see their decision undone with no idea why.
    with pytest.raises(ValueError):
        acceptance_expiry(NOW - timedelta(minutes=1), NOW)
    with pytest.raises(ValueError):
        acceptance_expiry(NOW, NOW)


def test_a_naive_end_date_is_read_as_utc() -> None:
    naive = datetime(2026, 12, 31, 23, 59)
    assert acceptance_expiry(naive, NOW) == naive.replace(tzinfo=UTC)


def test_an_end_date_is_returned_in_utc() -> None:
    later = datetime(2026, 12, 31, 23, 59, tzinfo=timezone(timedelta(hours=2)))
    assert acceptance_expiry(later, NOW) == datetime(2026, 12, 31, 21, 59, tzinfo=UTC)


def test_the_sweep_is_scheduled() -> None:
    from app.workers.celery_app import celery_app

    entry = celery_app.conf.beat_schedule["expire-acceptances"]
    assert entry["task"] == "cloudguard.expire_acceptances"
    assert entry["schedule"] <= 300
