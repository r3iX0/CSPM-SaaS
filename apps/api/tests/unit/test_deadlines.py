"""When a fix is due, and how fixes went against it (DECISIONS.md section 225).

A task's own date wins over the policy; the policy counts from first detection, by severity; a
severity with no policy has no deadline. Progress counts verified fixes by severity, takes each
severity's median days to fix, and counts a fix with no deadline as neither on time nor late.
"""

from datetime import UTC, date, datetime, timedelta, timezone
from uuid import uuid4

from app.core.enums import Severity
from app.services import deadlines
from app.services.deadlines import Fix, deadline, fix_within, progress

DETECTED = datetime(2026, 9, 1, 22, 30, tzinfo=UTC)
POLICY = fix_within(
    {Severity.CRITICAL: 7, Severity.HIGH: 30, Severity.MEDIUM: None, Severity.LOW: None}
)


def test_a_date_somebody_set_wins_over_the_policy() -> None:
    due = deadline(date(2026, 12, 1), Severity.CRITICAL, DETECTED, POLICY)
    assert due == deadlines.Deadline(due_on=date(2026, 12, 1), by_policy=False)


def test_the_policy_counts_from_first_detection() -> None:
    due = deadline(None, Severity.CRITICAL, DETECTED, POLICY)
    assert due == deadlines.Deadline(due_on=date(2026, 9, 8), by_policy=True)


def test_first_detection_is_read_as_a_day_in_utc() -> None:
    # 00:30 on 2 September two hours east of UTC is still 1 September in UTC.
    east = DETECTED.astimezone(timezone(timedelta(hours=2)))
    assert deadline(None, Severity.HIGH, east, POLICY).due_on == date(2026, 10, 1)


def test_a_severity_without_a_policy_has_no_deadline() -> None:
    due = deadline(None, Severity.MEDIUM, DETECTED, POLICY)
    assert due == deadlines.Deadline(due_on=None, by_policy=False)


def test_no_policy_is_no_deadline_for_anything() -> None:
    for severity in Severity:
        assert deadline(None, severity, DETECTED, deadlines.NO_POLICY).due_on is None


def _fix(severity: Severity, days: float, due_on: date | None = None) -> Fix:
    return Fix(
        finding_id=uuid4(),
        title=f"{severity} fixed after {days} days",
        rule_id="AZ-STO-001",
        severity=severity,
        first_detected_at=DETECTED,
        resolved_at=DETECTED + timedelta(days=days),
        due_on=due_on,
    )


def test_a_fix_observed_on_its_due_day_is_on_time() -> None:
    assert _fix(Severity.HIGH, 6, due_on=date(2026, 9, 7)).on_time is True
    assert _fix(Severity.HIGH, 7, due_on=date(2026, 9, 7)).on_time is False


def test_a_fix_with_no_deadline_is_neither_on_time_nor_late() -> None:
    fix = _fix(Severity.LOW, 3)
    result = progress([fix], recent=10)
    assert fix.on_time is None
    assert (result.fixed, result.on_time, result.late) == (1, 0, 0)


def test_progress_takes_each_severitys_median_days_to_fix() -> None:
    fixes = [_fix(Severity.CRITICAL, days) for days in (1, 2, 9)] + [_fix(Severity.HIGH, 4.25)]
    by_severity = {row.severity: row for row in progress(fixes, recent=10).by_severity}

    assert by_severity[Severity.CRITICAL].fixed == 3
    assert by_severity[Severity.CRITICAL].median_days_to_fix == 2.0
    assert by_severity[Severity.HIGH].median_days_to_fix == 4.2
    assert by_severity[Severity.LOW].fixed == 0
    assert by_severity[Severity.LOW].median_days_to_fix is None


def test_progress_answers_every_severity_highest_first() -> None:
    severities = [row.severity for row in progress([], recent=10).by_severity]
    assert severities == [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


def test_progress_counts_on_time_and_late_across_severities() -> None:
    due = date(2026, 9, 5)
    fixes = [
        _fix(Severity.CRITICAL, 1, due_on=due),
        _fix(Severity.HIGH, 10, due_on=due),
        _fix(Severity.MEDIUM, 10),
    ]
    result = progress(fixes, recent=10)
    assert (result.fixed, result.on_time, result.late) == (3, 1, 1)


def test_progress_names_the_latest_fixes_first() -> None:
    fixes = [_fix(Severity.HIGH, days) for days in (3, 1, 2)]
    recent = progress(fixes, recent=2).recent
    assert [fix.days_to_fix for fix in recent] == [3, 2]
