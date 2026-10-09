"""Which acceptances wait for a second approver (DECISIONS.md section 239)."""

import pytest

from app.core.enums import Level, Severity
from app.services.approval_policy import highest, requires


def test_no_policy_never_waits() -> None:
    assert not requires(None, Severity.CRITICAL)


@pytest.mark.parametrize(
    ("severity", "waits"),
    [
        (Severity.CRITICAL, True),
        (Severity.HIGH, True),
        (Severity.MEDIUM, False),
        (Severity.LOW, False),
    ],
)
def test_a_policy_covers_its_severity_and_every_one_above(severity: Severity, waits: bool) -> None:
    assert requires(Severity.HIGH, severity) is waits


def test_a_routes_severity_is_read_from_its_string() -> None:
    assert requires(Severity.HIGH, "CRITICAL")
    assert not requires(Severity.HIGH, "LOW")


def test_an_unreadable_severity_is_never_the_way_round_the_policy() -> None:
    assert requires(Severity.CRITICAL, "SEVERE")


def test_a_finding_is_judged_at_the_highest_level_it_is_shown_at() -> None:
    """A Medium rule on a row the queue scores High waits under a High policy."""
    level = highest([Severity.MEDIUM, Level.HIGH])
    assert level is Severity.HIGH
    assert requires(Severity.HIGH, level)


def test_an_unscored_risk_does_not_lower_or_raise_a_finding() -> None:
    assert highest([Severity.MEDIUM, Level.UNKNOWN]) is Severity.MEDIUM
    assert highest([Level.UNKNOWN]) is None
