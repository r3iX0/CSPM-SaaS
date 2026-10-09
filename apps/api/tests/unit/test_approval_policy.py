"""Which acceptances wait for a second approver (DECISIONS.md section 239)."""

import pytest

from app.core.enums import Severity
from app.services.approval_policy import requires


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
