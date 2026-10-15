"""What it means for a scan to end, written down once (DECISIONS.md section 65, 108).

Five writers used to set a scan's terminal state, each with its own field set, and
one of them left the lease behind. The lifecycle module is the only place that
says which fields an ending sets, so these tests read a plain ``Scan`` and need no
database.
"""

import re
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.core.enums import ScanStatus
from app.models.scan import Scan
from app.services.scan_lifecycle import close, terminal_fields

NOW = datetime(2026, 10, 14, 12, 0, tzinfo=UTC)


def _running() -> Scan:
    return Scan(
        id=uuid4(),
        organization_id=uuid4(),
        status=ScanStatus.EVALUATING,
        lease_until=NOW + timedelta(minutes=10),
    )


def test_closing_a_scan_stamps_its_end_and_lets_go_of_the_lease() -> None:
    scan = _running()

    close(scan, ScanStatus.FAILED, message="The worker went away.", now=NOW)

    assert scan.status == ScanStatus.FAILED
    assert scan.completed_at == NOW
    assert scan.lease_until is None
    assert scan.error_message == "The worker went away."


def test_settling_a_scan_again_keeps_when_it_first_ended_and_what_it_said() -> None:
    scan = _running()
    close(scan, ScanStatus.PARTIAL, message="One subscription was not readable.", now=NOW)

    close(scan, ScanStatus.PARTIAL, now=NOW + timedelta(minutes=5))

    assert scan.completed_at == NOW
    assert scan.error_message == "One subscription was not readable."


def test_ending_a_scan_in_a_different_status_dates_the_new_ending() -> None:
    scan = _running()
    close(scan, ScanStatus.FAILED, message="Abandoned.", now=NOW)

    close(scan, ScanStatus.COMPLETED, now=NOW + timedelta(minutes=5))

    assert scan.status == ScanStatus.COMPLETED
    assert scan.completed_at == NOW + timedelta(minutes=5)


def test_a_scan_cannot_be_closed_in_a_status_that_is_still_running() -> None:
    scan = _running()

    with pytest.raises(ValueError, match=re.escape("'EVALUATING' is not an ending")):
        close(scan, ScanStatus.EVALUATING, now=NOW)

    assert scan.completed_at is None
    assert scan.lease_until == NOW + timedelta(minutes=10)


@pytest.mark.parametrize("late", [ScanStatus.COMPLETED, ScanStatus.PARTIAL, ScanStatus.FAILED])
def test_a_cancelled_scan_stays_cancelled_when_a_worker_finishes_late(late: ScanStatus) -> None:
    scan = _running()
    close(scan, ScanStatus.CANCELLED, message="Cancelled.", now=NOW)

    close(scan, late, message="Something else.", now=NOW + timedelta(minutes=5))

    assert scan.status == ScanStatus.CANCELLED
    assert scan.completed_at == NOW
    assert scan.error_message == "Cancelled."


def test_the_fields_of_an_ending_are_available_for_an_update_statement() -> None:
    fields = terminal_fields(ScanStatus.FAILED, "The broker refused it.", now=NOW)

    assert fields == {
        "status": ScanStatus.FAILED,
        "completed_at": NOW,
        "lease_until": None,
        "error_message": "The broker refused it.",
    }


def test_an_ending_with_nothing_to_say_leaves_the_message_column_out() -> None:
    fields = terminal_fields(ScanStatus.COMPLETED, now=NOW)

    assert fields == {
        "status": ScanStatus.COMPLETED,
        "completed_at": NOW,
        "lease_until": None,
    }


def test_a_long_message_is_cut_to_two_thousand_characters() -> None:
    scan = _running()

    close(scan, ScanStatus.FAILED, message="x" * 5000, now=NOW)

    assert scan.error_message == "x" * 2000
