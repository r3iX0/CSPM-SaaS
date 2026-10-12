"""The weekly digest and the overdue escalation say what they should, once (DECISIONS.md 237)."""

import uuid
from datetime import UTC, date, datetime, timedelta

import pytest

from app.core.enums import NotificationKind, Severity
from app.services import notifications
from app.services import work_digest as service
from app.services.work_digest import Work

MONDAY = date(2026, 10, 12)
ANA = uuid.UUID("00000000-0000-0000-0000-00000000000a")
BEN = uuid.UUID("00000000-0000-0000-0000-00000000000b")
NAMES = {ANA: "ana@example.com", BEN: "ben@example.com"}


def work(
    *,
    due_on: date | None,
    owner_id: uuid.UUID | None = ANA,
    severity: Severity = Severity.HIGH,
    title: str = "Storage allows public access",
    asset: str | None = "stacct1",
    tracked: bool = True,
) -> Work:
    return Work(
        finding_id=uuid.uuid4(),
        title=title,
        asset=asset,
        severity=severity,
        due_on=due_on,
        owner_id=owner_id,
        tracked=tracked,
    )


# ------------------------------------------------------------------ the hour


def test_slot_is_the_sending_hour_only() -> None:
    assert service.slot(datetime(2026, 10, 12, 7, 35, tzinfo=UTC)) == datetime(
        2026, 10, 12, 7, tzinfo=UTC
    )
    assert service.slot(datetime(2026, 10, 12, 6, 59, tzinfo=UTC)) is None
    assert service.slot(datetime(2026, 10, 12, 8, 0, tzinfo=UTC)) is None


# ------------------------------------------------------------------ digest


def test_digest_counts_overdue_due_this_week_and_fixed() -> None:
    items = [
        work(due_on=MONDAY - timedelta(days=3)),
        work(due_on=MONDAY - timedelta(days=1), owner_id=BEN),
        work(due_on=MONDAY),
        work(due_on=MONDAY + timedelta(days=6)),
        work(due_on=MONDAY + timedelta(days=7)),
        work(due_on=None),
    ]
    said = service.digest(items, 4, MONDAY, NAMES, solo=False)
    assert said is not None
    assert said.title == "This week: 2 overdue, 2 due this week, 4 fixed last week"
    assert "Overdue by owner: ana@example.com 1, ben@example.com 1." in (said.detail or "")
    assert "Due this week by owner: ana@example.com 2." in (said.detail or "")


def test_digest_says_nothing_when_there_is_nothing() -> None:
    assert service.digest([work(due_on=None)], 0, MONDAY, NAMES, solo=False) is None


def test_digest_with_only_fixes_says_nothing_is_overdue() -> None:
    said = service.digest([], 3, MONDAY, NAMES, solo=False)
    assert said is not None
    assert said.title == "This week: nothing overdue, 3 fixed last week"
    assert said.detail is None


def test_solo_digest_names_no_owner() -> None:
    said = service.digest([work(due_on=MONDAY - timedelta(days=1))], 0, MONDAY, NAMES, solo=True)
    assert said is not None
    assert "owner" not in (said.detail or "")


def test_untracked_overdue_work_is_counted_and_said_apart() -> None:
    items = [work(due_on=MONDAY - timedelta(days=2), tracked=False, owner_id=None)]
    said = service.digest(items, 0, MONDAY, NAMES, solo=False)
    assert said is not None
    assert said.title == "This week: 1 overdue"
    assert "nobody 1" in (said.detail or "")
    assert "1 of the overdue is not tracked yet." in (said.detail or "")


def test_a_member_with_no_address_is_named_by_id() -> None:
    stranger = uuid.UUID("12345678-0000-0000-0000-000000000000")
    said = service.digest(
        [work(due_on=MONDAY - timedelta(days=1), owner_id=stranger)], 0, MONDAY, NAMES, solo=False
    )
    assert said is not None
    assert "member 12345678 1" in (said.detail or "")


def test_owners_past_the_named_few_are_counted() -> None:
    owners = [uuid.uuid4() for _ in range(service.NAMED + 2)]
    items = [work(due_on=MONDAY - timedelta(days=1), owner_id=owner) for owner in owners]
    said = service.digest(items, 0, MONDAY, {}, solo=False)
    assert said is not None
    assert "2 more." in (said.detail or "")


# ------------------------------------------------------------------ escalation


def test_escalation_names_only_what_lapsed_yesterday_worst_first() -> None:
    yesterday = MONDAY - timedelta(days=1)
    items = [
        work(due_on=yesterday, severity=Severity.MEDIUM, title="B"),
        work(due_on=yesterday, severity=Severity.CRITICAL, title="A", owner_id=BEN),
        work(due_on=MONDAY - timedelta(days=5), title="Long overdue"),
        work(due_on=MONDAY, title="Due today"),
    ]
    said = service.overdue(items, MONDAY, NAMES, solo=False)
    assert said is not None
    assert said.title == "2 fixes went overdue today"
    assert said.detail == (
        "Critical: A on stacct1, ben@example.com. Medium: B on stacct1, ana@example.com."
    )


def test_one_lapsed_fix_is_named_in_the_title() -> None:
    said = service.overdue(
        [work(due_on=MONDAY - timedelta(days=1), asset=None)], MONDAY, NAMES, solo=True
    )
    assert said is not None
    assert said.title == "Overdue: Storage allows public access"
    assert said.detail == "High: Storage allows public access."


def test_no_escalation_when_nothing_lapsed() -> None:
    items = [work(due_on=MONDAY - timedelta(days=4)), work(due_on=None)]
    assert service.overdue(items, MONDAY, NAMES, solo=False) is None


def test_escalation_lists_a_few_and_counts_the_rest() -> None:
    items = [work(due_on=MONDAY - timedelta(days=1)) for _ in range(service.NAMED + 3)]
    said = service.overdue(items, MONDAY, NAMES, solo=False)
    assert said is not None
    assert (said.detail or "").endswith("And 3 more.")


# ------------------------------------------------------------------ derive


class _Result:
    def __init__(self, row: object | None) -> None:
        self._row = row

    def first(self) -> object | None:
        return self._row


class _Session:
    def __init__(self, *, said: bool) -> None:
        self.said = said

    async def execute(self, statement: object) -> _Result:
        return _Result(object() if self.said else None)

    async def get(self, model: object, key: object) -> None:
        raise AssertionError("nothing is read once both are written")


async def test_derive_does_nothing_outside_the_hour() -> None:
    session = _Session(said=False)
    at_noon = datetime(2026, 10, 12, 12, tzinfo=UTC)
    assert await service.derive(session, uuid.uuid4(), at_noon) == 0  # type: ignore[arg-type]


async def test_derive_reads_nothing_once_both_are_written() -> None:
    session = _Session(said=True)
    in_the_hour = datetime(2026, 10, 12, 7, 10, tzinfo=UTC)
    assert await service.derive(session, uuid.uuid4(), in_the_hour) == 0  # type: ignore[arg-type]


@pytest.mark.parametrize("kind", [NotificationKind.WORK_DIGEST, NotificationKind.WORK_OVERDUE])
def test_clock_kinds_never_move_the_event_watermark(kind: NotificationKind) -> None:
    assert kind not in notifications.EVENT_KINDS
