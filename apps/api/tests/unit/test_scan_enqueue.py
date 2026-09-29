"""A scan the broker refuses is marked FAILED, not left queued (DECISIONS.md section 158).

The scan row is committed before its message is sent, on the request's
``rls_session`` -- whose transaction cannot begin again after that commit. The
failure path used to commit a second time on it, which raised, answered 500 and
left the scan queued for ever: the one outcome the path existed to prevent.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy.dialects import postgresql

from app.core.enums import ScanStatus
from app.models.scan import Scan
from app.services import scans as service


class _Opened:
    """Every ``rls_session`` the helper opens, and what ran on it."""

    def __init__(self) -> None:
        self.users: list[UUID] = []
        self.statements: list[Any] = []

    def __call__(self, user_id: UUID) -> Any:
        @asynccontextmanager
        async def session() -> AsyncIterator[Any]:
            self.users.append(user_id)
            opened = self

            class _Session:
                async def execute(self, statement: Any) -> None:
                    opened.statements.append(statement)

            yield _Session()

        return session()


@pytest.fixture
def opened(monkeypatch: pytest.MonkeyPatch) -> _Opened:
    recorder = _Opened()
    monkeypatch.setattr(service, "rls_session", recorder)
    return recorder


def _scan() -> Scan:
    return Scan(id=uuid4(), organization_id=uuid4(), status=ScanStatus.QUEUED)


async def test_a_queued_scan_touches_nothing_else(opened: _Opened) -> None:
    sent: list[str] = []
    scan = _scan()

    await service.enqueue_or_fail(sent.append, scan, uuid4())

    assert sent == [str(scan.id)]
    assert opened.users == []
    assert scan.status == ScanStatus.QUEUED


async def test_a_refused_scan_is_failed_in_a_session_of_its_own(opened: _Opened) -> None:
    def refuse(_: str) -> None:
        raise ConnectionError("amqp://user:secret@broker:5672 refused")

    scan = _scan()
    user = uuid4()

    await service.enqueue_or_fail(refuse, scan, user, noun="replay")

    # A fresh row-level-secured session for the same user, never the caller's.
    assert opened.users == [user]
    [statement] = opened.statements
    compiled = statement.compile(dialect=postgresql.dialect())
    assert str(compiled).startswith("UPDATE scans SET")
    assert scan.organization_id in compiled.params.values()
    assert scan.id in compiled.params.values()

    assert scan.status == ScanStatus.FAILED
    assert scan.error_message == service.ENQUEUE_FAILED_MESSAGE.format(noun="replay")
    # The broker's own words are for the log, not the scans page.
    assert "secret" not in scan.error_message
