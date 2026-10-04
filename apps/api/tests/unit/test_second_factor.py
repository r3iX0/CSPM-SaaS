"""A session that skipped its user's second factor is refused (DECISIONS.md section 217).

The database answers whether the caller has a verified factor; these tests pin
what the API does with the answer, and that a two-factor session never asks.
The function itself is proven against PostgreSQL in
``tests/integration/test_second_factor.py``.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID, uuid4

import pytest

import app.core.deps as deps
from app.core.errors import SecondFactorRequired
from app.core.security import AuthenticatedUser


class _Result:
    def __init__(self, value: bool) -> None:
        self._value = value

    def scalar_one(self) -> bool:
        return self._value


class _Session:
    """Answers ``app.has_verified_factor()`` and records what it was asked."""

    def __init__(self, *, enrolled: bool) -> None:
        self.enrolled = enrolled
        self.statements: list[str] = []

    async def execute(self, statement: Any) -> _Result:
        self.statements.append(str(statement))
        return _Result(self.enrolled)


def _fake_rls_session(session: _Session):
    @asynccontextmanager
    async def fake(_user_id: UUID, _email: str | None = None) -> AsyncIterator[_Session]:
        yield session

    return fake


async def _open(user: AuthenticatedUser) -> None:
    sessions = deps.get_session(user)
    await sessions.__anext__()
    await sessions.aclose()


async def test_a_one_factor_session_of_an_enrolled_user_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _Session(enrolled=True)
    monkeypatch.setattr(deps, "rls_session", _fake_rls_session(session))
    with pytest.raises(SecondFactorRequired) as refused:
        await _open(AuthenticatedUser(id=uuid4(), second_factor=False))
    assert refused.value.status_code == 403
    assert refused.value.code == "MFA_REQUIRED"


async def test_a_one_factor_session_without_a_factor_is_let_through(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _Session(enrolled=False)
    monkeypatch.setattr(deps, "rls_session", _fake_rls_session(session))
    await _open(AuthenticatedUser(id=uuid4(), second_factor=False))
    assert session.statements == ["SELECT app.has_verified_factor()"]


async def test_a_two_factor_session_is_not_asked(monkeypatch: pytest.MonkeyPatch) -> None:
    session = _Session(enrolled=True)
    monkeypatch.setattr(deps, "rls_session", _fake_rls_session(session))
    await _open(AuthenticatedUser(id=uuid4(), second_factor=True))
    assert session.statements == []
