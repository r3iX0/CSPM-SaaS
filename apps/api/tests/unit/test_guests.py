"""A guest reads the demo and nothing else (DECISIONS.md section 219).

The parts that need no database: the account check on routes that act on the person, and
``get_tenant`` keeping a guest's view to the demo whatever memberships come back.
"""

from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from starlette.requests import Request

from app.core import deps
from app.core.errors import AccountRequired, OrganizationNotFound
from app.core.security import AuthenticatedUser

GUEST = AuthenticatedUser(id=uuid4(), guest=True)
ACCOUNT = AuthenticatedUser(id=uuid4(), email="person@example.com")


class _Result:
    def __init__(self, rows: list[tuple[Any, bool]]) -> None:
        self._rows = rows

    def all(self) -> list[tuple[Any, bool]]:
        return self._rows


class _Session:
    """Answers the membership query with the rows it was given, and nothing else."""

    def __init__(self, rows: list[tuple[Any, bool]]) -> None:
        self._rows = rows

    async def execute(self, *_: Any, **__: Any) -> _Result:
        return _Result(self._rows)


def _membership(role: str = "VIEWER") -> SimpleNamespace:
    return SimpleNamespace(organization_id=uuid4(), role=role, email=None)


def _request(organization_id: str | None = None) -> Request:
    query = f"organization_id={organization_id}".encode() if organization_id else b""
    return Request({"type": "http", "query_string": query, "headers": []})


class TestAccountRequired:
    async def test_a_guest_is_refused(self) -> None:
        with pytest.raises(AccountRequired):
            await deps.get_account_user(GUEST)

    async def test_an_account_passes(self) -> None:
        assert await deps.get_account_user(ACCOUNT) is ACCOUNT


class TestGuestTenant:
    async def test_a_guest_lands_in_the_demo(self) -> None:
        demo = _membership()
        tenant = await deps.get_tenant(_request(), GUEST, _Session([(demo, True)]))
        assert tenant.organization_id == demo.organization_id
        assert tenant.is_demo is True

    async def test_a_membership_outside_the_demo_opens_nothing_for_a_guest(self) -> None:
        # Nothing should ever give a guest this row; if something did, it is ignored.
        own, demo = _membership("OWNER"), _membership()
        session = _Session([(own, False), (demo, True)])
        tenant = await deps.get_tenant(_request(), GUEST, session)
        assert tenant.organization_id == demo.organization_id

    async def test_a_guest_cannot_ask_for_the_other_organization(self) -> None:
        own, demo = _membership("OWNER"), _membership()
        session = _Session([(own, False), (demo, True)])
        with pytest.raises(OrganizationNotFound):
            await deps.get_tenant(_request(str(own.organization_id)), GUEST, session)

    async def test_a_guest_who_never_joined_has_no_organization(self) -> None:
        own = _membership("OWNER")
        with pytest.raises(OrganizationNotFound):
            await deps.get_tenant(_request(), GUEST, _Session([(own, False)]))

    async def test_an_account_keeps_its_own_organization_first(self) -> None:
        own, demo = _membership("OWNER"), _membership()
        session = _Session([(own, False), (demo, True)])
        tenant = await deps.get_tenant(_request(), ACCOUNT, session)
        assert tenant.organization_id == own.organization_id
