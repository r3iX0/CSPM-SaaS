"""Guests, against the real database and the real API (DECISIONS.md section 219).

A guest is Supabase's anonymous user: a real token with no email and ``is_anonymous``. What
has to hold:

* A guest joins the demo and reads it like any visitor.
* A guest cannot become a member of anything else -- refused by the API on the routes that act
  on the person, and by the database whatever path the membership row takes.
* Stale guests are forgotten with what they left behind; a fresh guest and every account stay.
"""

import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import jwt
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.core.config import settings
from app.core.db import rls_session, service_session
from app.main import app
from app.services import guests as guests_service
from tests.integration.test_demo_organization import demo_org  # noqa: F401 -- a fixture

pytestmark = pytest.mark.integration

GUEST = uuid.UUID("dddddddd-0000-0000-0000-0000000000c1")
FRESH_GUEST = uuid.UUID("dddddddd-0000-0000-0000-0000000000c2")
OLD_ACCOUNT = uuid.UUID("dddddddd-0000-0000-0000-0000000000c3")


def guest_header(user_id: uuid.UUID) -> dict[str, str]:
    """A token in the shape Supabase issues for an anonymous sign-in: no email."""
    now = datetime.now(UTC)
    token = jwt.encode(
        {
            "sub": str(user_id),
            "aud": settings.jwt_audience,
            "role": "authenticated",
            "is_anonymous": True,
            "iat": now,
            "exp": now + timedelta(hours=1),
        },
        settings.supabase_jwt_secret,
        algorithm="HS256",
    )
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
async def client() -> AsyncIterator[AsyncClient]:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def users() -> AsyncIterator[None]:
    """Supabase's records for a guest from long ago, a guest from today and an old account."""
    old = datetime.now(UTC) - timedelta(days=settings.guest_retention_days + 10)
    async with service_session() as session:
        await session.execute(
            text(
                "INSERT INTO auth.users (id, is_anonymous, created_at) VALUES "
                "(:guest, true, :old), (:fresh, true, now()), (:account, false, :old)"
            ),
            {"guest": GUEST, "fresh": FRESH_GUEST, "account": OLD_ACCOUNT, "old": old},
        )
        await session.commit()
    yield
    async with service_session() as session:
        ids = {"a": GUEST, "b": FRESH_GUEST, "c": OLD_ACCOUNT}
        await session.execute(text("DELETE FROM auth.users WHERE id IN (:a, :b, :c)"), ids)
        await session.execute(
            text("DELETE FROM organization_members WHERE user_id IN (:a, :b, :c)"), ids
        )
        await session.commit()


class TestGuestInTheDemo:
    async def test_a_guest_joins_the_demo_and_reads_it(self, client, demo_org) -> None:  # noqa: F811
        joined = await client.post("/api/v1/organizations/demo/join", headers=guest_header(GUEST))
        assert joined.status_code == 200, joined.text
        assert joined.json()["data"]["id"] == str(demo_org)

        listed = await client.get("/api/v1/organizations", headers=guest_header(GUEST))
        assert [org["id"] for org in listed.json()["data"]] == [str(demo_org)]


class TestGuestOwnsNothing:
    async def test_the_api_refuses_a_guest_an_organization(self, client) -> None:
        response = await client.post(
            "/api/v1/organizations", json={"name": "Mine"}, headers=guest_header(GUEST)
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "ACCOUNT_REQUIRED"

    async def test_the_api_refuses_a_guest_an_invitation(self, client) -> None:
        response = await client.post(
            "/api/v1/invitations/accept", json={"token": "x" * 43}, headers=guest_header(GUEST)
        )
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "ACCOUNT_REQUIRED"

    async def test_the_database_refuses_a_guest_a_membership_outside_the_demo(self) -> None:
        # Straight at the function, past every route: the trigger is what refuses.
        with pytest.raises(DBAPIError, match="a guest can only join the demo"):
            async with rls_session(GUEST, guest=True) as session:
                await session.execute(
                    text("SELECT app.create_organization('Mine', :slug, NULL, NULL)"),
                    {"slug": f"mine-{uuid.uuid4().hex[:6]}"},
                )

    async def test_the_database_lets_a_guest_into_the_demo(self, demo_org) -> None:  # noqa: F811
        async with rls_session(GUEST, guest=True) as session:
            joined = (
                await session.execute(text("SELECT app.join_demo_organization()"))
            ).scalar_one()
        assert joined == demo_org


@pytest.mark.usefixtures("users")
class TestForgettingGuests:
    async def test_a_stale_guest_is_forgotten_with_its_membership(self, demo_org) -> None:  # noqa: F811
        for user in (GUEST, FRESH_GUEST):
            async with rls_session(user, guest=True) as session:
                await session.execute(text("SELECT app.join_demo_organization()"))

        before = datetime.now(UTC) - timedelta(days=settings.guest_retention_days)
        async with service_session() as session:
            forgotten = await guests_service.forget_stale(session, before)
            await session.commit()
            remaining = set(
                (
                    await session.execute(
                        text("SELECT id FROM auth.users WHERE id IN (:a, :b, :c)"),
                        {"a": GUEST, "b": FRESH_GUEST, "c": OLD_ACCOUNT},
                    )
                ).scalars()
            )
            members = set(
                (
                    await session.execute(
                        text("SELECT user_id FROM organization_members WHERE organization_id = :o"),
                        {"o": demo_org},
                    )
                ).scalars()
            )

        assert forgotten == 1
        assert remaining == {FRESH_GUEST, OLD_ACCOUNT}
        assert GUEST not in members
        assert FRESH_GUEST in members
