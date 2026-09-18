"""The shared demo organization, against the real database and the real API.

What has to hold, and why each one matters:

* Anybody signed in can join, and only ever as VIEWER -- the role is fixed in
  ``app.join_demo_organization``, not taken from the caller.
* Visitors cannot see one another. Everybody who ever explored the demo is a
  member of it, and the ordinary rule -- members see the membership list -- would
  hand each of them everyone else's user id.
* Nothing in the demo can be written, whatever the role.
* Somebody with an organization of their own lands in it, not in the demo.
"""

import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from app.core.db import rls_session, service_session
from app.main import app
from tests.integration.conftest import create_org_as
from tests.integration.test_api import auth_header

pytestmark = pytest.mark.integration

VISITOR_A = uuid.UUID("dddddddd-0000-0000-0000-00000000000a")
VISITOR_B = uuid.UUID("dddddddd-0000-0000-0000-00000000000b")


@pytest.fixture
async def demo_org(cleanup_orgs) -> uuid.UUID:
    async with service_session() as session:
        org_id = (
            await session.execute(
                text(
                    "INSERT INTO organizations (name, slug, is_demo) "
                    "VALUES ('CloudGuard demo', :slug, true) RETURNING id"
                ),
                {"slug": f"demo-{uuid.uuid4().hex[:6]}"},
            )
        ).scalar_one()
        await session.commit()
    cleanup_orgs.append(org_id)
    return org_id


async def join(user_id: uuid.UUID) -> uuid.UUID:
    async with rls_session(user_id) as session:
        return (
            await session.execute(text("SELECT app.join_demo_organization()"))
        ).scalar_one()


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


class TestJoining:
    async def test_a_visitor_joins_as_a_viewer(self, demo_org) -> None:
        assert await join(VISITOR_A) == demo_org
        async with rls_session(VISITOR_A) as session:
            role = (
                await session.execute(
                    text(
                        "SELECT role FROM organization_members "
                        "WHERE organization_id = :o AND user_id = :u"
                    ),
                    {"o": demo_org, "u": VISITOR_A},
                )
            ).scalar_one()
        assert role == "VIEWER"

    async def test_joining_twice_is_a_second_click_not_an_error(self, demo_org) -> None:
        await join(VISITOR_A)
        assert await join(VISITOR_A) == demo_org

    async def test_visitors_cannot_see_each_other(self, demo_org) -> None:
        await join(VISITOR_A)
        await join(VISITOR_B)
        async with rls_session(VISITOR_A) as session:
            visible = (
                await session.execute(
                    text("SELECT user_id FROM organization_members WHERE organization_id = :o"),
                    {"o": demo_org},
                )
            ).scalars().all()
        assert visible == [VISITOR_A]

    async def test_an_ordinary_organization_still_shows_its_members(self, cleanup_orgs) -> None:
        org = await create_org_as(VISITOR_A, "Visitor A Org")
        cleanup_orgs.append(org)
        async with service_session() as session:
            await session.execute(
                text(
                    "INSERT INTO organization_members (organization_id, user_id, role) "
                    "VALUES (:o, :u, 'VIEWER')"
                ),
                {"o": org, "u": VISITOR_B},
            )
            await session.commit()
        async with rls_session(VISITOR_A) as session:
            visible = set(
                (
                    await session.execute(
                        text(
                            "SELECT user_id FROM organization_members "
                            "WHERE organization_id = :o"
                        ),
                        {"o": org},
                    )
                ).scalars()
            )
        assert visible == {VISITOR_A, VISITOR_B}

    async def test_leaving_removes_only_the_callers_own_membership(self, demo_org) -> None:
        await join(VISITOR_A)
        await join(VISITOR_B)
        async with rls_session(VISITOR_A) as session:
            await session.execute(text("SELECT app.leave_demo_organization()"))
        async with service_session() as session:
            remaining = (
                await session.execute(
                    text("SELECT user_id FROM organization_members WHERE organization_id = :o"),
                    {"o": demo_org},
                )
            ).scalars().all()
        assert remaining == [VISITOR_B]


class TestThroughTheApi:
    async def test_join_endpoint_answers_with_the_demo(self, client, demo_org) -> None:
        response = await client.post(
            "/api/v1/organizations/demo/join", headers=auth_header(VISITOR_A)
        )
        assert response.status_code == 200, response.text
        body = response.json()["data"]
        assert body["id"] == str(demo_org)
        assert body["is_demo"] is True
        assert body["role"] == "VIEWER"

    async def test_nothing_in_the_demo_can_be_written(self, client, demo_org) -> None:
        await join(VISITOR_A)
        response = await client.patch(
            "/api/v1/organizations",
            json={"name": "Renamed"},
            headers={**auth_header(VISITOR_A), "X-Organization-Id": str(demo_org)},
        )
        assert response.status_code == 403
        assert "demo organization is read-only" in response.json()["error"]["message"]

    async def test_an_own_organization_wins_over_the_demo(
        self, client, demo_org, cleanup_orgs
    ) -> None:
        # Joined the demo first, created their own after. With no header the
        # request must act in their own organization -- an OWNER renaming it
        # succeeds, where the demo would have refused.
        await join(VISITOR_B)
        own = await create_org_as(VISITOR_B, "Visitor B Org")
        cleanup_orgs.append(own)

        listed = await client.get("/api/v1/organizations", headers=auth_header(VISITOR_B))
        ids = [row["id"] for row in listed.json()["data"]]
        assert ids[0] == str(own)
        assert str(demo_org) in ids

        renamed = await client.patch(
            "/api/v1/organizations", json={"name": "Visitor B Renamed"},
            headers=auth_header(VISITOR_B),
        )
        assert renamed.status_code == 200, renamed.text
        assert renamed.json()["data"]["id"] == str(own)
