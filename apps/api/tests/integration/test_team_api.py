"""Invitations and members, against the real database and the real API.

What has to hold (DECISIONS.md section 162):

* An invitation joins the invited address and nobody else -- the address is
  read from the caller's verified token inside ``app.accept_invitation``.
* A link is spent once, and a withdrawn or replaced one joins nobody.
* The invitations table is visible to owners and admins only.
* Only an owner changes an owner, and the last owner stays.
"""

import uuid

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from tests.integration.test_api import auth_header, make_org

pytestmark = pytest.mark.integration

OWNER = uuid.UUID("eeeeeeee-0000-0000-0000-00000000000a")
INVITEE = uuid.UUID("eeeeeeee-0000-0000-0000-00000000000b")
STRANGER = uuid.UUID("eeeeeeee-0000-0000-0000-00000000000c")

OWNER_EMAIL = "owner@example.com"
INVITEE_EMAIL = "invitee@example.com"


def as_(user: uuid.UUID, email: str, org: str | None = None) -> dict[str, str]:
    headers = auth_header(user, email)
    if org:
        headers["X-Organization-Id"] = org
    return headers


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture
async def org(client, cleanup_orgs) -> str:
    org_id = await make_org(client, OWNER, "Team Org")
    cleanup_orgs.append(uuid.UUID(org_id))
    return org_id


async def invite(client, org: str, email: str = INVITEE_EMAIL, role: str = "SECURITY_ANALYST"):
    response = await client.post(
        "/api/v1/invitations",
        json={"email": email, "role": role},
        headers=as_(OWNER, OWNER_EMAIL, org),
    )
    assert response.status_code == 201, response.text
    body = response.json()["data"]
    return body, body["link"].split("#", 1)[1]


async def accept(client, token: str, user: uuid.UUID = INVITEE, email: str = INVITEE_EMAIL):
    return await client.post(
        "/api/v1/invitations/accept", json={"token": token}, headers=as_(user, email)
    )


class TestInvitations:
    async def test_the_invited_address_joins_with_the_invited_role(self, client, org) -> None:
        _, token = await invite(client, org)

        preview = await client.post(
            "/api/v1/invitations/preview",
            json={"token": token},
            headers=as_(INVITEE, INVITEE_EMAIL),
        )
        assert preview.status_code == 200, preview.text
        assert preview.json()["data"]["organization_name"] == "Team Org"
        assert preview.json()["data"]["email_matches"] is True

        accepted = await accept(client, token)
        assert accepted.status_code == 200, accepted.text
        assert accepted.json()["data"]["id"] == org
        assert accepted.json()["data"]["role"] == "SECURITY_ANALYST"

        members = await client.get("/api/v1/members", headers=as_(OWNER, OWNER_EMAIL, org))
        emails = {m["email"]: m["role"] for m in members.json()["data"]}
        assert emails == {OWNER_EMAIL: "OWNER", INVITEE_EMAIL: "SECURITY_ANALYST"}

    async def test_a_forwarded_link_joins_nobody(self, client, org) -> None:
        _, token = await invite(client, org)
        response = await accept(client, token, STRANGER, "stranger@example.com")
        assert response.status_code == 403
        listed = await client.get(
            "/api/v1/organizations", headers=as_(STRANGER, "stranger@example.com")
        )
        assert org not in [row["id"] for row in listed.json()["data"]]

    async def test_a_link_is_spent_once(self, client, org) -> None:
        _, token = await invite(client, org)
        assert (await accept(client, token)).status_code == 200
        assert (await accept(client, token)).status_code == 409

    async def test_inviting_again_replaces_the_old_link(self, client, org) -> None:
        _, old = await invite(client, org)
        _, new = await invite(client, org)
        assert (await accept(client, old)).status_code == 409
        assert (await accept(client, new)).status_code == 200

    async def test_a_withdrawn_invitation_joins_nobody(self, client, org) -> None:
        created, token = await invite(client, org)
        revoked = await client.delete(
            f"/api/v1/invitations/{created['id']}", headers=as_(OWNER, OWNER_EMAIL, org)
        )
        assert revoked.status_code == 200
        assert (await accept(client, token)).status_code == 409

    async def test_only_owners_and_admins_see_invitations(self, client, org) -> None:
        _, token = await invite(client, org, role="VIEWER")
        await accept(client, token)
        response = await client.get(
            "/api/v1/invitations", headers=as_(INVITEE, INVITEE_EMAIL, org)
        )
        assert response.status_code == 403


class TestMembers:
    async def join(self, client, org: str, role: str) -> str:
        _, token = await invite(client, org, role=role)
        await accept(client, token)
        members = await client.get("/api/v1/members", headers=as_(OWNER, OWNER_EMAIL, org))
        return next(m["id"] for m in members.json()["data"] if m["email"] == INVITEE_EMAIL)

    async def test_the_last_owner_cannot_step_down(self, client, org) -> None:
        members = await client.get("/api/v1/members", headers=as_(OWNER, OWNER_EMAIL, org))
        me = next(m for m in members.json()["data"] if m["is_you"])
        response = await client.patch(
            f"/api/v1/members/{me['id']}",
            json={"role": "ADMIN"},
            headers=as_(OWNER, OWNER_EMAIL, org),
        )
        assert response.status_code == 409

    async def test_an_admin_cannot_touch_an_owner(self, client, org) -> None:
        await self.join(client, org, "ADMIN")
        members = await client.get("/api/v1/members", headers=as_(OWNER, OWNER_EMAIL, org))
        owner = next(m for m in members.json()["data"] if m["role"] == "OWNER")
        response = await client.delete(
            f"/api/v1/members/{owner['id']}", headers=as_(INVITEE, INVITEE_EMAIL, org)
        )
        assert response.status_code == 403

    async def test_a_removed_member_loses_the_organization(self, client, org) -> None:
        member_id = await self.join(client, org, "VIEWER")
        removed = await client.delete(
            f"/api/v1/members/{member_id}", headers=as_(OWNER, OWNER_EMAIL, org)
        )
        assert removed.status_code == 200
        listed = await client.get("/api/v1/organizations", headers=as_(INVITEE, INVITEE_EMAIL))
        assert org not in [row["id"] for row in listed.json()["data"]]
