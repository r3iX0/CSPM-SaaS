"""The audit trail against the real database (DECISIONS.md section 163).

* Nobody can edit or delete an entry through the application's role, whatever
  their own role -- the database refuses it, not the API.
* A change made through the API is on the trail, with who made it.
* Only owners and admins read it.
"""

import uuid

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.core.db import rls_session
from app.main import app
from tests.integration.test_api import auth_header, make_org

pytestmark = pytest.mark.integration

OWNER = uuid.UUID("ffffffff-0000-0000-0000-00000000000a")
INVITEE = uuid.UUID("ffffffff-0000-0000-0000-00000000000b")


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture
async def org(client, cleanup_orgs) -> str:
    org_id = await make_org(client, OWNER, "Audit Org")
    cleanup_orgs.append(uuid.UUID(org_id))
    return org_id


def owner(org: str) -> dict[str, str]:
    return {**auth_header(OWNER, "owner@example.com"), "X-Organization-Id": org}


async def test_a_change_is_on_the_trail_with_who_made_it(client, org) -> None:
    await client.patch("/api/v1/organizations", json={"name": "Audit Org 2"}, headers=owner(org))
    response = await client.get("/api/v1/audit-log?action=organization.", headers=owner(org))
    assert response.status_code == 200, response.text
    (entry,) = response.json()["data"]
    assert entry["action"] == "organization.updated"
    assert entry["actor_email"] == "owner@example.com"
    assert entry["details"] == {"changed": {"name": "Audit Org 2"}}
    assert entry["request_id"]


@pytest.mark.parametrize(
    "statement", ["UPDATE audit_logs SET action = 'x'", "DELETE FROM audit_logs"]
)
async def test_nobody_rewrites_the_trail(client, org, statement: str) -> None:
    await client.patch("/api/v1/organizations", json={"name": "Renamed"}, headers=owner(org))
    # As the organization's own owner, the most privileged member there is.
    with pytest.raises(DBAPIError, match="permission denied"):
        async with rls_session(OWNER) as session:
            await session.execute(
                text(f"{statement} WHERE organization_id = :org"), {"org": org}
            )


async def test_only_owners_and_admins_read_it(client, org) -> None:
    invited = await client.post(
        "/api/v1/invitations",
        json={"email": "viewer@example.com", "role": "VIEWER"},
        headers=owner(org),
    )
    token = invited.json()["data"]["link"].split("#", 1)[1]
    viewer = auth_header(INVITEE, "viewer@example.com")
    await client.post("/api/v1/invitations/accept", json={"token": token}, headers=viewer)

    response = await client.get(
        "/api/v1/audit-log", headers={**viewer, "X-Organization-Id": org}
    )
    assert response.status_code == 403
