"""An acceptance the policy covers waits for a second person (DECISIONS.md section 239).

Against real SQL and policies, because the guarantee is partly the database's: the four-eyes
check is a constraint, not only a branch in a service, and the tests say so by trying to go
round the service.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.core.db import service_session
from app.core.enums import FindingStatus
from app.main import app

# Imported as a module: a Test class imported by name is collected here too.
from tests.integration import test_api
from tests.integration.test_api import auth_header, make_org

pytestmark = pytest.mark.integration


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def add_member(org_id: uuid.UUID, user_id: uuid.UUID, role: str) -> None:
    async with service_session() as session:
        await session.execute(
            text(
                "INSERT INTO organization_members (organization_id, user_id, role) "
                "VALUES (:org, :user, :role)"
            ),
            {"org": org_id, "user": user_id, "role": role},
        )
        await session.commit()


@pytest.fixture
async def team(client, cleanup_orgs):
    """An analyst who asks, an admin who decides, and a policy covering High and above.

    The owner sets the policy and is otherwise left out: an owner's or admin's own acceptance
    is made at once, so only an analyst's waits.
    """
    owner, admin, analyst = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    org_id = uuid.UUID(await make_org(client, owner, "Four Eyes Ltd"))
    cleanup_orgs.append(org_id)
    await add_member(org_id, admin, "ADMIN")
    await add_member(org_id, analyst, "SECURITY_ANALYST")
    response = await client.patch(
        "/api/v1/organizations",
        json={"acceptance_approval_from": "HIGH"},
        headers=auth_header(owner),
    )
    assert response.status_code == 200, response.text
    assert response.json()["data"]["acceptance_approval_from"] == "HIGH"
    return org_id, analyst, admin, owner


async def accept(client, user, finding_id) -> dict:
    response = await client.post(
        f"/api/v1/findings/{finding_id}/accept-risk",
        json={
            "reason": "Behind the VPN until the rebuild",
            "expires_at": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        },
        headers=auth_header(user),
    )
    assert response.status_code == 200, response.text
    return response.json()["data"]


async def waiting(client, user) -> list[dict]:
    response = await client.get("/api/v1/acceptances", headers=auth_header(user))
    assert response.status_code == 200, response.text
    return response.json()["data"]


async def finding(client, user, finding_id) -> dict:
    response = await client.get(f"/api/v1/findings/{finding_id}", headers=auth_header(user))
    assert response.status_code == 200, response.text
    return response.json()["data"]


async def test_an_acceptance_the_policy_covers_changes_nothing_until_approved(client, team) -> None:
    org_id, analyst, admin, _ = team
    _, (finding_id,), _ = await test_api.TestRiskTriage()._seed(
        org_id, members=[FindingStatus.OPEN]
    )

    assert (await accept(client, analyst, finding_id))["status"] == "OPEN"
    pending = (await finding(client, analyst, finding_id))["pending_acceptance"]
    assert pending["reason"] == "Behind the VPN until the rebuild"
    (request,) = await waiting(client, admin)
    assert request["requested_by"] == str(analyst)

    approved = await client.post(
        f"/api/v1/acceptances/{request['id']}/approve", headers=auth_header(admin)
    )

    assert approved.status_code == 200, approved.text
    assert approved.json()["data"]["status"] == "ACTIVE"
    assert approved.json()["data"]["decided_by"] == str(admin)
    after = await finding(client, analyst, finding_id)
    assert after["status"] == "ACCEPTED_RISK"
    assert after["pending_acceptance"] is None
    assert await waiting(client, admin) == []


async def test_the_person_who_asked_cannot_approve_it(client, team) -> None:
    org_id, analyst, _, _ = team
    _, (finding_id,), _ = await test_api.TestRiskTriage()._seed(
        org_id, members=[FindingStatus.OPEN]
    )
    await accept(client, analyst, finding_id)
    (request,) = await waiting(client, analyst)

    response = await client.post(
        f"/api/v1/acceptances/{request['id']}/approve", headers=auth_header(analyst)
    )

    assert response.status_code == 403


async def test_the_database_refuses_a_self_approval_the_service_did_not_stop(client, team) -> None:
    org_id, analyst, _, _ = team
    _, (finding_id,), _ = await test_api.TestRiskTriage()._seed(
        org_id, members=[FindingStatus.OPEN]
    )
    await accept(client, analyst, finding_id)
    (request,) = await waiting(client, analyst)

    with pytest.raises(IntegrityError):
        async with service_session() as session:
            await session.execute(
                text(
                    "UPDATE exceptions SET status = 'ACTIVE', approved_by = :user, "
                    "decided_by = :user WHERE id = :id"
                ),
                {"user": analyst, "id": request["id"]},
            )
            await session.commit()


async def test_a_rejection_says_why_and_leaves_the_finding_open(client, team) -> None:
    org_id, analyst, admin, _ = team
    _, (finding_id,), _ = await test_api.TestRiskTriage()._seed(
        org_id, members=[FindingStatus.OPEN]
    )
    await accept(client, analyst, finding_id)
    (request,) = await waiting(client, admin)

    no_note = await client.post(
        f"/api/v1/acceptances/{request['id']}/reject", json={}, headers=auth_header(admin)
    )
    rejected = await client.post(
        f"/api/v1/acceptances/{request['id']}/reject",
        json={"note": "Not without a compensating control"},
        headers=auth_header(admin),
    )
    again = await client.post(
        f"/api/v1/acceptances/{request['id']}/approve", headers=auth_header(admin)
    )

    assert no_note.status_code == 422
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["data"]["decision_note"] == "Not without a compensating control"
    assert again.status_code == 409
    assert (await finding(client, analyst, finding_id))["status"] == "OPEN"


async def test_a_route_waits_as_its_findings_do(client, team) -> None:
    org_id, analyst, admin, _ = team
    _, _, route_id = await test_api.TestRiskTriage()._seed(
        org_id, members=[FindingStatus.OPEN], route=True
    )

    response = await client.post(
        f"/api/v1/risks/{route_id}/status",
        json={"status": "ACCEPTED", "reason": "By design: the bastion"},
        headers=auth_header(analyst),
    )
    assert response.status_code == 200, response.text
    assert response.json()["data"]["status"] != "ACCEPTED"
    (request,) = await waiting(client, admin)
    assert request["risk_id"] == str(route_id)

    approved = await client.post(
        f"/api/v1/acceptances/{request['id']}/approve", headers=auth_header(admin)
    )

    assert approved.status_code == 200, approved.text
    route = await client.get(f"/api/v1/risks/{route_id}", headers=auth_header(analyst))
    assert route.json()["data"]["status"] == "ACCEPTED"


async def test_below_the_threshold_an_acceptance_is_made_at_once(client, team) -> None:
    org_id, analyst, _, owner = team
    await client.patch(
        "/api/v1/organizations",
        json={"acceptance_approval_from": "CRITICAL"},
        headers=auth_header(owner),
    )
    _, (finding_id,), _ = await test_api.TestRiskTriage()._seed(
        org_id, members=[FindingStatus.OPEN]
    )

    assert (await accept(client, analyst, finding_id))["status"] == "ACCEPTED_RISK"


@pytest.mark.parametrize("decider", ["owner", "admin"])
async def test_an_owner_or_admin_accepts_at_once(client, team, decider) -> None:
    org_id, _, admin, owner = team
    person = owner if decider == "owner" else admin
    _, (finding_id,), route_id = await test_api.TestRiskTriage()._seed(
        org_id, members=[FindingStatus.OPEN], route=True
    )

    accepted = await accept(client, person, finding_id)
    route = await client.post(
        f"/api/v1/risks/{route_id}/status",
        json={"status": "ACCEPTED", "reason": "By design: the bastion"},
        headers=auth_header(person),
    )

    assert accepted["status"] == "ACCEPTED_RISK"
    assert route.status_code == 200, route.text
    assert route.json()["data"]["status"] == "ACCEPTED"
    assert await waiting(client, person) == []


async def test_an_admin_accepting_answers_the_request_waiting_on_it(client, team) -> None:
    org_id, analyst, admin, _ = team
    _, (finding_id,), _ = await test_api.TestRiskTriage()._seed(
        org_id, members=[FindingStatus.OPEN]
    )
    await accept(client, analyst, finding_id)
    assert len(await waiting(client, admin)) == 1

    assert (await accept(client, admin, finding_id))["status"] == "ACCEPTED_RISK"
    assert await waiting(client, admin) == []


async def test_a_request_whose_date_passes_undecided_ends(client, team) -> None:
    from app.services import acceptance

    org_id, analyst, admin, _ = team
    _, (finding_id,), _ = await test_api.TestRiskTriage()._seed(
        org_id, members=[FindingStatus.OPEN]
    )
    await accept(client, analyst, finding_id)

    later = datetime.now(UTC) + timedelta(days=31)
    async with service_session() as session:
        assert org_id in await acceptance.organizations_due(session, later)
        await acceptance.expire_due(session, org_id, later)
        await session.commit()

    assert await waiting(client, admin) == []


async def test_a_solo_organization_cannot_require_a_second_person(client, cleanup_orgs) -> None:
    owner = uuid.uuid4()
    org_id = uuid.UUID(await make_org(client, owner, "Alone Ltd"))
    cleanup_orgs.append(org_id)
    solo = await client.patch(
        "/api/v1/organizations", json={"mode": "SOLO"}, headers=auth_header(owner)
    )
    assert solo.status_code == 200, solo.text

    response = await client.patch(
        "/api/v1/organizations",
        json={"acceptance_approval_from": "HIGH"},
        headers=auth_header(owner),
    )

    assert response.status_code == 409
