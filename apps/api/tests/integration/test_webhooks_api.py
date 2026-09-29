"""Webhooks against the real database (DECISIONS.md section 164).

* Only owners and admins see or manage them, and the stored URL is never
  handed back whole.
* A notification is owed to an endpoint once, and only if it was written after
  the endpoint was made.
* A delivery that lands is marked sent; one that fails is retried later.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text

from app.core import outbound
from app.core.db import scan_session, service_session
from app.core.enums import DeliveryStatus
from app.main import app
from app.models.webhook import WebhookDelivery
from app.services import webhooks
from tests.integration.test_api import auth_header, make_org

pytestmark = pytest.mark.integration

OWNER = uuid.UUID("abababab-0000-0000-0000-00000000000a")
SLACK_URL = "https://hooks.slack.com/services/T000/B000/secretpart1234"


@pytest.fixture(autouse=True)
def public_dns(monkeypatch: pytest.MonkeyPatch) -> None:
    async def fake(host: str) -> list[str]:
        return ["93.184.216.34"]

    monkeypatch.setattr(outbound, "_addresses", fake)


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture
async def org(client, cleanup_orgs) -> str:
    org_id = await make_org(client, OWNER, "Webhook Org")
    cleanup_orgs.append(uuid.UUID(org_id))
    return org_id


def owner(org: str) -> dict[str, str]:
    return {**auth_header(OWNER, "owner@example.com"), "X-Organization-Id": org}


async def add_notification(org: str, created_at: datetime) -> uuid.UUID:
    async with service_session() as session:
        notification_id = (
            await session.execute(
                text(
                    "INSERT INTO notifications (organization_id, kind, title, subject_id, "
                    "event_at, created_at) VALUES (:org, 'VERIFIED_FIX', 'Fixed: x', :subject, "
                    ":at, :at) RETURNING id"
                ),
                {"org": org, "subject": uuid.uuid4().hex, "at": created_at},
            )
        ).scalar_one()
        await session.commit()
    return notification_id


async def create(client, org: str, url: str = SLACK_URL, fmt: str = "SLACK") -> dict:
    response = await client.post(
        "/api/v1/webhooks",
        json={"name": "Security channel", "url": url, "format": fmt, "kinds": ["VERIFIED_FIX"]},
        headers=owner(org),
    )
    assert response.status_code == 201, response.text
    return response.json()["data"]


async def test_the_url_is_never_handed_back_whole(client, org) -> None:
    created = await create(client, org)
    assert created["secret"] is None
    listed = await client.get("/api/v1/webhooks", headers=owner(org))
    (row,) = listed.json()["data"]
    assert row["url_preview"] == "hooks.slack.com/…1234"
    assert "secretpart" not in listed.text


async def test_a_generic_webhook_gets_a_secret_once(client, org) -> None:
    created = await create(client, org, "https://receiver.example.com/hook", "GENERIC")
    assert created["secret"] and len(created["secret"]) == 64
    listed = await client.get("/api/v1/webhooks", headers=owner(org))
    assert created["secret"] not in listed.text


async def test_a_private_address_is_refused_when_typed(client, org) -> None:
    response = await client.post(
        "/api/v1/webhooks",
        json={
            "name": "x",
            "url": "https://169.254.169.254/latest",
            "format": "GENERIC",
            "kinds": ["VERIFIED_FIX"],
        },
        headers=owner(org),
    )
    assert response.status_code == 422


async def test_a_notification_is_owed_once_and_only_if_newer(client, org) -> None:
    older = await add_notification(org, datetime.now(UTC) - timedelta(minutes=10))
    await create(client, org)
    newer = await add_notification(org, datetime.now(UTC) + timedelta(seconds=1))

    for _ in range(2):
        async with scan_session(uuid.UUID(org)) as session:
            await webhooks.enqueue(session, uuid.UUID(org), datetime.now(UTC))
            await session.commit()

    async with service_session() as session:
        owed = (
            (
                await session.execute(
                    select(WebhookDelivery.notification_id).where(
                        WebhookDelivery.organization_id == uuid.UUID(org)
                    )
                )
            )
            .scalars()
            .all()
        )
    assert owed == [newer]
    assert older not in owed


async def test_a_delivery_that_lands_is_sent_and_one_that_fails_is_retried(
    client, org, monkeypatch: pytest.MonkeyPatch
) -> None:
    await create(client, org)
    await add_notification(org, datetime.now(UTC) + timedelta(seconds=1))
    async with scan_session(uuid.UUID(org)) as session:
        await webhooks.enqueue(session, uuid.UUID(org), datetime.now(UTC))
        await session.commit()

    async def refused(*_args: object, **_kwargs: object) -> outbound.Outcome:
        return outbound.Outcome(ok=False, status=500, error="HTTP 500")

    monkeypatch.setattr(outbound, "post_json", refused)
    async with scan_session(uuid.UUID(org)) as session:
        assert (await webhooks.deliver_due(session, uuid.UUID(org)))["retrying"] == 1

    async with service_session() as session:
        delivery = (
            await session.execute(
                select(WebhookDelivery).where(WebhookDelivery.organization_id == uuid.UUID(org))
            )
        ).scalar_one()
        assert delivery.status is DeliveryStatus.PENDING
        assert delivery.attempts == 1
        assert delivery.next_attempt_at > datetime.now(UTC)
        # Due again now, for the second half of this test.
        await session.execute(
            text("UPDATE webhook_deliveries SET next_attempt_at = now() WHERE id = :id"),
            {"id": delivery.id},
        )
        await session.commit()

    async def landed(*_args: object, **_kwargs: object) -> outbound.Outcome:
        return outbound.Outcome(ok=True, status=200, error=None)

    monkeypatch.setattr(outbound, "post_json", landed)
    async with scan_session(uuid.UUID(org)) as session:
        assert (await webhooks.deliver_due(session, uuid.UUID(org)))["sent"] == 1


async def test_only_owners_and_admins_manage_webhooks(client, org) -> None:
    invited = await client.post(
        "/api/v1/invitations",
        json={"email": "analyst@example.com", "role": "SECURITY_ANALYST"},
        headers=owner(org),
    )
    token = invited.json()["data"]["link"].split("#", 1)[1]
    analyst = uuid.UUID("abababab-0000-0000-0000-00000000000b")
    headers = auth_header(analyst, "analyst@example.com")
    await client.post("/api/v1/invitations/accept", json={"token": token}, headers=headers)
    response = await client.get("/api/v1/webhooks", headers={**headers, "X-Organization-Id": org})
    assert response.status_code == 403


async def test_many_deliveries_are_owed_in_one_sweep(client, org) -> None:
    """Two endpoints and two notifications owe four deliveries, each with its own id.

    Every earlier test owed exactly one, which is why a statement that gave every
    row the same id -- and rolled the whole sweep back on the second -- passed.
    """
    await create(client, org)
    await create(client, org, "https://receiver.example.com/hook", "GENERIC")
    for _ in range(2):
        await add_notification(org, datetime.now(UTC) + timedelta(seconds=1))

    async with scan_session(uuid.UUID(org)) as session:
        owed = await webhooks.enqueue(session, uuid.UUID(org), datetime.now(UTC))
        await session.commit()
    assert owed == 4

    async with service_session() as session:
        ids = (
            (
                await session.execute(
                    select(WebhookDelivery.id).where(
                        WebhookDelivery.organization_id == uuid.UUID(org)
                    )
                )
            )
            .scalars()
            .all()
        )
    assert len(set(ids)) == 4
