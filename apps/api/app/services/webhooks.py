"""Notifications sent where a team already talks (DECISIONS.md section 164).

Three parts:

* **Endpoints**, managed by owners and admins through the API. A generic
  endpoint gets a signing secret, shown once. A Slack or Teams URL is its own
  credential, so the API only ever shows its host and last few characters.
* **Enqueueing**, in the notification sweep: every notification an enabled
  endpoint asked for becomes one delivery, once, by a unique pair. An endpoint
  is owed only what was written after it was created -- a new Slack channel is
  not flooded with last week.
* **Delivering**, in its own sweep every minute: due deliveries are claimed
  under a lease, sent outside any transaction through ``core/outbound`` (which
  refuses anything that leads inside), and recorded. A failure is retried on a
  widening schedule and then given up on, visibly.
"""

import asyncio
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from sqlalchemy import String, any_, cast, func, literal, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core import outbound
from app.core.config import settings
from app.core.db import commit_unless_externally_managed, rls_session
from app.core.deps import TenantContext
from app.core.enums import DeliveryStatus, NotificationKind, Role, WebhookFormat
from app.core.errors import NotFound, ValidationFailed
from app.models.notification import Notification
from app.models.webhook import WebhookDelivery, WebhookEndpoint
from app.services import audit

# After the first failure, then the second, and so on. Six attempts across about
# nine hours: long enough to ride out a receiver's deploy or an outage, short
# enough that "given up" is said the same working day.
RETRY_DELAYS = (
    timedelta(minutes=1),
    timedelta(minutes=5),
    timedelta(minutes=30),
    timedelta(hours=2),
    timedelta(hours=6),
)
MAX_ATTEMPTS = len(RETRY_DELAYS) + 1

# How long a claimed delivery is held by the sweep that claimed it. Longer than
# a batch can take (fifty sends, five at a time, five seconds each), so two
# sweeps overlapping never send the same one.
CLAIM_LEASE = timedelta(minutes=5)
BATCH = 50
CONCURRENCY = 5

# Notifications older than this are never enqueued, whatever else holds. Bounds
# the join the sweep runs, and a day-old notification is history, not news.
RECENT = timedelta(days=1)

ENDPOINT_LIMIT = 20


# ------------------------------------------------------------------ messages


@dataclass(frozen=True)
class Message:
    """What one delivery says. A notification, or the test's stand-in for one."""

    id: UUID
    organization_id: UUID
    kind: str
    title: str
    detail: str | None
    link: str | None
    event_at: datetime


def _absolute(link: str | None) -> str:
    base = settings.app_url.rstrip("/")
    return f"{base}{link}" if link and link.startswith("/") else base


def _slack_escape(text: str) -> str:
    # Slack's mrkdwn treats these three as control characters.
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render(fmt: WebhookFormat, message: Message) -> bytes:
    """The body a receiver of this format expects."""
    link = _absolute(message.link)
    payload: dict[str, Any]
    if fmt is WebhookFormat.SLACK:
        lines = [f"*{_slack_escape(message.title)}*"]
        if message.detail:
            lines.append(_slack_escape(message.detail))
        lines.append(f"<{link}|Open in Cleave>")
        payload = {"text": "\n".join(lines)}
    elif fmt is WebhookFormat.TEAMS:
        body: list[dict[str, Any]] = [
            {"type": "TextBlock", "text": message.title, "weight": "Bolder", "wrap": True}
        ]
        if message.detail:
            body.append({"type": "TextBlock", "text": message.detail, "wrap": True})
        payload = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": body,
                        "actions": [
                            {"type": "Action.OpenUrl", "title": "Open in Cleave", "url": link}
                        ],
                    },
                }
            ],
        }
    else:
        payload = {
            "type": "notification",
            "id": str(message.id),
            "organization_id": str(message.organization_id),
            "kind": message.kind,
            "title": message.title,
            "detail": message.detail,
            "link": link,
            "event_at": message.event_at.isoformat(),
        }
    return json.dumps(payload, separators=(",", ":")).encode()


def signature(secret: str, timestamp: str, body: bytes) -> str:
    """``sha256=`` and the HMAC of ``<timestamp>.<body>`` under the endpoint's secret.

    The timestamp is inside what is signed so a captured delivery cannot be
    replayed later with a fresh one; a receiver rejects one too old.
    """
    mac = hmac.new(secret.encode(), timestamp.encode() + b"." + body, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def headers_for(
    endpoint: WebhookEndpoint, delivery_id: UUID, kind: str, body: bytes
) -> dict[str, str]:
    if endpoint.format is not WebhookFormat.GENERIC or not endpoint.secret:
        return {}
    timestamp = str(int(time.time()))
    return {
        "X-Cleave-Event": kind,
        "X-Cleave-Delivery": str(delivery_id),
        "X-Cleave-Timestamp": timestamp,
        "X-Cleave-Signature": signature(endpoint.secret, timestamp, body),
    }


async def send(
    endpoint: WebhookEndpoint, message: Message, delivery_id: UUID
) -> outbound.Outcome:
    body = render(WebhookFormat(endpoint.format), message)
    return await outbound.post_json(
        endpoint.url, body, headers_for(endpoint, delivery_id, message.kind, body)
    )


def url_preview(url: str) -> str:
    """Enough of the URL to recognise it, never enough to use it."""
    parts = urlsplit(url)
    tail = parts.path.rstrip("/")[-4:]
    return f"{parts.hostname}/…{tail}" if tail else f"{parts.hostname}"


# -------------------------------------------------------------- endpoints (API)


def _manage(tenant: TenantContext) -> None:
    tenant.require_role(Role.OWNER, Role.ADMIN)


async def list_endpoints(session: AsyncSession, tenant: TenantContext) -> list[WebhookEndpoint]:
    _manage(tenant)
    return list(
        (
            await session.execute(
                select(WebhookEndpoint)
                .where(WebhookEndpoint.organization_id == tenant.organization_id)
                .order_by(WebhookEndpoint.created_at, WebhookEndpoint.id)
            )
        )
        .scalars()
        .all()
    )


async def _endpoint(
    session: AsyncSession, tenant: TenantContext, endpoint_id: UUID
) -> WebhookEndpoint:
    endpoint = (
        await session.execute(
            select(WebhookEndpoint).where(
                WebhookEndpoint.id == endpoint_id,
                WebhookEndpoint.organization_id == tenant.organization_id,
            )
        )
    ).scalar_one_or_none()
    if endpoint is None:
        raise NotFound("No such webhook in this organization")
    return endpoint


async def create_endpoint(
    session: AsyncSession,
    tenant: TenantContext,
    *,
    name: str,
    url: str,
    fmt: WebhookFormat,
    kinds: list[NotificationKind],
) -> tuple[WebhookEndpoint, str | None]:
    """Add an endpoint; return it with its signing secret, which is not shown again.

    The URL is checked -- form and every address it resolves to -- before it is
    stored, so a refusal is said to the person typing it rather than recorded,
    minutes later, on a delivery.
    """
    _manage(tenant)
    count = (
        await session.execute(
            select(func.count())
            .select_from(WebhookEndpoint)
            .where(WebhookEndpoint.organization_id == tenant.organization_id)
        )
    ).scalar_one()
    if count >= ENDPOINT_LIMIT:
        raise ValidationFailed(f"An organization may have at most {ENDPOINT_LIMIT} webhooks")
    try:
        await outbound.resolve(url)
    except outbound.OutboundRefused as exc:
        raise ValidationFailed(str(exc)) from exc

    secret = secrets.token_hex(32) if fmt is WebhookFormat.GENERIC else None
    endpoint = WebhookEndpoint(
        organization_id=tenant.organization_id,
        name=name,
        url=url.strip(),
        format=fmt,
        kinds=sorted({kind.value for kind in kinds}),
        secret=secret,
        enabled=True,
        created_by=tenant.user.id,
        created_at=datetime.now(UTC),
    )
    session.add(endpoint)
    await session.flush()
    await audit.record(
        session,
        tenant,
        "webhook.created",
        "webhook",
        endpoint.id,
        {"name": name, "format": fmt.value, "kinds": endpoint.kinds, "url": url_preview(url)},
    )
    await commit_unless_externally_managed(session)
    return endpoint, secret


async def update_endpoint(
    session: AsyncSession,
    tenant: TenantContext,
    endpoint_id: UUID,
    changes: dict[str, Any],
) -> WebhookEndpoint:
    _manage(tenant)
    endpoint = await _endpoint(session, tenant, endpoint_id)
    recorded: dict[str, Any] = {}
    if changes.get("name") is not None:
        endpoint.name = changes["name"]
        recorded["name"] = endpoint.name
    if changes.get("kinds") is not None:
        endpoint.kinds = sorted({NotificationKind(k).value for k in changes["kinds"]})
        recorded["kinds"] = endpoint.kinds
    if changes.get("enabled") is not None:
        endpoint.enabled = bool(changes["enabled"])
        recorded["enabled"] = endpoint.enabled
    if recorded:
        await audit.record(session, tenant, "webhook.updated", "webhook", endpoint.id, recorded)
    await commit_unless_externally_managed(session)
    return endpoint


async def delete_endpoint(
    session: AsyncSession, tenant: TenantContext, endpoint_id: UUID
) -> None:
    _manage(tenant)
    endpoint = await _endpoint(session, tenant, endpoint_id)
    await audit.record(
        session,
        tenant,
        "webhook.deleted",
        "webhook",
        endpoint.id,
        {"name": endpoint.name, "url": url_preview(endpoint.url)},
    )
    await session.delete(endpoint)
    await commit_unless_externally_managed(session)


async def test_endpoint(
    session: AsyncSession, tenant: TenantContext, endpoint_id: UUID
) -> outbound.Outcome:
    """Send a message that says it is a test, now, and say what came back.

    The request's connection goes back to the pool before the send, which can
    wait seconds on somebody else's server, and the result is recorded in a
    fresh session for the same user -- nothing a request triggers idles on a
    pooled connection (section 158).
    """
    _manage(tenant)
    stored = await _endpoint(session, tenant, endpoint_id)
    target = WebhookEndpoint(
        url=stored.url, format=stored.format, secret=stored.secret, name=stored.name
    )
    await session.close()

    message = Message(
        id=uuid4(),
        organization_id=tenant.organization_id,
        kind="TEST",
        title="Test from Cleave",
        detail=f"The webhook \u201c{target.name}\u201d is connected. Nothing has happened.",
        link="/settings",
        event_at=datetime.now(UTC),
    )
    outcome = await send(target, message, message.id)

    async with rls_session(tenant.user.id, tenant.user.email) as fresh:
        endpoint = await _endpoint(fresh, tenant, endpoint_id)
        _note(endpoint, outcome, datetime.now(UTC))
        await audit.record(
            fresh,
            tenant,
            "webhook.tested",
            "webhook",
            endpoint.id,
            {"ok": outcome.ok, "status": outcome.status},
        )
    return outcome


async def list_deliveries(
    session: AsyncSession, tenant: TenantContext, endpoint_id: UUID, limit: int
) -> list[tuple[WebhookDelivery, str]]:
    _manage(tenant)
    await _endpoint(session, tenant, endpoint_id)
    rows = (
        await session.execute(
            select(WebhookDelivery, Notification.title)
            .join(Notification, Notification.id == WebhookDelivery.notification_id)
            .where(
                WebhookDelivery.organization_id == tenant.organization_id,
                WebhookDelivery.endpoint_id == endpoint_id,
            )
            .order_by(WebhookDelivery.created_at.desc(), WebhookDelivery.id)
            .limit(limit)
        )
    ).all()
    return [(row[0], row[1]) for row in rows]


def _note(endpoint: WebhookEndpoint, outcome: outbound.Outcome, now: datetime) -> None:
    if outcome.ok:
        endpoint.last_success_at = now
    else:
        endpoint.last_failure_at = now
        endpoint.last_error = outcome.error


# ------------------------------------------------------------ sweeps (worker)


async def enqueue(session: AsyncSession, organization_id: UUID, now: datetime) -> int:
    """Owe every enabled endpoint the recent notifications it asked for, once.

    One statement, idempotent by the unique pair, so the sweep can run as often
    as it likes and overlap itself without owing anything twice.
    """
    chosen = (
        select(
            literal(organization_id).label("organization_id"),
            WebhookEndpoint.id,
            Notification.id,
        )
        .join(Notification, Notification.organization_id == WebhookEndpoint.organization_id)
        .where(
            WebhookEndpoint.organization_id == organization_id,
            WebhookEndpoint.enabled.is_(True),
            cast(Notification.kind, String) == any_(WebhookEndpoint.kinds),
            Notification.created_at >= WebhookEndpoint.created_at,
            Notification.created_at > now - RECENT,
        )
    )
    result = await session.execute(
        insert(WebhookDelivery)
        .from_select(["organization_id", "endpoint_id", "notification_id"], chosen)
        .on_conflict_do_nothing(index_elements=["endpoint_id", "notification_id"])
    )
    return int(getattr(result, "rowcount", 0) or 0)


def next_attempt(attempts: int, now: datetime) -> datetime | None:
    """When to try again after ``attempts`` failures, or None to give up."""
    if attempts >= MAX_ATTEMPTS:
        return None
    return now + RETRY_DELAYS[attempts - 1]


async def organizations_due(session: AsyncSession, now: datetime) -> list[UUID]:
    """Which organizations owe a delivery now. The one question asked across tenants."""
    return list(
        (
            await session.execute(
                select(WebhookDelivery.organization_id)
                .where(
                    WebhookDelivery.status == DeliveryStatus.PENDING,
                    WebhookDelivery.next_attempt_at <= now,
                )
                .distinct()
            )
        )
        .scalars()
        .all()
    )


async def deliver_due(session: AsyncSession, organization_id: UUID) -> dict[str, int]:
    """Send what this organization owes now, and record how each went.

    Claimed and committed first, so no transaction is open while a receiver
    takes its time answering, and a second sweep skips what this one holds.
    """
    now = datetime.now(UTC)
    claimed = list(
        (
            await session.execute(
                select(WebhookDelivery)
                .where(
                    WebhookDelivery.organization_id == organization_id,
                    WebhookDelivery.status == DeliveryStatus.PENDING,
                    WebhookDelivery.next_attempt_at <= now,
                )
                .order_by(WebhookDelivery.next_attempt_at)
                .limit(BATCH)
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .all()
    )
    for delivery in claimed:
        delivery.next_attempt_at = now + CLAIM_LEASE
    await session.commit()
    if not claimed:
        return {"sent": 0, "failed": 0, "retrying": 0}

    rows = (
        await session.execute(
            select(WebhookDelivery, WebhookEndpoint, Notification)
            .join(WebhookEndpoint, WebhookEndpoint.id == WebhookDelivery.endpoint_id)
            .join(Notification, Notification.id == WebhookDelivery.notification_id)
            .where(WebhookDelivery.id.in_([d.id for d in claimed]))
        )
    ).all()
    # Read, then out of the transaction before anything is sent.
    await session.commit()

    gate = asyncio.Semaphore(CONCURRENCY)

    async def attempt(
        delivery: WebhookDelivery, endpoint: WebhookEndpoint, notification: Notification
    ) -> outbound.Outcome:
        if not endpoint.enabled:
            return outbound.Outcome(ok=False, status=None, error="The webhook was turned off")
        message = Message(
            id=notification.id,
            organization_id=notification.organization_id,
            kind=NotificationKind(notification.kind).value,
            title=notification.title,
            detail=notification.detail,
            link=notification.link,
            event_at=notification.event_at,
        )
        async with gate:
            return await send(endpoint, message, delivery.id)

    outcomes = await asyncio.gather(*(attempt(d, e, n) for d, e, n in rows))

    counts = {"sent": 0, "failed": 0, "retrying": 0}
    done = datetime.now(UTC)
    for (delivery, endpoint, _), outcome in zip(rows, outcomes, strict=True):
        delivery.attempts += 1
        delivery.last_status = outcome.status
        delivery.last_error = outcome.error
        _note(endpoint, outcome, done)
        if outcome.ok:
            delivery.status = DeliveryStatus.SENT
            delivery.delivered_at = done
            counts["sent"] += 1
            continue
        retry = next_attempt(delivery.attempts, done) if endpoint.enabled else None
        if retry is None:
            delivery.status = DeliveryStatus.FAILED
            counts["failed"] += 1
        else:
            delivery.next_attempt_at = retry
            counts["retrying"] += 1
    await session.commit()
    return counts
