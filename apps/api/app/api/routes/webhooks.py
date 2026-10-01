"""Where notifications are sent beyond the bell. Owners and admins (DECISIONS.md 164)."""

from uuid import UUID

from fastapi import APIRouter, Query, status

from app.core.deps import Costly, DbSession, Tenant
from app.core.enums import DeliveryStatus, NotificationKind
from app.models.webhook import WebhookEndpoint
from app.schemas.common import ERROR_RESPONSES, Envelope, NoMeta, error_responses
from app.schemas.webhook import (
    WebhookCreate,
    WebhookCreatedOut,
    WebhookDeletedOut,
    WebhookDeliveryOut,
    WebhookOut,
    WebhookTestOut,
    WebhookUpdate,
)
from app.services import webhooks as service

router = APIRouter(prefix="/webhooks", tags=["webhooks"], responses=ERROR_RESPONSES)

WRITE = error_responses(403)


def _out(endpoint: WebhookEndpoint) -> WebhookOut:
    return WebhookOut(
        id=endpoint.id,
        name=endpoint.name,
        url_preview=service.url_preview(endpoint.url),
        format=endpoint.format,
        kinds=[NotificationKind(kind) for kind in endpoint.kinds],
        enabled=endpoint.enabled,
        created_at=endpoint.created_at,
        last_success_at=endpoint.last_success_at,
        last_failure_at=endpoint.last_failure_at,
        last_error=endpoint.last_error,
    )


@router.get("", responses=WRITE)
async def list_webhooks(session: DbSession, tenant: Tenant) -> Envelope[list[WebhookOut], NoMeta]:
    endpoints = await service.list_endpoints(session, tenant)
    return Envelope(data=[_out(e) for e in endpoints], meta=NoMeta())


@router.post("", status_code=status.HTTP_201_CREATED, responses=WRITE)
async def create_webhook(
    payload: WebhookCreate, session: DbSession, tenant: Tenant
) -> Envelope[WebhookCreatedOut, NoMeta]:
    """Add a webhook. A generic one's signing secret is in this answer and no other."""
    endpoint, secret = await service.create_endpoint(
        session,
        tenant,
        name=payload.name,
        url=payload.url,
        fmt=payload.format,
        kinds=payload.kinds,
    )
    return Envelope(
        data=WebhookCreatedOut(**_out(endpoint).model_dump(), secret=secret), meta=NoMeta()
    )


@router.patch("/{webhook_id}", responses=WRITE)
async def update_webhook(
    webhook_id: UUID, payload: WebhookUpdate, session: DbSession, tenant: Tenant
) -> Envelope[WebhookOut, NoMeta]:
    endpoint = await service.update_endpoint(
        session, tenant, webhook_id, payload.model_dump(exclude_unset=True)
    )
    return Envelope(data=_out(endpoint), meta=NoMeta())


@router.delete("/{webhook_id}", responses=WRITE)
async def delete_webhook(
    webhook_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[WebhookDeletedOut, NoMeta]:
    await service.delete_endpoint(session, tenant, webhook_id)
    return Envelope(data=WebhookDeletedOut(deleted=webhook_id), meta=NoMeta())


@router.post("/{webhook_id}/test", responses=WRITE, dependencies=[Costly])
async def test_webhook(
    webhook_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[WebhookTestOut, NoMeta]:
    """Send a test message now and say what the receiver answered."""
    outcome = await service.test_endpoint(session, tenant, webhook_id)
    return Envelope(
        data=WebhookTestOut(ok=outcome.ok, status=outcome.status, error=outcome.error),
        meta=NoMeta(),
    )


@router.get("/{webhook_id}/deliveries", responses=WRITE)
async def list_webhook_deliveries(
    webhook_id: UUID,
    session: DbSession,
    tenant: Tenant,
    limit: int = Query(default=20, ge=1, le=100),
) -> Envelope[list[WebhookDeliveryOut], NoMeta]:
    """The most recent deliveries to this webhook, and how each went."""
    rows = await service.list_deliveries(session, tenant, webhook_id, limit)
    return Envelope(
        data=[
            WebhookDeliveryOut(
                id=delivery.id,
                title=title,
                status=delivery.status,
                attempts=delivery.attempts,
                last_status=delivery.last_status,
                last_error=delivery.last_error,
                created_at=delivery.created_at,
                delivered_at=delivery.delivered_at,
                next_attempt_at=(
                    delivery.next_attempt_at if delivery.status is DeliveryStatus.PENDING else None
                ),
            )
            for delivery, title in rows
        ],
        meta=NoMeta(),
    )
