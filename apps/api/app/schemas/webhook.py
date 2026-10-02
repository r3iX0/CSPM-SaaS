"""Webhooks as the API takes and hands them out (DECISIONS.md section 164)."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import DeliveryStatus, NotificationKind, WebhookFormat
from app.schemas.common import RequestModel


class WebhookCreate(RequestModel):
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "name": "Security channel",
                    "url": "https://hooks.example.com/services/<path>",
                    "format": "GENERIC",
                    "kinds": ["VERIFIED_FIX"],
                }
            ]
        }
    )

    name: str = Field(min_length=1, max_length=120)
    url: str = Field(min_length=12, max_length=2048)
    format: WebhookFormat = WebhookFormat.GENERIC
    kinds: list[NotificationKind] = Field(min_length=1)


class WebhookUpdate(RequestModel):
    """Only what is sent changes. The URL and format are fixed: a new one is a new webhook."""

    name: str | None = Field(default=None, min_length=1, max_length=120)
    kinds: list[NotificationKind] | None = Field(default=None, min_length=1)
    enabled: bool | None = None


class WebhookOut(BaseModel):
    id: UUID
    name: str
    # Host and the last few characters, never the whole URL: a Slack or Teams
    # URL is itself the credential.
    url_preview: str
    format: WebhookFormat
    kinds: list[NotificationKind]
    enabled: bool
    created_at: datetime
    last_success_at: datetime | None
    last_failure_at: datetime | None
    last_error: str | None


class WebhookCreatedOut(WebhookOut):
    """The webhook, and for a generic one its signing secret -- shown this once."""

    secret: str | None


class WebhookDeletedOut(BaseModel):
    deleted: UUID


class WebhookTestOut(BaseModel):
    ok: bool
    status: int | None
    error: str | None


class WebhookDeliveryOut(BaseModel):
    id: UUID
    title: str
    status: DeliveryStatus
    attempts: int
    last_status: int | None
    last_error: str | None
    created_at: datetime
    delivered_at: datetime | None
    next_attempt_at: datetime | None
