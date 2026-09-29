"""Where notifications are sent beyond the bell, and what was sent (DECISIONS.md 164)."""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import DeliveryStatus, WebhookFormat
from app.models.base import Base, StrEnumType, TenantOwned, UUIDPrimaryKey


class WebhookEndpoint(UUIDPrimaryKey, TenantOwned, Base):
    """A URL an owner or admin asked Cleave to tell, and about what."""

    __tablename__ = "webhook_endpoints"

    name: Mapped[str] = mapped_column(String(120), nullable=False)
    # A Slack or Teams URL is itself the credential, so it is never returned
    # whole once stored -- only its host and last few characters.
    url: Mapped[str] = mapped_column(Text, nullable=False)
    format: Mapped[WebhookFormat] = mapped_column(StrEnumType(WebhookFormat, 16), nullable=False)
    # NotificationKind values.
    kinds: Mapped[list[str]] = mapped_column(ARRAY(String), nullable=False)
    # Signs a generic endpoint's deliveries. Shown once, at creation.
    secret: Mapped[str | None] = mapped_column(String(64))
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_by: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_failure_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)


class WebhookDelivery(UUIDPrimaryKey, TenantOwned, Base):
    """One notification owed to one endpoint, until it lands or is given up on."""

    __tablename__ = "webhook_deliveries"

    endpoint_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("webhook_endpoints.id", ondelete="CASCADE"),
        nullable=False,
    )
    notification_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("notifications.id", ondelete="CASCADE"),
        nullable=False,
    )
    status: Mapped[DeliveryStatus] = mapped_column(
        StrEnumType(DeliveryStatus, 16), nullable=False, default=DeliveryStatus.PENDING
    )
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    last_status: Mapped[int | None] = mapped_column(Integer)
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
