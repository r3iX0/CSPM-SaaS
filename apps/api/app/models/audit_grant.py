"""A grant to read one sealed package, and what was done through it (DECISIONS.md section 211)."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, ForeignKey, Index, String, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TenantOwned


class AuditGrant(TenantOwned, Base):
    """One address's right to read one package, for a while.

    Not a membership: an auditor never becomes a member, so nothing that asks ``app.is_member``
    reaches them. They read through ``SECURITY DEFINER`` functions that begin by checking this
    row, and the application only ever writes the columns it names here. ``opened_by`` and
    ``opened_at`` are written by ``app.open_audit_grant`` and by nothing else, which is what
    makes the first person to open a link its only reader.

    ``created_at`` and ``expires_at`` are the database's time, never the application's, so the
    90-day ceiling in the table's check cannot be tripped by a clock a few milliseconds apart.
    """

    __tablename__ = "audit_grants"
    __table_args__ = (
        Index(
            "uq_audit_grants_one_live",
            "package_id",
            "email",
            unique=True,
            postgresql_where=text("revoked_at IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # The composite foreign key to ``(audit_packages.id, organization_id)`` lives in the
    # migration, because SQLAlchemy would need a second constraint to say it.
    package_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_by: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    opened_by: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True))
    opened_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True))


class AuditGrantEvent(TenantOwned, Base):
    """What a grant's functions did: it was opened, or its archive was taken.

    Never written by the application: the functions write it, in the transaction that gave the
    access, so a read through a grant cannot happen without its entry.
    """

    __tablename__ = "audit_grant_events"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    grant_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("audit_grants.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    event: Mapped[str] = mapped_column(String(32), nullable=False)
    detail: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
