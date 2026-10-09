import uuid
from datetime import date, datetime

from sqlalchemy import Boolean, Date, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import ExceptionStatus, Priority, RemediationStatus
from app.models.base import Base, StrEnumType, TenantOwned, Timestamps, UUIDPrimaryKey


class RemediationTask(UUIDPrimaryKey, TenantOwned, Timestamps, Base):
    __tablename__ = "remediation_tasks"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    risk_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("risks.id", ondelete="SET NULL")
    )
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True))
    status: Mapped[RemediationStatus] = mapped_column(
        StrEnumType(RemediationStatus, 16), nullable=False, default=RemediationStatus.TODO
    )
    priority: Mapped[Priority] = mapped_column(
        StrEnumType(Priority, 16), nullable=False, default=Priority.MEDIUM
    )
    due_date: Mapped[date | None] = mapped_column(Date)
    estimated_effort_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    notes: Mapped[str | None] = mapped_column(Text)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RiskException(UUIDPrimaryKey, TenantOwned, Base):
    """An intentionally accepted risk.

    Accepted is not hidden: the finding stays queryable and the acceptance is
    recorded in audit_logs (SECURITY.md section 4).
    """

    __tablename__ = "exceptions"

    # A finding, or -- only while an acceptance waits for a second approver -- a route or an
    # escalation; never both (migration 0062, DECISIONS.md section 239).
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE")
    )
    risk_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("risks.id", ondelete="CASCADE")
    )
    requested_by: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    # Whoever made it take effect: the person who asked, or the second approver. NULL until then.
    approved_by: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True))
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[ExceptionStatus] = mapped_column(
        StrEnumType(ExceptionStatus, 16), nullable=False, default=ExceptionStatus.ACTIVE
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    # The policy covered it, so whoever decides may not be whoever asked; the database refuses
    # it otherwise (``ck_exceptions_four_eyes``).
    second_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    decided_by: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Why a request was rejected, said to the person who asked.
    decision_note: Mapped[str | None] = mapped_column(Text)


class AuditLog(UUIDPrimaryKey, TenantOwned, Base):
    __tablename__ = "audit_logs"

    user_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True))
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[uuid.UUID | None] = mapped_column(PGUUID(as_uuid=True))
    audit_metadata: Mapped[dict] = mapped_column("metadata", JSONB, nullable=False, default=dict)
    ip_address: Mapped[str | None] = mapped_column(INET)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
