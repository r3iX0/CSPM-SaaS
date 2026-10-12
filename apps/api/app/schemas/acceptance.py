"""Acceptances that waited for a second approver, as the API gives them (DECISIONS.md §239)."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import ExceptionStatus
from app.schemas.common import RequestModel


class AcceptanceOut(BaseModel):
    """One acceptance that asked for a second approver, and what became of it."""

    id: UUID
    #: The finding it is about, or else the route or escalation (``risk_id``); never both.
    finding_id: UUID | None
    risk_id: UUID | None
    subject_title: str
    subject_severity: str
    #: The finding's or route's status now: a request overtaken by a fix says so.
    subject_status: str
    reason: str
    expires_at: datetime | None
    status: ExceptionStatus
    requested_by: UUID
    requested_by_email: str | None
    created_at: datetime
    decided_by: UUID | None
    decided_by_email: str | None
    decided_at: datetime | None
    #: Why it was rejected, for the person who asked.
    decision_note: str | None


class AcceptanceReject(RequestModel):
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [{"note": "Not without a compensating control on the subnet."}]
        }
    )

    #: Said to the person who asked, so it is required.
    note: str = Field(min_length=1, max_length=2000)
