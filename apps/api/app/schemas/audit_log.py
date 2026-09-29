"""The audit trail as the API hands it out (DECISIONS.md section 163)."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel


class AuditEntryOut(BaseModel):
    id: UUID
    # Dotted, subject first: ``member.role_changed``, ``scan.started``.
    action: str
    resource_type: str
    resource_id: UUID | None
    # Null for a change nobody made by hand: an acceptance that expired.
    actor_id: UUID | None
    # The actor's address as their membership holds it now; null once they
    # have left, when ``actor_id`` is what remains.
    actor_email: str | None
    ip_address: str | None
    request_id: str | None
    details: dict[str, Any]
    created_at: datetime
