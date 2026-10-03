"""Grants to read a sealed package, as owners make them and auditors open them (section 211).

An owner's grant carries the address it is for and when it ends; the link is handed back once,
with the grant that was just made, and is never stored. An auditor's view of a grant is smaller:
which package, whose, and until when. The token goes in a body, so it stays out of URLs and logs.
"""

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, StringConstraints

from app.schemas.common import RequestModel

#: PENDING: made and not yet opened. OPENED: bound to the person who opened it. The other two
#: end it, and REVOKED wins where both are true.
GrantStatus = Literal["PENDING", "OPENED", "EXPIRED", "REVOKED"]

#: How long a grant lasts when the owner does not say, and the most it may.
DEFAULT_DAYS = 30
MAX_DAYS = 90

GrantEventName = Literal["OPENED", "ARCHIVE_DOWNLOADED"]


class AuditGrantCreate(RequestModel):
    """What an owner chooses. The token, the time and who made it are the server's."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "package_id": "6b1e0f3c-5a62-4c0f-9a43-2f7a8b9c0d11",
                    "email": "auditor@example.com",
                    "expires_in_days": 30,
                }
            ]
        }
    )

    package_id: UUID
    email: EmailStr = Field(description="The address the auditor will sign in with.")
    expires_in_days: int = Field(default=DEFAULT_DAYS, ge=1, le=MAX_DAYS)


class AuditGrantOut(BaseModel):
    id: UUID
    package_id: UUID
    email: str
    status: GrantStatus
    created_by: UUID
    created_at: datetime
    expires_at: datetime
    #: When the auditor first opened the link, and null while nobody has.
    opened_at: datetime | None
    revoked_at: datetime | None


class AuditGrantCreatedOut(AuditGrantOut):
    """The grant, and its link -- shown this once and never again."""

    link: str


class AuditGrantRevokedOut(BaseModel):
    revoked: UUID


class AuditGrantEventOut(BaseModel):
    id: UUID
    grant_id: UUID
    event: GrantEventName
    #: The account that did it: the auditor, not the owner.
    user_id: UUID
    detail: dict[str, object]
    at: datetime


class GrantToken(RequestModel):
    """A token from a grant link. In a body, so it stays out of URLs and logs."""

    model_config = ConfigDict(json_schema_extra={"examples": [{"token": "x" * 43}]})

    token: Annotated[str, StringConstraints(min_length=20, max_length=200)]


class AuditorGrantOut(BaseModel):
    """A grant as the auditor it is for sees it."""

    id: UUID
    package_id: UUID
    package_name: str
    #: The organization's name as it is now, for context. The sealed package names the
    #: organization by id, since a display name can change after an audit.
    organization_name: str
    email: str
    opened_at: datetime
    expires_at: datetime
