"""Members of an organization, and invitations to become one."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.core.enums import Role
from app.schemas.common import RequestModel

InvitationStatus = Literal["OPEN", "EXPIRED", "ACCEPTED", "REVOKED"]


class MemberOut(BaseModel):
    id: UUID
    user_id: UUID
    # None until the member next signs in: the address is copied from their
    # verified token, and rows older than that copy have none yet.
    email: str | None
    role: Role
    joined_at: datetime
    is_you: bool


class MemberUpdate(RequestModel):
    role: Role


class MemberRemovedOut(BaseModel):
    removed: UUID


class InvitationCreate(RequestModel):
    email: EmailStr
    role: Role = Role.VIEWER

    @field_validator("role")
    @classmethod
    def _not_owner(cls, role: Role) -> Role:
        # Ownership is granted by an owner to somebody already inside, never
        # handed to an address through a link that can be forwarded.
        if role is Role.OWNER:
            raise ValueError("Invite as another role, then make them an owner once they join")
        return role


class InvitationOut(BaseModel):
    id: UUID
    email: str
    role: Role
    status: InvitationStatus
    invited_by: UUID
    created_at: datetime
    expires_at: datetime


class InvitationCreatedOut(InvitationOut):
    """The invitation, and its link -- shown this once and never again."""

    link: str


class InvitationRevokedOut(BaseModel):
    revoked: UUID


class InvitationToken(RequestModel):
    """A token from an invitation link. In a body, so it stays out of URLs and logs."""

    token: str = Field(min_length=20, max_length=200)


class InvitationPreviewOut(BaseModel):
    organization_name: str
    role: Role
    email: str
    status: InvitationStatus
    # Whether the signed-in account is the one invited, so the page can say
    # "sign in as the invited address" before a click that would be refused.
    email_matches: bool
