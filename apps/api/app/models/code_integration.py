"""A GitHub App installation linked to an organization (migration 0055, DECISIONS.md §231)."""

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, String, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TenantOwned, UUIDPrimaryKey


class CodeIntegration(UUIDPrimaryKey, TenantOwned, Base):
    """One installation of Cleave's GitHub App, and the organization it belongs to."""

    __tablename__ = "code_integrations"

    provider: Mapped[str] = mapped_column(String(16), nullable=False, default="github")
    # Unique: an installation belongs to one organization.
    installation_id: Mapped[int] = mapped_column(BigInteger, nullable=False, unique=True)
    # The GitHub account it is installed on, for display: an organization or a user.
    account_login: Mapped[str] = mapped_column(String(100), nullable=False)
    account_type: Mapped[str] = mapped_column(String(16), nullable=False)
    connected_by: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    connected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
