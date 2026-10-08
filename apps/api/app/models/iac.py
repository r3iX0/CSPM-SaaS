"""The customer's Terraform state index (migration 0054, DECISIONS.md §229)."""

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, String, Text, func
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TenantOwned, UUIDPrimaryKey


class IacIndex(UUIDPrimaryKey, TenantOwned, Base):
    """One upload of one state: a repository, the directory Terraform ran in, a workspace."""

    __tablename__ = "iac_indexes"

    # GitHub's numeric id, which survives a rename; ``repository`` is for display.
    repository_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    repository: Mapped[str] = mapped_column(String(200), nullable=False)
    working_directory: Mapped[str] = mapped_column(String(500), nullable=False, default="")
    workspace: Mapped[str] = mapped_column(String(100), nullable=False, default="default")
    commit_sha: Mapped[str] = mapped_column(String(64), nullable=False)
    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )


class IacIndexEntry(UUIDPrimaryKey, TenantOwned, Base):
    """One managed resource of an index: where in code the asset with this id is defined."""

    __tablename__ = "iac_index_entries"

    index_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("iac_indexes.id", ondelete="CASCADE"), nullable=False
    )
    address: Mapped[str] = mapped_column(Text, nullable=False)
    type: Mapped[str] = mapped_column(String(100), nullable=False)
    instance_key: Mapped[str | None] = mapped_column(Text)
    # Lower-cased Azure Resource Manager id.
    resource_id: Mapped[str] = mapped_column(Text, nullable=False)
