import uuid

from sqlalchemy import Boolean, ForeignKey, String, UniqueConstraint, false
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import Role
from app.models.base import Base, StrEnumType, Timestamps, UUIDPrimaryKey


class Organization(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(200), nullable=False, unique=True, index=True)
    industry: Mapped[str | None] = mapped_column(String(120))
    country: Mapped[str | None] = mapped_column(String(2))
    # The shared, read-only demo estate (migration 0036). At most one row has
    # it; every write in it is refused whatever the caller's role
    # (``TenantContext.require_write``).
    is_demo: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=false()
    )

    members: Mapped[list["OrganizationMember"]] = relationship(
        back_populates="organization", cascade="all, delete-orphan"
    )


class OrganizationMember(UUIDPrimaryKey, Timestamps, Base):
    __tablename__ = "organization_members"
    __table_args__ = (UniqueConstraint("organization_id", "user_id"),)

    organization_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    # References auth.users(id) in Supabase. Not a DB-level FK: the auth schema
    # is owned by Supabase and may live outside our migration's reach.
    user_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False, index=True)
    role: Mapped[Role] = mapped_column(StrEnumType(Role, 32), nullable=False, default=Role.OWNER)

    organization: Mapped[Organization] = relationship(back_populates="members")
