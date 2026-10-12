"""Who owns the work on an asset, by where it sits or how it is tagged (migration 0058, §236)."""

import uuid

from sqlalchemy import ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import OwnershipScope
from app.models.base import Base, StrEnumType, TenantOwned, Timestamps, UUIDPrimaryKey


class OwnershipRule(UUIDPrimaryKey, TenantOwned, Timestamps, Base):
    """One scope and the member who owns the work on the assets in it.

    The columns a scope needs are set and the rest are null, held by a check
    in the migration: a subscription names its account, a resource group its
    account and name, a tag its key and value, and the default nothing.
    """

    __tablename__ = "ownership_rules"

    scope: Mapped[OwnershipScope] = mapped_column(StrEnumType(OwnershipScope, 16), nullable=False)
    cloud_account_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cloud_accounts.id", ondelete="CASCADE")
    )
    resource_group: Mapped[str | None] = mapped_column(String(90))
    tag_key: Mapped[str | None] = mapped_column(String(512))
    tag_value: Mapped[str | None] = mapped_column(String(256))
    # Not an FK: auth.users belongs to Supabase. A rule whose owner has since
    # left the organization is skipped when routing, and said so when listed.
    owner_id: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    created_by: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
