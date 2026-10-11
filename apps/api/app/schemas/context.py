from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.enums import Level
from app.schemas.common import RequestModel


class ContextDeclarationIn(RequestModel):
    """What a customer says about a subscription.

    Every field optional, and omitting one is not the same as clearing it --
    a PUT replaces the whole declaration, so a field left out is a field the
    customer is no longer claiming. That is the honest reading of "this is my
    statement about this subscription": a statement is replaced entire, not
    patched, or nobody can tell what it currently says without diffing.

    ``UNKNOWN`` is deliberately not accepted for either level. UNKNOWN is
    CloudGuard's own answer for "nothing said anything", and a customer
    declaring it would be asserting an absence -- which is what leaving the
    field out already does, more clearly.
    """

    environment: str | None = Field(default=None, max_length=64)
    criticality: Level | None = None
    data_sensitivity: Level | None = None
    note: str | None = Field(default=None, max_length=2000)

    @field_validator("criticality", "data_sensitivity")
    @classmethod
    def _not_unknown(cls, value: Level | None) -> Level | None:
        if value is Level.UNKNOWN:
            raise ValueError(
                "UNKNOWN is what Cleave says when nothing is known. To say "
                "nothing about this, leave the field out."
            )
        return value


class ContextDeclarationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    cloud_account_id: UUID
    environment: str | None = None
    criticality: Level | None = None
    data_sensitivity: Level | None = None
    note: str | None = None
    declared_by_user_id: UUID | None = None
    declared_at: datetime


class AssetDeclarationIn(RequestModel):
    """What a customer says about one asset's data (DECISIONS.md section 251).

    A level, never UNKNOWN, for the reason a subscription's declaration refuses
    it. Applied as a floor: it raises and never lowers, so declaring LOW on an
    asset the capture already ranks HIGH changes nothing.
    """

    data_sensitivity: Level
    note: str | None = Field(default=None, max_length=2000)

    @field_validator("data_sensitivity")
    @classmethod
    def _known(cls, value: Level) -> Level:
        if value is Level.UNKNOWN:
            raise ValueError("UNKNOWN is not a declaration: leave the asset undeclared instead")
        return value


class AssetDeclarationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    resource_id: UUID
    data_sensitivity: Level
    note: str | None = None
    declared_by_user_id: UUID | None = None
    declared_at: datetime
