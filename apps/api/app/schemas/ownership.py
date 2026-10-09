"""Ownership rules: who owns the work on the assets of a scope (DECISIONS.md §236)."""

from datetime import datetime
from typing import Self
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.core.enums import OwnershipScope
from app.schemas.common import RequestModel

_NEEDS: dict[OwnershipScope, set[str]] = {
    OwnershipScope.DEFAULT: set(),
    OwnershipScope.SUBSCRIPTION: {"cloud_account_id"},
    OwnershipScope.RESOURCE_GROUP: {"cloud_account_id", "resource_group"},
    OwnershipScope.TAG: {"tag_key", "tag_value"},
}
_SCOPED = ("cloud_account_id", "resource_group", "tag_key", "tag_value")


class OwnershipRuleIn(RequestModel):
    """A scope and its owner. Send exactly the fields the scope needs, and no other."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "scope": "TAG",
                    "tag_key": "owner",
                    "tag_value": "platform-team",
                    "owner_id": "6b1e2f4a-8c3d-4e5f-9a7b-1c2d3e4f5a6b",
                }
            ]
        }
    )

    scope: OwnershipScope
    cloud_account_id: UUID | None = None
    # Azure's limits: 90 characters for a group's name, 512 for a tag's key, 256 for its value.
    resource_group: str | None = Field(default=None, min_length=1, max_length=90)
    tag_key: str | None = Field(default=None, min_length=1, max_length=512)
    tag_value: str | None = Field(default=None, min_length=1, max_length=256)
    owner_id: UUID

    @model_validator(mode="after")
    def _fields_of_scope(self) -> Self:
        needs = _NEEDS[self.scope]
        given = {name for name in _SCOPED if getattr(self, name) is not None}
        if missing := needs - given:
            raise ValueError(f"A {self.scope.value} rule needs {', '.join(sorted(missing))}")
        if extra := given - needs:
            raise ValueError(f"A {self.scope.value} rule takes no {', '.join(sorted(extra))}")
        return self


class OwnershipRuleUpdate(RequestModel):
    """Hand the scope to another member."""

    owner_id: UUID


class OwnershipRuleOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    scope: OwnershipScope
    cloud_account_id: UUID | None = None
    resource_group: str | None = None
    tag_key: str | None = None
    tag_value: str | None = None
    owner_id: UUID
    #: False once the owner has left: the rule is then skipped when routing.
    owner_is_member: bool = True
    created_at: datetime
