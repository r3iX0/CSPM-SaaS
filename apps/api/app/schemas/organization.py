from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.enums import OrganizationMode, Role, Severity
from app.schemas.common import RequestModel


class OrganizationCreate(RequestModel):
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [{"name": "Contoso Security", "industry": "Finance", "country": "AL"}]
        }
    )

    name: str = Field(min_length=2, max_length=200)
    industry: str | None = Field(default=None, max_length=120)
    country: str | None = Field(default=None, min_length=2, max_length=2)

    @field_validator("country")
    @classmethod
    def _upper(cls, v: str | None) -> str | None:
        return v.upper() if v else v


class FixWithinDays(RequestModel):
    """How many days after first detection a finding is due, by severity (DECISIONS.md §225).

    A severity left null has no deadline. Sent whole, as one statement of the policy: a form that
    lowers Critical to seven days says what High is too, so a reader of the change knows the
    policy that resulted.
    """

    model_config = ConfigDict(
        json_schema_extra={"examples": [{"critical": 7, "high": 30, "medium": 90, "low": None}]}
    )

    critical: int | None = Field(default=None, ge=1, le=365)
    high: int | None = Field(default=None, ge=1, le=365)
    medium: int | None = Field(default=None, ge=1, le=365)
    low: int | None = Field(default=None, ge=1, le=365)


class OrganizationUpdate(RequestModel):
    """A correction to how an organization describes itself.

    Every field optional and applied only when present, which is the opposite
    of ``ContextDeclarationIn`` and deliberately so. That one is a *statement*
    about a subscription, replaced entire so a reader always knows what it
    currently claims. This is a profile: a form that saves only the name must
    not silently clear the country nobody touched.

    The slug is not here. It is an identifier that already appears in stored
    references, and quietly changing it when somebody fixes a typo in a display
    name would be renaming a thing rather than relabelling it.
    """

    name: str | None = Field(default=None, min_length=2, max_length=200)
    industry: str | None = Field(default=None, max_length=120)
    country: str | None = Field(default=None, min_length=2, max_length=2)
    # Owners and admins, as the rest of this model. Null clears every deadline.
    fix_within_days: FixWithinDays | None = None
    # Solo only with one member and no open invitation; ``409`` otherwise (§236).
    mode: OrganizationMode | None = None
    # The lowest severity whose acceptance waits for a second owner or admin; null for none.
    # A team's only: ``409`` in solo, where there is nobody else to approve (§239).
    acceptance_approval_from: Severity | None = None

    @field_validator("country")
    @classmethod
    def _upper_country(cls, v: str | None) -> str | None:
        return v.upper() if v else v


class OrganizationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    slug: str
    industry: str | None = None
    country: str | None = None
    created_at: datetime
    is_demo: bool = False
    fix_within_days: FixWithinDays = FixWithinDays()
    #: One person or a team (§236). Solo leaves out members, ownership rules and task owners.
    mode: OrganizationMode = OrganizationMode.TEAM
    #: The lowest severity whose acceptance waits for a second approver, or null (§239). Kept
    #: through a switch to solo, where it does nothing, and in force again with a team.
    acceptance_approval_from: Severity | None = None

    @field_validator("mode", mode="before")
    @classmethod
    def _team_until_written(cls, v: object) -> object:
        # An organization not yet flushed has no mode; the column's default is TEAM.
        return OrganizationMode.TEAM if v is None else v


class OrganizationMembershipOut(OrganizationOut):
    """An organization, and the caller's role in it."""

    role: Role


class LeftDemoOut(BaseModel):
    left: bool


class OrganizationDeletedOut(BaseModel):
    deleted: UUID
