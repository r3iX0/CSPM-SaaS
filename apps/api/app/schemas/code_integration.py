"""Cleave's GitHub App: linking installations, and the state index they upload (§231)."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.remediation.iac.index import MAX_ENTRIES
from app.schemas.common import RequestModel


class GitHubInstallationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    installation_id: int
    account_login: str
    account_type: str
    connected_at: datetime


class GitHubStatusOut(BaseModel):
    """Whether GitHub is offered here, and the installations this organization has linked."""

    available: bool
    installations: list[GitHubInstallationOut]


class GitHubConnectOut(BaseModel):
    """Where to install the App; GitHub brings the person back with what to link."""

    install_url: str


class GitHubLinkIn(RequestModel):
    """What GitHub hands back after an installation, posted by the signed-in person."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [{"installation_id": 12345678, "code": "<code>", "state": "<state>"}]
        }
    )

    installation_id: int = Field(ge=1)
    code: str = Field(min_length=1, max_length=200)
    state: str = Field(min_length=1, max_length=2000)


class IacIndexEntryIn(RequestModel):
    """One managed azurerm resource: the four fields, and nothing else of its state."""

    address: str = Field(min_length=1, max_length=1000)
    type: str = Field(min_length=1, max_length=100)
    index: int | str | None = None
    id: str = Field(min_length=1, max_length=1100)


class IacIndexIn(RequestModel):
    """One Terraform state's index, from ``tools/iac/github/cleave-index.sh``.

    The repository and the commit come from the job's signed token, never from
    the body, so an upload cannot name a repository it was not run for.
    """

    working_directory: str = Field(default="", max_length=500)
    workspace: str = Field(default="default", pattern=r"^[A-Za-z0-9_.-]{1,100}$")
    entries: list[IacIndexEntryIn] = Field(max_length=MAX_ENTRIES)


class IacIndexOut(BaseModel):
    repository: str
    working_directory: str
    workspace: str
    commit_sha: str
    entries: int


class FixPullRequestIn(RequestModel):
    """Ask for one rule's fix as pull requests, one per repository its assets are in."""

    model_config = ConfigDict(json_schema_extra={"examples": [{"rule_id": "AZ-STO-002"}]})

    rule_id: str = Field(min_length=1, max_length=128)


class FixPullRequestFindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    finding_id: UUID
    address: str
    #: PENDING until the worker has read the repository, then EDITED or DECLINED.
    outcome: str
    reason: str | None = None
    path: str | None = None
    line: int | None = None


class FixPullRequestOut(BaseModel):
    """One rule's fix in one repository, from queued to merged (DECISIONS.md §232)."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    rule_id: str
    repository: str
    #: QUEUED, OPENING, OPEN, MERGED, CLOSED, DECLINED or FAILED.
    state: str
    pr_number: int | None = None
    pr_url: str | None = None
    decline_reason: str | None = None
    detail: str | None = None
    created_at: datetime
    findings: list[FixPullRequestFindingOut] = Field(default_factory=list)


class FixPullRequestsQueuedOut(BaseModel):
    pull_requests: list[FixPullRequestOut]
    #: Failing findings no uploaded state index names, so no pull request covers.
    not_indexed: int
