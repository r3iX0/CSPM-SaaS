from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import (
    ConnectionScope,
    Provider,
    ScanStatus,
    ScanStepKind,
    ScanStepStatus,
    ScanTrigger,
    TaskOutcome,
)
from app.schemas.common import ClosedModel, RequestModel


class ScanCreate(RequestModel):
    model_config = ConfigDict(
        json_schema_extra={
            "examples": [{"cloud_account_id": "6b1e0c2a-5d1f-4a52-9a43-2f7f4f7d9c10"}]
        }
    )

    cloud_account_id: UUID


class ScanOut(BaseModel):
    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "examples": [
                {
                    "id": "0f4c8a52-7d3e-4e0b-8a52-1c9d2b7e6f31",
                    "cloud_account_id": None,
                    "connection_id": "6b1e0c2a-5d1f-4a52-9a43-2f7f4f7d9c10",
                    "status": "QUEUED",
                    "resource_count": 0,
                    "rule_count": 0,
                    "finding_count": 0,
                    "created_at": "2026-10-01T09:30:00Z",
                    "trigger": "MANUAL",
                }
            ]
        },
    )

    id: UUID
    # One of these says what the scan covered. ``connection_id`` is the
    # tenant-wide form; ``cloud_account_id`` is a single subscription.
    cloud_account_id: UUID | None = None
    connection_id: UUID | None = None
    status: ScanStatus
    started_at: datetime | None = None
    completed_at: datetime | None = None
    resource_count: int
    rule_count: int
    finding_count: int
    error_message: str | None = None
    #: As stored on the scan, by category.
    collection_errors: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    # True when nothing has collected this scan for long enough that a worker
    # is probably not running at all.
    stuck_in_queue: bool = False

    triggered_by_user_id: UUID | None = None
    # Why it ran. A NULL user stopped being able to carry this once scans could
    # start themselves: an old manual scan whose user record had gone looked
    # exactly like a scheduled one.
    trigger: ScanTrigger = ScanTrigger.MANUAL
    # Set when this run re-evaluated an earlier scan's snapshot rather than
    # collecting. ``evaluation_only`` says it re-evaluated a capture that is no
    # longer current, so its counts describe what the rules would have found and
    # no finding was created, resolved or reopened.
    replay_of_scan_id: UUID | None = None
    evaluation_only: bool = False
    progress_done: int = 0
    progress_total: int = 0
    # Live while running, fixed once finished.
    duration_seconds: int | None = None


class ScopeSubscriptionOut(ClosedModel):
    subscription_id: str | None
    subscription_name: str | None
    in_scope: bool


class ScanScopeOut(ClosedModel):
    """What a scan pointed at, and which identity read it
    (``services.scans.scan_context``)."""

    #: Every subscription the scan covered; a list of one for a single one.
    subscriptions: list[ScopeSubscriptionOut]
    subscription_count: int
    provider: Provider | None
    #: The first subscription, for a panel that names one.
    subscription_id: str | None
    subscription_name: str | None
    tenant_id: str | None
    connection_name: str | None
    scope_type: ConnectionScope | None
    scope_path: str | None
    #: CloudGuard's service principal in the customer's own tenant: the object
    #: id they can look up in their directory and revoke.
    service_principal_object_id: str | None
    role_version: str | None


class ScanStageOut(ClosedModel):
    """One stage, what it did and how long it took (``services.scans.scan_stages``)."""

    stage: ScanStepKind
    #: The subscription it ran for, or the directory; ``None`` for a stage
    #: over the whole scan.
    scope: str | None
    status: ScanStepStatus
    attempt: int
    #: Live while it runs.
    duration_seconds: float | None
    error: str | None
    #: The sub-phase ANALYZE is in, written fenced on the attempt.
    phase: str | None


class ScanDetailOut(ScanOut):
    """A single scan with everything the detail panel shows.

    Separate from ``ScanOut`` because the list renders dozens of these and none
    of it is cheap: the scope panel reads two more tables and the breakdown
    aggregates findings. The event stream pushes this same document.
    """

    scope: ScanScopeOut | None = None
    #: Open findings this scan most recently detected, by severity.
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    # What each stage did and how long it took. Answers "why was this scan
    # slow", which had no answer while a scan was one task with one start and
    # one end time.
    stages: list[ScanStageOut] = Field(default_factory=list)
    # How many unresolved findings a purge would take with it, so the
    # confirmation can state a number rather than a category.
    purgeable_finding_count: int = 0


class WorkerStatusOut(BaseModel):
    """Whether any worker is listening, asked of the broker rather than guessed."""

    workers: int
    #: Whether the broker itself answered.
    reachable: bool
    detail: str


class ScanDeletedOut(ClosedModel):
    deleted: UUID
    #: Unresolved findings deleted with it; resolved ones never are.
    findings_purged: int


class CollectionTaskOut(ClosedModel):
    """One reading the scan took, and what came of it."""

    #: The subscription's name, or the directory.
    subscription: str
    cloud_account_id: UUID | None
    task: str
    category: str
    outcome: TaskOutcome
    detail: str | None
    item_count: int
    evidence_id: UUID
    #: Findings that rest on this reading.
    finding_count: int
    collected_at: datetime
    #: ``[{"path", "api_version"}]``, as stored.
    endpoints: list[dict[str, str]]


class CollectionStatusOut(ClosedModel):
    """What a scan could and could not read (``services.scans.collection_status``)."""

    tasks: list[CollectionTaskOut]
    total: int
    complete: int
    partial: int
    failed: int
    skipped: int
    #: Refused because the tenant lacks a licence the reading needs.
    unavailable: int
    degraded_categories: list[str]


class CoverageGapOut(BaseModel):
    rule_id: str
    #: ``None`` for a check about the tenant rather than one resource.
    resource_id: UUID | None
    reason: str


class CoverageOut(BaseModel):
    """Reported separately from the security score on purpose.

    Folding coverage into the score would make "why is my score 84?"
    unanswerable without also explaining coverage maths (RISK_ENGINE.md 3).
    """

    coverage_ratio: float
    evaluated: int
    conclusive: int
    unknown: int
    #: Up to two hundred of the checks that could not tell, and why.
    gaps: list[CoverageGapOut] = Field(default_factory=list)
