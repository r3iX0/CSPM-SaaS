from datetime import date, datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.core.enums import (
    FindingEvent,
    FindingStatus,
    Level,
    Priority,
    RemediationStatus,
    RiskKind,
    RiskStatus,
    RuleState,
    Severity,
    TaskOutcome,
    VerificationStatus,
)


class ResourceSummary(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    resource_type: str
    region: str | None = None
    environment: str | None = None
    criticality: Level
    data_sensitivity: Level
    public_exposure: Level


class FindingOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    rule_id: str
    severity: Severity
    status: FindingStatus
    title: str
    description: str
    evidence: dict = Field(default_factory=dict)
    remediation: str
    rule_version: str
    risk_score: float | None = None
    first_detected_at: datetime
    last_detected_at: datetime
    resolved_at: datetime | None = None
    resolved_by_scan_id: UUID | None = None
    resource: ResourceSummary | None = None


class RiskOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    # Whether this is one observation scored for its asset, or several of them
    # seen as a route. The two rank against each other in the same list, so the
    # list has to say which is which.
    kind: RiskKind = RiskKind.FINDING
    # The route, hop by hop. Empty for a finding risk, which is about one asset
    # and has no route to describe.
    path: list = Field(default_factory=list)
    title: str
    description: str
    risk_score: float
    risk_level: Level
    status: str
    asset_criticality: Level
    data_sensitivity: Level
    internet_exposure: Level
    exploitability: float
    business_impact: float
    score_breakdown: dict = Field(default_factory=dict)
    #: The reading a route was last seen in. ``None`` on a finding risk, which
    #: is about one asset and takes its reading from the finding, and on a route
    #: recorded before this was tracked.
    observed_scan_id: UUID | None = None
    #: When an accepted risk comes back to the queue. For a finding risk the
    #: earliest end date among its members' running acceptances, for a route
    #: its own. ``None`` when not accepted, or accepted with no end date.
    accepted_until: datetime | None = None
    due_date: date | None = None


class FindingDetail(FindingOut):
    """Everything the finding detail page needs to answer WHAT / WHY / HOW BAD /
    HOW DO I FIX IT / DID THE FIX WORK (UI.md section 3)."""

    rule_name: str | None = None
    rationale: str | None = None
    category: str | None = None
    compliance_mappings: dict = Field(default_factory=dict)
    estimated_effort_minutes: int = 30
    risk: RiskOut | None = None
    priority: Priority | None = None


class AcceptRiskRequest(BaseModel):
    reason: str = Field(min_length=10, max_length=2000)
    expires_at: datetime | None = None


class RiskStatusRequest(BaseModel):
    """A decision about a risk. ``reason`` is required to accept one."""

    status: RiskStatus
    reason: str | None = Field(default=None, min_length=10, max_length=2000)
    # When the acceptance runs out. A finding risk's goes to each member's
    # exception, a route's to the risk itself; the expiry sweep reopens either
    # once it passes (DECISIONS.md §104). Only with ACCEPTED, and never past.
    expires_at: datetime | None = None


class BulkRiskStatusRequest(RiskStatusRequest):
    # Bounded: a queue page, not the estate. Each finding risk writes an event,
    # an audit row and possibly an exception per member.
    risk_ids: list[UUID] = Field(min_length=1, max_length=100)


class RemediationCreate(BaseModel):
    finding_id: UUID
    assigned_to: UUID | None = None
    due_date: date | None = None
    notes: str | None = Field(default=None, max_length=2000)


class RemediationUpdate(BaseModel):
    status: RemediationStatus | None = None
    assigned_to: UUID | None = None
    due_date: date | None = None
    notes: str | None = Field(default=None, max_length=2000)


class RemediationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    finding_id: UUID
    risk_id: UUID | None = None
    assigned_to: UUID | None = None
    status: RemediationStatus
    priority: Priority
    due_date: date | None = None
    estimated_effort_minutes: int
    notes: str | None = None
    completed_at: datetime | None = None
    created_at: datetime
    # Attack paths through the finding's asset, wherever on them it sits. A
    # fact about the asset, not a promise about the fix: which routes a fix
    # closes is the choke points' question, and only a link can answer it
    # (DECISIONS.md section 127). Filled by the queue listing; zero elsewhere.
    on_routes: int = 0


class VerificationOut(BaseModel):
    """Where a claimed fix has got to.

    ``detail`` is the field that matters and it is written for a person: the
    three ways of not being verified -- too soon, still failing, could not tell
    -- are the same open finding and entirely different news, and a status code
    alone leaves the reader to guess which one they are looking at.
    """

    model_config = ConfigDict(from_attributes=True)

    status: VerificationStatus
    claimed_at: datetime
    # What has to become true for this to close, as it was declared when the
    # claim was made.
    expected_state: list[dict] = []
    attempts: int
    last_state: RuleState | None = None
    next_attempt_at: datetime | None = None
    settled_at: datetime | None = None
    detail: str | None = None


class FindingEventOut(BaseModel):
    """One transition in a finding's life.

    Carries who or what caused it, because "resolved" means something different
    depending on the answer: a scan observing the check pass is verification,
    and a person moving the status is a decision.
    """

    model_config = ConfigDict(from_attributes=True)

    event: FindingEvent
    previous_status: FindingStatus | None = None
    current_status: FindingStatus
    scan_id: UUID | None = None
    user_id: UUID | None = None
    detail: str | None = None
    observed_at: datetime


class EvidenceCitationOut(BaseModel):
    """One reading a finding rests on.

    The citation rather than the excerpt. ``findings.evidence`` already says
    what the rule saw; this says where it came from and whether it can still be
    followed back to the bytes.
    """

    model_config = ConfigDict(from_attributes=True)

    evidence_key: str
    # Where the reading was taken. ``None`` is the directory: a tenant-wide read
    # did not happen in a subscription, and naming one would point somebody at a
    # scope that is fine.
    cloud_account_id: UUID | None = None
    outcome: TaskOutcome | None = None
    item_count: int | None = None
    # The actions the read was made under, so a customer asking "how did you
    # even see this" gets the permission rather than a shrug.
    permissions: list[str] = []
    #: ``[{"path", "api_version"}]``. Empty where the scan has been pruned, or
    #: where the reading predates CloudGuard recording it.
    endpoints: list[dict[str, str]] = []
    content_hash: str | None = None
    # When the *provider* was read. For a carried reading this is older than the
    # scan that raised the finding, which is the question the age answers.
    collected_at: datetime
    age_seconds: int
    source_scan_id: UUID | None = None
    # Whether the payload is still stored. A citation whose bytes have aged out
    # is still a true statement about what was read, and saying so beats a link
    # that 404s when somebody follows it.
    payload_available: bool
