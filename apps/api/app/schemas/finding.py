from datetime import date, datetime
from typing import Any, Literal
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
from app.schemas.attack_path import AttackPathOut
from app.schemas.rule import RemediationSpecOut


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


class RiskPathStepOut(BaseModel):
    """One hop of a route as a risk stores it.

    Written at scan time (``services/scan/correlation.py``) and read back from
    JSONB, so every field is a plain string: a value renamed in an enum since
    would otherwise turn a stored route into a 500. Narrower than the hop the
    attack-path routes compute live -- no ``facts`` or ``detail``, which were
    never stored.
    """

    source: str
    source_id: str
    relationship: str
    target: str
    target_id: str
    description: str


class RiskOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    # Whether this is one observation scored for its asset, or several of them
    # seen as a route. The two rank against each other in the same list, so the
    # list has to say which is which.
    kind: RiskKind = RiskKind.FINDING
    # The route, hop by hop. Empty for a finding risk, which is about one asset
    # and has no route to describe.
    path: list[RiskPathStepOut] = Field(default_factory=list)
    title: str
    description: str
    risk_score: float
    risk_level: Level
    status: RiskStatus
    asset_criticality: Level
    data_sensitivity: Level
    internet_exposure: Level
    exploitability: float
    business_impact: float
    # Six weighted components on a finding risk; the worst member, amplifier
    # and hops on a route. Stored as scored, so left open.
    score_breakdown: dict[str, Any] = Field(default_factory=dict)
    #: The reading a route was last seen in. ``None`` on a finding risk, which
    #: is about one asset and takes its reading from the finding, and on a route
    #: recorded before this was tracked.
    observed_scan_id: UUID | None = None
    #: When an accepted risk comes back to the queue. For a finding risk the
    #: earliest end date among its members' running acceptances, for a route
    #: its own. ``None`` when not accepted, or accepted with no end date.
    accepted_until: datetime | None = None
    due_date: date | None = None


class RiskListItemOut(RiskOut):
    """A queue row, which has to say what deciding about it would decide."""

    # Open findings this risk covers -- forty on a grouped risk -- and, on a
    # finding risk, open routes it is on (DECISIONS.md section 103).
    finding_count: int
    route_count: int


class RiskMemberOut(BaseModel):
    """A finding a risk was built from, named enough to be recognised."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    rule_id: str
    title: str
    severity: Severity
    status: FindingStatus


class RiskDetailOut(RiskOut):
    """One risk, with the findings it was built from."""

    # When the route was last seen. ``None`` where a route predates this being
    # tracked, or where the scan that saw it has been pruned. Both mean "we
    # cannot say when", which the page must not render as "just now".
    observed_at: datetime | None
    findings: list[RiskMemberOut]


class RiskStatusOut(BaseModel):
    """What a bulk decision left each risk at."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    status: RiskStatus


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


class RemediationUpdatedOut(RemediationOut):
    """A task after a change, with what happens next where that is not obvious."""

    #: Set when the task is marked done: that does not resolve the finding --
    #: only an observation does -- and the customer is told CloudGuard will
    #: look again. ``None`` otherwise.
    note: str | None = None


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


class FindingDetail(FindingOut):
    """Everything the finding detail page needs to answer WHAT / WHY / HOW BAD /
    HOW DO I FIX IT / DID THE FIX WORK (UI.md section 3)."""

    risk: RiskOut | None = None
    priority: Priority
    estimated_effort_minutes: int
    timeline: list[FindingEventOut]
    # Null until somebody claims a fix. Present afterwards whether or not
    # CloudGuard has settled it -- "checking, and it has not appeared yet" is
    # the answer a customer who has just done the work is waiting for.
    verification: VerificationOut | None = None
    # When an accepted finding comes back to the queue. ``None`` when it is not
    # accepted, or accepted with no end date (DECISIONS.md section 104).
    accepted_until: datetime | None = None
    # From the rule registry, as it is today. ``None`` for a finding whose rule
    # has since left the registry, which is a fact about CloudGuard rather than
    # about the finding.
    rule_name: str | None = None
    rationale: str | None = None
    category: str | None = None
    #: What must become true, and the CLI, Terraform and policy generated from
    #: it -- the object the rules routes publish.
    remediation_spec: RemediationSpecOut | None = None
    compliance_mappings: dict[str, list[str]] = Field(default_factory=dict)


class FindingAttackPathOut(AttackPathOut):
    """A route through a finding's asset, and where on it the asset sits: an
    entry is how somebody gets in, a target is what they are coming for, and a
    step between is the link most likely worth cutting."""

    asset_role: Literal["ENTRY", "STEP", "TARGET"]


class FindingAttackPathsMeta(BaseModel):
    total: int
    #: The asset's provider id; ``None`` for a finding tied to no asset.
    asset: str | None


class FindingProvenanceOut(BaseModel):
    rule_id: str
    # The rule as it was when this finding was raised, not as it is now.
    rule_version: str
    #: ``None`` when no citation was recorded; an empty list would say the rule
    #: reads nothing, and the two must not be answered the same way.
    evidence: list[EvidenceCitationOut] | None


class FindingProvenanceMeta(BaseModel):
    total: int
    recorded: bool


class RescanQueuedOut(BaseModel):
    scan_id: UUID
    finding_id: UUID
    message: str


class IacEditOut(BaseModel):
    attribute: str
    #: The value as the file had it; ``None`` where the argument was added.
    before: str | None
    after: str
    #: 1-based, in the edited file.
    line: int


class IacDiffOut(BaseModel):
    """A finding's fix written into the customer's Terraform, or why it was not.

    A decline is an answer, not an error (DECISIONS.md §184): the file was read
    and the edit would have needed a guess. ``decline_reason`` is for a program
    to branch on; ``detail`` is the sentence a person reads.
    """

    filename: str
    outcome: Literal["patched", "declined"]
    diff: str | None
    edits: list[IacEditOut]
    decline_reason: str | None
    detail: str | None
    #: From the lock file, where one was sent. ``None`` means not known -- the
    #: edit was checked against ``checked_against``, not against the release
    #: the customer runs.
    provider_version: str | None
    checked_against: list[str]
    #: How the block was found: ``name`` (its literal name is the asset's) or
    #: ``sole_block`` (the only block of the type in the uploaded file, its
    #: name an expression -- the reviewer should check it is the right one).
    #: ``None`` on a decline.
    matched_by: Literal["name", "sole_block"] | None = None
