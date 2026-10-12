"""Finding queries and the workflow actions on a finding."""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, NamedTuple
from uuid import UUID

from sqlalchemy import DateTime, Select, case, func, literal, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement, UnaryExpression

from app.compliance.crosswalk import compliance_mappings_for
from app.core.config import get_settings
from app.core.db import commit_unless_externally_managed
from app.core.deps import TenantContext
from app.core.enums import (
    Confidence,
    ContextSource,
    ExceptionStatus,
    FindingEvent,
    FindingStatus,
    Level,
    RiskKind,
    Severity,
    TaskOutcome,
)
from app.core.errors import FindingNotFound, ValidationFailed
from app.models.cloud_connection import CloudConnection
from app.models.finding import Finding, FindingEvidence
from app.models.history import FindingEventRecord
from app.models.remediation import RiskException
from app.models.resource import ResourceRecord
from app.models.risk import Risk, RiskFinding
from app.models.rule import Rule
from app.models.scan import Evidence, EvidenceBlob, Scan
from app.models.verification import RemediationVerification
from app.remediation import Comparison, ExpectedState, azure_policy, terraform_hints
from app.risk import confidence
from app.risk.confidence import Assessment, AssetContext
from app.risk.scorer import default_scorer
from app.risk.triage import acceptance_expiry, finding_risk_status
from app.rules.registry import get_rule
from app.schemas.confidence import ConfidenceOut
from app.schemas.finding import (
    ConditionOut,
    EvidenceCitationOut,
    EvidencePackageOut,
    LimitationOut,
    PackageFindingOut,
    PackageRemediationOut,
    PackageResourceOut,
    PackageRuleOut,
    PackageVerificationOut,
    VerificationOut,
)
from app.schemas.rule import (
    CollectionStateOut,
    EqualsStateOut,
    ExpectedStateOut,
    RemediationSpecOut,
    TerraformHintOut,
)
from app.services import approval_policy
from app.services import audit as audit_service
from app.services import verification as verification_service

SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}

# The same ranking expressed for the database, so "worst first" survives
# pagination. Sorting severity in Python could only ever order the page it was
# handed, which puts the CRITICAL on page four below the LOW on page one.
SEVERITY_SORT = case(SEVERITY_ORDER, value=Finding.severity, else_=9)

# Every ordering ends on the id. Scores and detection times tie constantly --
# one scan stamps every finding it raises -- and PostgreSQL orders ties however
# the plan happens to, so without it the same offset can return a different
# row on the next request and a page can repeat or skip a finding.
SORTS: dict[str, tuple[UnaryExpression[Any], ...]] = {
    # Risk first by default: the product's claim is that it tells you what
    # matters here, not what the rulebook says in the abstract.
    "risk": (
        Finding.risk_score.desc().nullslast(),
        Finding.last_detected_at.desc(),
        Finding.id.asc(),
    ),
    "severity": (SEVERITY_SORT.asc(), Finding.risk_score.desc().nullslast(), Finding.id.asc()),
    "recent": (Finding.last_detected_at.desc(), Finding.id.asc()),
}


@dataclass(frozen=True)
class FindingFilters:
    """What narrows the findings list, short of confidence (which is filtered and counted)."""

    severity: Severity | None = None
    status: FindingStatus | None = None
    rule_id: str | None = None
    resource_id: UUID | None = None
    evidence_id: UUID | None = None
    environment: str | None = None
    search: str | None = None


class FindingRow(NamedTuple):
    """A listed finding, its asset, and the two facts its confidence is judged from."""

    finding: Finding
    resource: ResourceRecord | None
    #: The oldest reading it cites, or when it was last detected where none is cited.
    observed_at: datetime
    #: Its connection's ``scan_interval_hours``; ``None`` where scanned by hand.
    interval_hours: int | None


def _observed_at_sql() -> ColumnElement[datetime]:
    """When the provider was read for a finding: its oldest citation.

    The oldest rather than the newest, because a finding is only as current as
    the stalest reading it rests on. A finding with no citation -- raised before
    citations were recorded, or by a rule that reads nothing -- is as old as its
    last detection, which is the last time anything looked.
    """
    oldest = (
        select(func.min(FindingEvidence.collected_at))
        .where(FindingEvidence.finding_id == Finding.id)
        .correlate(Finding)
        .scalar_subquery()
    )
    return func.coalesce(oldest, Finding.last_detected_at)


def _confidence_sql(
    observed_at: ColumnElement[datetime],
    interval_hours: ColumnElement[int | None],
    now: datetime,
) -> ColumnElement[str]:
    """``confidence.assess_finding`` in SQL, so the list can filter and count by it.

    Built from the same constants rather than restated, and held to the Python
    by an integration test over the same rows (``test_finding_confidence``).
    """
    interval = func.make_interval(
        0, 0, 0, 0, func.coalesce(interval_hours, confidence.MANUAL_INTERVAL_HOURS)
    )
    fresh_until = observed_at + interval * confidence.FRESH_INTERVALS
    stale_at = observed_at + func.greatest(
        interval * confidence.STALE_INTERVALS,
        func.make_interval(0, 0, 0, confidence.STALE_FLOOR.days),
    )
    # NULL for a tenant-wide finding, whose asset columns are all NULL, which a
    # CASE reads as false: a finding with no asset has no context to doubt.
    context_doubt = or_(
        ResourceRecord.criticality == Level.UNKNOWN,
        ResourceRecord.data_sensitivity == Level.UNKNOWN,
        ResourceRecord.criticality_source == ContextSource.INFERRED,
        ResourceRecord.data_sensitivity_source == ContextSource.INFERRED,
    )
    now_sql = literal(now, DateTime(timezone=True))
    return case(
        (now_sql >= stale_at, literal(Confidence.LOW.value)),
        (or_(now_sql >= fresh_until, context_doubt), literal(Confidence.MEDIUM.value)),
        else_=literal(Confidence.HIGH.value),
    )


def _filtered_findings(tenant: TenantContext, filters: FindingFilters, now: datetime) -> Select:
    """Findings matching ``filters``, joined to what their confidence is judged from.

    The connection is the asset's, or the scan's for a tenant-wide finding.
    Columns: the finding, its asset, ``observed_at``, ``interval_hours`` and
    ``confidence``.
    """
    observed_at = _observed_at_sql()
    interval_hours: ColumnElement[int | None] = CloudConnection.scan_interval_hours.expression
    stmt = (
        select(
            Finding,
            ResourceRecord,
            observed_at.label("observed_at"),
            interval_hours.label("interval_hours"),
            _confidence_sql(observed_at, interval_hours, now).label("confidence"),
        )
        .outerjoin(ResourceRecord, ResourceRecord.id == Finding.resource_id)
        .outerjoin(Scan, Scan.id == Finding.scan_id)
        .outerjoin(
            CloudConnection,
            CloudConnection.id == func.coalesce(ResourceRecord.connection_id, Scan.connection_id),
        )
        .where(Finding.organization_id == tenant.organization_id)
    )
    return _narrowed(stmt, tenant, filters)


async def list_findings(
    session: AsyncSession,
    tenant: TenantContext,
    filters: FindingFilters,
    *,
    confidence_level: Confidence | None,
    sort: str,
    limit: int,
    offset: int,
    now: datetime,
) -> tuple[list[FindingRow], int]:
    """One page of findings, each with its asset, and how many match in all.

    Filtered, ordered and cut in the database: a page that filtered only the rows it held would
    search one page of an estate and report "nothing matches" for the rest. Confidence filters
    and never sorts (DECISIONS.md §262): the order is the risk's.
    """
    stmt = _filtered_findings(tenant, filters, now)
    if confidence_level is not None:
        level = stmt.selected_columns.confidence
        stmt = stmt.where(level == confidence_level.value)

    total = (await session.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (await session.execute(stmt.order_by(*SORTS[sort]).limit(limit).offset(offset))).all()
    return [
        FindingRow(finding, resource, observed_at, interval)
        for finding, resource, observed_at, interval, _level in rows
    ], total


async def confidence_counts(
    session: AsyncSession, tenant: TenantContext, filters: FindingFilters, now: datetime
) -> dict[Confidence, int]:
    """How the filtered findings divide by confidence, every level present."""
    inner = _filtered_findings(tenant, filters, now).subquery()
    rows = await session.execute(
        select(inner.c.confidence, func.count()).group_by(inner.c.confidence)
    )
    counted: dict[str, int] = {str(level): int(count) for level, count in rows.tuples().all()}
    return {level: int(counted.get(level.value, 0)) for level in Confidence}


def _narrowed(stmt: Select, tenant: TenantContext, filters: FindingFilters) -> Select:
    """The findings list's filters, applied to a statement already joined to the asset."""
    severity, status, rule_id = filters.severity, filters.status, filters.rule_id
    resource_id, evidence_id = filters.resource_id, filters.evidence_id
    environment, search = filters.environment, filters.search

    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if status:
        stmt = stmt.where(Finding.status == status)
    if rule_id:
        stmt = stmt.where(Finding.rule_id == rule_id)
    if resource_id:
        stmt = stmt.where(Finding.resource_id == resource_id)
    if evidence_id:
        # "What rests on this reading" -- the citation chain walked from the
        # evidence end, which is what a person looking at a failed or stale
        # listing on the scans page is actually asking.
        #
        # Filtered on the reading rather than on its key, because a key spans
        # every subscription and every scan that read it: the count offered
        # beside a reading and the rows this returns have to be the same set,
        # or the link is a number that does not survive being clicked.
        stmt = stmt.where(
            Finding.id.in_(
                select(FindingEvidence.finding_id).where(
                    FindingEvidence.organization_id == tenant.organization_id,
                    FindingEvidence.evidence_id == evidence_id,
                )
            )
        )
    if environment:
        stmt = stmt.where(ResourceRecord.environment == environment)
    if search:
        # Three ways a person names the same finding: what it is called, the
        # rule that raised it, and the resource it was found on.
        needle = f"%{search}%"
        stmt = stmt.where(
            or_(
                Finding.title.ilike(needle),
                Finding.rule_id.ilike(needle),
                ResourceRecord.name.ilike(needle),
            )
        )
    return stmt


async def resource_of(session: AsyncSession, finding: Finding) -> ResourceRecord | None:
    """The asset a finding was raised on, or ``None`` for a tenant-wide finding."""
    if finding.resource_id is None:
        return None
    return await session.get(ResourceRecord, finding.resource_id)


async def get_finding(session: AsyncSession, tenant: TenantContext, finding_id: UUID) -> Finding:
    finding = (
        await session.execute(
            select(Finding).where(
                Finding.id == finding_id,
                Finding.organization_id == tenant.organization_id,
            )
        )
    ).scalar_one_or_none()
    if finding is None:
        raise FindingNotFound()
    return finding


async def load_detail(session: AsyncSession, tenant: TenantContext, finding: Finding) -> dict:
    """Assemble everything the finding detail page asks for."""
    resource = (
        await session.get(ResourceRecord, finding.resource_id) if finding.resource_id else None
    )

    rule_row = (
        await session.execute(select(Rule).where(Rule.rule_id == finding.rule_id))
    ).scalar_one_or_none()

    risk = await own_risk(session, finding)

    effort = rule_row.estimated_effort_minutes if rule_row else 30
    score = float(finding.risk_score) if finding.risk_score is not None else 0.0
    now = datetime.now(UTC)

    return {
        # How current it is and how settled its rank, judged exactly as the
        # list judged it (DECISIONS.md §262).
        "confidence": ConfidenceOut.of(
            confidence_of(await row_of(session, tenant, finding, now), now)
        ),
        "condition": condition_of(finding),
        "finding": finding,
        "resource": resource,
        "rule": rule_row,
        "risk": risk,
        "priority": default_scorer.priority(score, effort),
        "estimated_effort_minutes": effort,
        # Everything that has happened to it, which two timestamps could not
        # say: a finding raised, fixed, regressed and fixed again looked
        # exactly like one raised and fixed once.
        "timeline": await timeline(session, finding),
        # Where the claimed fix has got to, if somebody has claimed one. The
        # answer to "did my work count" belongs on the page where the work was
        # reported, and the interesting part of it is the sentence: "still
        # failing" and "CloudGuard could not read enough to tell" are the same
        # open finding and entirely different news.
        "verification": await latest_verification(session, finding),
    }


async def accept_risk(
    session: AsyncSession,
    tenant: TenantContext,
    finding: Finding,
    reason: str,
    expires_at: datetime | None,
) -> Finding:
    """Record a deliberate decision not to fix something, or ask for one (§239).

    Accepted is not hidden: the finding keeps its risk score, stays queryable,
    and the decision is written to the audit log (SECURITY.md section 4).

    Where the organization asks a second person to approve acceptances of this
    severity, nothing about the finding changes here: the request is written as
    a PENDING exception, and the finding is returned as it was, which is how the
    caller can tell the acceptance is waiting rather than made.
    """
    if finding.status == FindingStatus.RESOLVED:
        raise ValidationFailed("This finding is already resolved")
    try:
        expires_at = acceptance_expiry(expires_at, datetime.now(UTC))
    except ValueError as exc:
        raise ValidationFailed(str(exc)) from exc

    policy = await approval_policy.policy_for(session, tenant)
    if policy is not None and approval_policy.requires(
        policy, await approval_policy.level_of_finding(session, finding)
    ):
        await approval_policy.request(
            session, tenant, finding_id=finding.id, reason=reason, expires_at=expires_at
        )
        await commit_unless_externally_managed(session)
        return finding

    exception = RiskException(
        organization_id=tenant.organization_id,
        finding_id=finding.id,
        requested_by=tenant.user.id,
        approved_by=tenant.user.id,
        reason=reason,
        expires_at=expires_at,
        status=ExceptionStatus.ACTIVE,
        created_at=datetime.now(UTC),
    )
    await apply_acceptance(session, tenant, finding, exception)
    await commit_unless_externally_managed(session)
    return finding


async def apply_acceptance(
    session: AsyncSession,
    tenant: TenantContext,
    finding: Finding,
    exception: RiskException,
) -> None:
    """Make an acceptance take effect: the exception runs and the finding is accepted.

    The one path for both an acceptance made at once and one a second person
    approved (§239). ``tenant`` is whoever made it take effect, so the timeline
    and the audit row name the approver where there was one. The caller commits.
    """
    # One acceptance at a time. A finding accepted again used to keep the first
    # exception ACTIVE beside the second, and once expiry was enforced the older
    # date would have reopened a finding the newer decision still covered.
    running = update(RiskException).where(
        RiskException.finding_id == finding.id,
        RiskException.status == ExceptionStatus.ACTIVE,
    )
    if exception.id is not None:
        # An approved request is already a row; it is about to become the running one.
        running = running.where(RiskException.id != exception.id)
    await session.execute(running.values(status=ExceptionStatus.REVOKED))
    # A request still waiting on it is answered by this one (§239), whoever made it take effect.
    await approval_policy.withdraw(
        session, finding.organization_id, finding_id=finding.id, keep=exception.id
    )

    _record_event(
        session,
        tenant,
        finding,
        FindingEvent.RISK_ACCEPTED,
        FindingStatus.ACCEPTED_RISK,
        detail=exception.reason,
    )
    finding.status = FindingStatus.ACCEPTED_RISK

    # A risk somebody has decided to live with is not a fix waiting to be
    # confirmed. Left pending, the scheduler would keep starting scans to settle
    # a question that has been answered by a decision instead of by evidence.
    await verification_service.abandon(
        session,
        tenant.organization_id,
        finding.id,
        reason="The risk was accepted, so Cleave stopped checking for a fix.",
    )

    session.add(exception)

    await resync_own_risk(session, finding)

    await record_audit(
        session,
        tenant,
        action="finding.accept_risk",
        resource_type="finding",
        resource_id=finding.id,
        metadata={
            "reason": exception.reason,
            "rule_id": finding.rule_id,
            "requested_by": str(exception.requested_by),
            "second_approval": exception.second_approval,
        },
    )


async def set_status(
    session: AsyncSession,
    tenant: TenantContext,
    finding: Finding,
    status: FindingStatus,
) -> Finding:
    """Move a finding through the workflow.

    RESOLVED is deliberately not settable here. A finding resolves when a scan
    observes the fix, never because someone said so (RULE_ENGINE.md section 3).
    """
    if status == FindingStatus.RESOLVED:
        raise ValidationFailed(
            "Findings cannot be marked resolved by hand. Fix the issue and run a "
            "rescan — Cleave resolves it once a scan confirms the fix."
        )

    _record_event(session, tenant, finding, FindingEvent.STATUS_CHANGED, status)
    if finding.status == FindingStatus.ACCEPTED_RISK and status != FindingStatus.ACCEPTED_RISK:
        # Taking an acceptance back ends it. Left ACTIVE, the exception kept
        # saying the organization had decided to live with a finding that was
        # back in the queue asking for a decision.
        await session.execute(
            update(RiskException)
            .where(
                RiskException.finding_id == finding.id,
                RiskException.status == ExceptionStatus.ACTIVE,
            )
            .values(status=ExceptionStatus.REVOKED)
        )
    finding.status = status
    await resync_own_risk(session, finding)
    await record_audit(
        session,
        tenant,
        action="finding.status_change",
        resource_type="finding",
        resource_id=finding.id,
        metadata={"status": status.value, "rule_id": finding.rule_id},
    )
    await commit_unless_externally_managed(session)
    return finding


def _record_event(
    session: AsyncSession,
    tenant: TenantContext,
    finding: Finding,
    event: FindingEvent,
    new_status: FindingStatus,
    *,
    detail: str | None = None,
) -> None:
    """Write the transition to the finding's own timeline.

    Beside the audit log rather than instead of it, and the difference is who
    is asking. The audit log answers "what has anybody in this organization
    done", for a security reviewer; this answers "what happened to *this
    finding*", for whoever is looking at it -- and only the second is complete,
    because it also holds the transitions a scan made, which no person did.
    """
    session.add(
        FindingEventRecord(
            organization_id=tenant.organization_id,
            finding_id=finding.id,
            scan_id=finding.scan_id,
            user_id=tenant.user.id,
            event=event,
            previous_status=finding.status,
            current_status=new_status,
            detail=detail,
            observed_at=datetime.now(UTC),
        )
    )


async def timeline(
    session: AsyncSession, finding: Finding, limit: int = 50
) -> list[FindingEventRecord]:
    """Everything that has happened to this finding, newest first."""
    return list(
        (
            await session.execute(
                select(FindingEventRecord)
                .where(FindingEventRecord.finding_id == finding.id)
                .order_by(FindingEventRecord.observed_at.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )


async def latest_verification(
    session: AsyncSession, finding: Finding
) -> RemediationVerification | None:
    """The most recent claim that this finding was fixed, settled or not.

    Newest rather than pending, because a settled verification is the more
    useful answer once there is one: a customer looking at a finding that is
    still open after they fixed it wants to be told why, not told nothing on
    the grounds that CloudGuard has finished asking.
    """
    return (
        await session.execute(
            select(RemediationVerification)
            .where(RemediationVerification.finding_id == finding.id)
            .order_by(RemediationVerification.claimed_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


async def own_risk(session: AsyncSession, finding: Finding) -> Risk | None:
    """The risk that is *about* this finding, rather than any risk containing it.

    A finding used to have at most one risk, so every caller here read the
    junction with ``scalar_one_or_none`` and got it. Scenario risks broke that
    assumption without breaking the query's shape: a finding on an attack path
    is linked twice -- once to its own risk and once to the route it is part of
    -- so those callers began raising ``MultipleResultsFound`` on exactly the
    findings the graph had found something interesting about.

    Filtering on the kind restores the guarantee rather than papering over it
    with ``first()``: there is exactly one FINDING risk per finding, and picking
    an arbitrary row would have quietly attached a remediation task, or an
    accepted-risk status, to a route instead of to the thing somebody clicked.
    """
    return (
        await session.execute(
            select(Risk)
            .join(RiskFinding, RiskFinding.risk_id == Risk.id)
            .where(
                RiskFinding.finding_id == finding.id,
                Risk.kind == RiskKind.FINDING,
            )
        )
    ).scalar_one_or_none()


async def accepted_until(session: AsyncSession, finding: Finding) -> datetime | None:
    """The end date of the acceptance running on this finding, if it has one."""
    if finding.status != FindingStatus.ACCEPTED_RISK:
        return None
    return (
        await session.execute(
            select(RiskException.expires_at)
            .where(
                RiskException.finding_id == finding.id,
                RiskException.status == ExceptionStatus.ACTIVE,
            )
            .order_by(RiskException.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


async def resync_own_risk(session: AsyncSession, finding: Finding) -> None:
    """Bring the finding's own risk into line with every member it has.

    Written through rather than set: a grouped risk is forty findings, and
    accepting one of them is not accepting the risk (``finding_risk_status``).
    """
    risk = await own_risk(session, finding)
    if risk is None:
        return
    members = (
        await session.execute(
            select(Finding.status)
            .join(RiskFinding, RiskFinding.finding_id == Finding.id)
            .where(RiskFinding.risk_id == risk.id)
        )
    ).scalars()
    risk.status = finding_risk_status(members, risk.status)


# The one audit writer, under the name its callers already use.
record_audit = audit_service.record


def rule_metadata(rule_id: str) -> dict:
    """Rule detail straight from the registry, for fields the mirror omits."""
    rule = get_rule(rule_id)
    if rule is None:
        return {}
    return {
        "rule_name": rule.name,
        "rationale": rule.rationale,
        "category": rule.category,
        "estimated_effort_minutes": rule.estimated_effort_minutes,
        # The machine-readable half of the remediation, beside the prose the
        # finding already carries. Read from the registry rather than the
        # finding, deliberately: the prose is snapshot-copied so an old finding
        # keeps the guidance it was raised with, while this describes what
        # CloudGuard checks *today* -- and being told to satisfy a condition
        # that is no longer the one being checked would be worse than not being
        # told at all.
        "remediation_spec": remediation_detail(rule_id),
        # Every control this rule is evidence toward, including those the
        # crosswalk adds (DECISIONS.md section 168).
        "compliance_mappings": compliance_mappings_for(rule.rule_id, rule.compliance_mappings),
    }


def _state_json(state: ExpectedState) -> ExpectedStateOut:
    """One expected state, in a shape that cannot be misread.

    ``comparison`` travels with the value because without it a collection
    expectation serializes as ``equals: null``, which reads as "this must be
    null" rather than "this must not be empty". The witness goes out too: for a
    network rule it is the clearest statement of what is being looked for, and
    a customer can compare it against what they have.
    """
    if state.comparison is Comparison.EQUALS:
        return EqualsStateOut(
            field=state.field,
            comparison=state.comparison,
            describes=state.describes,
            equals=state.equals,
            also_accepts=list(state.also_accepts),
            example=state.example,
        )
    return CollectionStateOut(
        field=state.field,
        comparison=state.comparison,
        describes=state.describes,
        example=state.example,
    )


def remediation_detail(rule_id: str) -> RemediationSpecOut | None:
    """What must become true, plus the artifacts generated from that.

    ``None`` where a rule has no declaration yet, which is a different answer
    from a declaration saying no policy can enforce it: the first is work not
    done, the second is a fact about the check. The API keeps them apart because
    a customer reading "no preventive policy" deserves to know which they are
    looking at.
    """
    rule = get_rule(rule_id)
    if rule is None or rule.remediation_spec is None:
        return None

    spec = rule.remediation_spec
    policy = azure_policy(rule.rule_id, rule.name, spec)
    return RemediationSpecOut(
        expected_state=[_state_json(state) for state in spec.expected],
        # Who the expectation is about, where it is not everyone. A rule that
        # returns NOT_APPLICABLE for every ordinary account is not passing them.
        applies_when=spec.applies_when,
        cli=list(spec.cli),
        terraform=[TerraformHintOut(**hint) for hint in terraform_hints(spec)],
        # Present where a policy can genuinely refuse this misconfiguration,
        # null where none can. A definition invented for the second case would
        # deploy and check nothing.
        azure_policy=policy,
        enforceable=spec.enforceable,
        notes=spec.notes,
    )


async def load_provenance(
    session: AsyncSession, tenant: TenantContext, finding: Finding
) -> list[dict] | None:
    """Where this finding's evidence came from.

    ``None`` rather than ``[]`` for a finding with no citations, and the
    distinction is the point: an empty list would conflate "this rule reads
    nothing" with "this finding was raised before CloudGuard recorded where its
    evidence came from", and a customer asking how we know cannot be answered
    with a shrug that looks like an answer.

    Joined out to the reading itself where it survives, so outcome, item count
    and the permissions the read was made under come along. Where the scan has
    since been pruned the citation still stands on its own copied fields --
    which is why they are copied.
    """
    links = (
        (
            await session.execute(
                select(FindingEvidence)
                .where(
                    FindingEvidence.organization_id == tenant.organization_id,
                    FindingEvidence.finding_id == finding.id,
                )
                .order_by(FindingEvidence.evidence_key)
            )
        )
        .scalars()
        .all()
    )
    if not links:
        return None

    evidence_ids = [link.evidence_id for link in links if link.evidence_id]
    readings = (
        {
            row.id: row
            for row in (
                await session.execute(
                    select(Evidence).where(
                        Evidence.organization_id == tenant.organization_id,
                        Evidence.id.in_(evidence_ids),
                    )
                )
            )
            .scalars()
            .all()
        }
        if evidence_ids
        else {}
    )

    # Which payloads are still held. One query for all of them rather than one
    # per citation, and asked of the blob store rather than assumed from the
    # hash being non-null: a hash records what was read, and retention prunes
    # the bytes on its own schedule.
    hashes = [link.content_hash for link in links if link.content_hash]
    stored: set[str] = set()
    if hashes:
        stored = set(
            (
                await session.execute(
                    select(EvidenceBlob.content_hash).where(
                        EvidenceBlob.organization_id == tenant.organization_id,
                        EvidenceBlob.content_hash.in_(hashes),
                    )
                )
            )
            .scalars()
            .all()
        )

    now = datetime.now(UTC)
    out: list[dict] = []
    for link in links:
        reading = readings.get(link.evidence_id) if link.evidence_id else None
        out.append(
            {
                "evidence_key": link.evidence_key,
                "cloud_account_id": reading.cloud_account_id if reading else None,
                "outcome": reading.outcome if reading else None,
                "item_count": reading.item_count if reading else None,
                "permissions": list(reading.permissions or []) if reading else [],
                # What was called, and under which contract. The api-version is
                # the half that settles an argument: a field absent from the
                # capture is a setting nobody set, or a contract too old to
                # return it, and only the second is CloudGuard's doing.
                "endpoints": list(reading.endpoints or []) if reading else [],
                "content_hash": link.content_hash,
                "collected_at": link.collected_at,
                # Computed here rather than left to the client, because the
                # client would compute it against its own clock and a reading
                # that looks four days old on one machine and four hours old on
                # another is worse than no figure at all.
                "age_seconds": max(0, int((now - link.collected_at).total_seconds())),
                "source_scan_id": link.source_scan_id,
                "payload_available": bool(link.content_hash and link.content_hash in stored),
            }
        )
    return out


# -- Confidence and the evidence package (DECISIONS.md §262) --------------------


def asset_context(resource: ResourceRecord | None) -> AssetContext | None:
    """The context a finding's rank multiplies, as its asset records it."""
    if resource is None:
        return None
    return AssetContext(
        criticality=resource.criticality,
        criticality_source=resource.criticality_source,
        data_sensitivity=resource.data_sensitivity,
        data_sensitivity_source=resource.data_sensitivity_source,
    )


def confidence_of(row: FindingRow, now: datetime) -> Assessment:
    """A listed finding's confidence, from the same inputs the list filtered it on."""
    return confidence.assess_finding(
        row.observed_at, row.interval_hours, asset_context(row.resource), now
    )


async def row_of(
    session: AsyncSession, tenant: TenantContext, finding: Finding, now: datetime
) -> FindingRow:
    """One finding as the list would carry it.

    Read through the list's own statement rather than assembled beside it, so a
    finding's page and its row in the list cannot disagree about its confidence.
    """
    stmt = _filtered_findings(tenant, FindingFilters(), now).where(Finding.id == finding.id)
    row, resource, observed_at, interval_hours, _level = (await session.execute(stmt)).one()
    return FindingRow(row, resource, observed_at, interval_hours)


def condition_of(finding: Finding) -> list[ConditionOut]:
    """What must be true for the finding to close, beside what its excerpt recorded.

    The expected half is the rule's declaration as checked today -- the same one
    the fix is generated from -- and the observed half is this finding's own
    excerpt. A field the excerpt does not carry is said to be unrecorded rather
    than shown as null: an absent key and a setting that is null are different
    facts, and only one of them is about the asset.
    """
    rule = get_rule(finding.rule_id)
    if rule is None or rule.remediation_spec is None:
        return []
    observed = finding.evidence or {}
    out: list[ConditionOut] = []
    for state in rule.remediation_spec.expected:
        scalar = state.comparison is Comparison.EQUALS
        out.append(
            ConditionOut(
                field=state.field,
                describes=state.describes,
                comparison=state.comparison,
                expected=state.equals if scalar else state.example,
                also_accepts=list(state.also_accepts) if scalar else [],
                observed=observed.get(state.field),
                observed_recorded=state.field in observed,
            )
        )
    return out


def limitations_of(
    finding: Finding,
    citations: list[dict] | None,
    condition: list[ConditionOut],
) -> list[LimitationOut]:
    """Where the record behind a finding is thinner than a reader might assume.

    Facts about the record, never about the estate, and each says what it means
    in a sentence: a list of codes would be a list a customer has to look up.
    """
    out: list[LimitationOut] = []
    rule = get_rule(finding.rule_id)
    if citations is None:
        out.append(
            LimitationOut(
                code="NOT_CITED",
                detail=(
                    "Cleave did not record where this finding's evidence came from; the next "
                    "scan that detects it will."
                ),
            )
        )
    else:
        pruned = sorted(c["evidence_key"] for c in citations if not c["payload_available"])
        if pruned:
            out.append(
                LimitationOut(
                    code="PAYLOAD_PRUNED",
                    detail=(
                        f"The capture behind {', '.join(pruned)} is no longer stored; its hash "
                        "still identifies exactly what was read."
                    ),
                )
            )
        out.extend(
            LimitationOut(
                code="READING_INCOMPLETE",
                detail=(
                    f"The {c['evidence_key']} reading came back {str(c['outcome']).lower()}: what "
                    "it listed is real, and what it missed is not known."
                ),
            )
            for c in citations
            if c["outcome"] is not None and c["outcome"] != TaskOutcome.COMPLETE
        )
    if rule is None:
        out.append(
            LimitationOut(
                code="RULE_RETIRED",
                detail=f"{finding.rule_id} has left Cleave's rules; nothing checks this today.",
            )
        )
    elif rule.version != finding.rule_version:
        out.append(
            LimitationOut(
                code="RULE_CHANGED",
                detail=(
                    f"Raised by version {finding.rule_version}; Cleave checks version "
                    f"{rule.version} today, which the next scan applies."
                ),
            )
        )
    if rule is not None and not condition:
        out.append(
            LimitationOut(
                code="CONDITION_UNDECLARED",
                detail=(
                    "This rule declares no machine-readable expected state; its condition is "
                    "the rule's description."
                ),
            )
        )
    return out


async def evidence_package(
    session: AsyncSession, tenant: TenantContext, finding: Finding, now: datetime
) -> EvidencePackageOut:
    """Everything a finding rests on, as one document to attach to a ticket or an audit.

    Assembled from what the detail page shows, never from a second account of
    it: the same confidence the list filtered on, the same citations "How we
    know" lists, the same condition the fix is generated from.
    """
    row = await row_of(session, tenant, finding, now)
    citations = await load_provenance(session, tenant, finding)
    rule = get_rule(finding.rule_id)
    condition = condition_of(finding)
    verification = await latest_verification(session, finding)
    keys = sorted({str(c["evidence_key"]) for c in citations or []})
    reads = f" ({', '.join(keys)})" if keys else ""
    return EvidencePackageOut(
        generated_at=now,
        build=get_settings().railway_git_commit_sha or None,
        finding=PackageFindingOut.model_validate(finding),
        resource=PackageResourceOut.model_validate(row.resource) if row.resource else None,
        rule=PackageRuleOut(
            rule_id=finding.rule_id,
            version=finding.rule_version,
            current_version=rule.version if rule else None,
            name=rule.name if rule else None,
        ),
        condition=condition,
        observed=dict(finding.evidence or {}),
        citations=(
            [EvidenceCitationOut.model_validate(c) for c in citations]
            if citations is not None
            else None
        ),
        confidence=ConfidenceOut.of(confidence_of(row, now)),
        limitations=limitations_of(finding, citations, condition),
        remediation=PackageRemediationOut(
            guidance=finding.remediation, spec=remediation_detail(finding.rule_id)
        ),
        verification=PackageVerificationOut(
            method="RESCAN",
            detail=(
                f"A scan reads the same evidence again{reads} and closes this finding when the "
                "check passes. Nobody can close it by hand."
            ),
            latest=VerificationOut.model_validate(verification) if verification else None,
        ),
    )
