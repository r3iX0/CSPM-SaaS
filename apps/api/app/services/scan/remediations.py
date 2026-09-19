"""A rescan verifies remediation by itself.

Where a previous scan produced FAIL and this one produces PASS, the finding is
resolved automatically and stamped with the scan that proved it. Nobody clicks
"verified" (RULE_ENGINE.md section 3).
"""

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select

from app.core.enums import (
    FindingEvent,
    FindingStatus,
    RiskStatus,
    RuleState,
    VerificationStatus,
)
from app.core.logging import get_logger
from app.models.finding import Finding
from app.models.history import FindingEventRecord
from app.models.resource import ResourceRecord
from app.models.risk import Risk, RiskFinding
from app.models.verification import RemediationVerification
from app.rules.engine import EvaluatedResult, EvaluationReport
from app.services import verification as verification_service
from app.services.scan.context import AnalyzeContext
from app.services.scan.scope import finding_scope, verification_scope

log = get_logger(__name__)


async def verify_remediations(
    ctx: AnalyzeContext, report: EvaluationReport, id_map: dict[str, UUID]
) -> None:
    """Auto-resolve findings this scan proved fixed.

    The scan result *is* the verification. A finding resolves only on an
    explicit PASS -- an UNKNOWN this time round leaves it open, because
    failing to look is not the same as looking and finding nothing.

    Scoped to what this scan actually read, which is a correctness point as
    much as a cost one. Unscoped, a rescan of one subscription loaded every
    open finding in the tenant and compared them against its own passes --
    harmless only because a key from another subscription could not match.
    The scope says the intent instead of relying on that.
    """
    session, org_id, scan = ctx.session, ctx.org_id, ctx.scan
    passed: set[tuple[str, UUID | None]] = {
        (rule_id, id_map.get(provider_id) if provider_id else None)
        for rule_id, provider_id in report.passes
    }
    now = datetime.now(UTC)
    # Settled first, and regardless of whether anything passed. A scan that
    # proves nothing is still an observation: it is how a claimed fix that
    # did not work eventually gets told so, and how one CloudGuard cannot
    # see gets called insufficient evidence rather than left in silence.
    await _settle_verifications(ctx, report, id_map, now=now)

    if not passed:
        await ctx.writer.commit()
        return
    open_findings = (
        (
            await session.execute(
                select(Finding)
                .outerjoin(ResourceRecord, ResourceRecord.id == Finding.resource_id)
                .where(
                    Finding.organization_id == org_id,
                    Finding.status.in_(
                        [FindingStatus.OPEN, FindingStatus.IN_PROGRESS]
                    ),
                    finding_scope(ctx.account_ids, ctx.connection_id),
                )
            )
        )
        .scalars()
        .all()
    )

    resolved = [
        finding
        for finding in open_findings
        if (finding.rule_id, finding.resource_id) in passed
    ]
    if not resolved:
        # Nothing to close, but the verifications settled above are still
        # this scan's work. Returning without committing would throw away
        # the attempt it just spent, and the customer would be told nothing
        # for a scan that did look.
        await ctx.writer.commit()
        return

    # Both lookups batched. They ran inside the loop -- one statement for the
    # risk link and another for the risk -- so proving twenty fixes cost
    # forty round trips, on the one path the product is sold on.
    links = (
        (
            await session.execute(
                select(RiskFinding).where(
                    RiskFinding.organization_id == org_id,
                    RiskFinding.finding_id.in_([f.id for f in resolved]),
                )
            )
        )
        .scalars()
        .all()
    )
    risks = {
        risk.id: risk
        for risk in (
            await session.execute(
                select(Risk).where(Risk.id.in_([link.risk_id for link in links]))
            )
        )
        .scalars()
        .all()
    } if links else {}

    for finding in resolved:
        ctx.writer.add(
            FindingEventRecord,
            finding_id=finding.id,
            scan_id=scan.id,
            event=FindingEvent.RESOLVED,
            previous_status=finding.status,
            current_status=FindingStatus.RESOLVED,
            detail=(
                "A scan observed the check passing on the same asset, "
                "so CloudGuard closed it."
            ),
            observed_at=now,
        )
        finding.status = FindingStatus.RESOLVED
        finding.resolved_at = now
        finding.resolved_by_scan_id = scan.id
        log.info(
            "finding.auto_resolved",
            finding_id=str(finding.id),
            rule_id=finding.rule_id,
            verified_by_scan=str(scan.id),
        )

    # A risk closes when nothing it groups is still open, which for a risk
    # with one finding is the same sentence as before. For a grouped one it
    # is the difference between "the policy is written" and "one of the
    # forty administrators registered an authenticator app": closing on the
    # first member would report the whole problem fixed while thirty-nine
    # accounts still had no second factor.
    #
    # The findings resolved above are excluded by id rather than by status.
    # They are mutated in the session and not yet flushed, so the database
    # still reports them open and would keep every risk alive.
    resolved_ids = [finding.id for finding in resolved]
    risk_ids = {link.risk_id for link in links}
    still_open = set(
        (
            await session.execute(
                select(RiskFinding.risk_id)
                .join(Finding, Finding.id == RiskFinding.finding_id)
                .where(
                    RiskFinding.organization_id == org_id,
                    RiskFinding.risk_id.in_(risk_ids),
                    Finding.status.in_(
                        [FindingStatus.OPEN, FindingStatus.IN_PROGRESS]
                    ),
                    Finding.id.notin_(resolved_ids),
                )
            )
        )
        .scalars()
        .all()
    )

    for risk_id in risk_ids:
        risk = risks.get(risk_id)
        if risk is not None and risk_id not in still_open:
            risk.status = RiskStatus.RESOLVED
            risk.resolved_at = now

    await ctx.writer.commit()


async def _settle_verifications(
    ctx: AnalyzeContext,
    report: EvaluationReport,
    id_map: dict[str, UUID],
    *,
    now: datetime,
) -> None:
    """Apply this scan's verdicts to the fixes customers say they have made.

    Every scan does this, not only one started to verify something. A
    nightly scan that happens to pass the rule a customer fixed this morning
    has answered their question, and making them wait for a scan with the
    right label on it would be ceremony.

    Scoped to what this scan read. A verification about a subscription this
    scan never opened has not been observed by it, and spending one of its
    attempts would burn the customer's answer on a scan that never looked.

    A pending verification this scan reached no verdict on **still counts as
    an attempt**, recorded as UNKNOWN. That is the honest reading -- the
    scan covered the scope and produced nothing about that asset, usually
    because the asset is no longer in the environment being returned -- and
    without it a verification whose asset vanished would stay pending for
    ever, with the scheduler starting scans to settle a question that can no
    longer be answered.
    """
    pending = (
        (
            await ctx.session.execute(
                select(RemediationVerification).where(
                    RemediationVerification.organization_id == ctx.org_id,
                    RemediationVerification.status == VerificationStatus.PENDING,
                    verification_scope(ctx.account_ids, ctx.connection_id),
                )
            )
        )
        .scalars()
        .all()
    )
    if not pending:
        return

    observed: dict[tuple[str, UUID | None], RuleState] = {}
    # Least specific first, so an explicit verdict always wins: a rule can
    # produce a gap for one asset and a pass for another in the same run.
    for gap in report.gaps:
        observed[_verdict_key(gap, id_map)] = RuleState.UNKNOWN
    for failure in report.failures:
        observed[_verdict_key(failure, id_map)] = RuleState.FAIL
    for rule_id, provider_id in report.passes:
        observed[(rule_id, id_map.get(provider_id) if provider_id else None)] = (
            RuleState.PASS
        )

    for verification in pending:
        state = observed.get(
            (verification.rule_id, verification.resource_id), RuleState.UNKNOWN
        )
        outcome = verification_service.observe(
            verification, state, scan_id=ctx.scan.id, now=now
        )
        log.info(
            "verification.observed",
            verification_id=str(verification.id),
            rule_id=verification.rule_id,
            state=state.value,
            attempts=verification.attempts,
            outcome=outcome.value,
        )


def _verdict_key(
    result: EvaluatedResult, id_map: dict[str, UUID]
) -> tuple[str, UUID | None]:
    provider_id = (
        result.resource.provider_resource_id if result.resource is not None else None
    )
    return result.rule.rule_id, id_map.get(provider_id) if provider_id else None
