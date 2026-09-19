"""The posture as it stood after this scan, kept so movement is measurable."""

from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import FindingStatus, Level, RiskKind, RiskStatus
from app.models.finding import Finding
from app.models.risk import Risk, RiskFinding, RiskHistory
from app.risk.scorer import default_scorer
from app.services.scan.context import AnalyzeContext


async def record_posture(ctx: AnalyzeContext) -> None:
    """Write down what the posture was, so movement becomes measurable.

    Only a scan that observed something reaches here -- a replay of a
    superseded capture reports what today's rules would have found and
    changes nothing, so recording an entry for it would make the line move
    on a day nobody looked at the environment.

    Stamped with when the provider was *read*. For a live scan that is now;
    for a replay of the newest capture it is when that capture was taken,
    and plotting either on write time would date the evidence wrongly.

    One entry per scan, corrected rather than duplicated if ANALYZE runs
    twice: a retried step is the same reading, and a second row would show
    as real movement in posture.
    """
    session, org_id, scan = ctx.session, ctx.org_id, ctx.scan
    counts = await _posture_counts(session, org_id)
    entry = (
        await session.execute(
            select(RiskHistory).where(RiskHistory.scan_id == scan.id)
        )
    ).scalar_one_or_none()

    if entry is None:
        entry = RiskHistory(organization_id=org_id, scan_id=scan.id)
        session.add(entry)

    entry.observed_at = ctx.observed_at
    entry.security_score = counts["security_score"]
    entry.open_finding_count = counts["open_finding_count"]
    entry.findings_by_severity = counts["findings_by_severity"]
    entry.risk_bands = counts["risk_bands"]
    entry.attack_path_count = counts["attack_path_count"]
    await ctx.writer.commit()


async def _posture_counts(session: AsyncSession, org_id: UUID) -> dict:
    """The numbers as they stand right now, for one organization.

    Computed the same way the dashboard computes them, and stored rather
    than recomputed later for the reason a time series exists at all: a
    finding reclassified next month must not silently rewrite what last
    month's posture was.
    """
    open_statuses = [FindingStatus.OPEN, FindingStatus.IN_PROGRESS]

    severity_rows = (
        await session.execute(
            select(Finding.severity, func.count())
            .where(
                Finding.organization_id == org_id,
                Finding.status.in_(open_statuses),
            )
            .group_by(Finding.severity)
        )
    ).all()

    # Finding risks only, exactly as the security score counts them: a
    # scenario groups findings already counted here, and including it would
    # charge the customer twice for one problem.
    #
    # Counted distinctly, because the join fans a risk out across its
    # members. A rule that groups its findings has one risk with forty of
    # them, and counting join rows would deduct forty times for the one
    # problem grouping exists to state once.
    band_rows = (
        await session.execute(
            select(
                Risk.risk_level,
                func.coalesce(Risk.known_risk_level, Risk.risk_level),
                func.count(func.distinct(Risk.id)),
            )
            .join(RiskFinding, RiskFinding.risk_id == Risk.id)
            .join(Finding, Finding.id == RiskFinding.finding_id)
            .where(
                Risk.organization_id == org_id,
                Risk.kind == RiskKind.FINDING,
                Finding.status.in_(open_statuses),
            )
            .group_by(
                Risk.risk_level,
                func.coalesce(Risk.known_risk_level, Risk.risk_level),
            )
        )
    ).all()

    paths = (
        await session.execute(
            select(func.count())
            .select_from(Risk)
            .where(
                Risk.organization_id == org_id,
                Risk.kind == RiskKind.ATTACK_PATH,
                Risk.status != RiskStatus.RESOLVED,
            )
        )
    ).scalar_one()

    bands: dict[Level, int] = {}
    open_levels: list[Level] = []
    for level, known, count in band_rows:
        bands[Level(level)] = bands.get(Level(level), 0) + int(count)
        open_levels.extend([Level(known)] * int(count))

    return {
        "security_score": default_scorer.security_score(open_levels),
        # Findings, from the findings. It used to be the width of the band
        # query, which was the same number only while every risk had
        # exactly one member.
        "open_finding_count": sum(int(count) for _, count in severity_rows),
        "findings_by_severity": {
            str(severity): int(count) for severity, count in severity_rows
        },
        "risk_bands": {level.value: count for level, count in bands.items()},
        "attack_path_count": int(paths),
    }
