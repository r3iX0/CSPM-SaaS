"""The posture as it stood after this scan, kept so movement is measurable."""

from sqlalchemy import select

from app.models.risk import RiskHistory
from app.services.posture_reading import read_posture
from app.services.scan.context import AnalyzeContext
from app.services.score_movement import rule_versions


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

    The numbers are the posture reading the dashboard reads, stored rather than
    recomputed later for the reason a time series exists at all: a finding
    reclassified next month must not silently rewrite what last month's posture
    was.
    """
    session, org_id, scan = ctx.session, ctx.org_id, ctx.scan
    reading = await read_posture(session, org_id)
    entry = (
        await session.execute(select(RiskHistory).where(RiskHistory.scan_id == scan.id))
    ).scalar_one_or_none()

    if entry is None:
        entry = RiskHistory(organization_id=org_id, scan_id=scan.id)
        session.add(entry)

    entry.observed_at = ctx.observed_at
    entry.security_score = reading.security_score
    entry.open_finding_count = reading.open_finding_count
    entry.findings_by_severity = reading.findings_by_severity
    entry.risk_bands = reading.risk_bands
    entry.attack_path_count = reading.attack_path_count
    entry.charges = reading.ledger
    entry.rule_versions = rule_versions()
    await ctx.writer.commit()
