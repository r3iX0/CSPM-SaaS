"""What the rules covered: a count per rule, and a row per check that could not
reach a verdict."""

from uuid import UUID

from app.models.scan import ScanEvaluationGap, ScanRuleResult
from app.rules.engine import EvaluationReport
from app.services.scan.context import AnalyzeContext


async def persist_coverage(
    ctx: AnalyzeContext, report: EvaluationReport, id_map: dict[str, UUID]
) -> None:
    """Aggregate counts per rule, plus one row per UNKNOWN.

    PASS and NOT_APPLICABLE are counted only. Storing them per resource would
    add resources x rules rows per scan for no benefit
    (RULE_ENGINE.md section 2).

    Written by every run, a replay of a superseded capture included: coverage
    describes the evaluation, not the environment, so it is the one thing an
    evaluation-only run is entitled to record.
    """
    for rule_id, coverage in report.coverage.items():
        ctx.writer.add(
            ScanRuleResult,
            scan_id=ctx.scan.id,
            rule_id=rule_id,
            evaluated_count=coverage.evaluated_count,
            passed_count=coverage.passed_count,
            failed_count=coverage.failed_count,
            unknown_count=coverage.unknown_count,
            not_applicable_count=coverage.not_applicable_count,
        )

    for gap in report.gaps:
        resource_uuid = (
            id_map.get(gap.resource.provider_resource_id) if gap.resource else None
        )
        ctx.writer.add(
            ScanEvaluationGap,
            scan_id=ctx.scan.id,
            rule_id=gap.rule.rule_id,
            resource_id=resource_uuid,
            reason=(gap.result.message or "Rule could not be evaluated")[:1000],
        )

    await ctx.writer.commit()
