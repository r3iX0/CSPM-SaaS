"""How the two engines checked each other on a scan.

The read side of ``engine_divergences`` and ``assessment_captures``: what the
second engine ran, what it could not read, and every asset where a native rule
and the Prowler checks answering the same question disagreed (DECISIONS.md
section 150).

Expected disagreements -- pairs ``tools/prowler/curation.json`` records as
asking slightly different questions -- are listed apart from unexpected ones.
An unexpected disagreement is a bug in one engine or the other, and the point
of this view is that somebody goes and finds out which.
"""

from collections import Counter
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.enums import ScanStatus
from app.core.vocabulary import words
from app.models.assessment import AssessmentCapture, EngineDivergence
from app.models.cloud_account import CloudAccount
from app.models.resource import ResourceRecord
from app.models.rule import Rule
from app.models.scan import Scan
from app.prowler.catalog import enabled_checks, load
from app.rules.registry import RULE_REGISTRY

# Rows returned in one response. The summary and the pairs count every one; the
# list is for reading, and a scan whose engines disagree about more assets than
# this has a systematic difference the pairs already name.
DIVERGENCE_LIMIT = 500


def engine_summary() -> dict:
    checks = enabled_checks()
    return {
        "enabled": settings.assess_enabled,
        "prowler_version": load().prowler_version,
        "checks_enabled": len(checks),
        "checks_covered": sum(1 for check in checks if check.covered_by),
        "native_rules": len(RULE_REGISTRY),
    }


async def _scan(
    session: AsyncSession, organization_id: UUID, scan_id: UUID | None
) -> Scan | None:
    """The scan asked for, or the newest finished one the second engine ran in."""
    query = select(Scan).where(Scan.organization_id == organization_id)
    if scan_id is not None:
        return (await session.execute(query.where(Scan.id == scan_id))).scalar_one_or_none()
    return (
        await session.execute(
            query.where(
                Scan.status.in_([ScanStatus.COMPLETED, ScanStatus.PARTIAL]),
                select(AssessmentCapture.id)
                .where(AssessmentCapture.scan_id == Scan.id)
                .exists(),
            )
            .order_by(Scan.completed_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()


def _empty() -> dict:
    return {
        "assessments": [],
        "summary": {"total": 0, "unexpected": 0, "by_kind": {}},
        "pairs": [],
        "divergences": [],
    }


async def _assessments(session: AsyncSession, organization_id: UUID, scan: Scan) -> list[dict]:
    captures = (
        await session.execute(
            select(AssessmentCapture, CloudAccount.display_name, CloudAccount.account_name)
            .outerjoin(CloudAccount, CloudAccount.id == AssessmentCapture.cloud_account_id)
            .where(
                AssessmentCapture.scan_id == scan.id,
                AssessmentCapture.organization_id == organization_id,
            )
            .order_by(AssessmentCapture.created_at)
        )
    ).all()
    listed = []
    for capture, display_name, account_name in captures:
        errors = capture.errors or {}
        listed.append(
            {
                "scope": (
                    f"the {words(capture.provider).directory}"
                    if capture.cloud_account_id is None
                    else display_name or account_name
                ),
                "provider": capture.provider.value,
                "outcome": capture.outcome,
                "engine_version": capture.engine_version,
                "checks_requested": capture.checks_requested,
                "checks_completed": capture.checks_completed,
                "result_count": capture.result_count,
                "fatal": errors.get("fatal"),
                "services_unread": sorted((errors.get("services") or {}).keys()),
                "checks_raised": sorted((errors.get("checks") or {}).keys()),
                "duration_seconds": (
                    round((capture.finished_at - capture.started_at).total_seconds(), 1)
                    if capture.started_at and capture.finished_at
                    else None
                ),
            }
        )
    return listed


async def audit(
    session: AsyncSession, organization_id: UUID, scan_id: UUID | None = None
) -> dict:
    scan = await _scan(session, organization_id, scan_id)
    if scan is None:
        return {"engine": engine_summary(), "scan": None, **_empty()}

    in_scan = (
        EngineDivergence.scan_id == scan.id,
        EngineDivergence.organization_id == organization_id,
    )

    by_kind: Counter[str] = Counter()
    unexpected = 0
    for kind, expected, count in (
        await session.execute(
            select(EngineDivergence.kind, EngineDivergence.expected, func.count())
            .where(*in_scan)
            .group_by(EngineDivergence.kind, EngineDivergence.expected)
        )
    ).all():
        by_kind[kind] += int(count)
        if not expected:
            unexpected += int(count)

    notes = load().divergence_notes
    pairs = [
        {
            "rule_id": rule_id,
            "rule_name": rule_name,
            "checks": sorted({part for joined in checks for part in joined.split(",")}),
            "count": int(count),
            "expected": bool(expected),
            "note": notes.get(rule_id),
        }
        for rule_id, rule_name, expected, count, checks in (
            await session.execute(
                select(
                    EngineDivergence.rule_id,
                    Rule.name,
                    EngineDivergence.expected,
                    func.count(),
                    func.array_agg(func.distinct(EngineDivergence.check_id)),
                )
                .outerjoin(Rule, Rule.rule_id == EngineDivergence.rule_id)
                .where(*in_scan)
                .group_by(EngineDivergence.rule_id, Rule.name, EngineDivergence.expected)
                # Unexpected first, then by how often the pair disagreed.
                .order_by(EngineDivergence.expected, func.count().desc())
            )
        ).all()
    ]

    rows = (
        await session.execute(
            select(EngineDivergence, ResourceRecord.name, ResourceRecord.resource_type, Rule.name)
            .outerjoin(ResourceRecord, ResourceRecord.id == EngineDivergence.resource_id)
            .outerjoin(Rule, Rule.rule_id == EngineDivergence.rule_id)
            .where(*in_scan)
            .order_by(EngineDivergence.expected, EngineDivergence.rule_id)
            .limit(DIVERGENCE_LIMIT)
        )
    ).all()
    divergences = [
        {
            "rule_id": divergence.rule_id,
            "rule_name": rule_name,
            "check_id": divergence.check_id,
            "kind": divergence.kind,
            "native_state": divergence.native_state,
            "prowler_state": divergence.prowler_state,
            "expected": divergence.expected,
            "detail": divergence.detail,
            "resource": (
                {
                    "id": str(divergence.resource_id),
                    "name": resource_name,
                    "resource_type": str(resource_type) if resource_type else None,
                }
                if divergence.resource_id
                else None
            ),
            "provider_resource_id": divergence.provider_resource_id,
        }
        for divergence, resource_name, resource_type, rule_name in rows
    ]

    return {
        "engine": engine_summary(),
        "scan": {
            "id": str(scan.id),
            "status": scan.status.value,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        },
        "assessments": await _assessments(session, organization_id, scan),
        "summary": {
            "total": sum(by_kind.values()),
            "unexpected": unexpected,
            "by_kind": dict(by_kind),
        },
        "pairs": pairs,
        "divergences": divergences,
    }
