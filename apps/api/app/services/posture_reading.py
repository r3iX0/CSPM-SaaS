"""The posture as it stands right now, computed once (DECISIONS.md section 235).

The dashboard, the stored history and the score movement each read the same
rows and did the same arithmetic, and the dashboard's "movement since the last
scan" subtracted one copy from the other, so any filter that drifted in one
silently corrupted the delta. A reading is the one answer all of them take.
"""

from collections.abc import Mapping
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import FindingStatus, Level, RiskKind, RiskStatus
from app.models.finding import Finding
from app.models.risk import Risk, RiskFinding
from app.risk.scorer import default_scorer

OPEN = (FindingStatus.OPEN, FindingStatus.IN_PROGRESS)


@dataclass(frozen=True)
class PostureReading:
    """One organization's posture at one moment."""

    security_score: int
    open_finding_count: int
    findings_by_severity: dict[str, int]
    risk_bands: dict[str, int]
    attack_path_count: int
    charges: Mapping[UUID, tuple[Level, Level]]

    @property
    def ledger(self) -> dict[str, str]:
        """The charges as a reading stores them: each risk to the band it was charged at.

        Kept risk by risk as well as in total, so the next reading can say which
        risks moved the score.
        """
        return {str(risk_id): known.value for risk_id, (_ranked, known) in self.charges.items()}


async def open_charges(
    session: AsyncSession, organization_id: UUID
) -> dict[UUID, tuple[Level, Level]]:
    """Every open finding risk, to its ranked band and the band the score charges.

    Finding risks only, and each once: a scenario groups findings already
    charged here, and a risk grouping forty findings is one problem stated once.
    Two bands per risk, and they are not the same question. ``risk_level`` ranks,
    cautiously: an unclassified production database must not sort below a dev box
    somebody tagged. ``known_risk_level`` is what CloudGuard can demonstrate, and
    is what the score charges, coalesced so risks written before it existed
    charge as they did (RISK_ENGINE.md section 3).
    """
    rows = await session.execute(
        select(Risk.id, Risk.risk_level, func.coalesce(Risk.known_risk_level, Risk.risk_level))
        .join(RiskFinding, RiskFinding.risk_id == Risk.id)
        .join(Finding, Finding.id == RiskFinding.finding_id)
        .where(
            Risk.organization_id == organization_id,
            Risk.kind == RiskKind.FINDING,
            Finding.status.in_(OPEN),
        )
        .distinct()
    )
    return {
        risk_id: (Level(ranked), Level(known or ranked)) for risk_id, ranked, known in rows.tuples()
    }


async def read_posture(session: AsyncSession, organization_id: UUID) -> PostureReading:
    """The posture of one organization as it stands in the database right now."""
    severity_rows = await session.execute(
        select(Finding.severity, func.count())
        .where(Finding.organization_id == organization_id, Finding.status.in_(OPEN))
        .group_by(Finding.severity)
    )
    paths = (
        await session.execute(
            select(func.count())
            .select_from(Risk)
            .where(
                Risk.organization_id == organization_id,
                Risk.kind == RiskKind.ATTACK_PATH,
                Risk.status != RiskStatus.RESOLVED,
            )
        )
    ).scalar_one()
    return reading_from(
        charges=await open_charges(session, organization_id),
        severity_counts={str(severity): int(count) for severity, count in severity_rows.all()},
        attack_path_count=int(paths),
    )


def charged_score(charges: Mapping[UUID, tuple[Level, Level]]) -> int:
    """The security score these charges add up to.

    The score deducts by the band CloudGuard can demonstrate (the second of the
    pair), not the band that ranks (the first): coverage is reported beside the
    score and not folded into it (RISK_ENGINE.md section 3).
    """
    return default_scorer.security_score([known for _ranked, known in charges.values()])


def reading_from(
    *,
    charges: Mapping[UUID, tuple[Level, Level]],
    severity_counts: Mapping[str, int],
    attack_path_count: int,
) -> PostureReading:
    """Build a reading from what the queries returned.

    The distribution shown to a reader is the ranked one, because the risks list
    is sorted by it; only the deduction uses the other band.
    """
    bands: dict[str, int] = {}
    for ranked, _known in charges.values():
        bands[ranked.value] = bands.get(ranked.value, 0) + 1
    return PostureReading(
        security_score=charged_score(charges),
        open_finding_count=sum(severity_counts.values()),
        findings_by_severity=dict(severity_counts),
        risk_bands=bands,
        attack_path_count=attack_path_count,
        charges=charges,
    )
