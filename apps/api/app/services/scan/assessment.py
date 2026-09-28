"""The second engine's captures, read back for ANALYZE; and its audit, written.

The database half of ``app/prowler/ingest.py``, kept apart so the ingest stays
a set of pure functions. Two jobs:

* :func:`stored_assessments` reads a scan's ``assessment_captures`` into the
  shape the ingest takes, naming each scope the way a customer reads it.
* :func:`persist_divergences` writes where the two engines disagreed.
"""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Provider
from app.core.errors import SnapshotUnavailable
from app.core.logging import get_logger
from app.core.vocabulary import words
from app.models.assessment import AssessmentCapture, EngineDivergence
from app.models.cloud_account import CloudAccount
from app.prowler.ingest import Divergence, StoredAssessment
from app.services.scan.context import AnalyzeContext

log = get_logger(__name__)


async def stored_assessments(
    session: AsyncSession, org_id: UUID, scan_id: UUID
) -> list[StoredAssessment]:
    """Every Prowler run stored under one scan, ready to interpret.

    A run whose payload has been pruned is still returned, with no content:
    the ingest then reports its checks as UNKNOWN for that scope rather than
    as never having run -- the run happened, and what it found is what is
    gone.
    """
    rows = (
        await session.execute(
            select(AssessmentCapture, CloudAccount.display_name, CloudAccount.account_name)
            .outerjoin(CloudAccount, CloudAccount.id == AssessmentCapture.cloud_account_id)
            .where(
                AssessmentCapture.scan_id == scan_id,
                AssessmentCapture.organization_id == org_id,
            )
            .order_by(AssessmentCapture.created_at)
        )
    ).all()

    stored: list[StoredAssessment] = []
    for capture, display_name, account_name in rows:
        try:
            content: dict | None = capture.content
        except SnapshotUnavailable:
            content = None
        vocabulary = words(capture.provider)
        if capture.cloud_account_id is None:
            label = f"the {vocabulary.directory}"
        else:
            name = display_name or account_name or str(capture.cloud_account_id)
            label = f"{vocabulary.account} {name}"
        stored.append(
            StoredAssessment(
                cloud_account_id=capture.cloud_account_id,
                provider=Provider(capture.provider),
                engine_version=capture.engine_version,
                outcome=capture.outcome,
                errors=dict(capture.errors or {}),
                content=content,
                scope_label=label,
            )
        )
    return stored


async def persist_divergences(
    ctx: AnalyzeContext, divergences: list[Divergence], id_map: dict[str, UUID]
) -> None:
    """One row per disagreement, append-only through the writer.

    Written by a replay of a superseded capture too: like coverage, it
    describes the evaluation rather than the environment.
    """
    for divergence in divergences:
        resource = divergence.resource
        ctx.writer.add(
            EngineDivergence,
            scan_id=ctx.scan.id,
            rule_id=divergence.rule_id,
            check_id=divergence.check_id[:128],
            resource_id=id_map.get(resource.provider_resource_id) if resource else None,
            provider_resource_id=resource.provider_resource_id if resource else None,
            native_state=divergence.native_state.value,
            prowler_state=divergence.prowler_state.value,
            kind=divergence.kind,
            expected=divergence.expected,
            detail=divergence.detail,
        )
    if divergences:
        log.info(
            "scan.engine_divergences",
            scan_id=str(ctx.scan.id),
            total=len(divergences),
            unexpected=sum(1 for divergence in divergences if not divergence.expected),
        )
