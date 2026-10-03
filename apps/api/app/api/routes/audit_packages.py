"""Sealed audit packages: seal one, read it, check it, and take the evidence away.

Owners and administrators only. A package is the assessment of chosen frameworks as it stood on
the latest completed scan, copied out of the tables retention and re-scans keep rewriting, and
never changed afterwards (DECISIONS.md section 208). So there is no ``PATCH`` and no ``DELETE``
here: a wrong package is sealed again, and the old one stays what it was.

The archive is a file and not an envelope, for the reason a report is: the caller is saving a
document. It is built in a worker thread, one at a time, into a spooled file after the connection
has gone back to the pool, and streamed from there (DECISIONS.md section 158).
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import IO
from uuid import UUID

import anyio
from fastapi import APIRouter, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from starlette.background import BackgroundTask

from app.api.links import created
from app.compliance import package as manifest_module
from app.core.deps import Costly, DbSession, Tenant
from app.models.audit_package import AuditPackage, AuditPackageItem
from app.schemas.audit_package import (
    AuditPackageCreate,
    AuditPackageDetailOut,
    AuditPackageOut,
    EvidenceOut,
    FrameworkAssessmentOut,
    PackageFrameworkOut,
    VerificationOut,
)
from app.schemas.common import ERROR_RESPONSES, Envelope, NoMeta, PageMeta, error_responses
from app.services import audit_packages as service

router = APIRouter(prefix="/audit-packages", tags=["audit-packages"], responses=ERROR_RESPONSES)

ADMIN_ONLY = error_responses(403)

# Archives are built one at a time. The build is CPU-bound and holds one payload in memory at a
# time, and one at a time bounds both however many owners press download together.
_ARCHIVE_BUILDS = anyio.CapacityLimiter(1)

_CHUNK = 64 * 1024


def _out(package: AuditPackage) -> AuditPackageOut:
    return AuditPackageOut(
        id=package.id,
        name=package.name,
        frameworks=[PackageFrameworkOut.model_validate(h) for h in package.frameworks],
        scan_id=package.scan_id,
        scan_status=package.scan_status,
        scan_completed_at=package.scan_completed_at,
        period_start=package.period_start,
        period_end=package.period_end,
        manifest_sha256=package.manifest_sha256,
        sealed_by=package.sealed_by,
        sealed_at=package.sealed_at,
    )


def _detail(
    package: AuditPackage,
    items: list[AuditPackageItem],
    payloads: tuple[int, int],
) -> AuditPackageDetailOut:
    counts = manifest_module.control_status_counts(package.controls)
    outcomes: dict[str, int] = {}
    for item in items:
        outcomes[item.outcome.value] = outcomes.get(item.outcome.value, 0) + 1
    return AuditPackageDetailOut(
        **_out(package).model_dump(),
        assessment=[
            FrameworkAssessmentOut(
                framework_id=framework_id,
                controls=sum(counts[framework_id].values()),
                statuses=counts[framework_id],
            )
            for framework_id in package.framework_ids
            if framework_id in counts
        ],
        evidence=EvidenceOut(
            readings=len(items),
            outcomes=dict(sorted(outcomes.items())),
            payloads_named=payloads[0],
            payloads_stored=payloads[1],
        ),
    )


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Costly],
    responses=error_responses(403, 409),
)
async def seal_audit_package(
    payload: AuditPackageCreate,
    request: Request,
    response: Response,
    session: DbSession,
    tenant: Tenant,
) -> Envelope[AuditPackageOut, NoMeta]:
    """Seal the latest completed scan's assessment of these frameworks as a package.

    ``409`` when nothing has been assessed yet, or when a scan finished while the package was
    being sealed (seal again). ``422`` for a framework this organization is not measured by.
    """
    package = await service.seal(
        session,
        tenant,
        name=payload.name,
        framework_ids=payload.framework_ids,
        period_start=payload.period_start,
        period_end=payload.period_end,
    )
    created(request, response, "get_audit_package", package_id=package.id)
    return Envelope(data=_out(package), meta=NoMeta())


@router.get("", responses=ADMIN_ONLY)
async def list_audit_packages(
    session: DbSession,
    tenant: Tenant,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> Envelope[list[AuditPackageOut], PageMeta]:
    """This organization's sealed packages, newest first."""
    packages, total = await service.list_packages(session, tenant, limit=limit, offset=offset)
    return Envelope(
        data=[_out(package) for package in packages],
        meta=PageMeta(total=total, limit=limit, offset=offset),
    )


@router.get("/{package_id}", responses=ADMIN_ONLY)
async def get_audit_package(
    package_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[AuditPackageDetailOut, NoMeta]:
    """A package's header, how each framework's controls came out, and what they rest on.

    The controls themselves are in the archive. How many payloads are stored is answered live:
    retention prunes them, so it can only fall.
    """
    package, items = await service.get_package(session, tenant, package_id)
    payloads = await service.payload_availability(session, tenant, items)
    return Envelope(data=_detail(package, items, payloads), meta=NoMeta())


@router.get("/{package_id}/verification", responses=ADMIN_ONLY)
async def verify_audit_package(
    package_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[VerificationOut, NoMeta]:
    """Whether the stored rows still give the hash the package was sealed under.

    A read, and idempotent. ``verified: false`` means a row was changed behind the application's
    back; the two digests are given so the answer can be checked rather than believed.
    """
    result = await service.verify_package(session, tenant, package_id)
    return Envelope(
        data=VerificationOut(
            verified=result.matches,
            sealed_sha256=result.sealed_sha256,
            recomputed_sha256=result.recomputed_sha256,
            checked_at=datetime.now(UTC),
        ),
        meta=NoMeta(),
    )


@router.get(
    "/{package_id}/archive",
    response_class=StreamingResponse,
    dependencies=[Costly],
    responses={
        200: {
            "description": (
                "The package as a zip: the manifest, one CSV of controls per framework, the "
                "gaps, the readings, the captured payloads and a SHA256SUMS that checks them."
            ),
            "content": {"application/zip": {}},
        },
        **error_responses(403, 409),
    },
)
async def download_audit_package_archive(
    package_id: UUID, session: DbSession, tenant: Tenant
) -> StreamingResponse:
    """The package, and the evidence it names, as files an auditor can check without Cleave.

    The download is written to the audit trail, which makes this a ``GET`` that records an
    entry: evidence leaving the system belongs on the trail, and the entry is an append-only
    record and not state a repeat changes. ``409`` when the evidence is more than one archive
    holds.
    """
    inputs = await service.archive_inputs(session, tenant, package_id)
    # The entry is committed before the build, and the connection goes back to the pool: the
    # build is slow, and held, the connection would idle through it and through the wait for its
    # turn while every other request queued for one (DECISIONS.md section 158).
    await session.commit()
    await session.close()

    spool, size = await anyio.to_thread.run_sync(
        service.build_archive, inputs, limiter=_ARCHIVE_BUILDS
    )
    return StreamingResponse(
        _chunks(spool),
        media_type="application/zip",
        headers={
            "Content-Length": str(size),
            "Content-Disposition": f'attachment; filename="{service.archive_filename(inputs)}"',
        },
        background=BackgroundTask(spool.close),
    )


def _chunks(spool: IO[bytes]) -> Iterator[bytes]:
    while chunk := spool.read(_CHUNK):
        yield chunk
