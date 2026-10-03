"""Sealing an assessment so it can be shown, and checked, after the estate moves on.

Owners and admins seal, read and export; nobody changes a package afterwards. A package is the
latest completed scan's assessment of the chosen frameworks, with every control's
verdict and every reading those verdicts rest on copied out of the tables that
retention and re-scans keep rewriting (DECISIONS.md section 204).

Services flush and the route commits, because the row-level-security claims live
in the request's transaction (DECISIONS.md section 194). The audit entry is
written in that same transaction, so a package that does not commit leaves no
entry claiming it exists.
"""

import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime
from tempfile import SpooledTemporaryFile
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.compliance import archive
from app.compliance import package as manifest_module
from app.core.deps import TenantContext
from app.core.enums import Role, ScanStatus
from app.core.errors import ArchiveTooLarge, ConflictError, NotFound, ValidationFailed
from app.core.payloads import compress
from app.models.audit_package import AuditPackage, AuditPackageItem
from app.models.scan import Evidence, EvidenceBlob
from app.services import audit
from app.services import compliance as compliance_service

# The catalogue's header, kept as it was when sealed.
_FRAMEWORK_HEADER = (
    "id",
    "name",
    "short_name",
    "version",
    "authority",
    "url",
    "summary",
    "scope_note",
)

MAX_FRAMEWORKS = 6

# The uncompressed payload bytes one archive may carry. It is built in a worker thread and spooled
# to disk, so this bounds the time a download can take and the evidence read into memory at once
# (compressed, about a tenth of it), not the zip.
MAX_ARCHIVE_PAYLOAD_BYTES = 256 * 1_000_000
_BLOB_BATCH = 100
_SPOOL_BYTES = 16 * 1024 * 1024


def _check_request(
    framework_ids: list[str], period_start: date | None, period_end: date | None
) -> None:
    if not framework_ids:
        raise ValidationFailed("Choose at least one framework to seal")
    if len(set(framework_ids)) != len(framework_ids):
        raise ValidationFailed("Each framework can be chosen once")
    if len(framework_ids) > MAX_FRAMEWORKS:
        raise ValidationFailed(f"A package holds at most {MAX_FRAMEWORKS} frameworks")
    if period_start and period_end and period_start > period_end:
        raise ValidationFailed("The audit period ends before it starts")


async def _assess(
    session: AsyncSession, tenant: TenantContext, framework_ids: list[str]
) -> list[dict[str, Any]]:
    """Each framework's live assessment, refusing one this organization is not measured by.

    Offered frameworks only, the same set the compliance page lists: sealing CIS
    Azure for an AWS-only organization would produce a package of controls nothing
    read, which is a document that looks like an assessment and is not one.
    """
    providers = await compliance_service.connected_providers(session, tenant.organization_id)
    offered = {framework.id for framework in compliance_service.frameworks_for(providers)}
    unknown = sorted(set(framework_ids) - offered)
    if unknown:
        raise ValidationFailed(f"Not a framework this organization is measured by: {unknown!r}")

    details: list[dict[str, Any]] = []
    for framework_id in framework_ids:
        detail = await compliance_service.get_framework_detail(
            session, tenant.organization_id, framework_id
        )
        if detail is None:
            raise ValidationFailed(f"No such framework: {framework_id!r}")
        details.append(detail)
    return details


def _closing_scan(details: list[dict[str, Any]]) -> dict[str, Any]:
    """The one scan every framework was assessed from.

    Frameworks are assessed one after another, so a scan that completes between
    two of them would split a package across two states of the estate -- and the
    package would claim one. Sealing again is the remedy, and cheap.
    """
    assessments = [detail["assessment"] for detail in details]
    if any(assessment is None for assessment in assessments):
        raise ConflictError("Nothing has been assessed yet. Run a scan before sealing a package.")
    scan_ids = {assessment["scan_id"] for assessment in assessments}
    if len(scan_ids) != 1:
        raise ConflictError("A scan finished while the package was being sealed. Try again.")
    return assessments[0]


async def _readings_of(
    session: AsyncSession, tenant: TenantContext, scan_id: UUID, keys: set[str]
) -> list[Evidence]:
    if not keys:
        return []
    rows = await session.execute(
        select(Evidence).where(
            Evidence.organization_id == tenant.organization_id,
            Evidence.scan_id == scan_id,
            Evidence.evidence_key.in_(keys),
        )
    )
    return list(rows.scalars().all())


async def seal(
    session: AsyncSession,
    tenant: TenantContext,
    *,
    name: str,
    framework_ids: list[str],
    period_start: date | None = None,
    period_end: date | None = None,
) -> AuditPackage:
    """Seal the latest assessment of these frameworks as a package.

    The readings kept are only those the chosen frameworks' controls declare
    they rest on. A package for one framework does not carry the whole estate's
    configuration, which is data an auditor was not asked about.
    """
    tenant.require_role(Role.OWNER, Role.ADMIN)
    _check_request(framework_ids, period_start, period_end)

    details = await _assess(session, tenant, framework_ids)
    assessment = _closing_scan(details)
    scan_id = UUID(assessment["scan_id"])

    controls: list[dict] = []
    for framework_id, detail in zip(framework_ids, details, strict=True):
        controls.extend(manifest_module.seal_controls(framework_id, detail["controls"]))
    keys = {key for control in controls for key in control["evidence_keys"]}
    readings = await _readings_of(session, tenant, scan_id, keys)

    completed_at = assessment["completed_at"]
    package = AuditPackage(
        id=uuid.uuid4(),
        organization_id=tenant.organization_id,
        name=name,
        framework_ids=list(framework_ids),
        frameworks=[{key: detail[key] for key in _FRAMEWORK_HEADER} for detail in details],
        controls=controls,
        scan_id=scan_id,
        scan_status=ScanStatus(assessment["scan_status"]),
        scan_completed_at=datetime.fromisoformat(completed_at) if completed_at else None,
        period_start=period_start,
        period_end=period_end,
        manifest_version=manifest_module.MANIFEST_VERSION,
        manifest_sha256="",
        sealed_by=tenant.user.id,
        sealed_at=datetime.now(UTC),
    )
    items = [
        AuditPackageItem(
            package_id=package.id,
            organization_id=tenant.organization_id,
            **manifest_module.item_fields(reading),
        )
        for reading in readings
    ]
    package.manifest_sha256 = manifest_module.manifest_digest(
        manifest_module.manifest(package, items)
    )

    session.add(package)
    session.add_all(items)
    await session.flush()
    await audit.record(
        session,
        tenant,
        "audit_package.sealed",
        "audit_package",
        package.id,
        {
            "name": name,
            "frameworks": list(framework_ids),
            "scan_id": assessment["scan_id"],
            "manifest_sha256": package.manifest_sha256,
        },
    )
    return package


def _require_reader(tenant: TenantContext) -> None:
    """Owners and administrators read a package, as row-level security already says.

    Asked here as well, so a viewer is told why and not shown an empty list: the database would
    answer both a viewer and a stranger with nothing, and a person denied should not have to
    guess which they are.
    """
    tenant.require_role(Role.OWNER, Role.ADMIN)


async def list_packages(
    session: AsyncSession, tenant: TenantContext, *, limit: int = 50, offset: int = 0
) -> tuple[list[AuditPackage], int]:
    """A page of this organization's packages, newest first, and how many there are."""
    _require_reader(tenant)
    scope = AuditPackage.organization_id == tenant.organization_id
    total = (
        await session.execute(select(func.count()).select_from(AuditPackage).where(scope))
    ).scalar_one()
    rows = await session.execute(
        select(AuditPackage)
        .where(scope)
        .order_by(AuditPackage.sealed_at.desc(), AuditPackage.id)
        .limit(limit)
        .offset(offset)
    )
    return list(rows.scalars().all()), total


async def get_package(
    session: AsyncSession, tenant: TenantContext, package_id: UUID
) -> tuple[AuditPackage, list[AuditPackageItem]]:
    """A package and its readings, or ``NotFound`` for one this organization does not hold."""
    _require_reader(tenant)
    package = (
        await session.execute(
            select(AuditPackage).where(
                AuditPackage.id == package_id,
                AuditPackage.organization_id == tenant.organization_id,
            )
        )
    ).scalar_one_or_none()
    if package is None:
        raise NotFound("No such audit package")
    rows = await session.execute(
        select(AuditPackageItem).where(
            AuditPackageItem.package_id == package.id,
            AuditPackageItem.organization_id == tenant.organization_id,
        )
    )
    return package, list(rows.scalars().all())


@dataclass(frozen=True)
class Verification:
    """The hash a package was sealed under, and the one its rows give now."""

    matches: bool
    sealed_sha256: str
    recomputed_sha256: str


async def verify_package(
    session: AsyncSession, tenant: TenantContext, package_id: UUID
) -> Verification:
    """Whether the stored rows still match the hash the package was sealed under."""
    package, items = await get_package(session, tenant, package_id)
    recomputed = manifest_module.recompute(package, items)
    return Verification(
        matches=recomputed == package.manifest_sha256,
        sealed_sha256=package.manifest_sha256,
        recomputed_sha256=recomputed,
    )


async def payload_availability(
    session: AsyncSession, tenant: TenantContext, items: Sequence[AuditPackageItem]
) -> tuple[int, int]:
    """How many distinct payloads a package's readings name, and how many are still stored.

    Answered live and not sealed: retention can prune a payload any day, and the count that was
    true on the sealing date is not the one an auditor needs before they ask for the files.
    """
    named = {item.content_hash for item in items if item.content_hash}
    if not named:
        return 0, 0
    held = (
        await session.execute(
            select(func.count()).where(
                EvidenceBlob.organization_id == tenant.organization_id,
                EvidenceBlob.content_hash.in_(named),
            )
        )
    ).scalar_one()
    return len(named), held


@dataclass(frozen=True)
class ArchiveInputs:
    """Everything an archive is built from, read out of the database before it is built."""

    package: AuditPackage
    items: list[AuditPackageItem]
    stored_payloads: dict[str, bytes]


def _payload_bytes(items: Sequence[AuditPackageItem]) -> int:
    """The uncompressed size of every distinct payload the readings name."""
    sizes: dict[str, int] = {}
    for item in items:
        if item.content_hash:
            sizes[item.content_hash] = max(sizes.get(item.content_hash, 0), item.byte_size)
    return sum(sizes.values())


async def archive_inputs(
    session: AsyncSession, tenant: TenantContext, package_id: UUID
) -> ArchiveInputs:
    """Read a package and the payloads it names, and record that they are being taken.

    Refuses a package whose evidence is more than one archive will hold, before reading any of
    it: the answer is a ``409`` naming the limit, not a worker out of memory. A larger package
    wants a background export, which is not built.

    The entry is written here, in the request's transaction, and the route commits it before the
    archive is built. That is a record of access and not of success -- a failed build still
    leaves the entry -- because evidence leaving the system should err toward being on the trail.
    """
    package, items = await get_package(session, tenant, package_id)
    total = _payload_bytes(items)
    if total > MAX_ARCHIVE_PAYLOAD_BYTES:
        raise ArchiveTooLarge(
            f"This package names {total // 1_000_000} MB of evidence and one archive holds "
            f"{MAX_ARCHIVE_PAYLOAD_BYTES // 1_000_000} MB. Seal fewer frameworks, or ask for "
            "the evidence in parts."
        )

    hashes = sorted({item.content_hash for item in items if item.content_hash})
    stored: dict[str, bytes] = {}
    for start in range(0, len(hashes), _BLOB_BATCH):
        rows = await session.execute(
            select(
                EvidenceBlob.content_hash, EvidenceBlob.payload_compressed, EvidenceBlob.payload
            ).where(
                EvidenceBlob.organization_id == tenant.organization_id,
                EvidenceBlob.content_hash.in_(hashes[start : start + _BLOB_BATCH]),
            )
        )
        for content_hash, compressed, legacy in rows.all():
            # Rows written before compression hold the payload as JSON, and are stored the way
            # the archive reads them. The archive hashes what it inflates, so a legacy row whose
            # serialization differs is reported as corrupt and not shipped under a hash it lacks.
            if compressed is not None:
                stored[content_hash] = compressed
            elif legacy is not None:
                stored[content_hash] = compress(legacy)

    await audit.record(
        session,
        tenant,
        "audit_package.exported",
        "audit_package",
        package.id,
        {
            "name": package.name,
            "manifest_sha256": package.manifest_sha256,
            "payloads_named": len(hashes),
            "payloads_read": len(stored),
        },
    )
    await session.flush()
    return ArchiveInputs(package=package, items=items, stored_payloads=stored)


def archive_filename(inputs: ArchiveInputs) -> str:
    return f"{archive.archive_name(inputs.package)}.zip"


def build_archive(inputs: ArchiveInputs) -> tuple[SpooledTemporaryFile[bytes], int]:
    """Write the archive to a spooled file and say how big it is.

    Synchronous and CPU-bound, so the route runs it in a thread. Spooled, so a small archive
    stays in memory and a large one goes to disk instead of being held whole beside the evidence
    it was built from.
    """
    # Not a ``with``: the caller streams from it and closes it when the response is done.
    spool: SpooledTemporaryFile[bytes] = SpooledTemporaryFile(max_size=_SPOOL_BYTES)  # noqa: SIM115
    try:
        archive.write_archive(spool, inputs.package, inputs.items, inputs.stored_payloads)
    except BaseException:
        spool.close()
        raise
    size = spool.tell()
    spool.seek(0)
    return spool, size
