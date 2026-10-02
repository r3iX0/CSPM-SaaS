"""Sealing an assessment so it can be shown, and checked, after the estate moves on.

Owners and admins seal; nobody changes a package afterwards. A package is the
latest completed scan's assessment of the chosen frameworks, with every control's
verdict and every reading those verdicts rest on copied out of the tables that
retention and re-scans keep rewriting (DECISIONS.md section 197).

Services flush and the route commits, because the row-level-security claims live
in the request's transaction (DECISIONS.md section 194). The audit entry is
written in that same transaction, so a package that does not commit leaves no
entry claiming it exists.
"""

import uuid
from datetime import UTC, date, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.compliance import package as manifest_module
from app.core.deps import TenantContext
from app.core.enums import Role, ScanStatus
from app.core.errors import ConflictError, NotFound, ValidationFailed
from app.models.audit_package import AuditPackage, AuditPackageItem
from app.models.scan import Evidence
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


async def list_packages(session: AsyncSession, tenant: TenantContext) -> list[AuditPackage]:
    """This organization's packages, newest first. Row-level security limits who sees any."""
    rows = await session.execute(
        select(AuditPackage)
        .where(AuditPackage.organization_id == tenant.organization_id)
        .order_by(AuditPackage.sealed_at.desc(), AuditPackage.id)
    )
    return list(rows.scalars().all())


async def get_package(
    session: AsyncSession, tenant: TenantContext, package_id: UUID
) -> tuple[AuditPackage, list[AuditPackageItem]]:
    """A package and its readings, or ``NotFound`` for one this organization does not hold."""
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


async def verify_package(session: AsyncSession, tenant: TenantContext, package_id: UUID) -> bool:
    """Whether the stored rows still match the hash the package was sealed under."""
    package, items = await get_package(session, tenant, package_id)
    return manifest_module.verify(package, items)
