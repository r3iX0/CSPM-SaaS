"""Audit packages as the API takes and hands them out (DECISIONS.md section 204).

A package is a sealed record, so it has a create model and output models and no update model:
nothing about one changes after it is sealed. The controls themselves are not in these answers.
They are hundreds of rows of verdicts, rules and readings, and the archive carries them; what
the screen needs is the package's header and how its controls came out.
"""

from datetime import date, datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from app.core.enums import ScanStatus
from app.schemas.common import ClosedModel, RequestModel

PackageName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]
FrameworkId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9_.]{1,40}$")]


class AuditPackageCreate(RequestModel):
    """What a person chooses when sealing. The scan, the verdicts and the time are the server's."""

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {
                    "name": "SOC 2 Type II, FY2026",
                    "framework_ids": ["SOC2", "ISO_27001"],
                    "period_start": "2026-01-01",
                    "period_end": "2026-09-30",
                }
            ]
        }
    )

    name: PackageName
    framework_ids: list[FrameworkId] = Field(
        min_length=1,
        description=(
            "Frameworks to assess, each one this organization is offered. A package holds a "
            "handful, and each can be chosen once."
        ),
    )
    period_start: date | None = Field(
        default=None,
        description=(
            "The audit period the customer declares. Informational: the evidence is one scan."
        ),
    )
    period_end: date | None = None


class PackageFrameworkOut(ClosedModel):
    """A framework as the catalogue described it when the package was sealed."""

    id: str
    name: str
    short_name: str
    version: str
    authority: str
    url: str
    summary: str
    scope_note: str


class AuditPackageOut(BaseModel):
    id: UUID
    name: str
    frameworks: list[PackageFrameworkOut]
    #: The one scan every framework was assessed from. It may since have been pruned.
    scan_id: UUID
    #: ``PARTIAL`` matters most: an assessment with a hole in it says so.
    scan_status: ScanStatus
    scan_completed_at: datetime | None
    period_start: date | None
    period_end: date | None
    #: SHA-256 of the canonical manifest, also in ``manifest.json`` in the archive and in the
    #: audit trail entry written when the package was sealed.
    manifest_sha256: str
    sealed_by: UUID
    sealed_at: datetime


class FrameworkAssessmentOut(ClosedModel):
    """How one framework's controls came out when the package was sealed."""

    framework_id: str
    controls: int
    #: Every status as a key, zeroes included.
    statuses: dict[str, int]


class EvidenceOut(ClosedModel):
    """What the package's controls rest on, and what is still held of it."""

    #: Readings the controls name, one per listing, scope and region.
    readings: int
    #: Readings by outcome (``COMPLETE``, ``PARTIAL``, ``FAILED``...).
    outcomes: dict[str, int]
    #: Distinct payloads the readings name, and how many of them are stored today. Retention
    #: prunes payloads, so the second number can only fall: the first is what was sealed.
    payloads_named: int
    payloads_stored: int


class AuditPackageDetailOut(AuditPackageOut):
    assessment: list[FrameworkAssessmentOut]
    evidence: EvidenceOut


class VerificationOut(BaseModel):
    """Whether a package's stored rows still give the hash it was sealed under."""

    verified: bool
    sealed_sha256: str
    recomputed_sha256: str
    checked_at: datetime
