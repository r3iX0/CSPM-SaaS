"""The dashboard's one payload.

Built as a dict by ``services/dashboard.py``, which the PDF report and the
pipeline tests read as one, and validated here by the route. Every model is a
``ClosedModel``, so a key the service adds and this file does not declare fails
rather than disappearing from the response.
"""

from datetime import date, datetime
from typing import Any
from uuid import UUID

from app.core.enums import Level, RiskKind, ScanStatus
from app.schemas.common import ClosedModel


class PostureOut(ClosedModel):
    """The posture at one scan, as it was stored then."""

    observed_at: datetime
    security_score: int
    open_finding_count: int
    findings_by_severity: dict[str, int]
    risk_bands: dict[str, int]
    attack_path_count: int


class ActivityWeekOut(ClosedModel):
    """Findings raised, fixed and come back in one week."""

    #: The Monday the week starts on.
    week: date
    detected: int
    resolved: int
    reopened: int


class RouteEndsOut(ClosedModel):
    """The pair a route is keyed by on the attack-path page."""

    entry_id: str
    target_id: str


class TopRiskOut(ClosedModel):
    id: UUID
    title: str
    risk_score: float
    risk_level: Level
    kind: RiskKind
    internet_exposure: Level
    data_sensitivity: Level
    asset_criticality: Level
    #: The asset a finding risk is about, when it is about exactly one.
    asset_id: UUID | None
    #: Where a route's graph opens; ``None`` for a finding risk.
    route: RouteEndsOut | None


class CoverageCategoryOut(ClosedModel):
    name: str
    readings: int
    incomplete: int


class ContextCoverageOut(ClosedModel):
    """Open risks on assets CloudGuard could and could not classify."""

    unclassified: int
    classified: int
    ratio: float


class CoverageOut(ClosedModel):
    """Kept beside the score, never folded into it."""

    #: ``None`` before the first scan.
    ratio: float | None
    unknown: int
    conclusive: int
    categories: list[CoverageCategoryOut]
    context: ContextCoverageOut


class FreshnessOut(ClosedModel):
    """How recently the provider was read; the oldest reading is the headline."""

    readings: int
    oldest_at: datetime | None
    newest_at: datetime | None
    stale_hours: float | None
    unusable: int


class RegionOut(ClosedModel):
    """One region, or -- both ``None`` -- everything tied to none."""

    region: str | None
    provider: str | None
    assets: int
    open_findings: int
    by_severity: dict[str, int]
    readings: int
    unread: int


class LastScanOut(ClosedModel):
    id: UUID
    status: ScanStatus
    completed_at: datetime | None
    resource_count: int
    rule_count: int
    finding_count: int
    #: As stored on the scan, by category.
    collection_errors: dict[str, Any]


class DashboardOut(ClosedModel):
    security_score: int
    #: ``None`` where there is no previous reading to have moved from.
    score_delta: int | None
    history: list[PostureOut]
    findings_by_severity: dict[str, int]
    findings_by_status: dict[str, int]
    risk_bands: dict[str, int]
    open_finding_count: int
    asset_count: int
    verified_resolved_last_30_days: int
    remediation_rate: float
    remediation_activity: list[ActivityWeekOut]
    top_risks: list[TopRiskOut]
    coverage: CoverageOut
    evidence_freshness: FreshnessOut
    regions: list[RegionOut]
    last_scan: LastScanOut | None
