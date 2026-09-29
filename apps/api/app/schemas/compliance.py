"""A framework's assessment as the compliance pages show it.

``services/compliance.py`` builds these as dicts, because the export and the
PDF report read the same dicts and pop from them. The routes validate the
finished dict here, and every model is a ``ClosedModel``: a key the service
adds and this file does not declare is an error rather than a key quietly
missing from the response.
"""

from datetime import datetime
from uuid import UUID

from app.compliance.coverage import ControlStatus
from app.core.enums import ScanStatus, TaskOutcome
from app.schemas.common import ClosedModel


class ControlReadingOut(ClosedModel):
    """One provider listing a control's verdict rests on."""

    evidence_key: str
    #: ``None`` for a listing the rules declare and nothing read -- "this
    #: control is green and nobody looked".
    outcome: TaskOutcome | None
    #: How many scopes it was read in.
    scopes: int
    collected_at: datetime | None
    age_seconds: int | None
    permissions: list[str]
    #: Whether the payload is still stored, to follow back to the bytes.
    retained: bool


class ControlRuleOut(ClosedModel):
    """A rule a control is answered by, and what it found."""

    rule_id: str
    name: str
    #: From the rules mirror, as a plain string (see ``RuleOut``).
    severity: str
    open_finding_count: int
    unknown_count: int
    evaluated: bool
    #: Why it could not tell, where it could not; at most a few.
    unknown_reasons: list[str]


class ControlOut(ClosedModel):
    id: str
    title: str
    group: str
    technically_assessable: bool
    status: ControlStatus
    open_finding_count: int
    readings: list[ControlReadingOut]
    rules: list[ControlRuleOut]


class AssessmentOut(ClosedModel):
    """Which reading of the estate an assessment is of."""

    scan_id: UUID
    completed_at: datetime | None
    #: PARTIAL is an assessment with a hole in it.
    scan_status: ScanStatus


class FrameworkSummaryOut(ClosedModel):
    """One card on the compliance page."""

    id: str
    name: str
    short_name: str
    version: str
    authority: str
    url: str
    summary: str
    scope_note: str
    control_count: int
    #: Controls by ``ControlStatus``.
    status_counts: dict[str, int]
    #: ``None`` where no control could be assessed at all.
    coverage_ratio: float | None
    open_finding_count: int


class FrameworkDetailOut(FrameworkSummaryOut):
    assessed: bool
    #: ``None`` until a scan has completed: a catalogue, not an assessment.
    assessment: AssessmentOut | None
    controls: list[ControlOut]
