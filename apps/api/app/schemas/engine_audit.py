"""Where the two engines disagreed, as the Engine audit page shows it (DECISIONS.md
section 150).

Built as a dict by ``services/engine_audit.py`` and validated here by the route;
every model is a ``ClosedModel``. The kinds, outcomes and states are the plain
strings the scanner stores, not enums: they are written by a separate service
on its own release, and a value it adds should reach the page rather than fail
the whole audit.
"""

from datetime import datetime
from typing import Any
from uuid import UUID

from app.core.enums import Provider, ScanStatus
from app.schemas.common import ClosedModel


class EngineSummaryOut(ClosedModel):
    """The second engine as this deployment runs it."""

    enabled: bool
    prowler_version: str
    checks_enabled: int
    #: Checks a native rule already answers, compared rather than reported.
    checks_covered: int
    native_rules: int


class AuditScanOut(ClosedModel):
    id: UUID
    status: ScanStatus
    completed_at: datetime | None


class AssessmentRunOut(ClosedModel):
    """One ASSESS step: what the extended checks ran for one scope."""

    #: The subscription, or the directory.
    scope: str
    provider: Provider
    outcome: str
    engine_version: str
    checks_requested: int
    checks_completed: int
    result_count: int
    #: Why the run stopped, where it did, as the scanner recorded it.
    fatal: Any
    #: Services the checks could not read; silence is never a pass.
    services_unread: list[str]
    #: Checks that raised rather than answered.
    checks_raised: list[str]
    duration_seconds: float | None


class AuditSummaryOut(ClosedModel):
    total: int
    #: Disagreements the curation does not explain.
    unexpected: int
    by_kind: dict[str, int]


class DivergencePairOut(ClosedModel):
    """A rule and the checks that answered the same question, and how often
    they disagreed."""

    rule_id: str
    rule_name: str | None
    checks: list[str]
    count: int
    expected: bool
    #: Why they may disagree, where the curation says.
    note: str | None


class DivergenceResourceOut(ClosedModel):
    id: UUID
    name: str | None
    resource_type: str | None


class DivergenceOut(ClosedModel):
    """One asset where the two engines answered differently."""

    rule_id: str
    rule_name: str | None
    check_id: str
    kind: str
    native_state: str
    prowler_state: str
    expected: bool
    detail: str | None
    resource: DivergenceResourceOut | None
    provider_resource_id: str | None


class EngineAuditOut(ClosedModel):
    engine: EngineSummaryOut
    #: ``None`` when the second engine has not run in any finished scan.
    scan: AuditScanOut | None
    assessments: list[AssessmentRunOut]
    summary: AuditSummaryOut
    pairs: list[DivergencePairOut]
    #: The first few hundred; ``summary.total`` is the count.
    divergences: list[DivergenceOut]
