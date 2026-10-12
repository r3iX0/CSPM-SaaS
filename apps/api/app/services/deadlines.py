"""When a fix is due, and how an organization has done at fixing on time.

Nothing here reads the database or the clock: the queue and the progress report pass in what
they read, so each rule is proven by a unit test (DECISIONS.md section 225).

A deadline is the task's own due date when somebody set one, and otherwise the organization's
policy: this many days after the finding was first detected, by its severity. The clock starts at
detection rather than at tracking, because a deadline is about how long the exposure stands, and
a clock started by tracking would reward leaving work untracked.
"""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from statistics import median
from uuid import UUID

from app.core.enums import Severity

#: Highest first, the order every per-severity answer is given in.
SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)


@dataclass(frozen=True)
class FixWithin:
    """An organization's policy: days to fix, for the severities it sets one for."""

    days: Mapping[Severity, int]

    def due(self, severity: Severity, first_detected_at: datetime) -> date | None:
        """The day a finding of this severity, first seen then, is due; None without a policy."""
        days = self.days.get(severity)
        if days is None:
            return None
        return first_detected_at.astimezone(UTC).date() + timedelta(days=days)


#: No policy at all, every organization's state until an owner or an admin sets one.
NO_POLICY = FixWithin(days={})


def fix_within(days_by_severity: Mapping[Severity, int | None]) -> FixWithin:
    """The policy from the organization's four columns, leaving out a severity with none."""
    return FixWithin(
        days={severity: days for severity, days in days_by_severity.items() if days is not None}
    )


@dataclass(frozen=True)
class Deadline:
    """When a piece of work is due, and whether the policy said so rather than a person."""

    due_on: date | None
    by_policy: bool


def deadline(
    due_date: date | None,
    severity: Severity,
    first_detected_at: datetime,
    policy: FixWithin,
) -> Deadline:
    """A task's own due date, or else the policy's for its finding."""
    if due_date is not None:
        return Deadline(due_on=due_date, by_policy=False)
    due_on = policy.due(severity, first_detected_at)
    return Deadline(due_on=due_on, by_policy=due_on is not None)


@dataclass(frozen=True)
class Fix:
    """A finding a scan observed fixed, with the deadline it was held to."""

    finding_id: UUID
    title: str
    rule_id: str
    severity: Severity
    first_detected_at: datetime
    resolved_at: datetime
    due_on: date | None

    @property
    def days_to_fix(self) -> float:
        """Days from first detection to the scan that observed the fix."""
        return (self.resolved_at - self.first_detected_at).total_seconds() / 86_400

    @property
    def on_time(self) -> bool | None:
        """Whether the fix was observed by its due day; None where it had no deadline."""
        if self.due_on is None:
            return None
        return self.resolved_at.astimezone(UTC).date() <= self.due_on


@dataclass(frozen=True)
class SeverityProgress:
    """How one severity's fixes went."""

    severity: Severity
    fixed: int
    median_days_to_fix: float | None
    on_time: int
    late: int


@dataclass(frozen=True)
class Progress:
    """Every fix in a window, counted by severity, with the latest few named."""

    fixed: int
    on_time: int
    late: int
    by_severity: list[SeverityProgress]
    recent: list[Fix]


def progress(fixes: Iterable[Fix], *, recent: int) -> Progress:
    """Count the fixes, take each severity's median time to fix, and keep the latest ``recent``.

    A fix with no deadline counts as fixed and is neither on time nor late: it was held to
    nothing, and calling it on time would make a policy that is not set look met.
    """
    latest_first = sorted(fixes, key=lambda fix: fix.resolved_at, reverse=True)
    by_severity = [
        _severity(severity, [fix for fix in latest_first if fix.severity == severity])
        for severity in SEVERITY_ORDER
    ]
    return Progress(
        fixed=len(latest_first),
        on_time=sum(row.on_time for row in by_severity),
        late=sum(row.late for row in by_severity),
        by_severity=by_severity,
        recent=latest_first[:recent],
    )


def _severity(severity: Severity, fixes: Sequence[Fix]) -> SeverityProgress:
    days = [fix.days_to_fix for fix in fixes]
    return SeverityProgress(
        severity=severity,
        fixed=len(fixes),
        median_days_to_fix=round(median(days), 1) if days else None,
        on_time=sum(1 for fix in fixes if fix.on_time is True),
        late=sum(1 for fix in fixes if fix.on_time is False),
    )
