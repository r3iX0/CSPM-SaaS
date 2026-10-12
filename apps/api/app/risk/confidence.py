"""How sure Cleave is of a finding or a route (DECISIONS.md §262).

Two questions, answered together because a reader acts on them together:

- **Is it still true?** A finding is a statement about the estate as it was
  when the provider was read. Whether that reading is recent is judged against
  how often its connection is meant to be read, not against a fixed clock: a
  day-old reading is current for a connection scanned daily and overdue for one
  scanned hourly.
- **Is it ranked right?** A finding's risk multiplies how critical and how
  sensitive its asset is. Where nobody said, the scorer ranks cautiously
  (``RiskScorer._level_value``); where Cleave guessed from a name, it ranks on
  the guess. Either way the position is defensible and not established.

The answer changes what to do next -- look again, or declare the context --
and never where a finding sorts. A critical finding on a stale reading stays at
the top of the queue, marked as needing a rescan before anyone acts on it.

Pure: no clock is read here and no database is asked. The findings list
filters on the same judgement in SQL (``services/findings.py``), built from
the constants below so the two cannot drift apart.
"""

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from app.core.enums import Confidence, ConfidenceReason, ContextSource, Freshness, Level

#: The interval a connection with no schedule is held to. Scanned by hand, a
#: reading a day old is still the latest anybody meant to take.
MANUAL_INTERVAL_HOURS = 24
#: A reading is current for one and a half intervals: one missed scan's grace,
#: so a scan that ran late does not turn the queue amber.
FRESH_INTERVALS = 1.5
#: And stale after three, or after a week, whichever is later. A week is the
#: floor because below it "stale" would fire on an ordinary weekend for a
#: connection scanned every few hours, which teaches people to ignore it.
STALE_INTERVALS = 3
STALE_FLOOR = timedelta(days=7)

#: The context a customer can establish, as the API names it. Exposure is not
#: among them: it is read off the configuration rather than declared, so where it
#: is unknown no declaration could settle it, and a reason offering one would be
#: a remedy that does not exist. A rule that needs exposure and cannot read it
#: says so through its own evidence, as UNKNOWN.
CONTEXT_FIELDS = ("criticality", "data_sensitivity")


@dataclass(frozen=True)
class EvidenceWindow:
    """When a reading was taken, and until when it can be called current."""

    observed_at: datetime
    fresh_until: datetime
    stale_at: datetime

    def freshness(self, now: datetime) -> Freshness:
        if now >= self.stale_at:
            return Freshness.STALE
        if now >= self.fresh_until:
            return Freshness.AGING
        return Freshness.FRESH


def evidence_window(observed_at: datetime, interval_hours: int | None) -> EvidenceWindow:
    """The window a reading taken at ``observed_at`` stays current in.

    ``interval_hours`` is the connection's ``scan_interval_hours``; ``None``
    (scanned by hand) is held to :data:`MANUAL_INTERVAL_HOURS`.
    """
    interval = timedelta(hours=interval_hours or MANUAL_INTERVAL_HOURS)
    return EvidenceWindow(
        observed_at=observed_at,
        fresh_until=observed_at + interval * FRESH_INTERVALS,
        stale_at=observed_at + max(interval * STALE_INTERVALS, STALE_FLOOR),
    )


@dataclass(frozen=True)
class AssetContext:
    """The declarable context a finding's rank multiplies, and where each came from."""

    criticality: Level
    criticality_source: ContextSource
    data_sensitivity: Level
    data_sensitivity_source: ContextSource


@dataclass(frozen=True)
class Reason:
    """One way a finding falls short of HIGH, and the fields it is about."""

    code: ConfidenceReason
    #: For a context reason, which of :data:`CONTEXT_FIELDS`. Empty otherwise.
    fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class Assessment:
    level: Confidence
    freshness: Freshness
    window: EvidenceWindow
    reasons: tuple[Reason, ...]


def context_gaps(context: AssetContext) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Which context fields nobody established, and which Cleave guessed.

    A level that is UNKNOWN is unknown whatever its source says. A guess is a
    level Cleave inferred from a name (``ContextSource.INFERRED``); a type floor
    is not a guess -- a database holds data whatever it is called.
    """
    unknown = tuple(
        name
        for name, level in (
            ("criticality", context.criticality),
            ("data_sensitivity", context.data_sensitivity),
        )
        if level is Level.UNKNOWN
    )
    inferred = tuple(
        name
        for name, level, source in (
            ("criticality", context.criticality, context.criticality_source),
            ("data_sensitivity", context.data_sensitivity, context.data_sensitivity_source),
        )
        if level is not Level.UNKNOWN and source is ContextSource.INFERRED
    )
    return unknown, inferred


def assess(
    window: EvidenceWindow,
    now: datetime,
    *,
    unknown: Sequence[str] = (),
    inferred: Sequence[str] = (),
) -> Assessment:
    """Judge a reading's age and the context it was ranked on.

    Stale evidence is LOW: the finding may describe something already changed,
    so the next step is to look again. Ageing evidence or context that is
    unknown or guessed is MEDIUM: the finding stands, its rank is provisional.
    Context never takes a finding below MEDIUM, because a cautious default is
    a deliberate rank rather than a doubt about whether the misconfiguration
    is there.
    """
    freshness = window.freshness(now)
    reasons: list[Reason] = []
    if freshness is Freshness.STALE:
        reasons.append(Reason(ConfidenceReason.EVIDENCE_STALE))
    elif freshness is Freshness.AGING:
        reasons.append(Reason(ConfidenceReason.EVIDENCE_AGING))
    if unknown:
        reasons.append(Reason(ConfidenceReason.CONTEXT_UNKNOWN, tuple(unknown)))
    if inferred:
        reasons.append(Reason(ConfidenceReason.CONTEXT_INFERRED, tuple(inferred)))

    if freshness is Freshness.STALE:
        level = Confidence.LOW
    elif reasons:
        level = Confidence.MEDIUM
    else:
        level = Confidence.HIGH
    return Assessment(level=level, freshness=freshness, window=window, reasons=tuple(reasons))


def assess_finding(
    observed_at: datetime,
    interval_hours: int | None,
    context: AssetContext | None,
    now: datetime,
) -> Assessment:
    """A finding's confidence. ``context`` is ``None`` for a tenant-wide finding.

    A finding about the tenant has no asset whose context could be unknown, so
    only its evidence is judged.
    """
    unknown, inferred = context_gaps(context) if context is not None else ((), ())
    return assess(
        evidence_window(observed_at, interval_hours), now, unknown=unknown, inferred=inferred
    )


def assess_route(
    windows: Sequence[EvidenceWindow],
    target_sensitivity: Level,
    target_sensitivity_source: ContextSource,
    now: datetime,
) -> Assessment | None:
    """A route's confidence: its oldest reading, and how its target was judged sensitive.

    A route is only as current as its least current hop. A route exists only
    because its target counts as sensitive, so a target whose sensitivity was
    guessed from its name makes the whole route provisional; its entry's
    exposure is read off configuration and needs no such caveat. ``None`` when
    no hop has a reading, which is an absence of evidence rather than a verdict.
    """
    if not windows:
        return None
    oldest = min(windows, key=lambda window: window.observed_at)
    inferred = (
        ("data_sensitivity",)
        if target_sensitivity is not Level.UNKNOWN
        and target_sensitivity_source is ContextSource.INFERRED
        else ()
    )
    return assess(oldest, now, inferred=inferred)
