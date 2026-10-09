"""What a sealed audit package says, and the hash that says it was not changed.

The one place the manifest is defined. Sealing builds it and stores its SHA-256;
verifying builds it again from the stored rows and compares. Everything an
auditor is shown or handed derives from the same function, so there is no
second description of a package that could drift from the first.

**What the hash does and does not prove.** It proves the package's rows are the
ones that were sealed: edit a verdict, a timestamp or a reading's hash and the
manifest no longer matches. A reading's own ``content_hash`` proves that the
stored payload is the bytes CloudGuard captured. Neither proves the provider
said it -- that rests on CloudGuard having been the one to ask, which is why a
reading carries the permissions and api-version it was made under, and why the
archive's README says this in as many words (DECISIONS.md section 208).

Pure functions. Nothing here touches the database, so the whole document is
testable without a scan, and it is deterministic: the same rows always give the
same bytes, which is what makes the hash worth taking.
"""

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, time, timedelta
from enum import Enum
from typing import Any
from uuid import UUID

from app.compliance.coverage import ControlStatus
from app.core.payloads import digest
from app.models.audit_package import AuditPackage, AuditPackageItem
from app.models.scan import Evidence

MANIFEST_VERSION = 2

#: The first version whose manifest carries the fixes (DECISIONS.md section 238). A package
#: sealed under version 1 is hashed without them, and still verifies as it was sealed.
FIXES_SINCE = 2

#: How many fixes one package keeps, the latest ones; ``total`` says how many there were.
MAX_FIXES = 5000

#: The window a package without a declared period looks back over for fixes: a year, the usual
#: audit cycle. Said in the manifest, so nobody has to guess it.
DEFAULT_FIX_WINDOW = timedelta(days=365)

# What changes with the clock rather than with the estate. ``age_seconds`` is
# relative to whoever asks, and ``retained`` is whether retention has run since:
# both are true of a package today and false of it next year, so a sealed
# document that carried them would be wrong about itself. They are answered live.
_VOLATILE_READING_FIELDS = frozenset({"age_seconds", "retained"})


def _iso(moment: datetime | None) -> str | None:
    """One spelling per instant, so the same moment always hashes the same.

    PostgreSQL hands back an aware datetime in whatever zone the session used;
    a fixture may hand back a naive one. Both are read as UTC.
    """
    if moment is None:
        return None
    aware = moment if moment.tzinfo else moment.replace(tzinfo=UTC)
    return aware.astimezone(UTC).isoformat()


def _date(value: date | None) -> str | None:
    return value.isoformat() if value else None


def _text(value: Enum | UUID | None) -> str | None:
    """An enum or a UUID as the string the manifest holds."""
    if value is None:
        return None
    return value.value if isinstance(value, Enum) else str(value)


def seal_controls(framework_id: str, controls: Iterable[Mapping[str, Any]]) -> list[dict]:
    """A framework's controls as they are kept: verdicts, rules, and what was read.

    Takes the control dicts ``services.compliance`` already builds for the screen
    and the export -- ``Any`` here is that service's own untyped document -- so a
    sealed verdict is the same number the customer saw and not a second
    calculation of it. What is dropped is the volatile fields, and what is added
    is the framework each control belongs to, since a package may hold several
    and a control id alone (``1.1``) is ambiguous between them.
    """
    sealed: list[dict] = []
    for control in controls:
        readings = [
            {key: value for key, value in reading.items() if key not in _VOLATILE_READING_FIELDS}
            for reading in control.get("readings") or []
        ]
        sealed.append(
            {
                "framework_id": framework_id,
                "id": control["id"],
                "title": control["title"],
                "group": control["group"],
                "technically_assessable": bool(control["technically_assessable"]),
                "status": control["status"],
                "open_finding_count": int(control["open_finding_count"]),
                "evidence_keys": sorted({reading["evidence_key"] for reading in readings}),
                "readings": readings,
                "rules": [dict(rule) for rule in control.get("rules") or []],
            }
        )
    return sealed


def item_fields(reading: Evidence) -> dict[str, Any]:
    """One reading, as the ``audit_package_items`` columns hold it.

    The keys are the item's own column names, so the service can build the row
    from them and ``manifest`` can describe the same row back.
    """
    return {
        "evidence_key": reading.evidence_key,
        "cloud_account_id": reading.cloud_account_id,
        "region": reading.region,
        "provider": reading.provider,
        "outcome": reading.outcome,
        "item_count": reading.item_count,
        "collected_at": reading.collected_at,
        # The scan that actually took the reading. A carried one is older than
        # the scan that holds it (``Evidence.source_scan_id``), and a package
        # that named the holder would date the reading wrongly.
        "source_scan_id": reading.source_scan_id or reading.scan_id,
        "permissions": list(reading.permissions or []),
        "endpoints": list(reading.endpoints or []),
        "content_hash": reading.content_hash,
        "byte_size": reading.byte_size,
    }


def _item(row: AuditPackageItem) -> dict[str, Any]:
    return {
        "evidence_key": row.evidence_key,
        "cloud_account_id": _text(row.cloud_account_id),
        "region": row.region,
        "provider": _text(row.provider),
        "outcome": _text(row.outcome),
        "item_count": row.item_count,
        "collected_at": _iso(row.collected_at),
        "source_scan_id": _text(row.source_scan_id),
        "permissions": sorted(row.permissions or []),
        "endpoints": sorted(
            (dict(endpoint) for endpoint in row.endpoints or []),
            key=lambda endpoint: (endpoint.get("path", ""), endpoint.get("api_version", "")),
        ),
        "content_hash": row.content_hash,
        "byte_size": row.byte_size,
    }


def _item_order(item: Mapping[str, Any]) -> tuple[str, str, str]:
    return (item["evidence_key"], item["cloud_account_id"] or "", item["region"] or "")


@dataclass(frozen=True)
class FixTask:
    """The task that tracked a fix: its state, and when a person marked it done."""

    id: UUID
    status: str
    marked_done_at: datetime | None


@dataclass(frozen=True)
class FixVerification:
    """The latest claim that a fix was made, and what CloudGuard's checking made of it."""

    id: UUID
    status: str
    claimed_at: datetime
    settled_at: datetime | None
    verified_by_scan_id: UUID | None
    attempts: int


@dataclass(frozen=True)
class FixChange:
    """A Fix-as-Code pull request that edited the code defining the fixed asset."""

    repository: str
    number: int
    url: str | None
    state: str


@dataclass(frozen=True)
class Fix:
    """One finding a scan observed fixed, and the trail of work behind it."""

    finding_id: UUID
    rule_id: str
    severity: str
    title: str
    asset: str | None
    asset_id: str | None
    first_detected_at: datetime
    fixed_at: datetime
    fixed_by_scan_id: UUID | None
    task: FixTask | None = None
    verification: FixVerification | None = None
    changes: Sequence[FixChange] = field(default_factory=tuple)


def fix_window(
    sealed_at: datetime, period_start: date | None, period_end: date | None
) -> tuple[datetime, datetime]:
    """The half-open window ``[start, end)`` a package's fixes are taken from.

    The declared period where there is one, as whole UTC days, and never past the sealing: a
    package cannot vouch for a fix nobody has observed yet. Without a start, the year before.
    """
    end = sealed_at
    if period_end is not None:
        end = min(end, datetime.combine(period_end + timedelta(days=1), time(), tzinfo=UTC))
    if period_start is not None:
        start = datetime.combine(period_start, time(), tzinfo=UTC)
    else:
        start = end - DEFAULT_FIX_WINDOW
    return start, end


def _fix(fix: Fix) -> dict[str, Any]:
    task = fix.task
    verification = fix.verification
    return {
        "finding_id": _text(fix.finding_id),
        "rule_id": fix.rule_id,
        "severity": fix.severity,
        "title": fix.title,
        "asset": fix.asset,
        "asset_id": fix.asset_id,
        "first_detected_at": _iso(fix.first_detected_at),
        "fixed_at": _iso(fix.fixed_at),
        "fixed_by_scan_id": _text(fix.fixed_by_scan_id),
        "task": None
        if task is None
        else {
            "id": _text(task.id),
            "status": task.status,
            "marked_done_at": _iso(task.marked_done_at),
        },
        "verification": None
        if verification is None
        else {
            "id": _text(verification.id),
            "status": verification.status,
            "claimed_at": _iso(verification.claimed_at),
            "settled_at": _iso(verification.settled_at),
            "verified_by_scan_id": _text(verification.verified_by_scan_id),
            "attempts": verification.attempts,
        },
        "pull_requests": sorted(
            (
                {
                    "repository": change.repository,
                    "number": change.number,
                    "url": change.url,
                    "state": change.state,
                }
                for change in fix.changes
            ),
            key=lambda change: (change["repository"], change["number"]),
        ),
    }


def seal_fixes(fixes: Iterable[Fix], start: datetime, end: datetime) -> dict[str, Any]:
    """The fixes section as it is kept and hashed: the window, how many, and the latest few.

    Ordered by when each was observed fixed, so the same fixes always give the same bytes.
    Bounded at ``MAX_FIXES``, keeping the latest, and ``total`` says what was left out rather
    than letting a cut list pass for a whole one.
    """
    ordered = sorted(fixes, key=lambda fix: (_iso(fix.fixed_at) or "", str(fix.finding_id)))
    return {
        "window": {"from": _iso(start), "to": _iso(end)},
        "total": len(ordered),
        "items": [_fix(fix) for fix in ordered[-MAX_FIXES:]],
    }


def manifest(package: AuditPackage, items: Sequence[AuditPackageItem]) -> dict[str, Any]:
    """The canonical description of a package: what it assessed, and on what.

    Built from the rows rather than from the request that created them, so the
    same function answers both "what do we seal" and "does this still match".
    The organization is named by id: its display name is free to change after
    an audit, and a manifest that included it would stop verifying the day
    somebody fixed a typo.
    """
    document: dict[str, Any] = {
        "manifest_version": package.manifest_version,
        "package": {
            "id": _text(package.id),
            "organization_id": _text(package.organization_id),
            "name": package.name,
            "sealed_at": _iso(package.sealed_at),
            "period_start": _date(package.period_start),
            "period_end": _date(package.period_end),
            "scan": {
                "id": _text(package.scan_id),
                "status": _text(package.scan_status),
                "completed_at": _iso(package.scan_completed_at),
            },
        },
        "frameworks": list(package.frameworks),
        "controls": list(package.controls),
        "evidence": sorted((_item(row) for row in items), key=_item_order),
    }
    if package.manifest_version >= FIXES_SINCE:
        document["fixes"] = package.fixes
    return document


def manifest_digest(document: dict[str, Any]) -> str:
    """SHA-256 of the manifest's canonical bytes, the same ones payloads use."""
    return digest(document)[0]


def recompute(package: AuditPackage, items: Sequence[AuditPackageItem]) -> str:
    """The digest these rows give now, to set beside the one the package was sealed under."""
    return manifest_digest(manifest(package, items))


def verify(package: AuditPackage, items: Sequence[AuditPackageItem]) -> bool:
    """Whether these rows still describe the package that was sealed."""
    return recompute(package, items) == package.manifest_sha256


def control_status_counts(controls: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, int]]:
    """How many of each framework's sealed controls hold each status.

    Every status is a key, zeroes included, as ``coverage.status_counts`` does for the live
    view: a legend that drops the absent ones is a legend that moves between packages.
    """
    counts: dict[str, dict[str, int]] = {}
    for control in controls:
        per_framework = counts.setdefault(
            control["framework_id"], {status.value: 0 for status in ControlStatus}
        )
        per_framework[control["status"]] += 1
    return counts
