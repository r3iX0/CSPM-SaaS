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
archive's README says this in as many words (DECISIONS.md section 204).

Pure functions. Nothing here touches the database, so the whole document is
testable without a scan, and it is deterministic: the same rows always give the
same bytes, which is what makes the hash worth taking.
"""

from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, date, datetime
from enum import Enum
from typing import Any
from uuid import UUID

from app.compliance.coverage import ControlStatus
from app.core.payloads import digest
from app.models.audit_package import AuditPackage, AuditPackageItem
from app.models.scan import Evidence

MANIFEST_VERSION = 1

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


def manifest(package: AuditPackage, items: Sequence[AuditPackageItem]) -> dict[str, Any]:
    """The canonical description of a package: what it assessed, and on what.

    Built from the rows rather than from the request that created them, so the
    same function answers both "what do we seal" and "does this still match".
    The organization is named by id: its display name is free to change after
    an audit, and a manifest that included it would stop verifying the day
    somebody fixed a typo.
    """
    return {
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
