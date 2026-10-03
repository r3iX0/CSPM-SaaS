"""A sealed audit package as the files an auditor is handed, which check themselves.

The export an auditor opens is a zip, and what is in it is built so that nobody has to take
Cleave's word for it. ``manifest.json`` is the canonical manifest, byte for byte what the package
was hashed over, so ``sha256sum manifest.json`` is the ``manifest_sha256`` sealed in the audit
trail. Each payload is written as the exact bytes it was captured as and named by their hash, so
the file name is the claim and ``sha256sum -c SHA256SUMS`` is the check. A payload that no longer
hashes to its name is left out and listed as a gap rather than shipped under a name it does not
earn (DECISIONS.md section 204).

**Nothing in the archive is live.** It carries no PDF and no assessment recomputed today: a report
rendered at download time would describe the estate now, in a file that claims to describe it on
the sealing date. Whether a payload is still stored is the one thing that can change, and it is
reported as it stands at the moment of the download.

**Gaps are listed beside passes.** ``gaps.csv`` carries every control Cleave could not reach, not
conclude on, or cannot observe, and every reading that failed, was partial, was never taken, or
whose bytes are gone. An export of only the green rows is the one document where that omission is
expensive, so it is not an option.

Deterministic: the same package and payloads give the same bytes, so a download can be compared
with the one before it. Pure apart from the file it writes to; nothing here touches the database.
"""

import csv
import hashlib
import io
import re
import zipfile
import zlib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import IO, Any

from app.compliance import package as manifest_module
from app.compliance.coverage import ControlStatus
from app.compliance.export import control_reading_summary
from app.core.payloads import canonical, inflate
from app.models.audit_package import AuditPackage, AuditPackageItem

# What a stored payload became in the archive. ``NONE`` is a reading that produced nothing, so
# there was never a hash to follow.
INCLUDED = "INCLUDED"
PRUNED = "PRUNED"
CORRUPT = "CORRUPT"
NONE = "NONE"

_HASH = re.compile(r"[0-9a-f]{64}")
_FILENAME_SAFE = re.compile(r"[^A-Za-z0-9._-]+")

# A spreadsheet runs a cell that starts with one of these as a formula, and a reason Cleave quotes
# from a provider is text an attacker may have influenced.
_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")

# The earliest date a zip entry can hold.
_ZIP_EPOCH = datetime(1980, 1, 1, tzinfo=UTC)

CONTROL_COLUMNS = (
    "framework",
    "framework_version",
    "scan_completed_at",
    "control_id",
    "control_group",
    "control_title",
    "status",
    "technically_assessable",
    "open_findings",
    "rules",
    "evidence_keys",
    "evidence_outcome",
    "evidence_oldest_read",
    "evidence_scopes",
    "inconclusive_reasons",
)
READING_COLUMNS = (
    "evidence_key",
    "cloud_account_id",
    "region",
    "provider",
    "outcome",
    "item_count",
    "collected_at",
    "source_scan_id",
    "permissions",
    "api_endpoints",
    "content_hash",
    "byte_size",
    "payload_status",
    "payload_file",
)
GAP_COLUMNS = ("framework", "control_id", "kind", "subject", "detail")


@dataclass(frozen=True)
class ArchiveSummary:
    """What went into an archive, for the audit trail and for the tests."""

    files: int
    payloads_included: int
    payloads_pruned: int
    payloads_corrupt: int
    gaps: int


def _slug(text: str, fallback: str) -> str:
    return _FILENAME_SAFE.sub("-", text).strip("-.") or fallback


def archive_name(package: AuditPackage) -> str:
    """The folder the archive unpacks to, and the stem of the file it is downloaded as."""
    return (
        f"audit-package-{_slug(package.name.lower(), 'package')}"
        f"-{package.sealed_at.astimezone(UTC):%Y-%m-%d}-{str(package.id)[:8]}"
    )


def _cell(value: object) -> str:
    text = "" if value is None else str(value)
    return f"'{text}" if text.startswith(_FORMULA_TRIGGERS) else text


def _csv(header: Sequence[str], rows: Iterable[Sequence[object]]) -> bytes:
    """RFC 4180 and CRLF, with a byte-order mark: Excel reads a file without one as Windows-1252
    and renders every non-ASCII character in a control title as mojibake."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\r\n")
    writer.writerow(header)
    for row in rows:
        writer.writerow([_cell(value) for value in row])
    return buffer.getvalue().encode("utf-8-sig")


def _frameworks(package: AuditPackage) -> dict[str, Mapping[str, Any]]:
    return {header["id"]: header for header in package.frameworks}


def _control_rows(package: AuditPackage, framework_id: str) -> list[list[object]]:
    header = _frameworks(package)[framework_id]
    completed = package.scan_completed_at.isoformat() if package.scan_completed_at else ""
    rows: list[list[object]] = []
    for control in package.controls:
        if control["framework_id"] != framework_id:
            continue
        readings = control.get("readings") or []
        outcome, oldest, scopes, _retained = control_reading_summary(readings)
        reasons = sorted(
            {
                reason
                for rule in control.get("rules") or []
                for reason in rule.get("unknown_reasons") or []
            }
        )
        rows.append(
            [
                header["short_name"],
                header["version"],
                completed,
                control["id"],
                control["group"],
                control["title"],
                control["status"],
                "yes" if control["technically_assessable"] else "no",
                control["open_finding_count"],
                # Semicolons, not commas, inside a cell: the file is delimited by commas.
                "; ".join(rule["rule_id"] for rule in control.get("rules") or []),
                "; ".join(control["evidence_keys"]),
                outcome,
                oldest,
                scopes,
                "; ".join(reasons),
            ]
        )
    return rows


def _gap_rows(
    package: AuditPackage,
    items: Sequence[AuditPackageItem],
    payload_status: Mapping[str, str],
) -> list[list[object]]:
    """Every control Cleave cannot speak to, and every reading that does not stand on its own."""
    rows: list[list[object]] = []
    for control in package.controls:
        framework = control["framework_id"]
        status = control["status"]
        if status == ControlStatus.INCONCLUSIVE:
            reasons = sorted(
                {
                    r
                    for rule in control.get("rules") or []
                    for r in rule.get("unknown_reasons") or []
                }
            )
            rows.append([framework, control["id"], "CONTROL_INCONCLUSIVE", "", "; ".join(reasons)])
        elif status == ControlStatus.NOT_ASSESSED:
            rows.append([framework, control["id"], "CONTROL_NOT_ASSESSED", "", "No scan has run."])
        elif status == ControlStatus.NOT_COVERED:
            if control["technically_assessable"]:
                kind, detail = "CONTROL_NOT_COVERED", "No rule reaches this control yet."
            else:
                kind = "CONTROL_NOT_ASSESSABLE"
                detail = "Organizational, procedural or physical: a scanner cannot observe it."
            rows.append([framework, control["id"], kind, "", detail])
        for reading in control.get("readings") or []:
            if reading.get("outcome") is None:
                rows.append(
                    [
                        framework,
                        control["id"],
                        "READING_NOT_READ",
                        reading["evidence_key"],
                        "The scan holds no reading of this listing.",
                    ]
                )
    for item in items:
        outcome = item.outcome.value
        subject = item.evidence_key
        if outcome != "COMPLETE":
            rows.append(["", "", f"READING_{outcome}", subject, f"Read in {item.region or 'all'}."])
        status = payload_status.get(item.content_hash or "", NONE)
        if status == PRUNED:
            rows.append(
                ["", "", "PAYLOAD_PRUNED", subject, f"{item.content_hash} is no longer stored."]
            )
        elif status == CORRUPT:
            rows.append(
                [
                    "",
                    "",
                    "PAYLOAD_CORRUPT",
                    subject,
                    f"{item.content_hash}: stored bytes do not hash to it.",
                ]
            )
    return rows


def _reading_rows(
    items: Sequence[AuditPackageItem], payload_status: Mapping[str, str]
) -> list[list[object]]:
    rows: list[list[object]] = []
    for item in sorted(
        items, key=lambda i: (i.evidence_key, str(i.cloud_account_id or ""), i.region or "")
    ):
        status = payload_status.get(item.content_hash or "", NONE)
        rows.append(
            [
                item.evidence_key,
                item.cloud_account_id or "",
                item.region or "",
                item.provider.value,
                item.outcome.value,
                item.item_count,
                item.collected_at.astimezone(UTC).isoformat(),
                item.source_scan_id or "",
                "; ".join(sorted(item.permissions or [])),
                "; ".join(
                    sorted(
                        f"{e.get('path', '')} ({e.get('api_version', '')})"
                        for e in item.endpoints or []
                    )
                ),
                item.content_hash or "",
                item.byte_size,
                status,
                f"evidence/payloads/{item.content_hash}.json" if status == INCLUDED else "",
            ]
        )
    return rows


def _readme(package: AuditPackage, summary: ArchiveSummary, root: str) -> bytes:
    frameworks = "\n".join(
        f"- {h['short_name']} {h['version']} ({h['authority']})" for h in package.frameworks
    )
    period = (
        f"{package.period_start} to {package.period_end}"
        if package.period_start or package.period_end
        else "not declared"
    )
    completed = package.scan_completed_at.isoformat() if package.scan_completed_at else "unknown"
    text = f"""\
Cleave audit package: {package.name}
{"=" * 60}

Sealed at     {package.sealed_at.astimezone(UTC).isoformat()}
Package id    {package.id}
Organization  {package.organization_id}
Evidence      scan {package.scan_id}, {package.scan_status.value}, completed {completed}
Audit period  {period} (declared by the customer; the evidence is the one scan above)
Manifest      sha256 {package.manifest_sha256}

Frameworks assessed:
{frameworks}

WHAT THIS IS
------------
A record of what Cleave read from the customer's cloud on the date above, and what each control's
verdict rests on. It is evidence for an auditor to test. It is not an opinion that any requirement
is met: only an auditor or a licensed assessor gives one. Nothing here changes after sealing.

HOW TO CHECK IT
---------------
From inside this folder:

    sha256sum -c SHA256SUMS        (on macOS: shasum -a 256 -c SHA256SUMS)

Every file listed there must say OK. Then check the manifest against the hash Cleave recorded in
its audit trail when the package was sealed (shown above):

    sha256sum manifest.json

Each evidence payload is stored as the exact bytes Cleave captured, named by its own SHA-256, so
its file name is the claim and the check above is the proof.

WHAT A HASH PROVES, AND WHAT IT DOES NOT
----------------------------------------
It proves these files are the ones that were sealed: change a verdict, a timestamp or a payload
and the check fails. It does not prove the cloud provider said what the payload says. That rests
on Cleave having been the one to ask, which is why every reading names the listing, the
permission it was read under and the API version. The hash binds the record. It cannot vouch for
the source.

WHAT IS HERE
------------
manifest.json            The package: every control's verdict and the rules behind it, and every
                         reading. Compact canonical JSON, byte for byte what was hashed; read it
                         with a JSON viewer or `jq .`.
controls/<framework>.csv One row per control, with its status, rules and the readings it rests on.
gaps.csv                 What Cleave could not reach, could not conclude on, or cannot observe,
                         and readings that failed, were partial, or whose bytes are gone. Read it
                         before the controls: a control that is green and unread is not a pass.
evidence/readings.csv    One row per reading: when, under which permission, and the payload hash.
evidence/payloads/       The captured provider responses, one file per distinct hash.
SHA256SUMS               The hash of every other file.

STATUSES
--------
FAILING         at least one rule is failing.
INCONCLUSIVE    nothing is failing but a rule could not be evaluated. Not a pass.
PASSING         every mapped rule was evaluated and none is failing.
NOT_ASSESSED    rules map to the control and no scan produced a result.
NOT_COVERED     no rule reaches the control. Whether a scanner could ever is in the
                technically_assessable column.

A scan that finished PARTIAL read less than the whole estate; its status is above, and so are
the readings that came back incomplete.

THIS ARCHIVE
------------
{summary.payloads_included} payload(s) included, {summary.payloads_pruned} no longer stored,
{summary.payloads_corrupt} stored but not matching their hash and left out, {summary.gaps} gap(s)
listed. Folder: {root}
"""
    return text.encode()


def _zip_time(package: AuditPackage) -> tuple[int, int, int, int, int, int]:
    moment = max(package.sealed_at.astimezone(UTC), _ZIP_EPOCH)
    return (moment.year, moment.month, moment.day, moment.hour, moment.minute, moment.second)


class _Writer:
    """Adds files to the zip and keeps each one's hash, for ``SHA256SUMS``."""

    def __init__(self, out: IO[bytes], root: str, when: tuple[int, int, int, int, int, int]):
        self._zip = zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6)
        self._root = root
        self._when = when
        self.sums: dict[str, str] = {}

    def add(self, path: str, content: bytes) -> None:
        info = zipfile.ZipInfo(f"{self._root}/{path}", date_time=self._when)
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        info.create_system = 3
        self._zip.writestr(info, content)
        self.sums[path] = hashlib.sha256(content).hexdigest()

    def __enter__(self) -> "_Writer":
        return self

    def __exit__(self, *exc: object) -> None:
        # Closed on the way out of a failure too, so a half-written zip is not left to a finalizer.
        self._zip.close()


def write_archive(
    out: IO[bytes],
    package: AuditPackage,
    items: Sequence[AuditPackageItem],
    stored_payloads: Mapping[str, bytes],
) -> ArchiveSummary:
    """Write ``package`` as a zip to ``out``.

    ``stored_payloads`` maps a content hash to the bytes retention holds for it, as stored
    (zlib over the canonical bytes). A hash with no entry has been pruned. Each is inflated and
    hashed here, one at a time, so an archive's memory is one payload and not all of them.
    """
    root = archive_name(package)
    writer = _Writer(out, root, _zip_time(package))
    with writer:
        payload_status: dict[str, str] = {}
        for content_hash in sorted({i.content_hash for i in items if i.content_hash}):
            stored = stored_payloads.get(content_hash)
            if stored is None or not _HASH.fullmatch(content_hash):
                payload_status[content_hash] = PRUNED
                continue
            try:
                content = inflate(stored)
            except zlib.error:  # Truncated or damaged: named in the gaps, left out of the files.
                payload_status[content_hash] = CORRUPT
                continue
            if hashlib.sha256(content).hexdigest() != content_hash:
                payload_status[content_hash] = CORRUPT
                continue
            writer.add(f"evidence/payloads/{content_hash}.json", content)
            payload_status[content_hash] = INCLUDED

        for framework_id in package.framework_ids:
            writer.add(
                f"controls/{_slug(framework_id, 'framework')}.csv",
                _csv(CONTROL_COLUMNS, _control_rows(package, framework_id)),
            )
        gaps = _gap_rows(package, items, payload_status)
        writer.add("gaps.csv", _csv(GAP_COLUMNS, gaps))
        writer.add(
            "evidence/readings.csv", _csv(READING_COLUMNS, _reading_rows(items, payload_status))
        )
        writer.add("manifest.json", canonical(manifest_module.manifest(package, items)))

        summary = ArchiveSummary(
            files=len(writer.sums) + 2,  # this README and SHA256SUMS
            payloads_included=sum(1 for s in payload_status.values() if s == INCLUDED),
            payloads_pruned=sum(1 for s in payload_status.values() if s == PRUNED),
            payloads_corrupt=sum(1 for s in payload_status.values() if s == CORRUPT),
            gaps=len(gaps),
        )
        writer.add("README.md", _readme(package, summary, root))
        # ``sha256sum -c`` format: the hash, two spaces, the path. It lists every file but itself.
        writer.add(
            "SHA256SUMS",
            "".join(f"{digest}  {path}\n" for path, digest in sorted(writer.sums.items())).encode(),
        )
        return summary
