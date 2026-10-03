"""The archive an auditor opens checks itself, and says what it could not give them.

An export is only worth handing over if the claims in it can be tested without Cleave: a
manifest that hashes to the sealed value, payloads named by their own hash, and a ``SHA256SUMS``
that ``sha256sum -c`` accepts. The tests here are the ways that goes wrong quietly -- a payload
shipped under a hash it does not have, a gap left out because the rest looked green, a cell a
spreadsheet would run as a formula, a name that climbs out of its folder.
"""

import csv
import hashlib
import io
import zipfile
from datetime import UTC

from app.compliance.archive import CORRUPT, PRUNED, archive_name, write_archive
from app.compliance.package import seal_controls
from app.core.enums import TaskOutcome
from app.core.payloads import compress, digest
from tests.unit.test_audit_package import HASH_A, HASH_B, control, item
from tests.unit.test_audit_package import sealed as sealed_package

PAYLOAD_A = {"resources": [{"id": "/x/storage-1", "https_only": True}]}
PAYLOAD_B = {"resources": [{"id": "/x/storage-2", "https_only": False}]}
HASH_OF_A = digest(PAYLOAD_A)[0]
HASH_OF_B = digest(PAYLOAD_B)[0]


FRAMEWORK = {
    "id": "NIS2",
    "name": "NIS2 Directive",
    "short_name": "NIS2",
    "version": "2024/2690",
    "authority": "European Union",
    "url": "https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj",
    "summary": "x",
    "scope_note": "y",
}


def sealed(items, **overrides):
    return sealed_package(items, frameworks=[FRAMEWORK], **overrides)


def build(package, items, stored=None) -> zipfile.ZipFile:
    out = io.BytesIO()
    write_archive(out, package, items, stored or {})
    return zipfile.ZipFile(io.BytesIO(out.getvalue()))


def files(archive: zipfile.ZipFile) -> dict[str, bytes]:
    root = archive.namelist()[0].split("/")[0]
    return {name.removeprefix(f"{root}/"): archive.read(name) for name in archive.namelist()}


def table(content: bytes) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(content.decode("utf-8-sig"))))


def standard() -> tuple:
    held = item(content_hash=HASH_OF_A, evidence_key="storage_accounts")
    return sealed([held]), [held], {HASH_OF_A: compress(PAYLOAD_A)}


class TestItChecksItself:
    def test_sha256sums_vouches_for_every_other_file(self) -> None:
        contents = files(build(*standard()))

        listed = {}
        for line in contents["SHA256SUMS"].decode().splitlines():
            expected, path = line.split("  ", 1)
            listed[path] = expected

        assert set(listed) == set(contents) - {"SHA256SUMS"}
        for path, expected in listed.items():
            assert hashlib.sha256(contents[path]).hexdigest() == expected, path

    def test_the_manifest_is_byte_for_byte_what_was_hashed(self) -> None:
        """So ``sha256sum manifest.json`` is the hash sealed in the audit trail."""
        package, items, stored = standard()
        manifest = files(build(package, items, stored))["manifest.json"]

        assert hashlib.sha256(manifest).hexdigest() == package.manifest_sha256

    def test_a_payload_is_named_by_its_own_hash_and_is_the_captured_bytes(self) -> None:
        contents = files(build(*standard()))

        name = f"evidence/payloads/{HASH_OF_A}.json"
        assert hashlib.sha256(contents[name]).hexdigest() == HASH_OF_A
        # The canonical bytes, not a pretty-printed copy: the file is the one that was hashed.
        assert contents[name] == b'{"resources":[{"https_only":true,"id":"/x/storage-1"}]}'

    def test_the_same_package_gives_the_same_bytes(self) -> None:
        package, items, stored = standard()
        first, second = io.BytesIO(), io.BytesIO()
        write_archive(first, package, items, stored)
        write_archive(second, package, items, stored)

        assert first.getvalue() == second.getvalue()

    def test_a_shared_payload_is_one_file(self) -> None:
        a = item(content_hash=HASH_OF_A, evidence_key="storage_accounts")
        b = item(content_hash=HASH_OF_A, evidence_key="storage_accounts", region="westeurope")
        archive = build(sealed([a, b]), [a, b], {HASH_OF_A: compress(PAYLOAD_A)})

        assert len([n for n in archive.namelist() if "/evidence/payloads/" in n]) == 1


class TestWhatItCannotGiveIsSaid:
    def test_a_pruned_payload_is_a_gap_and_not_a_file(self) -> None:
        held = item(content_hash=HASH_OF_A)
        contents = files(build(sealed([held]), [held]))

        assert not [n for n in contents if n.startswith("evidence/payloads/")]
        (reading,) = table(contents["evidence/readings.csv"])
        assert reading["payload_status"] == PRUNED
        assert reading["payload_file"] == ""
        assert "PAYLOAD_PRUNED" in {row["kind"] for row in table(contents["gaps.csv"])}

    def test_a_payload_that_no_longer_matches_its_hash_is_left_out_and_named(self) -> None:
        """Shipped under a name it does not earn, it would pass a casual look and fail the check
        -- or, worse, be trusted."""
        held = item(content_hash=HASH_OF_B)
        contents = files(build(sealed([held]), [held], {HASH_OF_B: compress(PAYLOAD_A)}))

        assert f"evidence/payloads/{HASH_OF_B}.json" not in contents
        (reading,) = table(contents["evidence/readings.csv"])
        assert reading["payload_status"] == CORRUPT
        assert "PAYLOAD_CORRUPT" in {row["kind"] for row in table(contents["gaps.csv"])}

    def test_damaged_bytes_are_corrupt_rather_than_an_error(self) -> None:
        held = item(content_hash=HASH_OF_A)
        contents = files(build(sealed([held]), [held], {HASH_OF_A: b"not zlib at all"}))

        (reading,) = table(contents["evidence/readings.csv"])
        assert reading["payload_status"] == CORRUPT

    def test_a_reading_that_produced_nothing_has_no_payload_and_is_not_called_pruned(
        self,
    ) -> None:
        failed = item(content_hash=None, outcome=TaskOutcome.FAILED, byte_size=0, item_count=0)
        contents = files(build(sealed([failed]), [failed]))

        (reading,) = table(contents["evidence/readings.csv"])
        assert reading["payload_status"] == "NONE"
        kinds = {row["kind"] for row in table(contents["gaps.csv"])}
        assert "READING_FAILED" in kinds
        assert "PAYLOAD_PRUNED" not in kinds

    def test_unconcluded_and_uncovered_controls_are_listed_beside_the_passes(self) -> None:
        unread = {
            "evidence_key": "storage_accounts",
            "outcome": None,
            "scopes": 0,
            "collected_at": None,
            "permissions": [],
        }
        refused = [{"rule_id": "AZ-X-001", "name": "x", "unknown_reasons": ["Role refused."]}]
        controls = seal_controls(
            "NIS2",
            [
                control(id="1.1", status="PASSING"),
                control(id="2.1", status="INCONCLUSIVE", rules=refused),
                control(id="3.1", status="NOT_COVERED", technically_assessable=True, readings=[]),
                control(id="4.1", status="NOT_COVERED", technically_assessable=False, readings=[]),
                control(id="5.1", status="NOT_ASSESSED"),
                control(id="6.1", status="PASSING", readings=[unread]),
            ],
        )
        contents = files(build(sealed([], controls=controls), []))
        rows = table(contents["gaps.csv"])

        assert {(row["control_id"], row["kind"]) for row in rows} == {
            ("2.1", "CONTROL_INCONCLUSIVE"),
            ("3.1", "CONTROL_NOT_COVERED"),
            ("4.1", "CONTROL_NOT_ASSESSABLE"),
            ("5.1", "CONTROL_NOT_ASSESSED"),
            ("6.1", "READING_NOT_READ"),
        }
        # The reason Cleave could not conclude travels with the gap.
        assert next(r for r in rows if r["control_id"] == "2.1")["detail"] == "Role refused."

    def test_a_failing_control_is_a_finding_and_not_a_gap(self) -> None:
        package = sealed([], controls=seal_controls("NIS2", [control(status="FAILING")]))

        assert table(files(build(package, []))["gaps.csv"]) == []

    def test_the_readme_says_what_a_hash_does_not_prove(self) -> None:
        package, items, stored = standard()
        readme = files(build(package, items, stored))["README.md"].decode()

        assert "does not prove the cloud provider said" in readme
        assert "not an opinion" in readme
        assert package.manifest_sha256 in readme


class TestItIsSafeToOpen:
    def test_a_cell_a_spreadsheet_would_run_is_quoted(self) -> None:
        hostile = control(
            title='=HYPERLINK("https://evil.example","click")',
            rules=[{"rule_id": "AZ-X-001", "name": "x", "unknown_reasons": ["+cmd|' /C calc'!A0"]}],
            status="INCONCLUSIVE",
        )
        package = sealed([], controls=seal_controls("NIS2", [hostile]))
        contents = files(build(package, []))

        (row,) = table(contents["controls/NIS2.csv"])
        assert row["control_title"].startswith("'=")
        assert row["inconclusive_reasons"].startswith("'+")
        (gap,) = table(contents["gaps.csv"])
        assert gap["detail"].startswith("'+")

    def test_csv_carries_a_byte_order_mark_for_excel(self) -> None:
        assert files(build(*standard()))["controls/NIS2.csv"].startswith(b"\xef\xbb\xbf")

    def test_no_entry_leaves_its_folder_whatever_the_package_is_called(self) -> None:
        package, items, stored = standard()
        package.name = "../../etc/passwd"
        archive = build(package, items, stored)

        root = archive_name(package)
        assert ".." not in root and "/" not in root
        assert all(
            name.startswith(f"{root}/") and ".." not in name.split("/")
            for name in archive.namelist()
        )

    def test_entries_are_dated_the_seal_and_not_the_download(self) -> None:
        package, items, stored = standard()
        sealed_at = package.sealed_at.astimezone(UTC)

        assert {info.date_time[:3] for info in build(package, items, stored).infolist()} == {
            (sealed_at.year, sealed_at.month, sealed_at.day)
        }

    def test_the_folder_names_the_package_the_date_and_the_id(self) -> None:
        package, _items, _stored = standard()
        package.name = "NIS2 audit 2026"

        assert (
            archive_name(package)
            == f"audit-package-nis2-audit-2026-2026-10-02-{str(package.id)[:8]}"
        )


def test_the_summary_counts_what_went_in() -> None:
    a = item(content_hash=HASH_OF_A, evidence_key="storage_accounts")
    b = item(content_hash=HASH_OF_B, evidence_key="vaults")
    gone = item(content_hash=HASH_A, evidence_key="disks")
    bad = item(content_hash=HASH_B, evidence_key="keys")
    stored = {
        HASH_OF_A: compress(PAYLOAD_A),
        HASH_OF_B: compress(PAYLOAD_B),
        HASH_B: compress(PAYLOAD_A),
    }
    summary = write_archive(io.BytesIO(), sealed([a, b, gone, bad]), [a, b, gone, bad], stored)

    assert (summary.payloads_included, summary.payloads_pruned, summary.payloads_corrupt) == (
        2,
        1,
        1,
    )
