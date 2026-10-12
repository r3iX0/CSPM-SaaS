"""A package carries the fixes behind its controls, and an older package still verifies.

DECISIONS.md section 238. The fixes are hashed into manifest version 2, so the risks are the ones
the manifest already guards against -- an order that depends on the query, a field edited after
sealing -- plus one new one: a package sealed before fixes existed must not stop verifying the
day they do.
"""

import uuid
from datetime import UTC, date, datetime, timedelta

from app.compliance.package import (
    DEFAULT_FIX_WINDOW,
    MAX_FIXES,
    Fix,
    FixChange,
    FixTask,
    FixVerification,
    fix_window,
    manifest,
    manifest_digest,
    seal_controls,
    seal_fixes,
    verify,
)
from tests.unit.test_audit_archive import build, files, sealed, table
from tests.unit.test_audit_package import SEALED_AT, control, item
from tests.unit.test_audit_package import sealed as sealed_package

START = datetime(2026, 1, 1, tzinfo=UTC)
END = datetime(2026, 10, 1, tzinfo=UTC)
FINDING = uuid.UUID("00000000-0000-0000-0000-0000000000f1")
SCAN = uuid.UUID("00000000-0000-0000-0000-0000000000f2")


def fix(**overrides) -> Fix:
    fields = {
        "finding_id": FINDING,
        "rule_id": "AZ-STO-001",
        "severity": "HIGH",
        "title": "Storage allows HTTP",
        "asset": "stacct1",
        "asset_id": "/subscriptions/s/resourceGroups/rg/providers/x/stacct1",
        "first_detected_at": datetime(2026, 3, 1, tzinfo=UTC),
        "fixed_at": datetime(2026, 3, 4, 12, tzinfo=UTC),
        "fixed_by_scan_id": SCAN,
        "task": FixTask(
            id=uuid.UUID("00000000-0000-0000-0000-0000000000f3"),
            status="DONE",
            marked_done_at=datetime(2026, 3, 4, 9, tzinfo=UTC),
        ),
        "verification": FixVerification(
            id=uuid.UUID("00000000-0000-0000-0000-0000000000f4"),
            status="VERIFIED",
            claimed_at=datetime(2026, 3, 4, 9, tzinfo=UTC),
            settled_at=datetime(2026, 3, 4, 12, tzinfo=UTC),
            verified_by_scan_id=SCAN,
            attempts=1,
        ),
        "changes": (
            FixChange(repository="acme/infra", number=42, url="https://x/42", state="MERGED"),
        ),
    }
    fields.update(overrides)
    return Fix(**fields)


# ------------------------------------------------------------------ the window


def test_the_window_is_the_declared_period_in_whole_utc_days() -> None:
    start, end = fix_window(SEALED_AT, date(2026, 1, 1), date(2026, 9, 30))
    assert (start, end) == (START, END)


def test_the_window_never_runs_past_the_sealing() -> None:
    _, end = fix_window(SEALED_AT, date(2026, 1, 1), date(2027, 12, 31))
    assert end == SEALED_AT


def test_without_a_period_the_window_is_the_year_before() -> None:
    assert fix_window(SEALED_AT, None, None) == (SEALED_AT - DEFAULT_FIX_WINDOW, SEALED_AT)


# ------------------------------------------------------------------ the section


def test_fixes_are_ordered_by_when_they_were_fixed() -> None:
    later = fix(finding_id=uuid.uuid4(), fixed_at=datetime(2026, 5, 1, tzinfo=UTC))
    section = seal_fixes([later, fix()], START, END)
    assert [item["fixed_at"] for item in section["items"]] == [
        "2026-03-04T12:00:00+00:00",
        "2026-05-01T00:00:00+00:00",
    ]
    assert section["window"] == {"from": START.isoformat(), "to": END.isoformat()}


def test_a_long_list_keeps_the_latest_and_counts_them_all() -> None:
    many = [
        fix(finding_id=uuid.uuid4(), fixed_at=START + timedelta(minutes=i))
        for i in range(MAX_FIXES + 3)
    ]
    section = seal_fixes(many, START, END)
    assert section["total"] == MAX_FIXES + 3
    assert len(section["items"]) == MAX_FIXES
    assert section["items"][0]["fixed_at"] == (START + timedelta(minutes=3)).isoformat()


def test_a_fix_records_its_task_verification_and_pull_request() -> None:
    (record,) = seal_fixes([fix()], START, END)["items"]
    assert record["task"]["status"] == "DONE"
    assert record["verification"]["status"] == "VERIFIED"
    assert record["pull_requests"] == [
        {"repository": "acme/infra", "number": 42, "url": "https://x/42", "state": "MERGED"}
    ]


def test_a_fix_nobody_tracked_is_still_a_fix() -> None:
    (record,) = seal_fixes([fix(task=None, verification=None, changes=())], START, END)["items"]
    assert record["task"] is None
    assert record["verification"] is None
    assert record["pull_requests"] == []


# ------------------------------------------------------------------ the manifest


def test_a_version_1_package_is_hashed_without_fixes_and_still_verifies() -> None:
    old = sealed_package([item()], manifest_version=1)
    assert "fixes" not in manifest(old, [item()])
    assert verify(old, [item()])


def test_editing_a_sealed_fix_breaks_the_seal() -> None:
    package = sealed_package([item()], fixes=seal_fixes([fix()], START, END))
    assert verify(package, [item()])

    package.fixes["items"][0]["verification"]["status"] = "STILL_FAILING"
    assert not verify(package, [item()])


def test_the_fixes_change_the_hash() -> None:
    with_none = sealed_package([item()], fixes=seal_fixes([], START, END))
    with_one = sealed_package([item()], fixes=seal_fixes([fix()], START, END))
    assert with_none.manifest_sha256 != with_one.manifest_sha256
    assert with_one.manifest_sha256 == manifest_digest(manifest(with_one, [item()]))


# ------------------------------------------------------------------ the archive


def test_fixes_csv_lists_a_fix_under_every_control_its_rule_supports() -> None:
    controls = seal_controls("NIS2", [control(), control(id="21.2.h", title="Hygiene")])
    package = sealed([item()], controls=controls, fixes=seal_fixes([fix()], START, END))
    rows = table(files(build(package, [item()]))["fixes.csv"])
    assert [row["control_id"] for row in rows] == ["21.2.d", "21.2.h"]
    assert rows[0]["days_to_fix"] == "3.5"
    assert rows[0]["verification_status"] == "VERIFIED"
    assert rows[0]["pull_requests"] == "acme/infra#42 MERGED"


def test_a_fix_of_a_rule_no_control_rests_on_is_not_listed() -> None:
    package = sealed([item()], fixes=seal_fixes([fix(rule_id="AZ-OTHER-001")], START, END))
    assert table(files(build(package, [item()]))["fixes.csv"]) == []


def test_the_readme_says_how_many_and_over_what_window() -> None:
    package = sealed([item()], fixes=seal_fixes([fix()], START, END))
    readme = files(build(package, [item()]))["README.md"].decode()
    assert "fixes.csv" in readme
    assert f"between {START.isoformat()} and {END.isoformat()}" in readme


def test_a_version_1_archive_has_no_fixes_file() -> None:
    package = sealed([item()], manifest_version=1)
    contents = files(build(package, [item()]))
    assert "fixes.csv" not in contents
    assert "fixes.csv" not in contents["README.md"].decode()
