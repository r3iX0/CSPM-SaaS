"""A sealed package says what it assessed, and says so the same way every time.

The hash is worth taking only if the same rows always give the same bytes and a
changed row never does, so the tests here are the ways that goes wrong quietly:
an ordering that depends on the query, a timestamp spelled two ways, a verdict
edited after sealing, and a field that changes with the clock being sealed in.
"""

import uuid
from datetime import UTC, date, datetime, timedelta, timezone

from app.compliance.package import (
    MANIFEST_VERSION,
    item_fields,
    manifest,
    manifest_digest,
    seal_controls,
    verify,
)
from app.core.enums import Provider, ScanStatus, TaskOutcome
from app.models.audit_package import AuditPackage, AuditPackageItem
from app.models.scan import Evidence

ORG = uuid.UUID("00000000-0000-0000-0000-0000000000a1")
PACKAGE = uuid.UUID("00000000-0000-0000-0000-0000000000b1")
SCAN = uuid.UUID("00000000-0000-0000-0000-0000000000c1")
ACCOUNT = uuid.UUID("00000000-0000-0000-0000-0000000000d1")
SEALED_AT = datetime(2026, 10, 2, 12, 0, tzinfo=UTC)
HASH_A = "a" * 64
HASH_B = "b" * 64


def control(**overrides) -> dict:
    base = {
        "id": "21.2.d",
        "title": "Encryption",
        "group": "Article 21",
        "technically_assessable": True,
        "status": "PASSING",
        "open_finding_count": 0,
        "rules": [{"rule_id": "AZ-STO-001", "name": "HTTPS only", "unknown_reasons": []}],
        "readings": [
            {
                "evidence_key": "storage_accounts",
                "outcome": "COMPLETE",
                "scopes": 2,
                "collected_at": "2026-10-02T09:00:00+00:00",
                "permissions": ["Microsoft.Storage/storageAccounts/read"],
                "age_seconds": 11000,
                "retained": True,
            }
        ],
    }
    base.update(overrides)
    return base


def item(**overrides) -> AuditPackageItem:
    fields = {
        "package_id": PACKAGE,
        "organization_id": ORG,
        "evidence_key": "storage_accounts",
        "cloud_account_id": ACCOUNT,
        "region": None,
        "provider": Provider.AZURE,
        "outcome": TaskOutcome.COMPLETE,
        "item_count": 3,
        "collected_at": datetime(2026, 10, 2, 9, 0, tzinfo=UTC),
        "source_scan_id": SCAN,
        "permissions": ["Microsoft.Storage/storageAccounts/read"],
        "endpoints": [{"path": "/subscriptions/x/storageAccounts", "api_version": "2023-05-01"}],
        "content_hash": HASH_A,
        "byte_size": 1200,
    }
    fields.update(overrides)
    return AuditPackageItem(**fields)


def package(**overrides) -> AuditPackage:
    fields = {
        "id": PACKAGE,
        "organization_id": ORG,
        "name": "NIS2 audit 2026",
        "framework_ids": ["NIS2"],
        "frameworks": [{"id": "NIS2", "short_name": "NIS2", "version": "2022"}],
        "controls": seal_controls("NIS2", [control()]),
        "scan_id": SCAN,
        "scan_status": ScanStatus.COMPLETED,
        "scan_completed_at": datetime(2026, 10, 2, 9, 5, tzinfo=UTC),
        "period_start": date(2026, 1, 1),
        "period_end": date(2026, 9, 30),
        "manifest_version": MANIFEST_VERSION,
        "manifest_sha256": "",
        "sealed_by": uuid.UUID("00000000-0000-0000-0000-0000000000e1"),
        "sealed_at": SEALED_AT,
    }
    fields.update(overrides)
    return AuditPackage(**fields)


def sealed(items: list[AuditPackageItem], **overrides) -> AuditPackage:
    sealed_package = package(**overrides)
    sealed_package.manifest_sha256 = manifest_digest(manifest(sealed_package, items))
    return sealed_package


def test_what_changes_with_the_clock_is_not_sealed_in() -> None:
    (sealed_control,) = seal_controls("NIS2", [control()])

    (reading,) = sealed_control["readings"]
    assert "age_seconds" not in reading
    assert "retained" not in reading
    # The part that is a fact about the estate stays.
    assert reading["collected_at"] == "2026-10-02T09:00:00+00:00"


def test_a_control_says_which_framework_it_belongs_to() -> None:
    (cis,) = seal_controls("CIS_AZURE_6.0", [control(id="1.1")])
    (nis2,) = seal_controls("NIS2", [control(id="1.1")])

    assert cis["framework_id"] != nis2["framework_id"]
    assert cis["evidence_keys"] == ["storage_accounts"]


def test_a_control_nothing_read_is_kept_as_unread_not_dropped() -> None:
    unread = control(
        status="INCONCLUSIVE",
        readings=[{"evidence_key": "key_vaults", "outcome": None, "scopes": 0}],
    )

    (sealed_control,) = seal_controls("NIS2", [unread])

    assert sealed_control["status"] == "INCONCLUSIVE"
    assert sealed_control["readings"][0]["outcome"] is None


def test_the_same_rows_hash_the_same_whatever_order_they_arrive_in() -> None:
    first = item(evidence_key="storage_accounts")
    second = item(evidence_key="key_vaults", content_hash=HASH_B)

    forward = manifest_digest(manifest(package(), [first, second]))
    backward = manifest_digest(manifest(package(), [second, first]))

    assert forward == backward


def test_one_instant_is_one_spelling_whatever_zone_it_came_back_in() -> None:
    utc = item(collected_at=datetime(2026, 10, 2, 9, 0, tzinfo=UTC))
    plus_two = item(collected_at=datetime(2026, 10, 2, 11, 0, tzinfo=timezone(timedelta(hours=2))))
    naive = item(collected_at=datetime(2026, 10, 2, 9, 0))

    digests = {manifest_digest(manifest(package(), [row])) for row in (utc, plus_two, naive)}

    assert len(digests) == 1


def test_a_sealed_package_verifies() -> None:
    items = [item()]

    assert verify(sealed(items), items)


def test_an_edited_verdict_no_longer_verifies() -> None:
    items = [item()]
    sealed_package = sealed(items)

    sealed_package.controls = seal_controls("NIS2", [control(status="FAILING")])

    assert not verify(sealed_package, items)


def test_an_edited_reading_hash_no_longer_verifies() -> None:
    items = [item()]
    sealed_package = sealed(items)

    items[0].content_hash = HASH_B

    assert not verify(sealed_package, items)


def test_a_reading_added_afterwards_no_longer_verifies() -> None:
    items = [item()]
    sealed_package = sealed(items)

    items.append(item(evidence_key="key_vaults", content_hash=HASH_B))

    assert not verify(sealed_package, items)


def test_a_reading_removed_afterwards_no_longer_verifies() -> None:
    items = [item(), item(evidence_key="key_vaults", content_hash=HASH_B)]
    sealed_package = sealed(items)

    assert not verify(sealed_package, items[:1])


def test_the_organization_is_named_by_id_so_renaming_it_does_not_break_the_seal() -> None:
    document = manifest(package(), [item()])

    assert document["package"]["organization_id"] == str(ORG)
    assert "organization" not in document["package"]


def test_the_manifest_carries_the_version_it_was_built_under() -> None:
    assert manifest(package(), [])["manifest_version"] == MANIFEST_VERSION


def test_a_failed_reading_is_still_a_cited_reading_with_no_hash() -> None:
    failed = item(outcome=TaskOutcome.FAILED, content_hash=None, item_count=0, byte_size=0)

    (entry,) = manifest(package(), [failed])["evidence"]

    assert entry["outcome"] == "FAILED"
    assert entry["content_hash"] is None


def test_a_carried_reading_is_dated_to_the_scan_that_took_it() -> None:
    collecting = uuid.UUID("00000000-0000-0000-0000-0000000000c2")
    carried = Evidence(
        scan_id=SCAN,
        source_scan_id=collecting,
        evidence_key="storage_accounts",
        provider=Provider.AZURE,
        outcome=TaskOutcome.COMPLETE,
        item_count=1,
        collected_at=datetime(2026, 9, 1, tzinfo=UTC),
        permissions=[],
        endpoints=[],
        content_hash=HASH_A,
        byte_size=10,
    )
    taken = Evidence(
        scan_id=SCAN,
        source_scan_id=None,
        evidence_key="key_vaults",
        provider=Provider.AZURE,
        outcome=TaskOutcome.COMPLETE,
        item_count=1,
        collected_at=datetime(2026, 10, 2, tzinfo=UTC),
        permissions=[],
        endpoints=[],
        content_hash=HASH_B,
        byte_size=10,
    )

    assert item_fields(carried)["source_scan_id"] == collecting
    assert item_fields(taken)["source_scan_id"] == SCAN
