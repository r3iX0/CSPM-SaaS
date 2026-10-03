"""Sealed audit packages against the real database (DECISIONS.md section 204).

What only a database can hold shut:

* A sealed package is immutable to everyone the application can be, and a row
  edited anyway no longer verifies.
* Another organization cannot read it, by id or by listing.
* It survives a round trip through JSONB with the hash it was sealed under,
  which a unit test over Python objects cannot say.
* Retention keeps the payload a package names while still pruning one nothing
  names, so the interlock is shown to hold something rather than everything.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from app.compliance.catalog import get_framework
from app.core.db import rls_session, service_session
from app.core.deps import TenantContext
from app.core.enums import (
    CloudAccountStatus,
    ConnectionScope,
    ConsentStatus,
    Provider,
    Role,
    ScanStatus,
    TaskOutcome,
)
from app.core.errors import ConflictError, NotFound, PermissionDenied, ValidationFailed
from app.core.security import AuthenticatedUser
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection
from app.models.scan import Evidence, EvidenceBlob, Scan
from app.services import audit_packages
from app.services import compliance as compliance_service
from app.services.retention import prune_blobs
from tests.integration.conftest import create_org_as

pytestmark = pytest.mark.integration

OWNER = uuid.UUID("22222222-0000-0000-0000-00000000000a")
OTHER = uuid.UUID("22222222-0000-0000-0000-00000000000b")
TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
FRAMEWORK = "NIS2"
PAYLOAD = {"resources": [{"id": "/x/vm-1"}]}
HELD_HASH = "c" * 64
UNPINNED_HASH = "d" * 64
NOW = datetime.now(UTC)


def tenant_of(user: uuid.UUID, org_id: uuid.UUID, role: Role = Role.OWNER) -> TenantContext:
    return TenantContext(
        user=AuthenticatedUser(id=user, email=f"{user}@example.com"),
        organization_id=org_id,
        role=role,
    )


async def make_estate(name: str, *, scanned: bool = True) -> uuid.UUID:
    """An organization with an Azure connection and, optionally, one completed scan."""
    org_id = await create_org_as(OWNER, name)
    async with service_session() as session:
        connection = CloudConnection(
            organization_id=org_id,
            provider=Provider.AZURE,
            name="tenant",
            scope_type=ConnectionScope.TENANT_ROOT,
            role_version="v1",
            tenant_id=TENANT,
            consent_status=ConsentStatus.GRANTED,
            rbac_verified_at=NOW,
            status=CloudAccountStatus.ACTIVE,
        )
        session.add(connection)
        await session.flush()
        account = CloudAccount(
            organization_id=org_id,
            connection_id=connection.id,
            provider=Provider.AZURE,
            account_name="Subscription 1",
            display_name="Subscription 1",
            tenant_id=TENANT,
            subscription_id="00000000-0000-0000-0000-000000000001",
            consent_status=ConsentStatus.GRANTED,
            rbac_verified_at=NOW,
            status=CloudAccountStatus.ACTIVE,
            in_scope=True,
        )
        session.add(account)
        await session.flush()
        if scanned:
            session.add(
                Scan(
                    organization_id=org_id,
                    connection_id=connection.id,
                    status=ScanStatus.COMPLETED,
                    completed_at=NOW,
                )
            )
        await session.commit()
    return org_id


async def framework_keys(org_id: uuid.UUID) -> list[str]:
    """The evidence keys the framework's controls declare, so readings can be given to them."""
    async with rls_session(OWNER) as session:
        detail = await compliance_service.get_framework_detail(session, org_id, FRAMEWORK)
    assert detail is not None
    keys = sorted(
        {
            reading["evidence_key"]
            for control in detail["controls"]
            for reading in control["readings"]
        }
    )
    assert len(keys) >= 2, f"{FRAMEWORK} needs two declared evidence keys for this test"
    return keys


async def read_estate(org_id: uuid.UUID, keys: list[str]) -> None:
    """One held reading and one failed one, on the organization's completed scan."""
    async with service_session() as session:
        scan = (
            await session.execute(
                text("SELECT id, connection_id FROM scans WHERE organization_id = :org"),
                {"org": org_id},
            )
        ).one()
        account_id = (
            await session.execute(
                text("SELECT id FROM cloud_accounts WHERE organization_id = :org"),
                {"org": org_id},
            )
        ).scalar_one()
        session.add(
            EvidenceBlob.of(
                organization_id=org_id,
                payload=PAYLOAD,
                content_hash=HELD_HASH,
                byte_size=40,
                observed_at=NOW,
            )
        )
        for key, outcome, content_hash in (
            (keys[0], TaskOutcome.COMPLETE, HELD_HASH),
            (keys[1], TaskOutcome.FAILED, None),
        ):
            session.add(
                Evidence(
                    organization_id=org_id,
                    scan_id=scan.id,
                    cloud_account_id=account_id,
                    connection_id=scan.connection_id,
                    provider=Provider.AZURE,
                    evidence_key=key,
                    category="test",
                    outcome=outcome,
                    item_count=1 if content_hash else 0,
                    collected_at=NOW - timedelta(hours=3),
                    permissions=["Microsoft.Resources/subscriptions/read"],
                    endpoints=[{"path": "/subscriptions/x/resources", "api_version": "2023-07-01"}],
                    content_hash=content_hash,
                    byte_size=40 if content_hash else 0,
                )
            )
        await session.commit()


async def seal_one(org_id: uuid.UUID) -> uuid.UUID:
    async with rls_session(OWNER) as session:
        package = await audit_packages.seal(
            session,
            tenant_of(OWNER, org_id),
            name="NIS2 audit",
            framework_ids=[FRAMEWORK],
        )
        await session.commit()
        return package.id


@pytest.fixture
async def estate(cleanup_orgs, rule_catalogue) -> uuid.UUID:
    org_id = await make_estate("Sealed Org")
    cleanup_orgs.append(org_id)
    await read_estate(org_id, await framework_keys(org_id))
    return org_id


async def test_a_sealed_package_keeps_what_was_read_and_verifies_after_a_round_trip(
    estate,
) -> None:
    package_id = await seal_one(estate)

    async with rls_session(OWNER) as session:
        package, items = await audit_packages.get_package(
            session, tenant_of(OWNER, estate), package_id
        )
        assert await audit_packages.verify_package(session, tenant_of(OWNER, estate), package_id)

    by_outcome = {item.outcome: item for item in items}
    assert by_outcome[TaskOutcome.COMPLETE].content_hash == HELD_HASH
    # A failed reading is cited too: it is the provenance behind an UNKNOWN.
    assert by_outcome[TaskOutcome.FAILED].content_hash is None
    assert package.framework_ids == [FRAMEWORK]
    assert {control["framework_id"] for control in package.controls} == {FRAMEWORK}
    assert len(package.controls) == len(get_framework(FRAMEWORK).controls)


@pytest.mark.parametrize(
    "standards",
    [
        ["SOC2", "ISO_27001", "PCI_DSS_4", "NIST_CSF_2.0", "CIS_CONTROLS_8.1"],
        ["CSA_CCM_4.1", "NIST_800_171_R2", "DORA"],
    ],
)
async def test_the_named_standards_seal_together_and_carry_every_control(
    estate, standards: list[str]
) -> None:
    """What an auditor names (DECISIONS.md sections 205 and 206). A package of several holds each
    standard whole -- the controls no rule reaches too -- and still verifies."""
    async with rls_session(OWNER) as session:
        package = await audit_packages.seal(
            session,
            tenant_of(OWNER, estate),
            name="Standards audit",
            framework_ids=standards,
        )
        await session.commit()
        package_id = package.id

    async with rls_session(OWNER) as session:
        package, _items = await audit_packages.get_package(
            session, tenant_of(OWNER, estate), package_id
        )
        assert await audit_packages.verify_package(session, tenant_of(OWNER, estate), package_id)

    assert package.framework_ids == standards
    for framework_id in standards:
        sealed = [c for c in package.controls if c["framework_id"] == framework_id]
        assert len(sealed) == len(get_framework(framework_id).controls)
        assert "NOT_COVERED" in {c["status"] for c in sealed}


async def test_sealing_is_on_the_audit_trail(estate) -> None:
    package_id = await seal_one(estate)

    async with rls_session(OWNER) as session:
        entries = (
            (
                await session.execute(
                    text(
                        "SELECT resource_id FROM audit_logs"
                        " WHERE organization_id = :org AND action = 'audit_package.sealed'"
                    ),
                    {"org": estate},
                )
            )
            .scalars()
            .all()
        )
    assert entries == [package_id]


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_packages SET name = 'edited'",
        "DELETE FROM audit_packages",
        "UPDATE audit_package_items SET content_hash = NULL",
        "DELETE FROM audit_package_items",
    ],
)
async def test_nobody_edits_a_sealed_package_through_the_application(
    estate, statement: str
) -> None:
    await seal_one(estate)

    # As the organization's own owner, the most privileged member there is.
    with pytest.raises(DBAPIError, match="permission denied"):
        async with rls_session(OWNER) as session:
            await session.execute(text(statement))


async def test_a_row_edited_behind_the_applications_back_no_longer_verifies(estate) -> None:
    package_id = await seal_one(estate)

    async with service_session() as session:
        await session.execute(
            text(
                "UPDATE audit_package_items SET content_hash = :forged"
                " WHERE package_id = :id AND content_hash IS NOT NULL"
            ),
            {"forged": "e" * 64, "id": package_id},
        )
        await session.commit()

    async with rls_session(OWNER) as session:
        assert not await audit_packages.verify_package(
            session, tenant_of(OWNER, estate), package_id
        )


async def test_another_organization_cannot_read_a_package(estate, cleanup_orgs) -> None:
    package_id = await seal_one(estate)
    other_org = await create_org_as(OTHER, "Somebody Else")
    cleanup_orgs.append(other_org)

    async with rls_session(OTHER) as session:
        tenant = tenant_of(OTHER, other_org)
        assert await audit_packages.list_packages(session, tenant) == []
        with pytest.raises(NotFound):
            await audit_packages.get_package(session, tenant, package_id)
        # Asked for under no organization's name at all, the database still says no.
        leaked = (
            await session.execute(
                text("SELECT count(*) FROM audit_packages WHERE id = :id"), {"id": package_id}
            )
        ).scalar_one()
        assert leaked == 0


async def test_a_viewer_cannot_seal(estate) -> None:
    async with rls_session(OWNER) as session:
        with pytest.raises(PermissionDenied, match="requires one of"):
            await audit_packages.seal(
                session,
                tenant_of(OWNER, estate, Role.VIEWER),
                name="nope",
                framework_ids=[FRAMEWORK],
            )


async def test_sealing_before_any_scan_is_refused_rather_than_dated_to_nothing(
    cleanup_orgs, rule_catalogue
) -> None:
    org_id = await make_estate("Unscanned Org", scanned=False)
    cleanup_orgs.append(org_id)

    with pytest.raises(ConflictError, match="Run a scan"):
        await seal_one(org_id)


async def test_a_framework_the_organization_is_not_measured_by_is_refused(estate) -> None:
    async with rls_session(OWNER) as session:
        with pytest.raises(ValidationFailed, match="Not a framework"):
            await audit_packages.seal(
                session,
                tenant_of(OWNER, estate),
                name="wrong cloud",
                framework_ids=["CIS_AWS_7.0"],
            )


async def test_retention_keeps_a_payload_a_package_names_and_prunes_one_nothing_names(
    estate,
) -> None:
    await seal_one(estate)
    long_ago = NOW - timedelta(days=400)

    async with service_session() as session:
        session.add(
            EvidenceBlob.of(
                organization_id=estate,
                payload={"other": True},
                content_hash=UNPINNED_HASH,
                byte_size=20,
                observed_at=long_ago,
            )
        )
        await session.flush()
        await session.execute(
            text("UPDATE evidence_blobs SET last_seen_at = :old WHERE organization_id = :org"),
            {"old": long_ago, "org": estate},
        )
        await session.commit()

    async with service_session() as session:
        pruned = await prune_blobs(session, estate, keep_days=30)
        await session.commit()
        remaining = set(
            (
                await session.execute(
                    text("SELECT content_hash FROM evidence_blobs WHERE organization_id = :org"),
                    {"org": estate},
                )
            )
            .scalars()
            .all()
        )

    assert pruned == 1
    assert HELD_HASH in remaining
    assert UNPINNED_HASH not in remaining
