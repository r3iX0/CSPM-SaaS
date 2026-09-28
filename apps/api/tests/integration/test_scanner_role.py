"""What ``cloudguard_scanner`` can do, proved against the real grants.

The scanner service runs third-party code with a customer's credentials in
memory, so its role holds column grants and policies narrow enough to say what
its job is: read the scope it was handed, keep its own ASSESS step's lease and
status, write its capture (migrations 0042 and 0043, DECISIONS.md sections 150
and 151). Every test here acts as that role inside one transaction -- ``SET
LOCAL ROLE`` from the owner connection, which CI's owner may do -- and declares
the organization the way ``apps/scanner/cloudguard_scanner/store.py`` does.
"""

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import service_session
from app.core.enums import (
    CloudAccountStatus,
    ConnectionScope,
    ConsentStatus,
    Provider,
    ScanStatus,
    ScanStepKind,
    ScanStepStatus,
)
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection
from app.models.scan import Scan, ScanStep
from tests.integration.conftest import create_org_as

pytestmark = pytest.mark.integration

USER = uuid.UUID("5ca11e40-0000-0000-0000-000000000001")


@pytest.fixture
async def assessed_scan(cleanup_orgs):
    """A scan with one COLLECT and one ASSESS step, both running."""
    org_id = await create_org_as(USER, "Scanner Role Org")
    cleanup_orgs.append(org_id)
    async with service_session() as session:
        connection = CloudConnection(
            organization_id=org_id,
            provider=Provider.AZURE,
            name="production",
            scope_type=ConnectionScope.TENANT_ROOT,
            role_version="v1",
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            consent_status=ConsentStatus.GRANTED,
            rbac_verified_at=datetime.now(UTC),
            status=CloudAccountStatus.ACTIVE,
        )
        session.add(connection)
        await session.flush()
        account = CloudAccount(
            organization_id=org_id,
            connection_id=connection.id,
            provider=Provider.AZURE,
            account_name="Production Subscription",
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            subscription_id="00000000-0000-0000-0000-000000000001",
            consent_status=ConsentStatus.GRANTED,
            rbac_verified_at=datetime.now(UTC),
            status=CloudAccountStatus.ACTIVE,
        )
        session.add(account)
        await session.flush()
        scan = Scan(
            organization_id=org_id,
            cloud_account_id=account.id,
            status=ScanStatus.DISCOVERING,
        )
        session.add(scan)
        await session.flush()
        steps = {
            kind: ScanStep(
                organization_id=org_id,
                scan_id=scan.id,
                kind=kind,
                cloud_account_id=account.id,
                status=ScanStepStatus.RUNNING,
                attempt=1,
                max_attempts=3,
            )
            for kind in (ScanStepKind.COLLECT, ScanStepKind.ASSESS)
        }
        session.add_all(steps.values())
        await session.commit()
        return org_id, scan.id, {kind: step.id for kind, step in steps.items()}


@asynccontextmanager
async def as_scanner(organization_id: uuid.UUID | None) -> AsyncIterator[AsyncSession]:
    async with service_session() as session, session.begin():
        await session.execute(text("SET LOCAL ROLE cloudguard_scanner"))
        if organization_id is not None:
            await session.execute(
                text("SELECT set_config('app.organization_id', :org, true)"),
                {"org": str(organization_id)},
            )
        yield session


_SETTLE = text(
    "UPDATE scan_steps SET status = 'SUCCEEDED', lease_until = NULL "
    "WHERE id = :id AND status = 'RUNNING' AND attempt = 1"
)


async def test_the_scanner_can_settle_its_own_assess_step(assessed_scan) -> None:
    org_id, _scan_id, steps = assessed_scan
    async with as_scanner(org_id) as session:
        settled = await session.execute(_SETTLE, {"id": steps[ScanStepKind.ASSESS]})
        assert settled.rowcount == 1


async def test_the_scanner_can_neither_see_nor_settle_any_other_step(assessed_scan) -> None:
    """Migration 0043: within its organization, only ASSESS steps are its."""
    org_id, scan_id, steps = assessed_scan
    async with as_scanner(org_id) as session:
        seen = (
            (
                await session.execute(
                    text("SELECT kind FROM scan_steps WHERE scan_id = :scan"),
                    {"scan": scan_id},
                )
            )
            .scalars()
            .all()
        )
        assert seen == [ScanStepKind.ASSESS.value]
        settled = await session.execute(_SETTLE, {"id": steps[ScanStepKind.COLLECT]})
        assert settled.rowcount == 0


async def test_the_scanner_sees_nothing_of_another_organization(assessed_scan) -> None:
    _org_id, _scan_id, steps = assessed_scan
    async with as_scanner(uuid.uuid4()) as session:
        settled = await session.execute(_SETTLE, {"id": steps[ScanStepKind.ASSESS]})
        assert settled.rowcount == 0


async def test_the_scanner_learns_a_scans_organization_and_nothing_else(assessed_scan) -> None:
    org_id, scan_id, _steps = assessed_scan
    async with as_scanner(None) as session:
        owner = (
            await session.execute(text("SELECT app.scan_owner(:scan)"), {"scan": scan_id})
        ).scalar_one()
    assert owner == org_id


@pytest.mark.parametrize(
    "statement",
    [
        "SELECT id FROM findings LIMIT 1",
        "SELECT id FROM cloud_resources LIMIT 1",
        "SELECT id FROM cloud_snapshots LIMIT 1",
        "SELECT error_message FROM scans LIMIT 1",
    ],
)
async def test_the_scanner_cannot_read_what_it_has_no_job_reading(
    assessed_scan, statement: str
) -> None:
    org_id, _scan_id, _steps = assessed_scan
    with pytest.raises((DBAPIError, ProgrammingError)) as refused:
        async with as_scanner(org_id) as session:
            await session.execute(text(statement))
    assert "permission denied" in str(refused.value).lower()
