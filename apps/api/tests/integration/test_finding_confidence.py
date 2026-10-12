"""Confidence over the real API: the SQL that filters agrees with the Python that explains.

The list filters and counts by confidence in the database and explains each row
in Python (DECISIONS.md §262). Two implementations of one judgement are only
safe if something holds them together, and this is it.
"""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.db import service_session
from app.core.enums import (
    CloudAccountStatus,
    ConnectionScope,
    ConsentStatus,
    ContextSource,
    FindingStatus,
    Level,
    Provider,
    ResourceType,
    Severity,
)
from app.main import app
from app.models.cloud_connection import CloudConnection
from app.models.finding import Finding, FindingEvidence
from app.models.resource import ResourceRecord
from app.remediation import Comparison
from app.rules.registry import enabled_rules
from tests.integration.test_api import auth_header, make_org

pytestmark = pytest.mark.integration


@pytest.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


def equals_rule() -> tuple[str, str, str]:
    """A registered rule declaring an EQUALS expectation: id, field, version."""
    for rule in enabled_rules():
        spec = rule.remediation_spec
        for state in spec.expected if spec else ():
            if state.comparison is Comparison.EQUALS:
                return rule.rule_id, state.field, rule.version
    raise AssertionError("No rule declares an EQUALS expectation")


async def estate(org_id: uuid.UUID) -> dict[str, uuid.UUID]:
    """Four findings on a connection read every six hours.

    ``fresh`` is read an hour ago on an asset whose context the customer
    declared: HIGH. ``ageing`` was read twelve hours ago, past nine hours'
    grace: MEDIUM. ``stale`` was read ten days ago: LOW. ``guessed`` is fresh
    on an asset whose criticality was inferred from its name: MEDIUM.
    """
    rule_id, field, version = equals_rule()
    now = datetime.now(UTC)
    ids: dict[str, uuid.UUID] = {}
    async with service_session() as session:
        connection = CloudConnection(
            organization_id=org_id,
            provider=Provider.AZURE,
            name="tenant",
            scope_type=ConnectionScope.TENANT_ROOT,
            role_version="v1",
            tenant_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            consent_status=ConsentStatus.GRANTED,
            status=CloudAccountStatus.ACTIVE,
            scan_interval_hours=6,
        )
        session.add(connection)
        await session.flush()

        for name, age, guessed in (
            ("fresh", timedelta(hours=1), False),
            ("ageing", timedelta(hours=12), False),
            ("stale", timedelta(days=10), False),
            ("guessed", timedelta(hours=1), True),
        ):
            record = ResourceRecord(
                organization_id=org_id,
                connection_id=connection.id,
                provider=Provider.AZURE,
                provider_resource_id=f"/subscriptions/s/{name}",
                resource_type=ResourceType.STORAGE_ACCOUNT,
                name=name,
                criticality=Level.HIGH,
                criticality_source=ContextSource.INFERRED if guessed else ContextSource.CUSTOMER,
                data_sensitivity=Level.HIGH,
                data_sensitivity_source=ContextSource.CUSTOMER,
                public_exposure=Level.LOW,
            )
            session.add(record)
            await session.flush()
            finding = Finding(
                organization_id=org_id,
                rule_id=rule_id,
                rule_version=version,
                resource_id=record.id,
                severity=Severity.HIGH,
                status=FindingStatus.OPEN,
                title=f"Finding on {name}",
                description="",
                evidence={field: "observed"},
                remediation="",
                risk_score=50,
                first_detected_at=now - age,
                last_detected_at=now,
            )
            session.add(finding)
            await session.flush()
            session.add(
                FindingEvidence(
                    organization_id=org_id,
                    finding_id=finding.id,
                    evidence_key="storage_accounts",
                    collected_at=now - age,
                    content_hash="0" * 64,
                )
            )
            ids[name] = finding.id
        await session.commit()
    return ids


class TestFindingConfidence:
    async def test_each_row_says_how_sure_and_the_counts_agree(self, client, cleanup_orgs) -> None:
        user = uuid.uuid4()
        org_id = uuid.UUID(await make_org(client, user, "Confidence Ltd"))
        cleanup_orgs.append(org_id)
        ids = await estate(org_id)

        body = (await client.get("/api/v1/findings", headers=auth_header(user))).json()

        level = {row["id"]: row["confidence"]["level"] for row in body["data"]}
        assert level[str(ids["fresh"])] == "HIGH"
        assert level[str(ids["ageing"])] == "MEDIUM"
        assert level[str(ids["stale"])] == "LOW"
        assert level[str(ids["guessed"])] == "MEDIUM"
        assert body["meta"]["confidence"] == {"HIGH": 1, "MEDIUM": 2, "LOW": 1}

    async def test_the_filter_returns_exactly_what_the_rows_say(self, client, cleanup_orgs) -> None:
        user = uuid.uuid4()
        org_id = uuid.UUID(await make_org(client, user, "Filter Ltd"))
        cleanup_orgs.append(org_id)
        ids = await estate(org_id)

        for wanted, names in (
            ("HIGH", {"fresh"}),
            ("MEDIUM", {"ageing", "guessed"}),
            ("LOW", {"stale"}),
        ):
            body = (
                await client.get(f"/api/v1/findings?confidence={wanted}", headers=auth_header(user))
            ).json()
            assert {row["id"] for row in body["data"]} == {str(ids[name]) for name in names}
            assert all(row["confidence"]["level"] == wanted for row in body["data"])
            assert body["meta"]["total"] == len(names)
            # Counted over every filter but confidence: the same in each view.
            assert body["meta"]["confidence"] == {"HIGH": 1, "MEDIUM": 2, "LOW": 1}

    async def test_the_detail_and_the_package_agree_with_the_list(
        self, client, cleanup_orgs
    ) -> None:
        user = uuid.uuid4()
        org_id = uuid.UUID(await make_org(client, user, "Package Ltd"))
        cleanup_orgs.append(org_id)
        ids = await estate(org_id)
        stale = ids["stale"]

        detail = (await client.get(f"/api/v1/findings/{stale}", headers=auth_header(user))).json()
        package = (
            await client.get(
                f"/api/v1/findings/{stale}/evidence-package", headers=auth_header(user)
            )
        ).json()

        assert detail["data"]["confidence"]["level"] == "LOW"
        assert detail["data"]["condition"][0]["observed"] == "observed"
        data = package["data"]
        assert data["format"] == "cleave.evidence-package"
        assert data["confidence"]["level"] == "LOW"
        assert data["resource"]["provider_resource_id"] == "/subscriptions/s/stale"
        assert data["citations"][0]["evidence_key"] == "storage_accounts"
        # No blob was stored for the hash, so the record says the bytes are gone.
        assert "PAYLOAD_PRUNED" in [limit["code"] for limit in data["limitations"]]
        assert data["verification"]["method"] == "RESCAN"

    async def test_another_tenants_package_is_not_found(self, client, cleanup_orgs) -> None:
        owner, stranger = uuid.uuid4(), uuid.uuid4()
        org_id = uuid.UUID(await make_org(client, owner, "Owner Ltd"))
        other = uuid.UUID(await make_org(client, stranger, "Stranger Ltd"))
        cleanup_orgs.extend([org_id, other])
        ids = await estate(org_id)

        response = await client.get(
            f"/api/v1/findings/{ids['fresh']}/evidence-package", headers=auth_header(stranger)
        )

        assert response.status_code == 404
