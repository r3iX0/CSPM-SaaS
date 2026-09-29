"""The finding's IaC diff against the real database (DECISIONS.md §166).

* An uploaded file comes back as a diff of the block defining the asset.
* A decline is a 200 with its reason, not an error.
* Another organization's finding is not found, whatever file is sent.
"""

import uuid
from datetime import UTC, datetime

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from tests.integration import test_api
from tests.integration.test_api import auth_header, make_org

pytestmark = pytest.mark.integration

ARM_ID = (
    "/subscriptions/00000000-0000-0000-0000-000000000001"
    "/resourceGroups/prod/providers/Microsoft.Storage/storageAccounts/payroll"
)
PAYROLL = b"""\
resource "azurerm_storage_account" "payroll" {
  name            = "payroll"
  min_tls_version = "TLS1_0"
}
"""


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def _finding_on_payroll(org_id: uuid.UUID) -> uuid.UUID:
    from sqlalchemy import select

    from app.core.db import service_session
    from app.core.enums import FindingStatus, Severity
    from app.models.finding import Finding
    from app.models.resource import ResourceRecord

    # Imported as a module: a Test class imported by name is collected here too.
    await test_api.TestAssetList()._asset_in_a_subscription(org_id, ARM_ID)
    async with service_session() as session:
        resource_id = (
            await session.execute(
                select(ResourceRecord.id).where(
                    ResourceRecord.organization_id == org_id,
                    ResourceRecord.provider_resource_id == ARM_ID,
                )
            )
        ).scalar_one()
        finding = Finding(
            organization_id=org_id,
            rule_id="AZ-STO-003",
            resource_id=resource_id,
            severity=Severity.HIGH,
            status=FindingStatus.OPEN,
            title="Storage account accepts plain HTTP",
            description="",
            remediation="",
            rule_version="1.0",
            first_detected_at=datetime.now(UTC),
            last_detected_at=datetime.now(UTC),
        )
        session.add(finding)
        await session.commit()
        return finding.id


async def _diff(client, user, finding_id, source: bytes = PAYROLL):
    return await client.post(
        f"/api/v1/findings/{finding_id}/iac-diff",
        files={"file": ("storage.tf", source, "text/plain")},
        headers=auth_header(user),
    )


async def test_an_uploaded_file_comes_back_as_a_diff(client, cleanup_orgs) -> None:
    user = uuid.uuid4()
    org_id = uuid.UUID(await make_org(client, user, "IaC Diff Ltd"))
    cleanup_orgs.append(org_id)
    finding_id = await _finding_on_payroll(org_id)

    response = await _diff(client, user, finding_id)

    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert data["outcome"] == "patched"
    assert data["filename"] == "storage.tf"
    assert '+  min_tls_version = "TLS1_2"\n' in data["diff"]
    assert "+  https_traffic_only_enabled = true\n" in data["diff"]


async def test_a_decline_is_an_answer(client, cleanup_orgs) -> None:
    user = uuid.uuid4()
    org_id = uuid.UUID(await make_org(client, user, "IaC Decline Ltd"))
    cleanup_orgs.append(org_id)
    finding_id = await _finding_on_payroll(org_id)

    # Two blocks named by expressions: which one is payroll is a guess.
    interpolated = PAYROLL.replace(b'"payroll"\n', b"var.name\n")
    twice = interpolated + interpolated.replace(b'"payroll" {', b'"other" {')
    response = await _diff(client, user, finding_id, twice)

    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert (data["outcome"], data["decline_reason"]) == ("declined", "interpolated_name")
    assert data["diff"] is None


async def test_the_only_block_in_the_upload_is_matched_and_says_so(client, cleanup_orgs) -> None:
    user = uuid.uuid4()
    org_id = uuid.UUID(await make_org(client, user, "IaC Sole Ltd"))
    cleanup_orgs.append(org_id)
    finding_id = await _finding_on_payroll(org_id)

    response = await _diff(client, user, finding_id, PAYROLL.replace(b'"payroll"\n', b"var.name\n"))

    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert (data["outcome"], data["matched_by"]) == ("patched", "sole_block")


async def test_another_organizations_finding_is_not_found(client, cleanup_orgs) -> None:
    owner, stranger = uuid.uuid4(), uuid.uuid4()
    org_id = uuid.UUID(await make_org(client, owner, "IaC Owner Ltd"))
    cleanup_orgs.append(org_id)
    cleanup_orgs.append(uuid.UUID(await make_org(client, stranger, "IaC Stranger Ltd")))
    finding_id = await _finding_on_payroll(org_id)

    response = await _diff(client, stranger, finding_id)

    assert response.status_code == 404
