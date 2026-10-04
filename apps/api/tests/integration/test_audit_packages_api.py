"""The audit package routes, through the real app (DECISIONS.md section 208).

What only the whole request path can show: an owner seals, reads, verifies and downloads, and
nobody else does. A viewer is told no and a stranger is told there is nothing, a body that names
a field the server owns is refused, and the archive that comes down the wire is the one that
checks itself.
"""

import hashlib
import io
import uuid
import zipfile

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from app.core.config import settings
from app.core.db import service_session
from app.core.enums import Role
from app.main import app
from app.models.organization import OrganizationMember
from app.services import audit_packages
from tests.integration.conftest import create_org_as
from tests.integration.test_api import auth_header
from tests.integration.test_audit_packages import (
    FRAMEWORK,
    HELD_HASH,
    OTHER,
    OWNER,
    framework_keys,
    make_estate,
    read_estate,
)

pytestmark = pytest.mark.integration

VIEWER = uuid.UUID("22222222-0000-0000-0000-00000000000c")
BASE = "/api/v1/audit-packages"


@pytest.fixture(autouse=True)
def _room_to_ask(monkeypatch):
    """The costly allowance is 20 a minute a person, and a test seals as often as that."""
    monkeypatch.setattr(settings, "rate_limit_costly_per_user", 10_000)


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture
async def estate(cleanup_orgs, rule_catalogue) -> uuid.UUID:
    org_id = await make_estate("Packaged Org")
    cleanup_orgs.append(org_id)
    await read_estate(org_id, await framework_keys(org_id))
    return org_id


def owner(org_id: uuid.UUID) -> dict[str, str]:
    return {**auth_header(OWNER, "owner@example.com"), "X-Organization-Id": str(org_id)}


async def seal(client: AsyncClient, org_id: uuid.UUID, **body) -> dict:
    response = await client.post(
        BASE,
        json={"name": "NIS2 audit", "framework_ids": [FRAMEWORK], **body},
        headers=owner(org_id),
    )
    assert response.status_code == 201, response.text
    return response.json()["data"]


class TestSealing:
    async def test_an_owner_seals_and_is_told_where_it_lives(self, client, estate) -> None:
        response = await client.post(
            BASE,
            json={
                "name": "  NIS2 audit  ",
                "framework_ids": [FRAMEWORK],
                "period_start": "2026-01-01",
                "period_end": "2026-09-30",
            },
            headers=owner(estate),
        )

        assert response.status_code == 201, response.text
        data = response.json()["data"]
        assert response.headers["Location"] == f"{BASE}/{data['id']}"
        assert data["name"] == "NIS2 audit"
        assert len(data["manifest_sha256"]) == 64
        assert [f["id"] for f in data["frameworks"]] == [FRAMEWORK]
        assert data["period_start"] == "2026-01-01"

    @pytest.mark.parametrize(
        ("body", "code"),
        [
            ({"name": "x", "framework_ids": []}, "VALIDATION_FAILED"),
            ({"name": "", "framework_ids": [FRAMEWORK]}, "VALIDATION_FAILED"),
            ({"name": "x", "framework_ids": [FRAMEWORK, FRAMEWORK]}, "VALIDATION_FAILED"),
            ({"name": "x", "framework_ids": ["NOT A FRAMEWORK"]}, "VALIDATION_FAILED"),
            ({"name": "x", "framework_ids": ["CIS_AWS_7.0"]}, "VALIDATION_FAILED"),
            (
                {
                    "name": "x",
                    "framework_ids": [FRAMEWORK],
                    "period_start": "2026-10-01",
                    "period_end": "2026-01-01",
                },
                "VALIDATION_FAILED",
            ),
            (
                {"name": "x", "framework_ids": [FRAMEWORK], "organization_id": str(uuid.uuid4())},
                "VALIDATION_FAILED",
            ),
            ({"name": "x", "framework_ids": [FRAMEWORK], "scan_id": str(uuid.uuid4())}, None),
        ],
    )
    async def test_a_bad_request_is_refused_naming_why(
        self, client, estate, body: dict, code: str | None
    ) -> None:
        response = await client.post(BASE, json=body, headers=owner(estate))

        assert response.status_code == 422, response.text
        assert response.json()["error"]["code"] == "VALIDATION_FAILED"

    async def test_nothing_is_sealed_before_a_scan(
        self, client, cleanup_orgs, rule_catalogue
    ) -> None:
        org_id = await make_estate("Unscanned", scanned=False)
        cleanup_orgs.append(org_id)

        response = await client.post(
            BASE, json={"name": "x", "framework_ids": [FRAMEWORK]}, headers=owner(org_id)
        )

        assert response.status_code == 409
        assert response.json()["error"]["code"] == "CONFLICT"


class TestReading:
    async def test_the_detail_says_how_the_controls_came_out_and_what_is_still_held(
        self, client, estate
    ) -> None:
        sealed = await seal(client, estate)

        response = await client.get(f"{BASE}/{sealed['id']}", headers=owner(estate))

        assert response.status_code == 200, response.text
        data = response.json()["data"]
        (assessment,) = data["assessment"]
        assert assessment["framework_id"] == FRAMEWORK
        assert assessment["controls"] == sum(assessment["statuses"].values())
        assert set(assessment["statuses"]) >= {"FAILING", "INCONCLUSIVE", "PASSING", "NOT_COVERED"}
        assert data["evidence"]["readings"] == 2
        assert data["evidence"]["outcomes"] == {"COMPLETE": 1, "FAILED": 1}
        assert data["evidence"]["payloads_named"] == 1
        assert data["evidence"]["payloads_stored"] == 1

    async def test_the_list_is_paged_newest_first(self, client, estate) -> None:
        first = await seal(client, estate, name="First")
        second = await seal(client, estate, name="Second")

        response = await client.get(f"{BASE}?limit=1", headers=owner(estate))

        assert response.status_code == 200
        body = response.json()
        assert [p["id"] for p in body["data"]] == [second["id"]]
        assert body["meta"] == {"total": 2, "limit": 1, "offset": 0}
        page_two = await client.get(f"{BASE}?limit=1&offset=1", headers=owner(estate))
        assert [p["id"] for p in page_two.json()["data"]] == [first["id"]]

    async def test_a_limit_over_the_cap_is_refused_and_not_truncated(self, client, estate) -> None:
        response = await client.get(f"{BASE}?limit=500", headers=owner(estate))

        assert response.status_code == 422

    async def test_an_unknown_package_is_not_found(self, client, estate) -> None:
        response = await client.get(f"{BASE}/{uuid.uuid4()}", headers=owner(estate))

        assert response.status_code == 404
        assert response.json()["error"]["code"] == "NOT_FOUND"


class TestVerification:
    async def test_an_untouched_package_verifies(self, client, estate) -> None:
        sealed = await seal(client, estate)

        response = await client.get(f"{BASE}/{sealed['id']}/verification", headers=owner(estate))

        data = response.json()["data"]
        assert data["verified"] is True
        assert data["sealed_sha256"] == data["recomputed_sha256"] == sealed["manifest_sha256"]

    async def test_a_row_changed_behind_the_applications_back_does_not(
        self, client, estate
    ) -> None:
        sealed = await seal(client, estate)
        async with service_session() as session:
            await session.execute(
                text(
                    "UPDATE audit_package_items SET item_count = item_count + 1"
                    " WHERE package_id = :id"
                ),
                {"id": sealed["id"]},
            )
            await session.commit()

        response = await client.get(f"{BASE}/{sealed['id']}/verification", headers=owner(estate))

        data = response.json()["data"]
        assert data["verified"] is False
        assert data["sealed_sha256"] == sealed["manifest_sha256"]
        assert data["recomputed_sha256"] != data["sealed_sha256"]


class TestArchive:
    async def test_the_download_checks_itself(self, client, estate) -> None:
        sealed = await seal(client, estate)

        response = await client.get(f"{BASE}/{sealed['id']}/archive", headers=owner(estate))

        assert response.status_code == 200, response.text
        assert response.headers["content-type"] == "application/zip"
        assert response.headers["content-disposition"].startswith('attachment; filename="')
        assert int(response.headers["content-length"]) == len(response.content)
        archive = zipfile.ZipFile(io.BytesIO(response.content))
        root = archive.namelist()[0].split("/")[0]
        files = {n.removeprefix(f"{root}/"): archive.read(n) for n in archive.namelist()}

        for line in files["SHA256SUMS"].decode().splitlines():
            expected, path = line.split("  ", 1)
            assert hashlib.sha256(files[path]).hexdigest() == expected, path
        assert hashlib.sha256(files["manifest.json"]).hexdigest() == sealed["manifest_sha256"]
        # The one held reading is there under its own hash; the failed one is a gap.
        assert f"evidence/payloads/{HELD_HASH}.json" in files
        gaps = files["gaps.csv"].decode("utf-8-sig")
        assert "READING_FAILED" in gaps and "CONTROL_NOT_COVERED" in gaps

    async def test_a_download_is_on_the_audit_trail(self, client, estate) -> None:
        sealed = await seal(client, estate)
        await client.get(f"{BASE}/{sealed['id']}/archive", headers=owner(estate))

        response = await client.get(
            "/api/v1/audit-log?action=audit_package.", headers=owner(estate)
        )

        entries = response.json()["data"]
        assert {e["action"] for e in entries} == {"audit_package.sealed", "audit_package.exported"}
        exported = next(e for e in entries if e["action"] == "audit_package.exported")
        assert exported["resource_id"] == sealed["id"]
        assert exported["details"]["manifest_sha256"] == sealed["manifest_sha256"]

    async def test_a_package_too_large_for_one_archive_is_refused_before_it_is_read(
        self, client, estate, monkeypatch
    ) -> None:
        sealed = await seal(client, estate)
        monkeypatch.setattr(audit_packages, "MAX_ARCHIVE_PAYLOAD_BYTES", 1)

        response = await client.get(f"{BASE}/{sealed['id']}/archive", headers=owner(estate))

        assert response.status_code == 409
        assert response.json()["error"]["code"] == "ARCHIVE_TOO_LARGE"


class TestWhoMayAsk:
    async def test_no_token_is_refused(self, client, estate) -> None:
        for method, path in (("GET", BASE), ("POST", BASE)):
            response = await client.request(method, path, json={"name": "x", "framework_ids": []})
            assert response.status_code == 401

    async def test_a_viewer_is_told_no_on_every_route(self, client, estate) -> None:
        sealed = await seal(client, estate)
        async with service_session() as session:
            session.add(
                OrganizationMember(organization_id=estate, user_id=VIEWER, role=Role.VIEWER)
            )
            await session.commit()
        headers = {**auth_header(VIEWER, "viewer@example.com"), "X-Organization-Id": str(estate)}

        for method, path in (
            ("POST", BASE),
            ("GET", BASE),
            ("GET", f"{BASE}/{sealed['id']}"),
            ("GET", f"{BASE}/{sealed['id']}/verification"),
            ("GET", f"{BASE}/{sealed['id']}/archive"),
        ):
            body = {"name": "x", "framework_ids": [FRAMEWORK]} if method == "POST" else None
            response = await client.request(method, path, json=body, headers=headers)
            assert response.status_code == 403, (method, path, response.text)
            assert response.json()["error"]["code"] == "PERMISSION_DENIED"

    async def test_another_organizations_owner_finds_nothing(
        self, client, estate, cleanup_orgs
    ) -> None:
        sealed = await seal(client, estate)
        other_org = await create_org_as(OTHER, "Somebody Else")
        cleanup_orgs.append(other_org)
        headers = {**auth_header(OTHER, "other@example.com"), "X-Organization-Id": str(other_org)}

        listing = await client.get(BASE, headers=headers)
        assert listing.json()["data"] == []
        for suffix in ("", "/verification", "/archive"):
            response = await client.get(f"{BASE}/{sealed['id']}{suffix}", headers=headers)
            assert response.status_code == 404, suffix
