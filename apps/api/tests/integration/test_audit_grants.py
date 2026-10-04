"""Auditor grants, through the real app and the real database (DECISIONS.md section 211).

What only the whole path can show. An owner makes a grant and an auditor opens it, as the address
it was made for and nobody else; the auditor reads that one package and nothing else; every read
checks the grant again, so a revoke or a changed address takes effect on the next request; and the
database, run as the roles the application runs as, holds shut what the application merely does
not do: no policy lets an auditor into a tenant table, no role writes an event, and an owner
cannot bind a grant to a person or take a revoke back.
"""

import hashlib
import io
import uuid
import zipfile
from datetime import datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, IntegrityError

from app.core.config import settings
from app.core.db import rls_session, service_session
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

AUDITOR = uuid.UUID("22222222-0000-0000-0000-00000000000d")
STRANGER = uuid.UUID("22222222-0000-0000-0000-00000000000e")
VIEWER = uuid.UUID("22222222-0000-0000-0000-00000000000c")
AUDITOR_EMAIL = "auditor@example.com"
STRANGER_EMAIL = "stranger@example.com"
PACKAGES = "/api/v1/audit-packages"
GRANTS = "/api/v1/audit-grants"
AUDITOR_GRANTS = "/api/v1/auditor/grants"


@pytest.fixture(autouse=True)
def _room_to_ask(monkeypatch):
    """The costly allowance is 20 a minute a person, and a test seals and downloads as often."""
    monkeypatch.setattr(settings, "rate_limit_costly_per_user", 10_000)


@pytest.fixture
async def client():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c


@pytest.fixture
async def estate(cleanup_orgs, rule_catalogue) -> uuid.UUID:
    org_id = await make_estate("Granted Org")
    cleanup_orgs.append(org_id)
    await read_estate(org_id, await framework_keys(org_id))
    return org_id


def owner(org_id: uuid.UUID) -> dict[str, str]:
    return {**auth_header(OWNER, "owner@example.com"), "X-Organization-Id": str(org_id)}


def auditor(user: uuid.UUID = AUDITOR, email: str = AUDITOR_EMAIL) -> dict[str, str]:
    """An auditor sends no organization: they have none."""
    return auth_header(user, email)


async def seal(client: AsyncClient, org_id: uuid.UUID) -> dict:
    response = await client.post(
        PACKAGES,
        json={"name": "NIS2 audit", "framework_ids": [FRAMEWORK]},
        headers=owner(org_id),
    )
    assert response.status_code == 201, response.text
    return response.json()["data"]


async def grant(
    client: AsyncClient,
    org_id: uuid.UUID,
    package_id: str,
    email: str = AUDITOR_EMAIL,
    **extra: object,
) -> dict:
    response = await client.post(
        GRANTS,
        json={"package_id": package_id, "email": email, **extra},
        headers=owner(org_id),
    )
    assert response.status_code == 201, response.text
    return response.json()["data"]


def token_of(made: dict) -> str:
    return made["link"].split("#", 1)[1]


async def open_link(client: AsyncClient, made: dict, headers: dict[str, str] | None = None):
    return await client.post(
        f"{AUDITOR_GRANTS}/open", json={"token": token_of(made)}, headers=headers or auditor()
    )


@pytest.fixture
async def package(client, estate) -> dict:
    return await seal(client, estate)


@pytest.fixture
async def opened(client, estate, package) -> dict:
    """A grant the auditor has opened, with the link it was made with."""
    made = await grant(client, estate, package["id"])
    response = await open_link(client, made)
    assert response.status_code == 200, response.text
    return made


async def events_of(client: AsyncClient, org_id: uuid.UUID, grant_id: str) -> list[dict]:
    response = await client.get(f"{GRANTS}/{grant_id}/events", headers=owner(org_id))
    assert response.status_code == 200, response.text
    return response.json()["data"]


class TestMakingAGrant:
    async def test_an_owner_grants_and_is_told_where_it_lives(
        self, client, estate, package
    ) -> None:
        response = await client.post(
            GRANTS,
            json={"package_id": package["id"], "email": "  Auditor@Example.com "},
            headers=owner(estate),
        )

        assert response.status_code == 201, response.text
        data = response.json()["data"]
        assert response.headers["Location"] == f"{GRANTS}/{data['id']}"
        assert data["email"] == AUDITOR_EMAIL
        assert data["status"] == "PENDING"
        assert data["opened_at"] is None
        assert "/auditor#" in data["link"]

    async def test_the_link_is_shown_once_and_only_its_hash_is_stored(
        self, client, estate, package
    ) -> None:
        made = await grant(client, estate, package["id"])
        token = token_of(made)

        listing = await client.get(GRANTS, headers=owner(estate))
        assert "link" not in listing.json()["data"][0]
        assert token not in listing.text
        async with service_session() as session:
            stored = (
                await session.execute(
                    text("SELECT token_hash FROM audit_grants WHERE id = :id"), {"id": made["id"]}
                )
            ).scalar_one()
        assert stored == hashlib.sha256(token.encode()).hexdigest()

    async def test_a_grant_lasts_thirty_days_by_default_and_ninety_at_most(
        self, client, estate, package
    ) -> None:
        made = await grant(client, estate, package["id"])
        longest = await grant(
            client, estate, package["id"], "other@example.com", expires_in_days=90
        )

        for data, days in ((made, 30), (longest, 90)):
            span = datetime.fromisoformat(data["expires_at"]) - datetime.fromisoformat(
                data["created_at"]
            )
            assert span == timedelta(days=days)
        too_long = await client.post(
            GRANTS,
            json={"package_id": package["id"], "email": AUDITOR_EMAIL, "expires_in_days": 91},
            headers=owner(estate),
        )
        assert too_long.status_code == 422

    @pytest.mark.parametrize(
        "extra",
        [
            {"email": "not-an-address"},
            {"expires_in_days": 0},
            {"organization_id": str(uuid.uuid4())},
            {"token_hash": "a" * 64},
        ],
    )
    async def test_a_bad_request_is_refused_naming_why(
        self, client, estate, package, extra
    ) -> None:
        body = {"package_id": package["id"], "email": AUDITOR_EMAIL, **extra}

        response = await client.post(GRANTS, json=body, headers=owner(estate))

        assert response.status_code == 422
        assert response.json()["error"]["code"] == "VALIDATION_FAILED"

    async def test_granting_again_replaces_the_old_grant(self, client, estate, package) -> None:
        first = await grant(client, estate, package["id"])
        second = await grant(client, estate, package["id"])

        old = await client.get(f"{GRANTS}/{first['id']}", headers=owner(estate))
        assert old.json()["data"]["status"] == "REVOKED"
        refused = await open_link(client, first)
        assert refused.status_code == 409
        assert (await open_link(client, second)).status_code == 200

    async def test_a_package_of_another_organization_is_not_found(
        self, client, estate, package, cleanup_orgs
    ) -> None:
        other_org = await create_org_as(OTHER, "Somebody Else")
        cleanup_orgs.append(other_org)
        headers = {**auth_header(OTHER, "other@example.com"), "X-Organization-Id": str(other_org)}

        response = await client.post(
            GRANTS, json={"package_id": package["id"], "email": AUDITOR_EMAIL}, headers=headers
        )

        assert response.status_code == 404

    async def test_granting_and_revoking_are_on_the_audit_trail(
        self, client, estate, package
    ) -> None:
        made = await grant(client, estate, package["id"])
        await client.delete(f"{GRANTS}/{made['id']}", headers=owner(estate))

        response = await client.get("/api/v1/audit-log?action=audit_grant.", headers=owner(estate))

        entries = response.json()["data"]
        assert {e["action"] for e in entries} == {"audit_grant.created", "audit_grant.revoked"}
        created = next(e for e in entries if e["action"] == "audit_grant.created")
        assert created["resource_id"] == made["id"]
        assert created["details"]["email"] == AUDITOR_EMAIL


class TestManagingGrants:
    async def test_a_grant_is_revoked_once_and_kept_as_history(
        self, client, estate, package
    ) -> None:
        made = await grant(client, estate, package["id"])

        first = await client.delete(f"{GRANTS}/{made['id']}", headers=owner(estate))
        second = await client.delete(f"{GRANTS}/{made['id']}", headers=owner(estate))

        assert first.status_code == 200
        assert first.json()["data"] == {"revoked": made["id"]}
        assert second.status_code == 409
        listing = await client.get(f"{GRANTS}?package_id={package['id']}", headers=owner(estate))
        assert [(g["id"], g["status"]) for g in listing.json()["data"]] == [(made["id"], "REVOKED")]

    async def test_the_list_is_paged_and_filtered_by_package(self, client, estate, package) -> None:
        second_package = await seal(client, estate)
        await grant(client, estate, package["id"], "a@example.com")
        await grant(client, estate, package["id"], "b@example.com")
        await grant(client, estate, second_package["id"], "c@example.com")

        everything = await client.get(GRANTS, headers=owner(estate))
        narrowed = await client.get(
            f"{GRANTS}?package_id={package['id']}&limit=1", headers=owner(estate)
        )

        assert everything.json()["meta"]["total"] == 3
        assert narrowed.json()["meta"] == {"total": 2, "limit": 1, "offset": 0}
        assert len(narrowed.json()["data"]) == 1
        over = await client.get(f"{GRANTS}?limit=201", headers=owner(estate))
        assert over.status_code == 422

    async def test_another_organizations_owner_finds_nothing(
        self, client, estate, package, cleanup_orgs
    ) -> None:
        made = await grant(client, estate, package["id"])
        other_org = await create_org_as(OTHER, "Somebody Else")
        cleanup_orgs.append(other_org)
        headers = {**auth_header(OTHER, "other@example.com"), "X-Organization-Id": str(other_org)}

        assert (await client.get(GRANTS, headers=headers)).json()["data"] == []
        for method, suffix in (("GET", ""), ("GET", "/events"), ("DELETE", "")):
            response = await client.request(
                method, f"{GRANTS}/{made['id']}{suffix}", headers=headers
            )
            assert response.status_code == 404, (method, suffix)

    async def test_no_token_and_a_viewer_are_refused(self, client, estate, package) -> None:
        made = await grant(client, estate, package["id"])
        async with service_session() as session:
            session.add(
                OrganizationMember(organization_id=estate, user_id=VIEWER, role=Role.VIEWER)
            )
            await session.commit()
        viewer = {**auth_header(VIEWER, "viewer@example.com"), "X-Organization-Id": str(estate)}

        for method, path in (
            ("POST", GRANTS),
            ("GET", GRANTS),
            ("GET", f"{GRANTS}/{made['id']}"),
            ("DELETE", f"{GRANTS}/{made['id']}"),
            ("GET", f"{GRANTS}/{made['id']}/events"),
        ):
            body = {"package_id": package["id"], "email": "x@example.com"}
            body = body if method == "POST" else None
            assert (await client.request(method, path, json=body)).status_code == 401
            response = await client.request(method, path, json=body, headers=viewer)
            assert response.status_code == 403, (method, path, response.text)
            assert response.json()["error"]["code"] == "PERMISSION_DENIED"


class TestOpeningALink:
    async def test_the_address_it_was_made_for_opens_it(self, client, estate, package) -> None:
        made = await grant(client, estate, package["id"])

        response = await open_link(client, made)

        assert response.status_code == 200, response.text
        data = response.json()["data"]
        assert data["id"] == made["id"]
        assert data["package_id"] == package["id"]
        assert data["package_name"] == "NIS2 audit"
        assert data["organization_name"] == "Granted Org"
        assert data["email"] == AUDITOR_EMAIL
        owners_view = await client.get(f"{GRANTS}/{made['id']}", headers=owner(estate))
        assert owners_view.json()["data"]["status"] == "OPENED"
        assert owners_view.json()["data"]["opened_at"] is not None

    async def test_another_address_is_refused_and_leaves_no_event(
        self, client, estate, package
    ) -> None:
        made = await grant(client, estate, package["id"])

        response = await open_link(client, made, auditor(STRANGER, STRANGER_EMAIL))

        assert response.status_code == 403
        assert response.json()["error"]["code"] == "PERMISSION_DENIED"
        assert await events_of(client, estate, made["id"]) == []
        owners_view = await client.get(f"{GRANTS}/{made['id']}", headers=owner(estate))
        assert owners_view.json()["data"]["status"] == "PENDING"

    async def test_a_token_without_an_address_is_refused(self, client, estate, package) -> None:
        made = await grant(client, estate, package["id"])

        response = await open_link(client, made, auth_header(AUDITOR, ""))

        assert response.status_code == 403

    async def test_the_same_address_under_another_account_is_refused_once_it_is_opened(
        self, client, estate, package
    ) -> None:
        made = await grant(client, estate, package["id"])
        assert (await open_link(client, made)).status_code == 200

        response = await open_link(client, made, auditor(STRANGER, AUDITOR_EMAIL))

        assert response.status_code == 409

    async def test_opening_again_as_the_same_account_is_fine_and_recorded(
        self, client, estate, package
    ) -> None:
        made = await grant(client, estate, package["id"])
        await open_link(client, made)
        await open_link(client, made)

        events = await events_of(client, estate, made["id"])

        assert [e["event"] for e in events] == ["OPENED", "OPENED"]
        assert {e["user_id"] for e in events} == {str(AUDITOR)}
        assert sorted(e["detail"]["first"] for e in events) == [False, True]

    async def test_a_token_that_is_not_a_link_is_not_found(self, client, estate) -> None:
        response = await client.post(
            f"{AUDITOR_GRANTS}/open", json={"token": "x" * 43}, headers=auditor()
        )

        assert response.status_code == 404

    async def test_a_withdrawn_or_expired_grant_does_not_open(
        self, client, estate, package
    ) -> None:
        withdrawn = await grant(client, estate, package["id"], "a@example.com")
        await client.delete(f"{GRANTS}/{withdrawn['id']}", headers=owner(estate))
        lapsed = await grant(client, estate, package["id"], "b@example.com")
        async with service_session() as session:
            await session.execute(
                text(
                    "UPDATE audit_grants SET created_at = now() - interval '3 days',"
                    " expires_at = now() - interval '1 day' WHERE id = :id"
                ),
                {"id": lapsed["id"]},
            )
            await session.commit()

        gone = await open_link(client, withdrawn, auditor(email="a@example.com"))
        late = await open_link(client, lapsed, auditor(email="b@example.com"))

        assert gone.status_code == 409
        assert late.status_code == 409
        listing = await client.get(GRANTS, headers=owner(estate))
        assert {g["status"] for g in listing.json()["data"]} == {"REVOKED", "EXPIRED"}


class TestReading:
    async def test_the_package_is_what_the_owner_sees(
        self, client, estate, package, opened
    ) -> None:
        response = await client.get(f"{AUDITOR_GRANTS}/{opened['id']}/package", headers=auditor())
        owners = await client.get(f"{PACKAGES}/{package['id']}", headers=owner(estate))

        assert response.status_code == 200, response.text
        assert response.json()["data"] == owners.json()["data"]

    async def test_verification_rebuilds_the_sealed_hash(self, client, package, opened) -> None:
        response = await client.get(
            f"{AUDITOR_GRANTS}/{opened['id']}/verification", headers=auditor()
        )

        data = response.json()["data"]
        assert data["verified"] is True
        assert data["sealed_sha256"] == data["recomputed_sha256"] == package["manifest_sha256"]

    async def test_a_row_changed_behind_the_applications_back_is_seen(
        self, client, package, opened
    ) -> None:
        async with service_session() as session:
            await session.execute(
                text(
                    "UPDATE audit_package_items SET item_count = item_count + 1"
                    " WHERE package_id = :id"
                ),
                {"id": package["id"]},
            )
            await session.commit()

        response = await client.get(
            f"{AUDITOR_GRANTS}/{opened['id']}/verification", headers=auditor()
        )

        assert response.json()["data"]["verified"] is False

    async def test_the_archive_checks_itself_and_is_on_the_grants_trail(
        self, client, estate, package, opened
    ) -> None:
        response = await client.get(f"{AUDITOR_GRANTS}/{opened['id']}/archive", headers=auditor())

        assert response.status_code == 200, response.text
        assert response.headers["content-type"] == "application/zip"
        archive = zipfile.ZipFile(io.BytesIO(response.content))
        root = archive.namelist()[0].split("/")[0]
        files = {n.removeprefix(f"{root}/"): archive.read(n) for n in archive.namelist()}
        for line in files["SHA256SUMS"].decode().splitlines():
            expected, path = line.split("  ", 1)
            assert hashlib.sha256(files[path]).hexdigest() == expected, path
        assert hashlib.sha256(files["manifest.json"]).hexdigest() == package["manifest_sha256"]
        assert f"evidence/payloads/{HELD_HASH}.json" in files
        events = await events_of(client, estate, opened["id"])
        assert [e["event"] for e in events] == ["ARCHIVE_DOWNLOADED", "OPENED"]
        assert events[0]["detail"] == {"manifest_sha256": package["manifest_sha256"]}

    async def test_reading_the_package_records_nothing(self, client, estate, opened) -> None:
        for suffix in ("", "/package", "/verification"):
            response = await client.get(
                f"{AUDITOR_GRANTS}/{opened['id']}{suffix}", headers=auditor()
            )
            assert response.status_code == 200, suffix

        events = await events_of(client, estate, opened["id"])

        assert [e["event"] for e in events] == ["OPENED"]

    async def test_a_package_too_large_is_refused_before_it_is_read_or_recorded(
        self, client, estate, opened, monkeypatch
    ) -> None:
        monkeypatch.setattr(audit_packages, "MAX_ARCHIVE_PAYLOAD_BYTES", 1)

        response = await client.get(f"{AUDITOR_GRANTS}/{opened['id']}/archive", headers=auditor())

        assert response.status_code == 409
        assert response.json()["error"]["code"] == "ARCHIVE_TOO_LARGE"
        assert [e["event"] for e in await events_of(client, estate, opened["id"])] == ["OPENED"]

    async def test_the_grants_an_account_holds_are_listed_until_they_end(
        self, client, estate, package, opened
    ) -> None:
        unopened = await grant(client, estate, package["id"], "later@example.com")

        listing = await client.get(AUDITOR_GRANTS, headers=auditor())
        assert [g["id"] for g in listing.json()["data"]] == [opened["id"]]
        assert unopened["id"] not in listing.text

        await client.delete(f"{GRANTS}/{opened['id']}", headers=owner(estate))
        after = await client.get(AUDITOR_GRANTS, headers=auditor())
        assert after.json()["data"] == []


class TestEveryReadChecksTheGrantAgain:
    async def test_a_revoke_takes_effect_on_the_next_request(self, client, estate, opened) -> None:
        paths = ("", "/package", "/verification", "/archive")
        for suffix in paths:
            ok = await client.get(f"{AUDITOR_GRANTS}/{opened['id']}{suffix}", headers=auditor())
            assert ok.status_code == 200, suffix

        await client.delete(f"{GRANTS}/{opened['id']}", headers=owner(estate))

        for suffix in paths:
            response = await client.get(
                f"{AUDITOR_GRANTS}/{opened['id']}{suffix}", headers=auditor()
            )
            assert response.status_code == 409, suffix

    async def test_an_expiry_takes_effect_on_the_next_request(self, client, opened) -> None:
        async with service_session() as session:
            await session.execute(
                text(
                    "UPDATE audit_grants SET created_at = now() - interval '3 days',"
                    " expires_at = now() - interval '1 day' WHERE id = :id"
                ),
                {"id": opened["id"]},
            )
            await session.commit()

        response = await client.get(f"{AUDITOR_GRANTS}/{opened['id']}/package", headers=auditor())

        assert response.status_code == 409

    async def test_a_changed_address_loses_access(self, client, opened) -> None:
        response = await client.get(
            f"{AUDITOR_GRANTS}/{opened['id']}/package",
            headers=auditor(AUDITOR, "new-address@example.com"),
        )

        assert response.status_code == 403

    async def test_another_account_cannot_use_the_grants_id(self, client, opened) -> None:
        for suffix in ("", "/package", "/verification", "/archive"):
            response = await client.get(
                f"{AUDITOR_GRANTS}/{opened['id']}{suffix}",
                headers=auditor(STRANGER, AUDITOR_EMAIL),
            )
            assert response.status_code == 404, suffix

    async def test_nothing_is_readable_before_the_link_is_opened(
        self, client, estate, package
    ) -> None:
        made = await grant(client, estate, package["id"])

        response = await client.get(f"{AUDITOR_GRANTS}/{made['id']}/package", headers=auditor())

        assert response.status_code == 404

    async def test_an_auditor_is_not_a_member_of_anything(self, client, opened) -> None:
        for path in ("/api/v1/audit-packages", "/api/v1/members", GRANTS):
            response = await client.get(path, headers=auditor())
            assert response.status_code == 404, path
            assert response.json()["error"]["code"] == "ORGANIZATION_NOT_FOUND"

    async def test_no_token_is_refused(self, client, opened) -> None:
        for method, path in (
            ("POST", f"{AUDITOR_GRANTS}/open"),
            ("GET", AUDITOR_GRANTS),
            ("GET", f"{AUDITOR_GRANTS}/{opened['id']}"),
            ("GET", f"{AUDITOR_GRANTS}/{opened['id']}/archive"),
        ):
            response = await client.request(method, path, json={"token": "x" * 43})
            assert response.status_code == 401, (method, path)


async def _as_auditor(sql: str, params: dict | None = None) -> list:
    """Run one statement as the role and claims an auditor's request carries."""
    async with rls_session(AUDITOR, AUDITOR_EMAIL) as session:
        return list((await session.execute(text(sql), params or {})).all())


class TestTheDatabaseHoldsItShut:
    async def test_no_policy_lets_an_auditor_into_a_tenant_table(
        self, client, package, opened
    ) -> None:
        for table in (
            "audit_packages",
            "audit_package_items",
            "evidence_blobs",
            "audit_grants",
            "audit_grant_events",
            "organizations",
            "organization_members",
            "cloud_connections",
        ):
            rows = await _as_auditor(f"SELECT count(*) FROM {table}")
            assert rows[0][0] == 0, table

    async def test_the_internal_check_is_not_callable_by_a_role(self, client, opened) -> None:
        with pytest.raises(DBAPIError, match="permission denied"):
            await _as_auditor("SELECT app.live_audit_grant(:id)", {"id": opened["id"]})

    async def test_a_payload_is_given_only_if_the_package_names_its_hash(
        self, client, estate, opened
    ) -> None:
        unnamed = "e" * 64
        async with service_session() as session:
            await session.execute(
                text(
                    "INSERT INTO evidence_blobs (organization_id, content_hash, payload)"
                    " VALUES (:org, :hash, '{\"x\": 1}'::jsonb)"
                ),
                {"org": estate, "hash": unnamed},
            )
            await session.commit()

        rows = await _as_auditor(
            "SELECT content_hash FROM app.audit_grant_blobs(:id, :hashes)",
            {"id": opened["id"], "hashes": [HELD_HASH, unnamed]},
        )

        assert [row[0] for row in rows] == [HELD_HASH]

    async def test_no_role_writes_an_event(self, client, estate, opened) -> None:
        async with rls_session(OWNER, "owner@example.com") as session:
            with pytest.raises(DBAPIError, match="permission denied"):
                await session.execute(
                    text(
                        "INSERT INTO audit_grant_events"
                        " (grant_id, organization_id, user_id, event)"
                        " VALUES (:grant, :org, :user, 'OPENED')"
                    ),
                    {"grant": opened["id"], "org": estate, "user": OWNER},
                )

    async def test_an_owner_cannot_bind_a_grant_to_a_person(self, client, estate, opened) -> None:
        async with rls_session(OWNER, "owner@example.com") as session:
            with pytest.raises(DBAPIError, match="permission denied"):
                await session.execute(
                    text("UPDATE audit_grants SET opened_by = :user WHERE id = :id"),
                    {"user": STRANGER, "id": opened["id"]},
                )

    async def test_an_owner_cannot_take_a_revoke_back(self, client, estate, opened) -> None:
        await client.delete(f"{GRANTS}/{opened['id']}", headers=owner(estate))

        async with rls_session(OWNER, "owner@example.com") as session:
            result = await session.execute(
                text("UPDATE audit_grants SET revoked_at = NULL, revoked_by = NULL WHERE id = :id"),
                {"id": opened["id"]},
            )
            assert result.rowcount == 0
        response = await client.get(f"{GRANTS}/{opened['id']}", headers=owner(estate))
        assert response.json()["data"]["status"] == "REVOKED"

    async def test_an_owner_cannot_make_a_grant_already_opened(
        self, client, estate, package
    ) -> None:
        async with rls_session(OWNER, "owner@example.com") as session:
            with pytest.raises(DBAPIError, match=r"permission denied|row-level security"):
                await session.execute(
                    text(
                        "INSERT INTO audit_grants (organization_id, package_id, email, token_hash,"
                        " created_by, expires_at, opened_by)"
                        " VALUES (:org, :package, 'a@example.com', :hash, :user,"
                        " now() + interval '1 day', :user)"
                    ),
                    {
                        "org": estate,
                        "package": package["id"],
                        "hash": "f" * 64,
                        "user": OWNER,
                    },
                )

    async def test_a_grant_cannot_name_another_organizations_package(
        self, client, estate, cleanup_orgs, rule_catalogue
    ) -> None:
        elsewhere = await make_estate("Elsewhere Org")
        cleanup_orgs.append(elsewhere)
        await read_estate(elsewhere, await framework_keys(elsewhere))
        foreign = await seal(client, elsewhere)

        async with rls_session(OWNER, "owner@example.com") as session:
            with pytest.raises(IntegrityError):
                await session.execute(
                    text(
                        "INSERT INTO audit_grants (organization_id, package_id, email, token_hash,"
                        " created_by, expires_at)"
                        " VALUES (:org, :package, 'a@example.com', :hash, :user,"
                        " now() + interval '1 day')"
                    ),
                    {
                        "org": estate,
                        "package": foreign["id"],
                        "hash": "f" * 64,
                        "user": OWNER,
                    },
                )

    async def test_a_grant_ends_with_its_organization(self, client, estate, opened) -> None:
        async with service_session() as session:
            await session.execute(text("DELETE FROM organizations WHERE id = :id"), {"id": estate})
            await session.commit()
            left = (
                await session.execute(
                    text("SELECT count(*) FROM audit_grants WHERE id = :id"), {"id": opened["id"]}
                )
            ).scalar_one()
            events = (
                await session.execute(
                    text("SELECT count(*) FROM audit_grant_events WHERE grant_id = :id"),
                    {"id": opened["id"]},
                )
            ).scalar_one()

        assert left == 0
        assert events == 0
