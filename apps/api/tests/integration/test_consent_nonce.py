"""Redeeming a consent link is durable, even when the callback then fails.

The unit tests in ``tests/unit/test_consent_binding.py`` prove the rule with a
session fake, which can show that a commit happened but not that a rollback
would have undone one. That is the failure this file exists for: the nonce used
to be cleared in memory and committed several provider calls later, so any
exception in between -- the tenant-rebind refusal, or a directory call that did
not answer -- took the spend down with the rest of the transaction and handed
the link back to whoever else held it.

So this runs against a real PostgreSQL transaction and asks the only question
that settles it: after the callback has failed, what does a *fresh* session see
in the column?
"""

import uuid
from typing import Any

import pytest
from sqlalchemy import text

from app.core.db import service_session
from app.core.enums import CloudAccountStatus, ConnectionScope, ConsentStatus, Provider
from app.core.errors import CloudConnectionError, ValidationFailed
from app.models.cloud_connection import CloudConnection
from app.services import cloud_connections as service

from .conftest import create_org_as

pytestmark = pytest.mark.integration


async def make_connection(organization_id: uuid.UUID, **overrides: Any) -> uuid.UUID:
    """A connection row with a live consent link on it."""
    async with service_session() as session:
        row = CloudConnection(
            organization_id=organization_id,
            provider=Provider.AZURE,
            name="Contoso",
            scope_type=ConnectionScope.TENANT_ROOT,
            consent_status=ConsentStatus.PENDING,
            status=CloudAccountStatus.PENDING,
            consent_nonce="link-sent-to-the-administrator",
        )
        for key, value in overrides.items():
            setattr(row, key, value)
        session.add(row)
        await session.commit()
        return row.id


async def stored_nonce(connection_id: uuid.UUID) -> str | None:
    """What a session that shares nothing with the callback's can see."""
    async with service_session() as session:
        return (
            await session.execute(
                text("SELECT consent_nonce FROM cloud_connections WHERE id = :id"),
                {"id": connection_id},
            )
        ).scalar_one()


@pytest.fixture
async def organization(cleanup_orgs: list[uuid.UUID]) -> uuid.UUID:
    org_id = await create_org_as(uuid.uuid4(), "Consent Nonce")
    cleanup_orgs.append(org_id)
    return org_id


async def test_a_refused_rebind_still_spends_the_link(organization: uuid.UUID) -> None:
    """The refusal raises. The spend has to have outlived it."""
    connection_id = await make_connection(organization, tenant_id="tenant-a")

    async with service_session() as session:
        with pytest.raises(ValidationFailed):
            await service.record_consent(
                session,
                connection_id,
                "tenant-b",
                nonce="link-sent-to-the-administrator",
            )

    assert await stored_nonce(connection_id) is None


async def test_a_failed_directory_call_still_spends_the_link(
    organization: uuid.UUID, monkeypatch: pytest.MonkeyPatch
) -> None:
    connection_id = await make_connection(organization)

    class _Failing:
        ready_to_deploy_detail = "ready"

        async def ensure_principal(self, _connection: CloudConnection) -> Any:
            raise CloudConnectionError("Entra did not answer")

    monkeypatch.setattr(service, "flow", lambda _connection: _Failing())

    async with service_session() as session:
        with pytest.raises(CloudConnectionError):
            await service.record_consent(
                session,
                connection_id,
                "tenant-a",
                nonce="link-sent-to-the-administrator",
            )

    assert await stored_nonce(connection_id) is None


async def test_a_wrong_nonce_leaves_the_link_alone(organization: uuid.UUID) -> None:
    """The guard is in front of the commit, so a guess writes nothing.

    Otherwise anyone who could reach the callback could burn a link they had
    not seen, which is the same denial of service the nonce was added to
    prevent a replay of.
    """
    connection_id = await make_connection(organization)

    async with service_session() as session:
        with pytest.raises(ValidationFailed):
            await service.record_consent(session, connection_id, "tenant-a", nonce="guess")

    assert await stored_nonce(connection_id) == "link-sent-to-the-administrator"
