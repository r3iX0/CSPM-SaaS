"""Why a connection did not verify, written down where an operator can read it.

``probe`` answers one question -- may CloudGuard read this environment yet --
and the setup screen turns that answer into a spinner or a green tick. The
answer is the right shape: a connection whose role is still being deployed
fails this on every five-second poll, and none of those failures is an incident.

What was wrong is that the *reason* went with it. Azure's account of the refusal
was caught and dropped, so a connection that would never verify looked
identical to one deploying normally, for the thirty minutes before the stalled
panel appears -- and diagnosing it meant reading Azure's portal, because
CloudGuard's own logs said nothing at all.

Verdict quiet, reason loud.
"""

import uuid
from typing import ClassVar

import pytest
import structlog

from app.connectors.azure import auth
from app.connectors.azure.client import AzureApiError
from app.connectors.azure.onboarding import AzureOnboarding
from app.core.enums import CloudAccountStatus, ConnectionScope, ConsentStatus, Provider
from app.models.cloud_connection import CloudConnection

TENANT = "8e482025-7ac9-4323-81e5-bc9fa528afd7"


def a_connection() -> CloudConnection:
    connection = CloudConnection(
        provider=Provider.AZURE,
        name="test",
        scope_type=ConnectionScope.TENANT_ROOT,
        role_version="v7",
        consent_status=ConsentStatus.GRANTED,
        status=CloudAccountStatus.PENDING,
    )
    connection.id = uuid.uuid4()
    connection.tenant_id = TENANT
    return connection


class FakeArm:
    """An ARM client that answers however a test needs it to."""

    subscriptions: ClassVar[list[dict]] = []
    listing_error: ClassVar[Exception | None] = None
    resources_error: ClassVar[Exception | None] = None

    def __init__(self, tokens: object) -> None:
        self.tokens = tokens

    async def __aenter__(self) -> "FakeArm":
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def list_subscriptions(self) -> list[dict]:
        if FakeArm.listing_error:
            raise FakeArm.listing_error
        return FakeArm.subscriptions

    async def list_resources(self, subscription_id: str) -> list[dict]:
        if FakeArm.resources_error:
            raise FakeArm.resources_error
        return []


@pytest.fixture(autouse=True)
def azure(monkeypatch: pytest.MonkeyPatch):
    class FakeTokens:
        def __init__(self, tenant_id: str) -> None:
            self.tenant_id = tenant_id

    monkeypatch.setattr(auth, "TokenProvider", FakeTokens)
    monkeypatch.setattr("app.connectors.azure.onboarding.ArmClient", FakeArm)
    FakeArm.subscriptions = [{"subscriptionId": "34a5438c-e5d8-4681-bcfe-be8fd94962ac"}]
    FakeArm.listing_error = None
    FakeArm.resources_error = None
    return FakeArm


async def probe_events(connection: CloudConnection) -> tuple[bool, list[dict]]:
    with structlog.testing.capture_logs() as captured:
        check = await AzureOnboarding().probe(connection)
    return check.ok, [e for e in captured if e.get("event") == "azure.probe_failed"]


async def test_a_refused_listing_says_what_azure_said() -> None:
    """The case this exists for: ARM answering 403 for a principal whose role
    assignment looks correct in the portal."""
    FakeArm.listing_error = AzureApiError(
        "Access denied. CloudGuard's scanner role is not assigned on this scope.",
        status_code=403,
    )

    ok, events = await probe_events(a_connection())

    assert ok is False
    (failure,) = events
    assert failure["reason"] == "subscriptions_unreadable"
    assert "scanner role is not assigned" in failure["error"]
    assert failure["tenant_id"] == TENANT


async def test_an_empty_listing_is_reported_as_its_own_reason() -> None:
    """Not an exception, and not the same fault. Azure answers a known
    principal holding no role anywhere with an empty list rather than a 403, so
    this is the shape of "nothing deployed yet" -- which is worth telling apart
    from a refusal when somebody insists the deployment succeeded."""
    FakeArm.subscriptions = []

    ok, events = await probe_events(a_connection())

    assert ok is False
    assert [e["reason"] for e in events] == ["no_subscriptions_readable"]


async def test_readable_subscriptions_with_unreadable_resources_is_distinct() -> None:
    """A role that grants the subscription listing and nothing under it. The
    two failures send somebody to different places, so they cannot share a
    line."""
    FakeArm.resources_error = AzureApiError("Access denied.", status_code=403)

    ok, events = await probe_events(a_connection())

    assert ok is False
    assert [e["reason"] for e in events] == ["resources_unreadable"]


async def test_a_tenant_with_no_token_is_named_as_such() -> None:
    """A deleted enterprise application fails here, before any ARM call. It
    read as an RBAC problem for as long as nothing logged which step failed."""

    def refuse(tenant_id: str) -> object:
        raise RuntimeError("AADSTS7000229: missing service principal in the tenant")

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(auth, "TokenProvider", refuse)
        ok, events = await probe_events(a_connection())

    assert ok is False
    (failure,) = events
    assert failure["reason"] == "no_token"
    assert "AADSTS7000229" in failure["error"]


async def test_a_working_connection_logs_nothing() -> None:
    """Every poll of every healthy connection passes through here."""
    ok, events = await probe_events(a_connection())

    assert ok is True
    assert events == []
