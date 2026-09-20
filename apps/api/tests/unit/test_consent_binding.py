"""What a consent callback is allowed to change, and how often.

The Entra admin-consent response is a plain query string, not a token. Nothing
in it proves anything: ``tenant`` is whatever the caller put in the URL, and the
signed ``state`` is verifiable by anyone holding it for as long as it has not
expired. Two rules stand behind the write that binds a connection to a directory,
and this is where they are pinned.

A link is redeemable once -- the nonce it carries has to match the one on the
row, and redeeming it clears that. And a connection that already names a tenant
is never repointed at a different one by a callback, because the tenant is what
every later token, graph call and scan is addressed to.
"""

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest

from app.core.enums import CloudAccountStatus, ConnectionScope, ConsentStatus, Provider
from app.core.errors import ValidationFailed
from app.models.cloud_connection import CloudConnection
from app.services import cloud_connections as service


def connection(**overrides: Any) -> CloudConnection:
    row = CloudConnection(
        id=uuid4(),
        organization_id=uuid4(),
        provider=Provider.AZURE,
        name="Contoso",
        scope_type=ConnectionScope.TENANT_ROOT,
        consent_status=ConsentStatus.PENDING,
        status=CloudAccountStatus.PENDING,
    )
    for key, value in overrides.items():
        setattr(row, key, value)
    return row


class _Session:
    """Just enough session to hand ``record_consent`` one row.

    A fake rather than a database: every rule under test is decided before any
    query is made, and the point of the test is that it is decided at all.
    """

    def __init__(self, row: CloudConnection | None) -> None:
        self.row = row
        self.committed = False
        # What ``commit_unless_externally_managed`` reads to decide whose
        # transaction this is. Empty means "yours", which is what a service
        # called outside a request sees.
        self.info: dict[str, object] = {}

    async def get(self, _model: object, _pk: object) -> CloudConnection | None:
        return self.row

    async def commit(self) -> None:
        self.committed = True


@pytest.fixture(autouse=True)
def _no_provider_calls(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stop ``record_consent`` reaching Entra once its checks have passed.

    Everything past the guards talks to a provider. These tests are about the
    guards, and a test that needed a directory to prove one would not be run.
    """

    class _Onboarding:
        ready_to_deploy_detail = "ready"

        async def ensure_principal(self, _connection: CloudConnection) -> Any:
            return type("Lookup", (), {"object_id": None, "problem": None})()

        async def grant_problem(self, _connection: CloudConnection) -> None:
            return None

        async def missing_grants(self, _connection: CloudConnection) -> None:
            return None

    monkeypatch.setattr(service, "flow", lambda _connection: _Onboarding())


async def test_the_nonce_has_to_match_the_one_that_was_issued() -> None:
    row = connection(consent_nonce="issued-to-the-customer")
    session = _Session(row)

    with pytest.raises(ValidationFailed):
        await service.record_consent(
            session, row.id, "attacker-tenant", nonce="guessed"
        )

    assert row.consent_status is ConsentStatus.PENDING
    assert row.tenant_id is None


async def test_a_connection_with_no_live_link_cannot_be_consented() -> None:
    """An empty stored nonce is not a nonce anybody can match.

    The comparison is against ``""`` when no link is outstanding, and an empty
    string compares equal to an empty string -- so this is the case that has to
    be refused before the comparison rather than by it.
    """
    row = connection(consent_nonce=None)
    session = _Session(row)

    with pytest.raises(ValidationFailed):
        await service.record_consent(session, row.id, "some-tenant", nonce="")

    assert row.consent_status is ConsentStatus.PENDING


async def test_a_redeemed_link_does_not_work_twice() -> None:
    row = connection(consent_nonce="one-time")
    session = _Session(row)

    await service.record_consent(session, row.id, "tenant-a", nonce="one-time")

    assert row.consent_status is ConsentStatus.GRANTED
    assert row.tenant_id == "tenant-a"
    assert row.consent_nonce is None

    with pytest.raises(ValidationFailed):
        await service.record_consent(session, row.id, "tenant-a", nonce="one-time")


async def test_a_second_directory_cannot_take_over_a_bound_connection() -> None:
    """The case the tenant parameter was worth attacking for.

    A fresh link on a connection that is already bound -- and a different tenant
    named on the way back in. Refused, and the link is spent regardless, so it
    cannot simply be presented again with the right answer.
    """
    row = connection(tenant_id="tenant-a", consent_nonce="fresh-link")
    session = _Session(row)

    with pytest.raises(ValidationFailed):
        await service.record_consent(session, row.id, "tenant-b", nonce="fresh-link")

    assert row.tenant_id == "tenant-a"
    assert row.consent_nonce is None


async def test_reconsenting_the_same_directory_is_allowed() -> None:
    """Re-granting is a real thing customers do.

    Consent is re-run whenever CloudGuard's registration asks for a permission
    the tenant has not granted, so the same directory answering again has to
    succeed -- it is only a *different* one that is refused.
    """
    row = connection(tenant_id="tenant-a", consent_nonce="fresh-link")
    session = _Session(row)

    await service.record_consent(session, row.id, "tenant-a", nonce="fresh-link")

    assert row.consent_status is ConsentStatus.GRANTED
    assert row.tenant_id == "tenant-a"


def test_a_live_link_is_reissued_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    """Polling must not invalidate the link the customer already sent on.

    The wizard reads the connection on a timer. A fresh nonce per read would
    mean the Global Administrator follows a link that expired the moment the
    page behind it refreshed.
    """
    issued = datetime.now(UTC) - timedelta(minutes=5)
    row = connection(consent_nonce="already-sent", consent_nonce_issued_at=issued)
    monkeypatch.setattr(
        service,
        "flow",
        lambda _c: type(
            "F", (), {"start_url": lambda _s, _c, *, nonce, issued_at: (f"url:{nonce}", None)}
        )(),
    )

    url, problem = service.issue_consent_url(row)

    assert url == "url:already-sent"
    assert problem is None
    assert row.consent_nonce == "already-sent"
    assert row.consent_nonce_issued_at == issued


def test_an_aged_out_link_is_replaced(monkeypatch: pytest.MonkeyPatch) -> None:
    stale = datetime.now(UTC) - timedelta(
        seconds=service.CONSENT_LINK_TTL_SECONDS + 60
    )
    row = connection(consent_nonce="long-gone", consent_nonce_issued_at=stale)
    monkeypatch.setattr(
        service,
        "flow",
        lambda _c: type(
            "F", (), {"start_url": lambda _s, _c, *, nonce, issued_at: (f"url:{nonce}", None)}
        )(),
    )

    url, _ = service.issue_consent_url(row)

    assert row.consent_nonce != "long-gone"
    assert url == f"url:{row.consent_nonce}"


def test_a_provider_with_no_consent_step_costs_no_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """AWS answers ``(None, None)``, and that must not touch the row.

    This is read on every poll of every connection. A provider that has no link
    to give would otherwise write a nonce it will never be asked for.
    """
    row = connection(provider=Provider.AWS)
    monkeypatch.setattr(
        service,
        "flow",
        lambda _c: type(
            "F", (), {"start_url": lambda _s, _c, *, nonce, issued_at: (None, None)}
        )(),
    )

    url, problem = service.issue_consent_url(row)

    assert (url, problem) == (None, None)
    assert row.consent_nonce is None
    assert row.consent_nonce_issued_at is None
