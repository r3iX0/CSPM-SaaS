"""Webhooks: where a delivery may go, what it says, and when it is tried again.

The first of those is the one that matters most. A webhook URL is the one place
a customer chooses where this service sends a request, from inside a private
network, so every way a URL could lead inside is refused here -- by form, by
what its name resolves to, and by pinning the connection to the address that
was checked (DECISIONS.md section 164).
"""

import hashlib
import hmac
import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from app.core import outbound
from app.core.enums import WebhookFormat
from app.models.webhook import WebhookEndpoint
from app.services import webhooks

NOW = datetime(2026, 9, 29, 12, 0, tzinfo=UTC)


@pytest.fixture
def resolving(monkeypatch: pytest.MonkeyPatch) -> Callable[..., None]:
    """Make every name resolve to the addresses given."""

    def use(*addresses: str) -> None:
        async def fake(host: str) -> list[str]:
            return sorted(addresses)

        monkeypatch.setattr(outbound, "_addresses", fake)

    return use


# ------------------------------------------------------------------- form


@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.example.com/x",
        "ftp://hooks.example.com/x",
        "https://user:pass@hooks.example.com/x",
        "https://hooks.example.com:8443/x",
        "https://hooks.example.com:notaport/x",
        "https://localhost/x",
        "https://metadata.internal/x",
        "https://127.0.0.1/x",
        "https://10.0.0.5/x",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/x",
        "https://[::ffff:10.0.0.1]/x",
        "https://100.64.0.1/x",
    ],
)
def test_a_url_that_could_lead_inside_is_refused_by_its_form(url: str) -> None:
    with pytest.raises(outbound.OutboundRefused):
        outbound.check_form(url)


def test_an_ordinary_receiver_passes_its_form() -> None:
    assert outbound.check_form("https://hooks.slack.com/services/T0/B0/xyz") == (
        "hooks.slack.com",
        "/services/T0/B0/xyz",
    )


async def test_a_name_that_resolves_inside_is_refused(resolving: Callable[..., None]) -> None:
    resolving("10.1.2.3")
    with pytest.raises(outbound.OutboundRefused, match="private"):
        await outbound.resolve("https://innocent.example.com/hook")


async def test_one_private_answer_among_public_ones_is_enough_to_refuse(
    resolving: Callable[..., None],
) -> None:
    """The connection could land on any of them."""
    resolving("93.184.216.34", "192.168.1.10")
    with pytest.raises(outbound.OutboundRefused):
        await outbound.resolve("https://mixed.example.com/hook")


async def test_a_public_name_is_pinned_to_the_address_checked(
    resolving: Callable[..., None],
) -> None:
    resolving("93.184.216.34")
    target = await outbound.resolve("https://receiver.example.com/hook?x=1")
    assert target.address == "93.184.216.34"
    assert outbound.pinned_url(target) == "https://93.184.216.34/hook?x=1"


def test_an_ipv6_address_is_bracketed_when_pinned() -> None:
    target = outbound.Target(
        url="https://r.example.com/h", host="r.example.com", address="2001:db8::1"
    )
    assert outbound.pinned_url(target) == "https://[2001:db8::1]/h"


# --------------------------------------------------------------- sending


async def test_the_request_goes_to_the_pinned_address_as_the_named_host(
    resolving: Callable[..., None],
) -> None:
    resolving("93.184.216.34")
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(204)

    outcome = await outbound.post_json(
        "https://receiver.example.com/hook",
        b"{}",
        {"X-Test": "1"},
        transport=httpx.MockTransport(handler),
    )
    assert outcome == outbound.Outcome(ok=True, status=204, error=None)
    (request,) = seen
    assert request.url.host == "93.184.216.34"
    assert request.headers["host"] == "receiver.example.com"
    # The certificate is verified against the name, not the address.
    assert request.extensions["sni_hostname"] == "receiver.example.com"


async def test_a_redirect_is_an_answer_not_an_instruction(
    resolving: Callable[..., None],
) -> None:
    resolving("93.184.216.34")
    transport = httpx.MockTransport(
        lambda request: httpx.Response(302, headers={"Location": "https://10.0.0.1/"})
    )
    outcome = await outbound.post_json("https://r.example.com/h", b"{}", {}, transport=transport)
    assert not outcome.ok
    assert outcome.status == 302


async def test_a_refused_url_is_an_outcome_not_an_exception() -> None:
    outcome = await outbound.post_json("http://r.example.com/h", b"{}", {})
    assert not outcome.ok
    assert outcome.error is not None and "https" in outcome.error


# ------------------------------------------------------------- messages


def message(**overrides: object) -> webhooks.Message:
    base: dict[str, object] = {
        "id": uuid.UUID(int=1),
        "organization_id": uuid.UUID(int=2),
        "kind": "REACHABLE_FINDING",
        "title": "Public blob access on <stprod>",
        "detail": "This asset stands on a route & more.",
        "link": "/findings/abc",
        "event_at": NOW,
    }
    base.update(overrides)
    return webhooks.Message(**base)  # type: ignore[arg-type]


def test_slack_gets_escaped_text_and_a_link(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(webhooks.settings, "app_url", "https://app.cleave.example")
    body = json.loads(webhooks.render(WebhookFormat.SLACK, message()))
    assert body["text"].startswith("*Public blob access on &lt;stprod&gt;*")
    assert "route &amp; more" in body["text"]
    assert body["text"].endswith("<https://app.cleave.example/findings/abc|Open in Cleave>")


def test_teams_gets_an_adaptive_card(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(webhooks.settings, "app_url", "https://app.cleave.example")
    body = json.loads(webhooks.render(WebhookFormat.TEAMS, message()))
    (attachment,) = body["attachments"]
    assert attachment["contentType"] == "application/vnd.microsoft.card.adaptive"
    card = attachment["content"]
    assert card["type"] == "AdaptiveCard"
    assert card["actions"][0]["url"] == "https://app.cleave.example/findings/abc"


def test_a_generic_receiver_gets_the_notification_and_a_signature() -> None:
    body = webhooks.render(WebhookFormat.GENERIC, message())
    assert json.loads(body)["kind"] == "REACHABLE_FINDING"

    endpoint = WebhookEndpoint(format=WebhookFormat.GENERIC, secret="s3cret")
    headers = webhooks.headers_for(endpoint, uuid.UUID(int=9), "REACHABLE_FINDING", body)
    expected = hmac.new(
        b"s3cret", headers["X-Cleave-Timestamp"].encode() + b"." + body, hashlib.sha256
    ).hexdigest()
    assert headers["X-Cleave-Signature"] == f"sha256={expected}"
    assert headers["X-Cleave-Delivery"] == str(uuid.UUID(int=9))


def test_slack_and_teams_are_not_signed() -> None:
    endpoint = WebhookEndpoint(format=WebhookFormat.SLACK, secret=None)
    assert webhooks.headers_for(endpoint, uuid.uuid4(), "VERIFIED_FIX", b"{}") == {}


def test_a_stored_url_is_shown_only_in_part() -> None:
    preview = webhooks.url_preview("https://hooks.slack.com/services/T0/B0/abcdefghijkl")
    assert preview == "hooks.slack.com/…ijkl"
    assert "T0" not in preview


# --------------------------------------------------------------- retries


def test_retries_widen_then_stop() -> None:
    delays = [webhooks.next_attempt(n, NOW) for n in range(1, webhooks.MAX_ATTEMPTS + 1)]
    assert delays[0] == NOW + timedelta(minutes=1)
    assert delays[-2] == NOW + timedelta(hours=6)
    assert delays[-1] is None


# ------------------------------------------------ a receiver that stalls


class _Drip(httpx.AsyncByteStream):
    """An answer that never ends: a byte, then a wait, for ever."""

    def __init__(self, pause: float) -> None:
        self.pause = pause
        self.sent = 0

    async def __aiter__(self):  # type: ignore[no-untyped-def]
        import asyncio

        while True:
            self.sent += 1
            yield b"x" * 1024
            await asyncio.sleep(self.pause)


async def test_a_receiver_that_drips_is_cut_off_at_the_deadline(
    resolving: Callable[..., None], monkeypatch: pytest.MonkeyPatch
) -> None:
    """httpx's read timeout restarts with every chunk; the deadline does not."""
    resolving("93.184.216.34")
    monkeypatch.setattr(outbound, "DEADLINE", 0.3)
    monkeypatch.setattr(outbound, "READ_LIMIT", 10**9)
    drip = _Drip(pause=0.05)
    transport = httpx.MockTransport(lambda request: httpx.Response(500, stream=drip))

    outcome = await outbound.post_json("https://r.example.com/h", b"{}", {}, transport=transport)
    assert not outcome.ok
    assert outcome.error == "No answer within 0.3 seconds"


async def test_an_endless_refusal_is_read_only_as_far_as_the_limit(
    resolving: Callable[..., None],
) -> None:
    resolving("93.184.216.34")
    drip = _Drip(pause=0)
    transport = httpx.MockTransport(lambda request: httpx.Response(500, stream=drip))

    outcome = await outbound.post_json("https://r.example.com/h", b"{}", {}, transport=transport)
    assert outcome.status == 500
    assert drip.sent <= outbound.READ_LIMIT // 1024 + 1
    assert outcome.error is not None and len(outcome.error) <= outbound.ERROR_EXCERPT + 20


def test_every_row_owed_gets_its_own_id_from_the_database() -> None:
    """One bound ``id`` for the whole INSERT..SELECT made the second row collide.

    Two or more deliveries owed in one sweep then failed the primary key, and
    the sweep's transaction -- the bell's notifications with it -- rolled back.
    """
    from sqlalchemy.dialects import postgresql

    compiled = str(
        webhooks.owed(uuid.uuid4(), NOW).compile(dialect=postgresql.dialect())
    )
    assert "%(id)s" not in compiled
    assert (
        "INSERT INTO webhook_deliveries (organization_id, endpoint_id, notification_id)"
        in compiled
    )
