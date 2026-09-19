"""What a 403 tells the customer.

Every collection category can fail, and the message it fails with is the whole
of what the customer sees -- it lands in ``collection_errors``, surfaces on the
scan as "affected checks are marked unknown, not passed", and is the only
instruction they get.

Both clients used to raise one sentence naming both remedies: check the Reader
role, and check admin consent. The two grants are independent -- a role
deployment on a subscription, and a Global Administrator consenting to
directory permissions -- and ``validate_connection`` already probes them
separately so the UI can say which one is missing. Merging them here threw that
away at the last step. Half of everyone reading it was sent to a blade that
looked correctly configured, because for their failure it was.

Identity is the case that made it obvious: every identity call goes through
Graph and none goes near Azure RBAC, so "check that the Reader role is
assigned" was advice that could never once have been right.
"""

import asyncio

import httpx
import pytest
import structlog

from app.connectors.azure import client as client_module
from app.connectors.azure.client import (
    MAX_ATTEMPTS,
    ArmClient,
    AzureApiError,
    GraphClient,
)


@pytest.fixture(autouse=True)
def waits(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    """Record backoff instead of serving it.

    Retrying for real made this file take a minute and a half. Recording the
    waits is also the better test: how long the client decided to wait is the
    behaviour worth asserting on, and sleeping through it proves nothing.
    """
    recorded: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        recorded.append(seconds)

    monkeypatch.setattr(client_module.asyncio, "sleep", fake_sleep)
    return recorded


class FakeTokens:
    def arm_token(self) -> str:
        return "arm-token"

    def graph_token(self) -> str:
        return "graph-token"


def client_returning(status: int, payload: dict | None = None, text: str = ""):
    """An httpx client that answers every request the same way."""

    def handler(request: httpx.Request) -> httpx.Response:
        if payload is not None:
            return httpx.Response(status, json=payload)
        return httpx.Response(status, text=text)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def error_from(client_cls, status: int, payload: dict | None = None, text: str = ""):
    async with client_cls(FakeTokens(), client_returning(status, payload, text)) as api:
        with pytest.raises(AzureApiError) as raised:
            await api.get("/anything")
    return raised.value


# ------------------------------------------------------------------ the split
async def test_an_arm_403_points_at_the_role_assignment() -> None:
    message = str(await error_from(ArmClient, 403))

    assert "scanner role" in message
    assert "Access control (IAM)" in message
    # It must not route an RBAC failure to the consent screen. Naming consent
    # only to rule it out is the point, so the check is on the destination.
    assert "Enterprise applications" not in message


async def test_a_graph_403_points_at_admin_consent() -> None:
    """The identity category is collected entirely through Graph."""
    message = str(await error_from(GraphClient, 403))

    assert "Admin consent" in message
    assert "Enterprise applications" in message
    # Said explicitly, because the instinct is to go and check RBAC.
    assert "Azure role assignments do not affect this" in message


async def test_neither_403_mentions_the_reader_role() -> None:
    """CloudGuard stopped asking for Reader when the custom role landed, so a
    customer sent to look for a Reader assignment will not find one even on a
    correctly configured connection."""
    for client_cls in (ArmClient, GraphClient):
        assert "Reader role" not in str(await error_from(client_cls, 403))


async def test_the_two_surfaces_do_not_share_a_message() -> None:
    """A regression guard. The failure being fixed here was one message doing
    the work of two, and the cheapest way to reintroduce it is to write a
    shared default and forget to override it."""
    assert str(await error_from(ArmClient, 403)) != str(
        await error_from(GraphClient, 403)
    )


# ------------------------------------------------------- Azure's own account
async def test_azure_s_own_message_is_carried_through() -> None:
    """Graph answers a missing grant with wording that names the shape of the
    problem better than anything written here can."""
    message = str(
        await error_from(
            GraphClient,
            403,
            {"error": {"message": "Insufficient privileges to complete the operation."}},
        )
    )
    assert "Insufficient privileges to complete the operation." in message
    assert "Azure reported:" in message


async def test_nothing_is_appended_when_azure_said_nothing() -> None:
    message = str(await error_from(ArmClient, 403, text=""))
    assert "Azure reported:" not in message
    assert message.endswith(".")


async def test_an_unparseable_body_does_not_mask_the_403() -> None:
    """The detail is a courtesy; the instruction is the point."""
    message = str(await error_from(ArmClient, 403, text="<html>gateway</html>"))
    assert "scanner role" in message


# --------------------------------------------------- the other status codes
async def test_throttling_is_still_reported_as_throttling() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, headers={"Retry-After": "30"})

    async with ArmClient(
        FakeTokens(), httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ) as api:
        with pytest.raises(AzureApiError) as raised:
            await api.get("/anything")

    assert "throttling" in str(raised.value)
    assert raised.value.azure_status_code == 429


async def test_other_failures_keep_their_status_and_detail() -> None:
    """Covers the shared detail extraction the 403 branch now reuses."""
    error = await error_from(ArmClient, 500, {"error": {"message": "Server blew up"}})
    assert "500" in str(error)
    assert "Server blew up" in str(error)
    assert error.azure_status_code == 500


# ------------------------------------------------------------------- retrying
def counting_client(statuses: list[int], headers: dict | None = None):
    """Answers with each status in turn, then 200."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        i = calls["n"]
        calls["n"] += 1
        if i < len(statuses):
            return httpx.Response(statuses[i], headers=headers or {}, json={})
        return httpx.Response(200, json={"value": []})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler)), calls


async def test_a_throttled_call_is_retried_rather_than_lost(waits) -> None:
    """One 429 used to cost every rule that depended on that category. Azure
    throttles ARM reads as ordinary behaviour, not as an incident."""
    transport, calls = counting_client([429, 429])

    async with ArmClient(FakeTokens(), transport) as api:
        assert await api.get("/anything") == {"value": []}

    assert calls["n"] == 3, "two refusals, then the answer"
    assert len(waits) == 2


async def test_azure_s_own_retry_hint_is_preferred_to_our_backoff(waits) -> None:
    """Azure is the only party that knows when the throttle lifts."""
    transport, _ = counting_client([429], headers={"Retry-After": "7"})

    async with ArmClient(FakeTokens(), transport) as api:
        await api.get("/anything")

    assert waits == [7.0]


async def test_a_retry_hint_longer_than_a_scan_will_wait_gives_up(waits) -> None:
    """Holding a worker for a minute to maybe succeed is worse than reporting
    the category unreadable now and letting the customer rescan."""
    transport, calls = counting_client([429, 429, 429, 429], headers={"Retry-After": "600"})

    async with ArmClient(FakeTokens(), transport) as api:
        with pytest.raises(AzureApiError):
            await api.get("/anything")

    assert calls["n"] == 1, "no point retrying on that hint"
    assert waits == []


async def test_server_errors_back_off_exponentially(waits) -> None:
    transport, calls = counting_client([500, 503])

    async with ArmClient(FakeTokens(), transport) as api:
        await api.get("/anything")

    assert calls["n"] == 3
    assert waits[0] < waits[1], "each wait longer than the last"


async def test_retrying_stops_at_the_attempt_limit(waits) -> None:
    transport, calls = counting_client([500] * 10)

    async with ArmClient(FakeTokens(), transport) as api:
        with pytest.raises(AzureApiError):
            await api.get("/anything")

    assert calls["n"] == MAX_ATTEMPTS


async def test_permission_errors_are_never_retried(waits) -> None:
    """A 403 will still be a 403 in two seconds, and retrying it would turn a
    clear permission error into a slow one."""
    transport, calls = counting_client([403] * 4)

    async with ArmClient(FakeTokens(), transport) as api:
        with pytest.raises(AzureApiError):
            await api.get("/anything")

    assert calls["n"] == 1
    assert waits == []


# ---------------------------------------------------------------- truncation
async def test_a_truncated_listing_is_recorded_on_the_client() -> None:
    """The defect this closes: a list cut off at the page cap is still a list,
    and the rules would have read it as the whole environment."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"value": [{"id": "x"}], "nextLink": "https://arm/next"}
        )

    async with ArmClient(
        FakeTokens(), httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ) as api:
        items = await api.get_all("/subscriptions/s/things", max_pages=3)

    assert len(items) == 3, "the pages it did read are still returned"
    assert api.truncated == {"/subscriptions/s/things"}


async def test_a_complete_listing_records_no_truncation() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"value": [{"id": "x"}]})

    async with ArmClient(
        FakeTokens(), httpx.AsyncClient(transport=httpx.MockTransport(handler))
    ) as api:
        await api.get_all("/subscriptions/s/things")

    assert api.truncated == set()


# ------------------------------------------------- what the log is left with
#
# A failing call used to leave nothing behind. The message above reaches the
# customer only when a *collector* raises it; the connection probe answers
# ok/not-ok and discards it, so a connection that would not verify produced a
# spinner in the browser and silence in the logs, and the only way to find out
# why was to open Azure's portal. These assert that the call says what happened
# where an operator can read it.
def logs_from(status: int, payload: dict | None = None, text: str = "", headers=None):
    """Every structlog event the client emitted for one failing call."""
    events: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        if payload is not None:
            return httpx.Response(status, json=payload, headers=headers)
        return httpx.Response(status, text=text, headers=headers)

    async def run() -> None:
        transport = httpx.MockTransport(handler)
        async with ArmClient(
            FakeTokens(), httpx.AsyncClient(transport=transport)
        ) as api:
            with pytest.raises(AzureApiError):
                await api.get("/subscriptions")

    with structlog.testing.capture_logs() as captured:
        asyncio.run(run())
    events.extend(captured)
    return [event for event in events if event.get("event") == "azure.request_failed"]


def test_a_failing_call_is_logged_with_azure_s_own_request_ids() -> None:
    """The two ids Microsoft support asks for first, and which cannot be
    recovered once the response is gone."""
    (failure,) = logs_from(
        403,
        {"error": {"code": "AuthorizationFailed", "message": "does not have access"}},
        headers={
            "x-ms-request-id": "req-1",
            "x-ms-correlation-request-id": "corr-1",
        },
    )

    assert failure["status"] == 403
    assert failure["url"].endswith("/subscriptions")
    assert failure["request_id"] == "req-1"
    assert failure["correlation_id"] == "corr-1"
    assert "AuthorizationFailed" in failure["detail"]
    assert "does not have access" in failure["detail"]


def test_an_html_body_is_logged_as_the_sentence_it_contains() -> None:
    """The failure that prompted this: ARM answers an authorization denial with
    JSON, so an HTML page means something in front of ARM refused the call --
    which is worth knowing and unreadable as raw markup. Truncated at 200
    characters, ``<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0...`` had not yet
    reached a single word of the explanation."""
    (failure,) = logs_from(
        403,
        text=(
            "<!DOCTYPE html PUBLIC '-//W3C//DTD XHTML 1.0 Transitional//EN'>"
            "<html><head><title>403 - Forbidden</title></head>"
            "<body>   <h2>Access is denied by the gateway.</h2>   </body></html>"
        ),
    )

    assert "Access is denied by the gateway." in failure["detail"]
    assert "<" not in failure["detail"]
    assert "DOCTYPE" not in failure["detail"]
    # One line, however the markup was laid out.
    assert "  " not in failure["detail"]


# Front Door's block page, as Railway received it from management.azure.com:
# a stylesheet first, then the sentence, then the references support asks for.
FRONT_DOOR_BLOCK = (
    "<!DOCTYPE html><html><head><title>Error</title><style type='text/css'>"
    "body { font-family:Arial; margin-left:40px; }img { border:0 none; }"
    "#content { margin-left: auto; margin-right: auto }"
    "#message h2 { font-size: 20px; font-weight: normal; color: #000000; "
    "margin: 34px 0px 0px 0px }#message p { font-size: 13px; color: #000000; "
    "margin: 7px 0px 0px 0px }#errorref { font-size: 11px; color: #737373; "
    "margin-top: 41px }</style></head><body><div id='content'><div id='message'>"
    "<h2>The request is blocked.</h2></div><div id='errorref'><span>"
    "20260919T182450Z-17d8f4c6b8dxk9tphC1LONnkx40000000ff0000000000a1b2"
    "</span></div></div></body></html>"
)


def test_a_block_page_logs_its_reference_not_its_stylesheet() -> None:
    """Stripping tags kept the CSS between them, which used most of the detail
    limit and cut the reference off -- the one string Microsoft support needs."""
    (failure,) = logs_from(403, text=FRONT_DOOR_BLOCK)

    assert "font-family" not in failure["detail"]
    assert "The request is blocked." in failure["detail"]
    assert "20260919T182450Z-17d8f4c6b8dxk9tphC1LONnkx40000000ff0000000000a1b2" in (
        failure["detail"]
    )
    assert failure["edge_blocked"] is True


def test_an_authorization_403_is_not_logged_as_an_edge_block() -> None:
    (failure,) = logs_from(
        403, {"error": {"code": "AuthorizationFailed", "message": "does not have access"}}
    )
    assert failure["edge_blocked"] is False


async def test_an_edge_block_is_not_blamed_on_the_role() -> None:
    """The failure that prompted this: every ARM call from Railway was refused by
    Front Door, and each one told the customer to go and check IAM -- where the
    role they had just deployed was sitting, correctly assigned."""
    for client_cls in (ArmClient, GraphClient):
        error = await error_from(client_cls, 403, text=FRONT_DOOR_BLOCK)
        message = str(error)

        assert "network edge" in message
        assert "not a permission problem" in message
        assert "Access control (IAM)" not in message
        assert "Enterprise applications" not in message
        assert "The request is blocked." in message
        assert error.azure_status_code == 403


def test_a_long_body_cannot_fill_the_log() -> None:
    """A poll runs every five seconds for as long as a setup is unfinished."""
    (failure,) = logs_from(500, text="<p>" + ("x" * 5000) + "</p>")

    assert len(failure["detail"]) <= client_module.DETAIL_LIMIT


def test_a_throttled_call_is_logged_too() -> None:
    """429 raises its own message and used to leave no trace of which call was
    throttled."""
    (failure,) = logs_from(429, text="slow down")

    assert failure["status"] == 429


# ------------------------------------------------- a provider switched off
async def test_an_unregistered_provider_hands_over_the_command() -> None:
    """Seen on a real subscription: Defender's plans answer 404 "Subscription
    Not Registered" until ``Microsoft.Security`` is registered, which read as a
    permission problem and is not one."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            404,
            json={"error": {"code": "SubscriptionNotRegistered",
                            "message": "Subscription Not Registered"}},
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    async with ArmClient(FakeTokens(), client) as api:
        with pytest.raises(AzureApiError) as raised:
            await api.get(
                "/subscriptions/s/providers/Microsoft.Security/pricings"
                "?api-version=2024-01-01"
            )

    message = str(raised.value)
    assert "az provider register -n Microsoft.Security" in message
    assert raised.value.azure_status_code == 404


async def test_the_namespace_azure_names_wins_over_the_url() -> None:
    message = str(
        await error_from(
            ArmClient,
            409,
            {"error": {"code": "MissingSubscriptionRegistration",
                       "message": "The subscription is not registered to use "
                                  "namespace 'Microsoft.Insights'."}},
        )
    )
    assert "az provider register -n Microsoft.Insights" in message


async def test_an_ordinary_404_gets_no_registration_advice() -> None:
    message = str(
        await error_from(ArmClient, 404, {"error": {"code": "ResourceNotFound"}})
    )
    assert "provider register" not in message
