"""A credential carried in a URL is not written down by the log or the error tracker.

Two routes take ``?token=`` because the caller cannot send a header, and a query string is
recorded by everything that sees the request. These hold the three places this API controls:
the redaction itself, the access log, and what Sentry is allowed to send (DECISIONS.md §195).
A webhook keeps its credential in the path instead, so an outbound URL is written down as its
host alone, and the HTTP client's own log line is not written at all (§198).
"""

import json
import logging
from typing import Any

import httpx
import pytest
import sentry_sdk

from app.core.logging import configure_logging
from app.core.redaction import (
    REDACTED,
    AccessLogRedactor,
    origin_only,
    redact_query_string,
    redact_url,
)
from app.core.sentry import init_sentry, scrub_breadcrumb, scrub_event

SECRET = "eyJhbGciOi.SECRET-VALUE"
WEBHOOK = f"https://hooks.slack.com/services/T0/B0/{SECRET}"


@pytest.mark.parametrize(
    ("query", "expected"),
    [
        ("", ""),
        ("limit=5&offset=10", "limit=5&offset=10"),
        (f"token={SECRET}", f"token={REDACTED}"),
        (f"TOKEN={SECRET}", f"TOKEN={REDACTED}"),
        (f"%74oken={SECRET}", f"%74oken={REDACTED}"),
        (f"state={SECRET}&code=abc&limit=5", f"state={REDACTED}&code={REDACTED}&limit=5"),
        ("token", "token"),
        ("token=", f"token={REDACTED}"),
        ("session_state=keep&tokens=keep", "session_state=keep&tokens=keep"),
        ("a=1&&b=2", "a=1&&b=2"),
    ],
)
def test_a_credential_value_is_replaced_and_everything_else_is_left_as_written(
    query: str, expected: str
) -> None:
    assert redact_query_string(query) == expected


def test_a_url_keeps_its_path_and_fragment() -> None:
    url = f"/api/v1/events/azure/2f6c?token={SECRET}&x=1#top"
    assert redact_url(url) == f"/api/v1/events/azure/2f6c?token={REDACTED}&x=1#top"
    assert redact_url("/api/v1/findings") == "/api/v1/findings"
    assert redact_url(f"https://api.example.com/t?token={SECRET}") == (
        f"https://api.example.com/t?token={REDACTED}"
    )


def test_the_access_log_never_writes_the_token(caplog: pytest.LogCaptureFixture) -> None:
    """Uvicorn's own format, which puts the request target in the record's arguments."""
    log = logging.getLogger("test.access")
    log.addFilter(AccessLogRedactor())
    try:
        with caplog.at_level(logging.INFO, logger="test.access"):
            log.info(
                '%s - "%s %s HTTP/%s" %d',
                "10.0.0.7:5000",
                "POST",
                f"/api/v1/events/azure/2f6c?token={SECRET}",
                "1.1",
                200,
            )
    finally:
        log.filters.clear()

    assert SECRET not in caplog.text
    assert f'POST /api/v1/events/azure/2f6c?token={REDACTED} HTTP/1.1" 200' in caplog.text


def test_configure_logging_attaches_the_redactor_once() -> None:
    access = logging.getLogger("uvicorn.access")
    before = list(access.filters)
    try:
        configure_logging()
        configure_logging()
        assert sum(isinstance(f, AccessLogRedactor) for f in access.filters) == 1
    finally:
        access.filters[:] = before


def test_a_sentry_event_loses_the_credential_in_its_request() -> None:
    event: dict[str, Any] = {
        "request": {
            "url": f"https://api.example.com/api/v1/events/azure/2f6c?token={SECRET}",
            "query_string": f"token={SECRET}&limit=5",
        },
        "breadcrumbs": {
            "values": [
                {"message": f"HTTP Request: GET https://x.example/a?token={SECRET}", "data": {}}
            ]
        },
    }

    scrubbed = scrub_event(event, {})

    assert SECRET not in json.dumps(scrubbed)
    assert scrubbed["request"]["query_string"] == f"token={REDACTED}&limit=5"


def test_a_sentry_query_held_as_pairs_or_a_mapping_is_scrubbed_too() -> None:
    pairs = scrub_event({"request": {"query_string": [["token", SECRET], ["limit", "5"]]}}, {})
    mapping = scrub_event({"request": {"query_string": {"state": SECRET, "limit": "5"}}}, {})

    assert pairs["request"]["query_string"] == [["token", REDACTED], ["limit", "5"]]
    assert mapping["request"]["query_string"] == {"state": REDACTED, "limit": "5"}


def test_a_breadcrumb_url_is_redacted_in_its_data_and_its_message() -> None:
    crumb = {
        "message": f"GET /t?token={SECRET}",
        "data": {"url": f"https://x.example/t?token={SECRET}", "http.query": f"code={SECRET}"},
    }

    assert SECRET not in json.dumps(scrub_breadcrumb(crumb))


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        (WEBHOOK, f"https://hooks.slack.com/{REDACTED}"),
        (f"https://203.0.113.9/services/T0/B0/{SECRET}", f"https://203.0.113.9/{REDACTED}"),
        (f"https://[2001:db8::1]:8443/x?token={SECRET}", f"https://[2001:db8::1]:8443/{REDACTED}"),
        (f"https://user:{SECRET}@x.example/", "https://x.example"),
        ("https://management.azure.com", "https://management.azure.com"),
        (f"/t?token={SECRET}", f"/t?token={REDACTED}"),
    ],
)
def test_an_outbound_url_keeps_only_where_it_went(url: str, expected: str) -> None:
    assert origin_only(url) == expected


def test_a_webhook_breadcrumb_loses_the_path_that_is_its_credential() -> None:
    crumb = {"type": "http", "category": "httplib", "data": {"url": WEBHOOK, "method": "POST"}}

    scrubbed = scrub_breadcrumb(crumb)

    assert SECRET not in json.dumps(scrubbed)
    assert scrubbed["data"]["url"] == f"https://hooks.slack.com/{REDACTED}"


def test_configure_logging_keeps_the_http_clients_request_lines_out() -> None:
    configure_logging()

    assert not logging.getLogger("httpx").isEnabledFor(logging.INFO)
    assert not logging.getLogger("httpcore").isEnabledFor(logging.INFO)


@pytest.fixture
def captured() -> Any:
    """Sentry started against a transport that keeps the event instead of sending it."""
    events: list[dict[str, Any]] = []
    init_sentry("https://public@example.invalid/1", "test", transport=events.append)
    try:
        yield events
    finally:
        sentry_sdk.init()


def test_sentry_sends_the_traceback_but_not_the_local_variables(captured: list[Any]) -> None:
    def deliver() -> None:
        webhook_url = f"https://hooks.slack.com/services/T0/B0/{SECRET}"
        raise RuntimeError(f"could not reach {len(webhook_url)} characters of url")

    try:
        deliver()
    except RuntimeError:
        sentry_sdk.capture_exception()

    assert captured, "no event was captured"
    frames = captured[0]["exception"]["values"][0]["stacktrace"]["frames"]
    assert any(frame["function"] == "deliver" for frame in frames)
    assert all("vars" not in frame for frame in frames)
    assert SECRET not in json.dumps(captured[0])


def test_a_webhook_call_before_an_error_does_not_reach_sentry(captured: list[Any]) -> None:
    """The real client, through Sentry's own HTTP integration, then an unrelated error."""
    configure_logging()
    transport = httpx.MockTransport(lambda request: httpx.Response(200))
    with httpx.Client(transport=transport) as client:
        client.post(WEBHOOK, json={"text": "scan finished"})
    sentry_sdk.capture_message("something else went wrong")

    assert captured, "no event was captured"
    assert SECRET not in json.dumps(captured[0])
