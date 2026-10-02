"""Error tracking that sends what an engineer needs and not what a customer owns.

Sentry's defaults capture the request body and the local variables of every frame in a traceback.
In this API those are webhook URLs (a Slack or Teams URL is itself the credential), signing
secrets, consent tokens and tenant identifiers, and Sentry's own key-name scrubbing cannot know
that a variable called ``url`` is one. So none of the three is sent: no body, no locals, no
personal data, and a query string loses the value of any key that carries a credential
(``app/core/redaction.py``). A traceback and a route are still enough to find a bug; the request
id on the event finds the log lines (DECISIONS.md §195).
"""

from typing import Any

import sentry_sdk

from app.core.redaction import (
    REDACTED,
    SENSITIVE_QUERY_KEYS,
    origin_only,
    redact_query_string,
    redact_url,
)


def _scrub_pairs(pairs: list[Any]) -> list[Any]:
    """A query string held as ``[[key, value], ...]``, with credential values replaced."""
    scrubbed = []
    for pair in pairs:
        if (
            isinstance(pair, list | tuple)
            and len(pair) == 2
            and str(pair[0]).lower() in SENSITIVE_QUERY_KEYS
        ):
            pair = [pair[0], REDACTED]
        scrubbed.append(pair)
    return scrubbed


def scrub_breadcrumb(crumb: dict[str, Any], hint: dict[str, Any] | None = None) -> dict[str, Any]:
    """Redact the URL a breadcrumb carries, in its data and in its message.

    The HTTP client integration records every outbound call as a breadcrumb, so an outbound URL
    with a credential in it is recorded whether or not an error follows. Its URL keeps only the
    scheme and host, because a webhook's credential is its path (DECISIONS.md §198); a message
    that holds a query loses the credential values in it.
    """
    data = crumb.get("data")
    if isinstance(data, dict):
        if isinstance(data.get("url"), str):
            data["url"] = origin_only(data["url"])
        if isinstance(data.get("http.query"), str):
            data["http.query"] = redact_query_string(data["http.query"])
    message = crumb.get("message")
    if isinstance(message, str) and "?" in message:
        crumb["message"] = redact_url(message)
    return crumb


def scrub_event(event: dict[str, Any], hint: dict[str, Any]) -> dict[str, Any]:
    """Redact the request's URL and query string, and every breadcrumb, before an event leaves."""
    request = event.get("request")
    if isinstance(request, dict):
        if isinstance(request.get("url"), str):
            request["url"] = redact_url(request["url"])
        query = request.get("query_string")
        if isinstance(query, str):
            request["query_string"] = redact_query_string(query)
        elif isinstance(query, list):
            request["query_string"] = _scrub_pairs(query)
        elif isinstance(query, dict):
            request["query_string"] = {
                key: REDACTED if str(key).lower() in SENSITIVE_QUERY_KEYS else value
                for key, value in query.items()
            }
    breadcrumbs = event.get("breadcrumbs")
    values = breadcrumbs.get("values") if isinstance(breadcrumbs, dict) else breadcrumbs
    if isinstance(values, list):
        for crumb in values:
            if isinstance(crumb, dict):
                scrub_breadcrumb(crumb)
    return event


def init_sentry(dsn: str, environment: str, *, transport: Any = None) -> None:
    """Start error tracking with nothing but the traceback and the route.

    ``transport`` is for tests, which capture the event instead of sending it.
    """
    sentry_sdk.init(
        dsn=dsn,
        environment=environment,
        send_default_pii=False,
        include_local_variables=False,
        max_request_body_size="never",
        before_send=scrub_event,  # type: ignore[arg-type]
        before_breadcrumb=scrub_breadcrumb,  # type: ignore[arg-type]
        transport=transport,
    )
