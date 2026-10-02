"""Keeping a credential that travels in a URL out of the places URLs get written.

Two routes take a credential in the query string because the caller cannot send a header: the
cloud event receivers (``?token=``, valid for a year) and the signed template and consent links
(``?token=``, ``?state=``). A query string is written down by everything between the browser and
the code -- the server's access log, a platform's edge log, an error tracker's request record --
so a token that is fine in transit is a stored credential by the end of the day. This is the one
place that knows which keys carry one, and the log filter and the error tracker both ask it
(API_GUIDELINES.md section 10, DECISIONS.md §195).
"""

import logging
from urllib.parse import unquote_plus, urlsplit

REDACTED = "[redacted]"

#: Query keys that carry a credential or a single-use value, compared lower-case after decoding.
SENSITIVE_QUERY_KEYS = frozenset(
    {
        "token",
        "state",
        "code",
        "id_token",
        "access_token",
        "refresh_token",
        "client_secret",
        "secret",
        "password",
        "signature",
        "api_key",
        "apikey",
        "key",
    }
)


def redact_query_string(query: str) -> str:
    """The query with the value of every sensitive key replaced, and the rest left as written.

    Split on ``&`` and ``=`` by hand rather than parsed and rebuilt, so an unrelated parameter
    keeps its exact bytes and an odd one (a key with no value, a doubled ``&``) is not
    normalised into something a person reading the log would not recognise.
    """
    if not query:
        return query
    parts = []
    for part in query.split("&"):
        key, equals, _ = part.partition("=")
        if equals and unquote_plus(key).strip().lower() in SENSITIVE_QUERY_KEYS:
            part = f"{key}={REDACTED}"
        parts.append(part)
    return "&".join(parts)


def redact_url(url: str) -> str:
    """A URL or a path with its query redacted. A fragment is kept; no scheme is needed."""
    path, question, rest = url.partition("?")
    if not question:
        return url
    query, hash_sign, fragment = rest.partition("#")
    return f"{path}?{redact_query_string(query)}{hash_sign}{fragment}"


def origin_only(url: str) -> str:
    """The scheme and host of an absolute URL, with anything after them replaced.

    For an outbound call the path can be the credential: a Slack or Teams webhook URL is a
    secret from end to end, and the call is pinned to an address, so nothing in the host says
    which kind of receiver it was. The host is enough to see where a request went. A value that
    is not an absolute URL falls back to query redaction.
    """
    parts = urlsplit(url)
    if not parts.scheme or not parts.hostname:
        return redact_url(url)
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    port = f":{parts.port}" if parts.port else ""
    rest = parts.path not in ("", "/") or parts.query or parts.fragment
    return f"{parts.scheme}://{host}{port}" + (f"/{REDACTED}" if rest else "")


class AccessLogRedactor(logging.Filter):
    """Redact the query string of every URL in an access-log record.

    Uvicorn writes ``client - "METHOD /path?query HTTP/1.1" status`` with the request target as
    one of the record's arguments, so the filter rewrites any string argument that holds a query
    before the message is formatted. It never drops a record.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(
                redact_url(arg) if isinstance(arg, str) and "?" in arg else arg
                for arg in record.args
            )
        return True
