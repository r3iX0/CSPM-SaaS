"""What every request passes through before a route sees it.

Three concerns, deliberately separate and deliberately written as raw ASGI
rather than as ``BaseHTTPMiddleware`` subclasses. Two of them have to act on a
request *before* its body has been read -- one refuses oversized bodies by
watching them arrive, the other refuses the request outright -- and
``BaseHTTPMiddleware`` buffers the body to hand it on, which is the thing being
guarded against.

Order matters and is set in ``main.py``, which documents it. The short version:
the two that reject requests sit *inside* CORS so a browser can read the
rejection, and the one that stamps headers sits outside everything so it stamps
every response, including CORS preflights and errors raised further in.
"""

import json
import time

from redis.asyncio import Redis
from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import settings
from app.core.errors import PayloadTooLarge, error_envelope
from app.core.logging import get_logger

log = get_logger(__name__)

# Sent on every response. Conservative, and chosen for an API that serves JSON
# plus one HTML document: the report at ``/reports/{kind}?format=html``, which
# is rendered from resource names, tag values and provider error text collected
# out of a customer's cloud. Jinja escapes all of it, and these are what stands
# behind that if it ever does not.
#
# ``default-src 'none'`` because nothing served here loads anything: the report
# carries its own stylesheet inline, which is also why ``style-src`` allows
# exactly that and no origin. The frontend is a separate deployment with its own
# policy (``apps/web/vercel.json``) -- this one would be far too strict for it,
# and applying an API's policy to an application is how a CSP ends up with
# ``unsafe-inline`` in it.
SECURITY_HEADERS: dict[str, str] = {
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
        "form-action 'none'; frame-ancestors 'none'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    # Names the interfaces this API would never have cause to use, so a
    # document it serves cannot ask for them either.
    "Permissions-Policy": "geolocation=(), microphone=(), camera=(), payment=()",
}

# Two years, with subdomains, and preload-eligible. Sent only over HTTPS: a
# browser ignores it on a plain connection, and sending it anyway would only
# mislead whoever is reading the response.
HSTS_HEADER = "max-age=63072000; includeSubDomains; preload"


class SecurityHeadersMiddleware:
    """Stamp the security headers on everything this API returns."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        secure = scope.get("scheme") == "https"

        async def stamped(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for name, value in SECURITY_HEADERS.items():
                    # Set rather than appended, and only when absent: a route
                    # that has deliberately chosen its own policy keeps it.
                    if name not in headers:
                        headers[name] = value
                if secure and "Strict-Transport-Security" not in headers:
                    headers["Strict-Transport-Security"] = HSTS_HEADER
            await send(message)

        await self.app(scope, receive, stamped)


class RequestSizeLimitMiddleware:
    """Refuse a request body larger than the API has any reason to accept.

    Both halves are needed. ``Content-Length`` is checked first because it lets
    an oversized request be refused before a byte of it is read -- but it is a
    claim, not a measurement, and a chunked request carries none at all. So the
    bytes are also counted as they arrive, and the stream is cut the moment the
    limit is passed.

    The endpoint this exists for is the change-event webhook: unauthenticated by
    necessity, reachable by anyone holding a connection's token, and its handler
    calls ``request.json()`` on whatever was posted.
    """

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = Headers(scope=scope).get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.max_bytes:
            await _refuse(send, 413, "PAYLOAD_TOO_LARGE", self._message())
            return

        received = 0

        async def counted() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    # Raised from inside ``receive``, so it surfaces wherever
                    # the handler was reading the body. Nothing further of the
                    # request is read.
                    #
                    # A domain error rather than a private sentinel, and that is
                    # not decoration. FastAPI wraps body parsing in
                    # ``except Exception`` and answers 400 "There was an error
                    # parsing the body" -- so a sentinel would be swallowed and
                    # the limit would report the wrong thing. ``HTTPException``
                    # is the one kind it re-raises, and ``AppError`` is one, so
                    # this reaches the app's own handler and renders in the
                    # usual envelope.
                    raise PayloadTooLarge(self._message())
            return message

        try:
            await self.app(scope, counted, send)
        except PayloadTooLarge:
            # The safety net for a path that does not go through FastAPI's
            # handler -- a raw ASGI route, or a body read after the response has
            # begun. Ordinarily the error is rendered further in and this never
            # runs.
            await _refuse(send, 413, "PAYLOAD_TOO_LARGE", self._message())

    def _message(self) -> str:
        return f"Request body exceeds the {self.max_bytes} byte limit."


# The routes that answer without a token, and the reason this list is here.
#
# ``RateLimitMiddleware`` runs before authentication, so it cannot ask whether a
# request *is* authenticated -- only whether it carries a header claiming to be.
# These are the paths where that claim buys nothing, because the handler never
# looks at it: a request to one of them is counted as anonymous however it is
# dressed.
#
# Kept as literals rather than derived from the route table, because the
# middleware is constructed before the router is mounted. ``tests/unit/
# test_middleware.py`` cross-checks this list against the live application's
# routes, so a new route that skips authentication fails the build here rather
# than quietly inheriting the larger ceiling.
OPEN_PATHS = frozenset(
    {
        "/api/v1/cloud-connections/azure/consent/callback",
        "/api/v1/cloud-accounts/azure/permissions",
    }
)
OPEN_PREFIXES = ("/api/v1/events/",)
# ``/api/v1/cloud-connections/{id}/template``: parameterised, so it is matched
# by its shape rather than by a literal.
OPEN_SUFFIXES = (("/api/v1/cloud-connections/", "/template"),)


def _normalise(path: str) -> str:
    """One spelling per path, so a trailing slash is not a second one."""
    return path.rstrip("/") or "/"


def is_open_route(path: str) -> bool:
    """Whether this path is served without a token by design."""
    path = _normalise(path)
    if path in OPEN_PATHS or path.startswith(OPEN_PREFIXES):
        return True
    return any(
        path.startswith(prefix) and path.endswith(suffix)
        for prefix, suffix in OPEN_SUFFIXES
    )


class RateLimitMiddleware:
    """A fixed-window request limit, counted in Redis.

    **In Redis, not in the process.** The API runs as more than one instance,
    and a per-process counter would hand out its whole allowance per instance
    while reporting that it had enforced a limit -- the failure being a control
    that looks present in the code and is not present in production.

    Two ceilings. The smaller one covers the surface reachable without a token:
    the webhook, the ARM template, the consent callback and the permissions
    list, none of which is reached in bursts by anything legitimate. The larger
    one is for a signed-in customer using the product, whose dashboard alone
    issues a handful of calls per page.

    **Which ceiling applies is decided by the path, not by the header.** This
    middleware runs long before anything verifies a token, so the presence of
    an ``Authorization`` header proves only that the caller typed one -- and
    taking it as proof let anyone reach the routes that need the smaller
    ceiling under the larger one, simply by attaching a header those routes
    never read. The routes that are unauthenticated by design are therefore
    always counted as anonymous; everywhere else, a credentialed request is
    counted as authenticated because a route that rejects a bad token has
    already done the work of answering it.

    **Fails open.** A Redis outage that also took down the API would turn a
    capacity problem into an outage, and rate limiting is a control against
    abuse rather than a guarantee of correctness -- the tenancy guarantees do
    not run through here. The failure is logged rather than swallowed.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        authenticated_limit: int,
        anonymous_limit: int,
        window_seconds: int,
        exempt_paths: frozenset[str] = frozenset({"/health"}),
    ) -> None:
        self.app = app
        self.authenticated_limit = authenticated_limit
        self.anonymous_limit = anonymous_limit
        self.window_seconds = window_seconds
        self.exempt_paths = exempt_paths

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = _normalise(scope.get("path", ""))
        # The platform's own health probe, which runs on a schedule this would
        # otherwise throttle.
        #
        # Matched exactly rather than by prefix. ``/health/ready`` sits under
        # the same prefix and opens a database connection on every call, so a
        # prefix match exempted an unauthenticated caller from the one control
        # standing between them and the request path's connection pool. Railway
        # probes ``/health``, which is the one that answers without touching
        # anything (railway.json, docs/DEPLOYMENT.md section 2).
        if path in self.exempt_paths:
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        authenticated = bool(headers.get("authorization")) and not is_open_route(path)
        limit = self.authenticated_limit if authenticated else self.anonymous_limit
        bucket = "auth" if authenticated else "anon"
        window = int(time.time()) // self.window_seconds
        key = f"ratelimit:{bucket}:{client_address(scope)}:{window}"

        if await self._exceeded(key, limit):
            log.warning("ratelimit.refused", path=path, bucket=bucket)
            await _refuse(
                send,
                429,
                "RATE_LIMITED",
                "Too many requests. Wait a moment and try again.",
                extra_headers=[(b"retry-after", str(self.window_seconds).encode())],
            )
            return

        await self.app(scope, receive, send)

    async def _exceeded(self, key: str, limit: int) -> bool:
        try:
            client = _redis()
            pipeline = client.pipeline()
            pipeline.incr(key)
            # Set every time rather than only on creation. One round trip
            # instead of two, and the window is fixed-width from its first
            # request either way -- a key that already carries a TTL simply has
            # the same one reapplied.
            pipeline.expire(key, self.window_seconds)
            count, _ = await pipeline.execute()
        except Exception as exc:
            log.warning("ratelimit.unavailable", error=str(exc))
            return False
        return int(count) > limit


def client_address(scope: Scope) -> str:
    """The address to hold responsible for this request.

    Not simply the socket address: this API is always behind a platform proxy,
    so every request would otherwise come from one address and a limit counted
    per client would be a limit counted per deployment.

    Not simply the first entry of ``X-Forwarded-For`` either -- that is supplied
    by the caller, who would then choose which bucket to fill. Only the hops the
    deployment actually has are trusted, counted from the right, because those
    are the ones written by infrastructure rather than by whoever is calling.
    """
    socket = scope.get("client")
    direct = socket[0] if socket else "unknown"

    hops = settings.trusted_proxy_hops
    if hops <= 0:
        return direct

    forwarded = Headers(scope=scope).get("x-forwarded-for")
    if not forwarded:
        return direct
    chain = [part.strip() for part in forwarded.split(",") if part.strip()]
    if len(chain) < hops:
        # Fewer hops than configured: the header did not come from where it was
        # expected to. The socket address is the only thing left that nobody
        # else wrote.
        return direct
    return chain[-hops]


_client: Redis | None = None


def _redis() -> Redis:
    """One connection pool for the process, built on first use.

    Built lazily for the same reason the database engines are: importing a
    module should not open a connection pool, or the package becomes
    unimportable wherever Redis is not reachable -- including test collection.
    """
    global _client
    if _client is None:
        _client = Redis.from_url(settings.redis_url, decode_responses=True)
    return _client


async def _refuse(
    send: Send,
    status: int,
    code: str,
    message: str,
    *,
    extra_headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    """Answer in the API's own envelope, so a refusal parses like anything else."""
    body = json.dumps(error_envelope(code, message)).encode()
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
        *(extra_headers or []),
    ]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": body})


__all__ = [
    "OPEN_PATHS",
    "OPEN_PREFIXES",
    "OPEN_SUFFIXES",
    "RateLimitMiddleware",
    "RequestSizeLimitMiddleware",
    "SecurityHeadersMiddleware",
    "client_address",
    "is_open_route",
]
