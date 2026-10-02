"""The three things every request passes through.

Exercised through a real ASGI app rather than by calling the middlewares
directly, because two of the three are about what happens to a request *before*
a handler sees it -- a body that is still arriving, a counter that decides
whether the handler runs at all -- and calling them directly would test the
arrangement this file exists to check.
"""

import re
import time
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, Response

from app.core import middleware as mw
from app.core.middleware import (
    SECURITY_HEADERS,
    RateLimitMiddleware,
    RequestContextMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
    client_address,
)
from app.core.request_context import (
    RateLimitReading,
    bound,
    note_rate_limit,
    tightest_rate_limit,
)


def app_with(*middlewares: tuple[type, dict[str, Any]]) -> FastAPI:
    app = FastAPI()

    @app.get("/thing")
    async def thing() -> dict:
        return {"ok": True}

    @app.post("/thing")
    async def post_thing(payload: dict) -> dict:
        return {"size": len(payload)}

    @app.get("/health")
    async def health() -> dict:
        return {"ok": True}

    @app.get("/health/ready")
    async def ready() -> dict:
        return {"ok": True}

    @app.post("/api/v1/events/{provider}/{connection_id}")
    async def webhook(provider: str, connection_id: str) -> dict:
        return {"ok": True, "provider": provider, "connection": connection_id}

    @app.get("/api/v1/cloud-connections/{connection_id}/template")
    async def template(connection_id: str) -> dict:
        return {"ok": True, "connection": connection_id}

    for cls, kwargs in middlewares:
        app.add_middleware(cls, **kwargs)
    return app


def client_for(app: FastAPI, *, base: str = "https://api.example.com") -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=base)


# --------------------------------------------------------------------- headers


async def test_every_response_carries_the_security_headers() -> None:
    app = app_with((SecurityHeadersMiddleware, {}))

    async with client_for(app) as client:
        response = await client.get("/thing")

    for name, value in SECURITY_HEADERS.items():
        assert response.headers[name] == value


async def test_hsts_is_sent_only_over_https() -> None:
    """A browser ignores it on a plain connection.

    Sending it anyway would put a claim in the response that the transport it
    arrived over cannot support, which misleads whoever reads it.
    """
    app = app_with((SecurityHeadersMiddleware, {}))

    async with client_for(app) as secure:
        assert "Strict-Transport-Security" in (await secure.get("/thing")).headers

    async with client_for(app, base="http://api.example.com") as plain:
        assert "Strict-Transport-Security" not in (await plain.get("/thing")).headers


async def test_hsts_is_sent_behind_a_proxy_that_ended_tls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Railway forwards plain HTTP, so the scheme alone never says https.

    The proxy's own ``X-Forwarded-Proto`` does -- the last entry, the one it
    wrote, and only while a proxy is configured.
    """
    app = app_with((SecurityHeadersMiddleware, {}))
    monkeypatch.setattr(mw.settings, "trusted_proxy_hops", 1)

    async with client_for(app, base="http://api.example.com") as proxied:
        response = await proxied.get("/thing", headers={"X-Forwarded-Proto": "https"})
        assert "Strict-Transport-Security" in response.headers

        forged_left = await proxied.get("/thing", headers={"X-Forwarded-Proto": "https, http"})
        assert "Strict-Transport-Security" not in forged_left.headers

    monkeypatch.setattr(mw.settings, "trusted_proxy_hops", 0)
    async with client_for(app, base="http://api.example.com") as direct:
        response = await direct.get("/thing", headers={"X-Forwarded-Proto": "https"})
        assert "Strict-Transport-Security" not in response.headers


async def test_an_error_response_is_stamped_too() -> None:
    """The headers matter most on the responses nobody wrote by hand."""
    app = app_with((SecurityHeadersMiddleware, {}))

    async with client_for(app) as client:
        response = await client.get("/no-such-route")

    assert response.status_code == 404
    assert response.headers["X-Content-Type-Options"] == "nosniff"


async def test_tenant_data_is_not_cached_and_a_route_may_choose_its_own_policy() -> None:
    """Under ``/api/`` is one organization's data: ``private, no-store`` unless a route says so."""
    app = app_with((SecurityHeadersMiddleware, {}))

    @app.get("/api/v1/own-policy")
    async def own_policy(response: Response) -> dict:
        response.headers["Cache-Control"] = "no-cache"
        return {"ok": True}

    async with client_for(app) as client:
        api = await client.get("/api/v1/cloud-connections/abc/template")
        own = await client.get("/api/v1/own-policy")
        outside = await client.get("/thing")

    assert api.headers["Cache-Control"] == "private, no-store"
    assert own.headers["Cache-Control"] == "no-cache"
    assert "Cache-Control" not in outside.headers


# ------------------------------------------------------------------ body limit


async def test_a_declared_oversized_body_is_refused() -> None:
    app = app_with((RequestSizeLimitMiddleware, {"max_bytes": 64}))

    async with client_for(app) as client:
        response = await client.post("/thing", content=b"x" * 256)

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "PAYLOAD_TOO_LARGE"


async def test_an_undeclared_oversized_body_is_refused_as_it_arrives() -> None:
    """A chunked request carries no ``Content-Length`` to check.

    This is the half that cannot be skipped: the declared length is a claim, and
    a sender who omits it would otherwise be unbounded.
    """

    async def chunks() -> Any:
        for _ in range(8):
            yield b"x" * 32

    app = app_with((RequestSizeLimitMiddleware, {"max_bytes": 64}))

    async with client_for(app) as client:
        response = await client.post("/thing", content=chunks())

    assert response.status_code == 413


async def test_a_body_within_the_limit_is_untouched() -> None:
    app = app_with((RequestSizeLimitMiddleware, {"max_bytes": 1024}))

    async with client_for(app) as client:
        response = await client.post("/thing", json={"a": 1, "b": 2})

    assert response.status_code == 200
    assert response.json()["size"] == 2


# ------------------------------------------------------------------ rate limit


class _Counter:
    """A Redis stand-in that counts, and one that refuses to.

    The refusing one is not a detail: failing open is a deliberate choice, and a
    choice nothing tests is a choice that survives until the outage.
    """

    def __init__(self, *, broken: bool = False) -> None:
        self.counts: dict[str, int] = {}
        self.broken = broken
        self.queued: list[str] = []

    def pipeline(self) -> "_Counter":
        return self

    def incr(self, key: str) -> None:
        self.queued.append(key)

    def expire(self, _key: str, _seconds: int) -> None:
        return None

    async def execute(self) -> list[int]:
        if self.broken:
            raise ConnectionError("redis is gone")
        key = self.queued.pop()
        self.counts[key] = self.counts.get(key, 0) + 1
        return [self.counts[key], True]


@pytest.fixture
def counter(monkeypatch: pytest.MonkeyPatch) -> _Counter:
    fake = _Counter()
    monkeypatch.setattr(mw, "_redis", lambda: fake)
    return fake


LIMITS = {"authenticated_limit": 3, "anonymous_limit": 1, "window_seconds": 60}


async def test_an_anonymous_caller_gets_the_smaller_ceiling(counter: _Counter) -> None:
    app = app_with((RateLimitMiddleware, LIMITS))

    async with client_for(app) as client:
        assert (await client.get("/thing")).status_code == 200
        refused = await client.get("/thing")

    assert refused.status_code == 429
    assert refused.headers["retry-after"] == "60"
    assert refused.json()["error"]["code"] == "RATE_LIMITED"


async def test_a_signed_in_caller_gets_the_larger_one(counter: _Counter) -> None:
    app = app_with((RateLimitMiddleware, LIMITS))
    headers = {"authorization": "Bearer token"}

    async with client_for(app) as client:
        for _ in range(3):
            assert (await client.get("/thing", headers=headers)).status_code == 200
        assert (await client.get("/thing", headers=headers)).status_code == 429


async def test_the_health_probe_is_never_throttled(counter: _Counter) -> None:
    """The platform calls it on a schedule this would otherwise refuse."""
    app = app_with((RateLimitMiddleware, LIMITS))

    async with client_for(app) as client:
        for _ in range(5):
            assert (await client.get("/health")).status_code == 200


async def test_readiness_is_not_exempt(counter: _Counter) -> None:
    """``/health/ready`` opens a database connection; the probe path does not.

    Exempting the whole prefix handed an unauthenticated caller an unlimited
    supply of connection checkouts from the pool the request path shares.
    """
    app = app_with((RateLimitMiddleware, LIMITS))

    async with client_for(app) as client:
        assert (await client.get("/health/ready")).status_code == 200
        assert (await client.get("/health/ready")).status_code == 429


async def test_a_trailing_slash_is_not_a_second_path(counter: _Counter) -> None:
    """``/health/`` is the exempt path, not a limited one wearing a slash."""
    app = app_with((RateLimitMiddleware, LIMITS))

    async with client_for(app) as client:
        for _ in range(5):
            assert (await client.get("/health/")).status_code != 429


async def test_every_counted_response_says_what_is_left(counter: _Counter) -> None:
    """A client can slow down before it is refused, if the response tells it how much is left."""
    app = app_with((RateLimitMiddleware, LIMITS), (RequestContextMiddleware, {}))
    headers = {"authorization": "Bearer token"}

    async with client_for(app) as client:
        seen = [await client.get("/thing", headers=headers) for _ in range(3)]

    assert [r.headers["X-RateLimit-Remaining"] for r in seen] == ["2", "1", "0"]
    assert {r.headers["X-RateLimit-Limit"] for r in seen} == {"3"}
    assert int(seen[0].headers["X-RateLimit-Reset"]) > time.time() - 1


async def test_a_refusal_carries_the_allowance_too(counter: _Counter) -> None:
    app = app_with((RateLimitMiddleware, LIMITS), (RequestContextMiddleware, {}))

    async with client_for(app) as client:
        await client.get("/thing")
        refused = await client.get("/thing")

    assert refused.status_code == 429
    assert refused.headers["X-RateLimit-Limit"] == "1"
    assert refused.headers["X-RateLimit-Remaining"] == "0"
    assert refused.headers["Retry-After"] == "60"


async def test_the_health_probe_reports_no_allowance(counter: _Counter) -> None:
    app = app_with((RateLimitMiddleware, LIMITS), (RequestContextMiddleware, {}))

    async with client_for(app) as client:
        response = await client.get("/health")

    assert "X-RateLimit-Limit" not in response.headers


def test_the_tightest_reading_is_the_one_reported() -> None:
    """Address, person and costly counters all speak; the one nearest refusing is the answer."""
    with bound("request", None):
        note_rate_limit(RateLimitReading(limit=1200, remaining=1100, reset=10))
        note_rate_limit(RateLimitReading(limit=300, remaining=5, reset=10))
        note_rate_limit(RateLimitReading(limit=20, remaining=15, reset=10))
        reading = tightest_rate_limit()

    assert reading is not None
    assert (reading.limit, reading.remaining) == (300, 5)
    assert tightest_rate_limit() is None, "a reading outlived its request"


# ------------------------------------------------------------- which ceiling


async def test_an_open_route_is_counted_as_anonymous_however_it_is_dressed(
    counter: _Counter,
) -> None:
    """A header the handler never reads must not buy the larger ceiling.

    This middleware runs before anything verifies a token, so ``Authorization``
    here is a claim and nothing more. On the routes that are served without one
    by design, the claim is worth nothing and is not allowed to change the
    count.
    """
    app = app_with((RateLimitMiddleware, LIMITS))
    headers = {"authorization": "Bearer anything-at-all"}

    async with client_for(app) as client:
        first = await client.post(
            "/api/v1/events/azure/11111111-1111-1111-1111-111111111111",
            json={},
            headers=headers,
        )
        second = await client.post(
            "/api/v1/events/azure/11111111-1111-1111-1111-111111111111",
            json={},
            headers=headers,
        )

    assert first.status_code == 200
    assert second.status_code == 429


async def test_the_parameterised_template_route_is_open_too(counter: _Counter) -> None:
    app = app_with((RateLimitMiddleware, LIMITS))
    headers = {"authorization": "Bearer anything-at-all"}
    path = "/api/v1/cloud-connections/2f6c/template"

    async with client_for(app) as client:
        assert (await client.get(path, headers=headers)).status_code == 200
        assert (await client.get(path, headers=headers)).status_code == 429


def test_open_routes_are_recognised_and_ordinary_ones_are_not() -> None:
    assert mw.is_open_route("/api/v1/cloud-connections/azure/consent/callback")
    assert mw.is_open_route("/api/v1/cloud-accounts/azure/permissions")
    assert mw.is_open_route("/api/v1/events/aws/2f6c")
    assert mw.is_open_route("/api/v1/cloud-connections/2f6c/template/")

    assert not mw.is_open_route("/api/v1/cloud-connections")
    assert not mw.is_open_route("/api/v1/cloud-connections/2f6c")
    assert not mw.is_open_route("/api/v1/findings")
    # A path that merely ends the right way, under another prefix.
    assert not mw.is_open_route("/api/v1/scans/2f6c/template")


def test_the_open_list_matches_the_application_routes() -> None:
    """The list in the middleware against the routes the app actually serves.

    The middleware is built before the router is mounted, so its list is
    literal -- and a literal list is one a new route can fall out of. This is
    what notices: every route that resolves without an authentication
    dependency has to be either a health path or one the middleware already
    counts as open, and nothing else may claim to be open.
    """
    from app.main import app as application

    def dependency_names(dependant: Any, seen: set[str]) -> set[str]:
        if dependant.call is not None:
            seen.add(getattr(dependant.call, "__name__", ""))
        for sub in dependant.dependencies:
            dependency_names(sub, seen)
        return seen

    authenticating = {"get_current_user", "get_tenant", "get_session"}
    unauthenticated: set[str] = set()
    for route in application.routes:
        dependant = getattr(route, "dependant", None)
        if dependant is None:
            continue
        if not dependency_names(dependant, set()) & authenticating:
            unauthenticated.add(route.path)

    # Path parameters are spelled ``{name}`` in the route table and are real
    # values in a request, so the matcher is asked about a filled-in path.
    def as_request_path(path: str) -> str:
        return re.sub(r"\{[^}]+\}", "2f6c", path)

    for path in unauthenticated:
        assert path.startswith("/health") or mw.is_open_route(as_request_path(path)), (
            f"{path} is served without authentication but is not in the "
            "middleware's open list, so it would be counted under the "
            "authenticated ceiling by anyone sending a header"
        )

    for path in mw.OPEN_PATHS:
        assert path in unauthenticated, (
            f"{path} is listed as open but the application authenticates it"
        )


async def test_the_limit_fails_open(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mw, "_redis", lambda: _Counter(broken=True))
    app = app_with((RateLimitMiddleware, LIMITS))

    async with client_for(app) as client:
        for _ in range(5):
            assert (await client.get("/thing")).status_code == 200


# ---------------------------------------------------------------- client address


def scope_with(forwarded: str | None, client: tuple[str, int] | None = ("10.0.0.1", 1)) -> dict:
    headers = [(b"x-forwarded-for", forwarded.encode())] if forwarded else []
    return {"type": "http", "headers": headers, "client": client}


def test_the_caller_cannot_choose_its_own_bucket(monkeypatch: pytest.MonkeyPatch) -> None:
    """``X-Forwarded-For`` is written by the caller before it is written to.

    With one proxy in front, only the last entry was added by infrastructure.
    Everything to the left of it is whatever the caller sent, so a limit counted
    on the leftmost entry is a limit anyone can step around.
    """
    monkeypatch.setattr(mw.settings, "trusted_proxy_hops", 1)

    spoofed = scope_with("1.2.3.4, 9.9.9.9, 203.0.113.7")

    assert client_address(spoofed) == "203.0.113.7"


def test_a_short_chain_falls_back_to_the_socket(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fewer hops than configured means the header came from somewhere else."""
    monkeypatch.setattr(mw.settings, "trusted_proxy_hops", 2)

    assert client_address(scope_with("1.2.3.4")) == "10.0.0.1"


def test_no_proxy_configured_means_the_header_is_ignored(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(mw.settings, "trusted_proxy_hops", 0)

    assert client_address(scope_with("1.2.3.4")) == "10.0.0.1"


async def test_every_response_names_its_request() -> None:
    """An id minted per request, returned in a header, readable inside it."""
    from app.core.request_context import current_request_id

    app = FastAPI()
    seen: list[str | None] = []

    @app.get("/thing")
    async def thing() -> dict:
        seen.append(current_request_id())
        return {"ok": True}

    app.add_middleware(mw.RequestContextMiddleware)
    async with client_for(app) as client:
        first = await client.get("/thing", headers={"X-Request-ID": "chosen-by-caller"})
        second = await client.get("/thing")

    ids = [first.headers["x-request-id"], second.headers["x-request-id"]]
    assert all(re.fullmatch(r"[0-9a-f]{32}", value) for value in ids)
    assert ids[0] != ids[1]
    # What the handler saw is what the caller was told, and a caller's own
    # choice of id is never adopted: it is written into the audit trail.
    assert seen == ids
    assert current_request_id() is None


async def test_the_audit_address_is_an_address_or_nothing() -> None:
    assert mw._valid_address("203.0.113.9") == "203.0.113.9"
    assert mw._valid_address("unknown") is None
    assert mw._valid_address("<script>") is None
