"""The three things every request passes through.

Exercised through a real ASGI app rather than by calling the middlewares
directly, because two of the three are about what happens to a request *before*
a handler sees it -- a body that is still arriving, a counter that decides
whether the handler runs at all -- and calling them directly would test the
arrangement this file exists to check.
"""

from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from app.core import middleware as mw
from app.core.middleware import (
    SECURITY_HEADERS,
    RateLimitMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
    client_address,
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


async def test_an_error_response_is_stamped_too() -> None:
    """The headers matter most on the responses nobody wrote by hand."""
    app = app_with((SecurityHeadersMiddleware, {}))

    async with client_for(app) as client:
        response = await client.get("/no-such-route")

    assert response.status_code == 404
    assert response.headers["X-Content-Type-Options"] == "nosniff"


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
