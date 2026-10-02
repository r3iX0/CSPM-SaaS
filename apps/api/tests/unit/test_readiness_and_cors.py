"""Readiness says which dependency is down, and CORS allows only what the web app uses.

``/health/ready`` is the one endpoint an operator calls to ask "can this instance do its work",
so a dependency that does not answer must be a ``503`` in the envelope that names it, not an
unhandled ``500``, and never the dependency's own error, which can carry an address or a
credential. The CORS lists are read off the application, as ``test_pagination_bounds`` reads page
sizes: a ``*`` coming back fails here (API_GUIDELINES.md sections 10 and 13).
"""

from collections.abc import Awaitable, Callable
from typing import Any

import httpx
import pytest
from fastapi.middleware.cors import CORSMiddleware

from app import main
from app.main import app


async def _answers() -> None:
    return None


def _failing(message: str) -> Callable[[], Awaitable[None]]:
    async def fail() -> None:
        raise RuntimeError(message)

    return fail


async def _get_ready() -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.get("/health/ready")


async def test_ready_when_the_database_and_the_broker_answer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(main, "ping", _answers)
    monkeypatch.setattr(main, "ping_redis", _answers)

    response = await _get_ready()

    assert response.status_code == 200
    assert response.json()["data"] == {"status": "ready", "database": "ok", "queue": "ok"}


async def test_a_database_that_does_not_answer_is_a_503_that_leaks_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(main, "ping", _failing("password authentication failed for user bob"))
    monkeypatch.setattr(main, "ping_redis", _answers)

    response = await _get_ready()

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "DATABASE_UNAVAILABLE"
    assert "bob" not in response.text


async def test_a_broker_that_does_not_answer_is_a_503_that_names_the_queue(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(main, "ping", _answers)
    monkeypatch.setattr(main, "ping_redis", _failing("redis://:hunter2@broker.internal:6379"))

    response = await _get_ready()

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "QUEUE_UNAVAILABLE"
    assert "hunter2" not in response.text


def _cors() -> dict[str, Any]:
    for middleware in app.user_middleware:
        if middleware.cls is CORSMiddleware:
            return dict(middleware.kwargs)
    raise AssertionError("the application has no CORS middleware")


def test_cors_allows_named_methods_and_headers_only() -> None:
    options = _cors()
    assert "*" not in options["allow_methods"]
    assert "*" not in options["allow_headers"]
    # What the web app sends: the token, the body type and the organization it is acting in.
    assert {"Authorization", "Content-Type", "X-Organization-Id"} <= set(options["allow_headers"])


def test_cors_is_not_credentialed_because_the_api_uses_no_cookies() -> None:
    """The token travels in ``Authorization``; credentialed mode would add cookies and certs."""
    assert _cors()["allow_credentials"] is False


def test_cors_exposes_what_a_client_reads_from_a_response() -> None:
    exposed = set(_cors()["expose_headers"])
    assert {"X-Request-ID", "X-RateLimit-Remaining", "Retry-After", "Location"} <= exposed
