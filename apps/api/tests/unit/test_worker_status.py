"""What the scans page is told when the task broker cannot be reached (DECISIONS.md section 158).

Any member may ask, so the answer is a sentence written for them. The broker's
own exception is for the log: it is written for an operator and can carry the
broker's address, credentials included.
"""

from typing import Any

import pytest

from app.api.routes import scans as route


async def test_an_unreachable_broker_is_described_not_quoted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def ping(**kwargs: Any) -> None:
        raise ConnectionError("Error connecting to redis://default:hunter2@redis.internal:6379")

    monkeypatch.setattr(route.celery_app.control, "ping", ping)

    response = await route.worker_status(tenant=object())  # type: ignore[arg-type]

    assert response.data.reachable is False
    assert response.data.workers == 0
    assert response.data.detail == route.WORKER_PING_FAILED
    assert "hunter2" not in response.data.detail
