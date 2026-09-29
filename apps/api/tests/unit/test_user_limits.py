"""The fair-use limit is per person, once the token says who that is.

The middleware counts by address before any token is verified, and one office
is one address: fifty people behind it shared 300 requests a minute. The
per-user count runs after verification, so it can neither be dodged by
forging a header nor shared out among colleagues (DECISIONS.md section 161).
"""

import time
import uuid

import jwt
import pytest

from app.core import deps
from app.core import middleware as mw
from app.core.config import settings
from app.core.errors import RateLimited


class _Counter:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}
        self.queued: list[str] = []

    def pipeline(self) -> "_Counter":
        return self

    def incr(self, key: str) -> None:
        self.queued.append(key)

    def expire(self, _key: str, _seconds: int) -> None:
        return None

    async def execute(self) -> list[int]:
        key = self.queued.pop()
        self.counts[key] = self.counts.get(key, 0) + 1
        return [self.counts[key], True]


@pytest.fixture
def counter(monkeypatch: pytest.MonkeyPatch) -> _Counter:
    fake = _Counter()
    monkeypatch.setattr(mw, "_redis", lambda: fake)
    monkeypatch.setattr(settings, "rate_limit_per_user", 3)
    monkeypatch.setattr(settings, "rate_limit_costly_per_user", 1)
    return fake


def bearer(user_id: uuid.UUID) -> str:
    token = jwt.encode(
        {"sub": str(user_id), "aud": "authenticated", "exp": int(time.time()) + 60},
        settings.supabase_jwt_secret,
        algorithm="HS256",
    )
    return f"Bearer {token}"


async def test_each_person_has_their_own_allowance(counter: _Counter) -> None:
    alice, bob = uuid.uuid4(), uuid.uuid4()
    for _ in range(3):
        await deps.get_current_user(bearer(alice))

    with pytest.raises(RateLimited) as refused:
        await deps.get_current_user(bearer(alice))
    assert refused.value.status_code == 429
    assert refused.value.headers == {"Retry-After": str(settings.rate_limit_window_seconds)}

    # A colleague behind the same address is not charged for it.
    await deps.get_current_user(bearer(bob))


async def test_a_token_that_fails_to_verify_is_not_counted(counter: _Counter) -> None:
    """Nobody can spend somebody else's allowance by naming them."""
    victim = uuid.uuid4()
    forged = jwt.encode({"sub": str(victim), "aud": "authenticated"}, "wrong", algorithm="HS256")
    with pytest.raises(Exception, match="Invalid"):
        await deps.get_current_user(f"Bearer {forged}")
    assert counter.counts == {}


async def test_costly_requests_have_a_smaller_allowance(counter: _Counter) -> None:
    user = await deps.get_current_user(bearer(uuid.uuid4()))
    await deps.limit_costly(user)
    with pytest.raises(RateLimited):
        await deps.limit_costly(user)
