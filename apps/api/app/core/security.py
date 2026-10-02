"""JWT verification.

CloudGuard does not implement authentication -- Supabase Auth does. This module
only *verifies* the token Supabase issued and extracts the user id. Nothing here
grants access to anything: authorization is membership resolution (app layer)
plus RLS (database layer).

Supabase signs tokens two different ways depending on the project's age and
settings:

* **ES256 / RS256** -- asymmetric, and the current default. The public keys are
  published at the project's JWKS endpoint; there is no shared secret to hold,
  and keys can rotate without redeploying this service.
* **HS256** -- the legacy shared secret (SUPABASE_JWT_SECRET).

Both are supported, chosen per token from the header's ``alg``. Critically the
algorithm is never treated as a *permission*: the token must verify under a key
appropriate to the algorithm it declares, and anything else -- including
``none`` -- is refused outright rather than falling through to a weaker check.
"""

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from functools import lru_cache
from typing import Any
from uuid import UUID

import httpx
import jwt
from jwt import PyJWK, PyJWKSet

from app.core.config import settings
from app.core.errors import NotAuthenticated
from app.core.logging import get_logger

log = get_logger(__name__)

# What Supabase issues. "none" and the wider symmetric family are deliberately
# absent: accepting an attacker-chosen algorithm is the classic JWT confusion
# attack.
ASYMMETRIC_ALGORITHMS = ("ES256", "RS256")
SYMMETRIC_ALGORITHMS = ("HS256",)
SUPPORTED_ALGORITHMS = ASYMMETRIC_ALGORITHMS + SYMMETRIC_ALGORITHMS

# The JWKS fetch is bounded three ways, because it runs before any signature is
# checked and so anyone can cause one: it is awaited rather than blocking the
# event loop, it gives up after ``JWKS_TIMEOUT_SECONDS``, and it happens at most
# once per ``JWKS_MIN_REFRESH_SECONDS`` however many unknown key ids arrive.
JWKS_TIMEOUT_SECONDS = 5.0
# How long a fetched set is trusted before it is read again, so a key Supabase
# revokes stops verifying within this long.
JWKS_LIFESPAN_SECONDS = 300.0
JWKS_MIN_REFRESH_SECONDS = 30.0


@dataclass(frozen=True)
class AuthenticatedUser:
    id: UUID
    email: str | None = None


async def _fetch_jwks(url: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=JWKS_TIMEOUT_SECONDS) as client:
        response = await client.get(url)
        response.raise_for_status()
        payload: dict[str, Any] = response.json()
        return payload


class SigningKeys:
    """The project's published signing keys, read without blocking and rarely.

    It replaced ``PyJWKClient``, which fetches synchronously -- on the event
    loop, from inside an async dependency, with a 30-second default timeout --
    and fetches again for every key id it does not recognise. The key id comes
    from the token's unverified header, so a stranger sending tokens with
    random ids could make every request wait on a round trip to Supabase and
    stall the whole API, health checks included (DECISIONS.md section 158).

    A fetch that fails keeps the last set: an unreachable Supabase should not
    sign out everybody whose token it already vouched for.
    """

    def __init__(
        self,
        url: str,
        *,
        fetch: Callable[[str], Awaitable[dict[str, Any]]] = _fetch_jwks,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._url = url
        self._fetch = fetch
        self._clock = clock
        self._keys: dict[str, PyJWK] = {}
        self._fetched_at: float | None = None
        self._attempted_at: float | None = None
        self._lock = asyncio.Lock()

    def _stale(self, now: float) -> bool:
        return self._fetched_at is None or now - self._fetched_at >= JWKS_LIFESPAN_SECONDS

    def _may_fetch(self, now: float) -> bool:
        return self._attempted_at is None or now - self._attempted_at >= JWKS_MIN_REFRESH_SECONDS

    async def get(self, kid: str) -> PyJWK | None:
        key = self._keys.get(kid)
        if key is not None and (not self._stale(self._clock()) or self._lock.locked()):
            # Fresh, or already being re-read by another request: answer from
            # what is held rather than queueing behind that fetch.
            return key

        async with self._lock:
            # Checked again after the wait: whoever held the lock may have just
            # fetched the key this request is asking for.
            now = self._clock()
            key = self._keys.get(kid)
            if (key is None or self._stale(now)) and self._may_fetch(now):
                await self._refresh(now)
            return self._keys.get(kid)

    async def _refresh(self, now: float) -> None:
        self._attempted_at = now
        try:
            jwks = PyJWKSet.from_dict(await self._fetch(self._url))
        except Exception as exc:
            log.warning("auth.jwks_fetch_failed", error=type(exc).__name__)
            return
        self._keys = {
            key.key_id: key
            for key in jwks.keys
            if key.key_id and key.public_key_use in ("sig", None)
        }
        self._fetched_at = now


@lru_cache
def _signing_keys() -> SigningKeys:
    base = settings.supabase_url.rstrip("/")
    return SigningKeys(f"{base}/auth/v1/.well-known/jwks.json")


async def _signing_key(header: dict[str, Any], algorithm: str) -> PyJWK | str:
    if algorithm in ASYMMETRIC_ALGORITHMS:
        if not settings.supabase_url:
            raise NotAuthenticated("Server has no Supabase project configured")
        kid = header.get("kid")
        key = await _signing_keys().get(kid) if isinstance(kid, str) and kid else None
        if key is None:
            raise NotAuthenticated(
                "Could not verify the token's signing key against the Supabase project"
            )
        return key

    if not settings.supabase_jwt_secret:
        raise NotAuthenticated(
            "Token is signed with a shared secret but SUPABASE_JWT_SECRET is not set"
        )
    return settings.supabase_jwt_secret


async def decode_token(token: str) -> AuthenticatedUser:
    """Verify a Supabase Auth JWT and return the caller's identity.

    Signature, expiry and audience are all checked. A token failing any of them
    is simply not authenticated -- we never fall through to a "best guess" user.
    """
    try:
        header = jwt.get_unverified_header(token)
        algorithm = header.get("alg", "")
    except jwt.InvalidTokenError as exc:
        raise NotAuthenticated("Malformed authentication token") from exc

    if algorithm not in SUPPORTED_ALGORITHMS:
        raise NotAuthenticated(f"Unsupported token signing algorithm: {algorithm or 'none'}")

    key = await _signing_key(header, algorithm)

    try:
        claims = jwt.decode(
            token,
            key,
            # Pinned to the one algorithm the header declared and whose key was
            # just resolved for it, so a token cannot be verified under another.
            algorithms=[algorithm],
            audience=settings.jwt_audience,
            options={"require": ["sub", "exp"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise NotAuthenticated("Token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise NotAuthenticated("Invalid authentication token") from exc

    try:
        user_id = UUID(str(claims["sub"]))
    except (KeyError, ValueError) as exc:
        raise NotAuthenticated("Token subject is not a valid user id") from exc

    return AuthenticatedUser(id=user_id, email=claims.get("email"))
