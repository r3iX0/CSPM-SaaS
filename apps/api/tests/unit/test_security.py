"""Token verification.

The only thing standing between a request and someone else's tenant, so the
failure modes matter more than the happy path: an unexpected algorithm, a
forged signature, a token that has expired, and the classic JWT confusion
attack where the attacker picks the algorithm.
"""

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

from app.core.config import Settings
from app.core.errors import NotAuthenticated
from app.core.security import (
    JWKS_LIFESPAN_SECONDS,
    JWKS_MIN_REFRESH_SECONDS,
    SigningKeys,
)

SECRET = "a-shared-hs256-secret"


@pytest.fixture(autouse=True)
def _hs256_project(monkeypatch: pytest.MonkeyPatch):
    """A legacy project that signs with a shared secret."""
    import app.core.security as security

    monkeypatch.setattr(
        security,
        "settings",
        Settings(
            app_env="test",
            supabase_url="https://abc.supabase.co",
            supabase_jwt_secret=SECRET,
        ),
    )
    security._signing_keys.cache_clear()
    return security


def make_token(
    *, secret: str = SECRET, alg: str = "HS256", key=None, kid: str | None = None, **overrides
) -> str:
    now = datetime.now(UTC)
    claims = {
        "sub": str(uuid4()),
        "email": "user@example.com",
        "aud": "authenticated",
        "iat": now,
        "exp": now + timedelta(hours=1),
        **overrides,
    }
    return jwt.encode(
        claims,
        key if key is not None else secret,
        algorithm=alg,
        headers={"kid": kid} if kid is not None else None,
    )


def _jwk(private_key: ec.EllipticCurvePrivateKey, kid: str) -> dict[str, Any]:
    published = ECAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
    return {**published, "kid": kid, "alg": "ES256", "use": "sig"}


class _Jwks:
    """A JWKS endpoint that counts how often it is read."""

    def __init__(self, keys: list[dict[str, Any]]) -> None:
        self.keys = keys
        self.fetches = 0
        self.fail = False

    async def __call__(self, url: str) -> dict[str, Any]:
        self.fetches += 1
        if self.fail:
            raise OSError("unreachable")
        return {"keys": self.keys}


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _publish(
    security: Any, monkeypatch: pytest.MonkeyPatch, keys: list[dict[str, Any]]
) -> _Jwks:
    """Point the module at a JWKS endpoint that serves ``keys``."""
    endpoint = _Jwks(keys)
    signing_keys = SigningKeys("https://abc.supabase.co/jwks", fetch=endpoint)
    monkeypatch.setattr(security, "_signing_keys", lambda: signing_keys)
    return endpoint


class TestAcceptsValidTokens:
    async def test_a_correctly_signed_token_identifies_the_user(self, _hs256_project) -> None:
        user_id = uuid4()
        token = make_token(sub=str(user_id))
        result = await _hs256_project.decode_token(token)
        assert result.id == user_id
        assert result.email == "user@example.com"


    async def test_an_es256_token_verifies_against_the_published_key(
        self, _hs256_project, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        private_key = ec.generate_private_key(ec.SECP256R1())
        _publish(_hs256_project, monkeypatch, [_jwk(private_key, "k1")])
        user_id = uuid4()
        token = make_token(alg="ES256", key=private_key, kid="k1", sub=str(user_id))
        assert (await _hs256_project.decode_token(token)).id == user_id


class TestRejectsBadTokens:
    async def test_a_forged_signature_is_rejected(self, _hs256_project) -> None:
        token = make_token(secret="not-the-real-secret")
        with pytest.raises(NotAuthenticated):
            await _hs256_project.decode_token(token)

    async def test_an_expired_token_is_rejected(self, _hs256_project) -> None:
        past = datetime.now(UTC) - timedelta(hours=2)
        token = make_token(exp=past, iat=past - timedelta(hours=1))
        with pytest.raises(NotAuthenticated, match="expired"):
            await _hs256_project.decode_token(token)

    async def test_a_token_for_another_audience_is_rejected(self, _hs256_project) -> None:
        token = make_token(aud="some-other-service")
        with pytest.raises(NotAuthenticated):
            await _hs256_project.decode_token(token)

    async def test_a_non_uuid_subject_is_rejected(self, _hs256_project) -> None:
        """The subject becomes the identity RLS resolves against."""
        token = make_token(sub="not-a-uuid")
        with pytest.raises(NotAuthenticated, match="not a valid user id"):
            await _hs256_project.decode_token(token)

    async def test_garbage_is_rejected(self, _hs256_project) -> None:
        with pytest.raises(NotAuthenticated):
            await _hs256_project.decode_token("not-a-jwt-at-all")


class TestAlgorithmConfusion:
    async def test_an_unsigned_token_is_rejected(self, _hs256_project) -> None:
        """alg=none is the oldest JWT attack there is."""
        token = jwt.encode(
            {"sub": str(uuid4()), "aud": "authenticated", "exp": 9999999999},
            key="",
            algorithm="none",
        )
        with pytest.raises(NotAuthenticated, match="Unsupported token signing algorithm"):
            await _hs256_project.decode_token(token)

    async def test_an_unexpected_algorithm_is_rejected(self, _hs256_project) -> None:
        token = make_token(secret=SECRET, alg="HS512")
        with pytest.raises(NotAuthenticated, match="Unsupported token signing algorithm"):
            await _hs256_project.decode_token(token)

    async def test_an_asymmetric_token_is_not_verified_with_the_shared_secret(
        self, _hs256_project, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The confusion attack in its dangerous form: an ES256 header must send
        us to the JWKS endpoint, never to the HS256 secret. Here the project
        publishes no key under that id, so the correct outcome is a clean
        refusal."""
        _publish(_hs256_project, monkeypatch, [])
        key = ec.generate_private_key(ec.SECP256R1())
        token = make_token(alg="ES256", key=key, kid="unpublished")
        with pytest.raises(NotAuthenticated):
            await _hs256_project.decode_token(token)


class TestMissingConfiguration:
    async def test_hs256_without_a_secret_says_so_precisely(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An asymmetric project has no shared secret; if a legacy token turns
        up anyway, the message should name the variable rather than read as a
        generic auth failure."""
        import app.core.security as security

        monkeypatch.setattr(
            security,
            "settings",
            Settings(
                app_env="test",
                supabase_url="https://abc.supabase.co",
                supabase_jwt_secret="",
            ),
        )
        with pytest.raises(NotAuthenticated, match="SUPABASE_JWT_SECRET"):
            await security.decode_token(make_token())


class TestSigningKeyFetches:
    """The JWKS fetch happens before any signature is checked, so anyone can
    ask for one; how often it happens is not theirs to decide (DECISIONS.md
    section 158)."""

    async def test_unknown_key_ids_do_not_each_fetch_the_set(self) -> None:
        endpoint = _Jwks([])
        keys = SigningKeys("https://abc.supabase.co/jwks", fetch=endpoint, clock=_Clock())
        for _ in range(50):
            assert await keys.get(str(uuid4())) is None
        assert endpoint.fetches == 1

    async def test_a_rotated_in_key_is_found_once_the_floor_has_passed(self) -> None:
        clock = _Clock()
        endpoint = _Jwks([])
        keys = SigningKeys("https://abc.supabase.co/jwks", fetch=endpoint, clock=clock)
        assert await keys.get("new") is None

        endpoint.keys = [_jwk(ec.generate_private_key(ec.SECP256R1()), "new")]
        clock.now += JWKS_MIN_REFRESH_SECONDS - 1
        assert await keys.get("new") is None
        clock.now += 1
        assert await keys.get("new") is not None
        assert endpoint.fetches == 2

    async def test_a_known_key_is_served_from_the_cache_until_it_is_stale(self) -> None:
        clock = _Clock()
        endpoint = _Jwks([_jwk(ec.generate_private_key(ec.SECP256R1()), "k1")])
        keys = SigningKeys("https://abc.supabase.co/jwks", fetch=endpoint, clock=clock)
        for _ in range(10):
            assert await keys.get("k1") is not None
        assert endpoint.fetches == 1

        clock.now += JWKS_LIFESPAN_SECONDS
        assert await keys.get("k1") is not None
        assert endpoint.fetches == 2

    async def test_a_revoked_key_stops_verifying_after_the_lifespan(self) -> None:
        clock = _Clock()
        endpoint = _Jwks([_jwk(ec.generate_private_key(ec.SECP256R1()), "k1")])
        keys = SigningKeys("https://abc.supabase.co/jwks", fetch=endpoint, clock=clock)
        assert await keys.get("k1") is not None

        endpoint.keys = [_jwk(ec.generate_private_key(ec.SECP256R1()), "k2")]
        clock.now += JWKS_LIFESPAN_SECONDS
        assert await keys.get("k1") is None

    async def test_a_failed_fetch_keeps_the_last_set(self) -> None:
        clock = _Clock()
        endpoint = _Jwks([_jwk(ec.generate_private_key(ec.SECP256R1()), "k1")])
        keys = SigningKeys("https://abc.supabase.co/jwks", fetch=endpoint, clock=clock)
        assert await keys.get("k1") is not None

        endpoint.fail = True
        clock.now += JWKS_LIFESPAN_SECONDS
        assert await keys.get("k1") is not None

    async def test_concurrent_first_requests_share_one_fetch(self) -> None:
        endpoint = _Jwks([_jwk(ec.generate_private_key(ec.SECP256R1()), "k1")])
        keys = SigningKeys("https://abc.supabase.co/jwks", fetch=endpoint, clock=_Clock())
        found = await asyncio.gather(*(keys.get("k1") for _ in range(20)))
        assert all(key is not None for key in found)
        assert endpoint.fetches == 1
