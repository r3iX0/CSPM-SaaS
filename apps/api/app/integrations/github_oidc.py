"""A GitHub Actions job's own OIDC token, as the state index upload's credential (§231).

A job granted ``id-token: write`` can ask GitHub for a short-lived token naming
its repository, ref and commit, signed with GitHub's published keys. That is
the whole credential: the customer stores no Cleave secret, and a token is good
for one repository's job for minutes. The audience must be Cleave's own API, so
a token minted for another service is refused here.
"""

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

import jwt

from app.core.config import settings
from app.core.errors import NotAuthenticated, NotConfigured
from app.core.security import SigningKeys

ISSUER = "https://token.actions.githubusercontent.com"
JWKS_URL = f"{ISSUER}/.well-known/jwks"


@dataclass(frozen=True)
class ActionsIdentity:
    """Which repository, ref and commit a job ran for, as GitHub signed it."""

    repository_id: int
    repository: str
    ref: str
    sha: str


@lru_cache
def _keys() -> SigningKeys:
    return SigningKeys(JWKS_URL)


async def verify(token: str, *, keys: SigningKeys | None = None) -> ActionsIdentity:
    """Check a job's token and say what it names; ``NotAuthenticated`` otherwise.

    RS256 only, GitHub's issuer, this API as the audience, and the expiry: a
    token failing any of them is not a credential, whatever it claims.
    """
    if not settings.api_url:
        # The audience is this API's own URL; without one there is nothing to hold it to.
        raise NotConfigured("API_URL is not set, so no GitHub Actions token can be checked")
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise NotAuthenticated("Not a GitHub Actions token") from exc
    kid = header.get("kid")
    if header.get("alg") != "RS256" or not isinstance(kid, str) or not kid:
        raise NotAuthenticated("Not a GitHub Actions token")
    key = await (keys or _keys()).get(kid)
    if key is None:
        raise NotAuthenticated("The token's signing key is not one of GitHub's")
    try:
        claims: dict[str, Any] = jwt.decode(
            token,
            key,
            algorithms=["RS256"],
            audience=settings.api_url,
            issuer=ISSUER,
            options={"require": ["exp", "iat", "iss", "aud"]},
        )
    except jwt.PyJWTError as exc:
        raise NotAuthenticated("The GitHub Actions token did not verify") from exc
    try:
        return ActionsIdentity(
            repository_id=int(claims["repository_id"]),
            repository=str(claims["repository"]),
            ref=str(claims["ref"]),
            sha=str(claims["sha"]),
        )
    except (KeyError, ValueError) as exc:
        raise NotAuthenticated("The GitHub Actions token names no repository") from exc
