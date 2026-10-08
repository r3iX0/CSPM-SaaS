"""Cleave's GitHub App, as GitHub's REST API sees it (DECISIONS.md §231).

Three identities, each for one job:

- **The App**, a JWT signed with its private key: asks GitHub which
  installation covers a repository, and mints installation tokens.
- **An installation**, a token minted per call and valid for an hour: reads a
  repository the customer installed the App on. Never stored.
- **A person**, the user token from the App's OAuth half during installation:
  proves the person linking an installation can see it. Used once, never stored.

Only fixed GitHub hosts are called, never a URL a customer typed, so these calls
need not go through ``core/outbound`` (§164).
"""

import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt

from app.core.config import settings
from app.core.errors import CodeHostError

API = "https://api.github.com"
OAUTH_TOKEN = "https://github.com/login/oauth/access_token"
TIMEOUT_SECONDS = 10.0
# A person with more installations than this links from a narrower account.
MAX_INSTALLATION_PAGES = 5
_HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}


@dataclass(frozen=True)
class Installation:
    installation_id: int
    account_login: str
    account_type: str


@dataclass(frozen=True)
class Repository:
    repository_id: int
    full_name: str
    default_branch: str


def install_url(state: str) -> str:
    """Where a person installs the App, carrying ``state`` back to the callback."""
    return f"https://github.com/apps/{settings.github_app_slug}/installations/new?state={state}"


def app_jwt(now: float | None = None) -> str:
    """The App's own token: RS256 with its private key, valid nine minutes.

    Issued a minute in the past, as GitHub recommends, so a clock slightly ahead
    of GitHub's is not refused.
    """
    issued = int(now if now is not None else time.time()) - 60
    # A dashboard field often holds the PEM on one line, its newlines written as a backslash and n.
    key = settings.github_app_private_key.replace("\\n", "\n")
    return jwt.encode(
        {"iat": issued, "exp": issued + 600, "iss": settings.github_app_client_id},
        key,
        algorithm="RS256",
    )


async def _request(
    method: str, url: str, *, token: str, scheme: str = "Bearer", **kwargs: Any
) -> httpx.Response:
    headers = {**_HEADERS, "Authorization": f"{scheme} {token}"}
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
            return await client.request(method, url, headers=headers, **kwargs)
    except httpx.HTTPError as exc:
        raise CodeHostError("GitHub did not answer.") from exc


def _json(response: httpx.Response, what: str) -> Any:
    if response.status_code >= 400:
        raise CodeHostError(f"GitHub refused to {what} ({response.status_code}).")
    return response.json()


async def user_token(code: str) -> str:
    """Exchange the code GitHub returned after installation for the person's token."""
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
            response = await client.post(
                OAUTH_TOKEN,
                headers={"Accept": "application/json"},
                json={
                    "client_id": settings.github_app_client_id,
                    "client_secret": settings.github_app_client_secret,
                    "code": code,
                },
            )
    except httpx.HTTPError as exc:
        raise CodeHostError("GitHub did not answer.") from exc
    token = _json(response, "exchange the sign-in code").get("access_token")
    if not isinstance(token, str) or not token:
        # GitHub answers 200 with an ``error`` for a code that is spent or expired.
        raise CodeHostError("GitHub did not accept the sign-in code; install again.")
    return token


async def user_installations(token: str) -> dict[int, Installation]:
    """The App's installations this person can see, by id."""
    found: dict[int, Installation] = {}
    for page in range(1, MAX_INSTALLATION_PAGES + 1):
        body = _json(
            await _request(
                "GET",
                f"{API}/user/installations",
                token=token,
                params={"per_page": 100, "page": page},
            ),
            "list your installations",
        )
        rows = body.get("installations", [])
        for row in rows:
            account = row.get("account") or {}
            found[int(row["id"])] = Installation(
                installation_id=int(row["id"]),
                account_login=str(account.get("login", "")),
                account_type=str(account.get("type", "")),
            )
        if len(rows) < 100:
            break
    return found


async def repository_installation(full_name: str) -> int | None:
    """Which installation of the App covers a repository; ``None`` if none does."""
    response = await _request("GET", f"{API}/repos/{full_name}/installation", token=app_jwt())
    if response.status_code == 404:
        return None
    return int(_json(response, "find the App's installation")["id"])


async def installation_token(installation_id: int) -> str:
    """An hour's token for one installation. Never stored."""
    body = _json(
        await _request(
            "POST", f"{API}/app/installations/{installation_id}/access_tokens", token=app_jwt()
        ),
        "issue an installation token",
    )
    return str(body["token"])


async def repository(full_name: str, installation_id: int) -> Repository:
    """A repository as the installation sees it: its id and its default branch."""
    body = _json(
        await _request(
            "GET",
            f"{API}/repos/{full_name}",
            token=await installation_token(installation_id),
        ),
        "read the repository",
    )
    return Repository(
        repository_id=int(body["id"]),
        full_name=str(body["full_name"]),
        default_branch=str(body["default_branch"]),
    )


def signed_by_github(body: bytes, signature: str | None) -> bool:
    """Whether a webhook delivery carries the App's secret's HMAC of its exact body."""
    if (
        not signature
        or not signature.startswith("sha256=")
        or not settings.github_app_webhook_secret
    ):
        return False
    expected = hmac.new(
        settings.github_app_webhook_secret.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature.removeprefix("sha256="), expected)
