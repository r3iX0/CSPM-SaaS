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

import base64
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


# -------------------------------------------------------------- pull requests
#: A repository's Terraform read for one pull request, at most: past this the
#: repository is declined rather than half-read (DECISIONS.md §232).
MAX_TERRAFORM_FILES = 400
MAX_TERRAFORM_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class OpenedPullRequest:
    number: int
    url: str


async def terraform_files(
    full_name: str, branch: str, token: str
) -> tuple[str, dict[str, str]] | str:
    """The branch's head commit and every ``.tf`` and lock file at it, or why not.

    Read through the Git Data API, never cloned, under file and byte caps. A
    tree GitHub truncated is refused, since a half-read repository would decline
    blocks that are there.
    """
    head = _json(
        await _request("GET", f"{API}/repos/{full_name}/git/ref/heads/{branch}", token=token),
        "read the default branch",
    )["object"]["sha"]
    tree = _json(
        await _request(
            "GET",
            f"{API}/repos/{full_name}/git/trees/{head}",
            token=token,
            params={"recursive": "1"},
        ),
        "read the repository tree",
    )
    if tree.get("truncated"):
        return "The repository is too large for GitHub to list in one tree."
    wanted = [
        item
        for item in tree.get("tree", [])
        if item.get("type") == "blob"
        and (item["path"].endswith(".tf") or item["path"].endswith(".terraform.lock.hcl"))
    ]
    if len(wanted) > MAX_TERRAFORM_FILES:
        return (
            f"The repository holds {len(wanted)} Terraform files; "
            f"at most {MAX_TERRAFORM_FILES} are read."
        )
    if sum(int(item.get("size", 0)) for item in wanted) > MAX_TERRAFORM_BYTES:
        return "The repository's Terraform is over 4 MiB."
    files: dict[str, str] = {}
    for item in wanted:
        blob = _json(
            await _request("GET", f"{API}/repos/{full_name}/git/blobs/{item['sha']}", token=token),
            "read a file",
        )
        try:
            files[item["path"]] = base64.b64decode(blob["content"]).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue  # Not UTF-8 text; Terraform would not read it either.
    return head, files


async def open_pull_request(
    full_name: str,
    *,
    token: str,
    base: str,
    base_sha: str,
    branch: str,
    files: dict[str, str],
    title: str,
    body: str,
) -> OpenedPullRequest:
    """Commit ``files`` on a new branch from ``base_sha`` and open a pull request to ``base``.

    Never a push to ``base``, and never a merge: a person merges (§190).
    """
    tree = _json(
        await _request(
            "POST",
            f"{API}/repos/{full_name}/git/trees",
            token=token,
            json={
                "base_tree": base_sha,
                "tree": [
                    {"path": path, "mode": "100644", "type": "blob", "content": content}
                    for path, content in sorted(files.items())
                ],
            },
        ),
        "write the edited files",
    )
    commit = _json(
        await _request(
            "POST",
            f"{API}/repos/{full_name}/git/commits",
            token=token,
            json={"message": title, "tree": tree["sha"], "parents": [base_sha]},
        ),
        "commit the edit",
    )
    _json(
        await _request(
            "POST",
            f"{API}/repos/{full_name}/git/refs",
            token=token,
            json={"ref": f"refs/heads/{branch}", "sha": commit["sha"]},
        ),
        "create the branch",
    )
    pull = _json(
        await _request(
            "POST",
            f"{API}/repos/{full_name}/pulls",
            token=token,
            json={"title": title, "head": branch, "base": base, "body": body},
        ),
        "open the pull request",
    )
    return OpenedPullRequest(number=int(pull["number"]), url=str(pull["html_url"]))
