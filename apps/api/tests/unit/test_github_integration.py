"""Cleave's GitHub App: who may link an installation, and whose index an upload is (§231).

An installation id arrives in a query string anybody can edit, so linking takes
GitHub's word for it through the linking person's own token. An index upload is
taken only with a GitHub Actions token for this API, from the default branch of a
repository whose installation some organization linked. GitHub itself is stubbed:
these prove the decisions, not the wire.
"""

import base64
import time
from contextlib import asynccontextmanager
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.deps import TenantContext
from app.core.enums import Role
from app.core.errors import (
    NotAuthenticated,
    NotConfigured,
    NotFound,
    PermissionDenied,
    ValidationFailed,
)
from app.core.security import AuthenticatedUser, SigningKeys
from app.core.signing import Purpose, sign_state
from app.integrations import github, github_oidc
from app.integrations.github_oidc import ActionsIdentity
from app.main import app
from app.schemas.code_integration import GitHubLinkIn, IacIndexEntryIn, IacIndexIn
from app.services import code_integrations as service

API_URL = "https://api.cleave.test"
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
ORG = uuid4()
SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"


@pytest.fixture(autouse=True)
def offered(monkeypatch: pytest.MonkeyPatch) -> None:
    from cryptography.hazmat.primitives import serialization

    pem = KEY.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    for name, value in {
        "api_url": API_URL,
        "github_app_id": "1",
        "github_app_slug": "cleave-test",
        "github_app_client_id": "Iv1.test",
        "github_app_client_secret": "client-secret",
        "github_app_private_key": pem.replace("\n", "\\n"),
        "github_app_webhook_secret": "hook-secret",
        "fix_prs_enabled": True,
    }.items():
        monkeypatch.setattr(settings, name, value)


# ------------------------------------------------------------- OIDC tokens
def _b64(n: int) -> str:
    return (
        base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()
    )


def _keys() -> SigningKeys:
    public = KEY.public_key().public_numbers()
    jwks = {
        "keys": [
            {"kty": "RSA", "kid": "k1", "use": "sig", "n": _b64(public.n), "e": _b64(public.e)}
        ]
    }

    async def fetch(_url: str) -> dict[str, Any]:
        return jwks

    return SigningKeys("https://example.test/jwks", fetch=fetch)


def _token(**claims: Any) -> str:
    now = int(time.time())
    body = {
        "iss": github_oidc.ISSUER,
        "aud": API_URL,
        "iat": now,
        "exp": now + 300,
        "repository": "contoso/infra",
        "repository_id": "42",
        "ref": "refs/heads/main",
        "sha": "a" * 40,
    } | claims
    return jwt.encode(
        {k: v for k, v in body.items() if v is not None},
        KEY,
        algorithm="RS256",
        headers={"kid": "k1"},
    )


async def test_a_jobs_token_names_its_repository_ref_and_commit() -> None:
    identity = await github_oidc.verify(_token(), keys=_keys())
    assert identity == ActionsIdentity(42, "contoso/infra", "refs/heads/main", "a" * 40)


@pytest.mark.parametrize(
    "claims",
    [
        {"aud": "https://elsewhere.test"},
        {"iss": "https://token.example.test"},
        {"exp": int(time.time()) - 10},
        {"repository_id": None},
    ],
    ids=["another_audience", "another_issuer", "expired", "no_repository"],
)
async def test_a_token_that_is_not_for_this_api_is_refused(claims: dict[str, Any]) -> None:
    with pytest.raises(NotAuthenticated):
        await github_oidc.verify(_token(**claims), keys=_keys())


async def test_a_shared_secret_token_is_refused() -> None:
    forged = jwt.encode({"aud": API_URL}, "guessable", algorithm="HS256", headers={"kid": "k1"})
    with pytest.raises(NotAuthenticated):
        await github_oidc.verify(forged, keys=_keys())


async def test_without_an_api_url_no_token_is_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "api_url", "")
    with pytest.raises(NotConfigured):
        await github_oidc.verify(_token(), keys=_keys())


# ----------------------------------------------------------- the App itself
def test_the_apps_jwt_is_signed_with_its_key_and_names_its_client() -> None:
    claims = jwt.decode(
        github.app_jwt(now=1_000_000),
        KEY.public_key(),
        algorithms=["RS256"],
        options={"verify_exp": False},
    )
    assert claims == {"iat": 999_940, "exp": 1_000_540, "iss": "Iv1.test"}


def test_a_delivery_is_believed_only_with_the_secrets_hmac() -> None:
    import hashlib
    import hmac

    body = b'{"action":"deleted"}'
    good = "sha256=" + hmac.new(b"hook-secret", body, hashlib.sha256).hexdigest()
    assert github.signed_by_github(body, good)
    assert not github.signed_by_github(body + b" ", good)
    assert not github.signed_by_github(body, None)


def test_an_unsigned_delivery_is_refused_over_http() -> None:
    response = TestClient(app).post(
        "/api/v1/integrations/github/events",
        content=b'{"action":"deleted","installation":{"id":1}}',
        headers={"X-GitHub-Event": "installation"},
    )
    assert response.status_code == 401


def test_an_upload_without_a_token_is_refused_over_http() -> None:
    response = TestClient(app).put("/api/v1/iac-indexes", json={"entries": []})
    assert response.status_code == 401


# ------------------------------------------------------------------ linking
def _tenant(user: UUID | None = None, role: Role = Role.OWNER) -> TenantContext:
    return TenantContext(user=AuthenticatedUser(id=user or uuid4()), organization_id=ORG, role=role)


class _Session:
    def __init__(self) -> None:
        self.added: list[Any] = []

    async def execute(self, _statement: object) -> Any:
        return SimpleNamespace(scalar_one_or_none=lambda: None)

    def add(self, row: Any) -> None:
        row.id = uuid4()
        self.added.append(row)

    @asynccontextmanager
    async def begin_nested(self) -> Any:
        yield

    async def flush(self) -> None:
        return None


@pytest.fixture
def gh(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {
        "listed": {7: github.Installation(7, "contoso", "Organization")},
        "audit": [],
    }

    async def user_token(code: str) -> str:
        return "user-token"

    async def user_installations(token: str) -> dict[int, github.Installation]:
        return state["listed"]

    async def record(*args: Any) -> None:
        state["audit"].append(args[2])

    monkeypatch.setattr(github, "user_token", user_token)
    monkeypatch.setattr(github, "user_installations", user_installations)
    monkeypatch.setattr(service.audit, "record", record)
    return state


def _link(
    tenant: TenantContext, installation_id: int = 7, state_user: UUID | None = None
) -> GitHubLinkIn:
    state = sign_state(
        {
            "organization_id": str(ORG),
            "user_id": str(state_user or tenant.user.id),
            "issued_at": int(time.time()),
        },
        purpose=Purpose.GITHUB_INSTALL,
    )
    return GitHubLinkIn(installation_id=installation_id, code="c", state=state)


async def test_an_installation_github_lists_for_the_person_is_linked(gh: dict[str, Any]) -> None:
    tenant, session = _tenant(), _Session()
    row = await service.link(session, tenant, _link(tenant))  # type: ignore[arg-type]
    assert (row.installation_id, row.account_login, row.organization_id) == (7, "contoso", ORG)
    assert gh["audit"] == ["github.linked"]


async def test_an_installation_id_github_does_not_list_is_refused(gh: dict[str, Any]) -> None:
    tenant = _tenant()
    with pytest.raises(PermissionDenied):
        await service.link(_Session(), tenant, _link(tenant, installation_id=8))  # type: ignore[arg-type]


async def test_a_state_started_by_someone_else_is_refused(gh: dict[str, Any]) -> None:
    tenant = _tenant()
    with pytest.raises(PermissionDenied):
        await service.link(_Session(), tenant, _link(tenant, state_user=uuid4()))  # type: ignore[arg-type]


async def test_a_state_for_another_purpose_is_refused(gh: dict[str, Any]) -> None:
    tenant = _tenant()
    payload = _link(tenant).model_copy(
        update={"state": sign_state({"issued_at": int(time.time())}, purpose=Purpose.CONSENT)}
    )
    with pytest.raises(ValidationFailed):
        await service.link(_Session(), tenant, payload)  # type: ignore[arg-type]


async def test_only_owners_and_admins_link(gh: dict[str, Any]) -> None:
    tenant = _tenant(role=Role.SECURITY_ANALYST)
    with pytest.raises(PermissionDenied):
        await service.link(_Session(), tenant, _link(tenant))  # type: ignore[arg-type]


async def test_nothing_is_offered_until_switched_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "fix_prs_enabled", False)
    with pytest.raises(NotFound):
        service.connect_url(_tenant())


# ------------------------------------------------------------------- upload
IDENTITY = ActionsIdentity(42, "contoso/infra", "refs/heads/main", "a" * 40)
UPLOAD = IacIndexIn(
    working_directory="infra/",
    entries=[
        IacIndexEntryIn(
            address="azurerm_key_vault.main",
            type="azurerm_key_vault",
            id=f"{SUB}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv",
        )
    ],
)


@pytest.fixture
def repo(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {
        "installation": 7,
        "repository": github.Repository(42, "contoso/infra", "main"),
        "linked": ORG,
        "stored": [],
    }

    async def repository_installation(full_name: str) -> int | None:
        return state["installation"]

    async def repository(full_name: str, installation_id: int) -> github.Repository:
        return state["repository"]

    class _Owner:
        async def execute(self, _statement: object) -> Any:
            return SimpleNamespace(scalar_one_or_none=lambda: state["linked"])

        async def commit(self) -> None:
            return None

    @asynccontextmanager
    async def service_session() -> Any:
        yield _Owner()

    async def replace_index(session: object, organization_id: UUID, **fields: Any) -> None:
        state["stored"].append((organization_id, fields))

    monkeypatch.setattr(github, "repository_installation", repository_installation)
    monkeypatch.setattr(github, "repository", repository)
    monkeypatch.setattr(service, "service_session", service_session)
    monkeypatch.setattr(service.iac_index, "replace_index", replace_index)
    return state


async def test_an_index_is_stored_under_the_organization_that_linked_its_repository(
    repo: dict[str, Any],
) -> None:
    out = await service.take_index(IDENTITY, UPLOAD)
    [(organization_id, fields)] = repo["stored"]
    assert organization_id == ORG
    assert (fields["working_directory"], fields["commit_sha"], out.entries) == (
        "infra",
        "a" * 40,
        1,
    )


@pytest.mark.parametrize(
    ("change", "identity"),
    [
        ({"installation": None}, IDENTITY),
        ({"linked": None}, IDENTITY),
        ({"repository": github.Repository(99, "contoso/infra", "main")}, IDENTITY),
        ({}, ActionsIdentity(42, "contoso/infra", "refs/heads/feature", "a" * 40)),
    ],
    ids=[
        "app_not_installed",
        "installation_not_linked",
        "repository_renamed_away",
        "not_default_branch",
    ],
)
async def test_an_index_from_anywhere_else_is_refused(
    repo: dict[str, Any], change: dict[str, Any], identity: ActionsIdentity
) -> None:
    repo.update(change)
    with pytest.raises(PermissionDenied):
        await service.take_index(identity, UPLOAD)
    assert repo["stored"] == []


async def test_a_working_directory_outside_the_repository_is_refused(repo: dict[str, Any]) -> None:
    with pytest.raises(ValidationFailed):
        await service.take_index(IDENTITY, UPLOAD.model_copy(update={"working_directory": "../x"}))
