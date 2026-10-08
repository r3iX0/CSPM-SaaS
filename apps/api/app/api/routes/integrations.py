"""Cleave's GitHub App: linking installations, its webhook, and the state index upload (§231).

Linking is a person's action, under their session. The webhook and the upload
are not: GitHub's deliveries carry an HMAC of the App's webhook secret, and an
upload carries the job's GitHub Actions token. Both are left out of the
published document, as the cloud event receivers are.
"""

import json
from typing import Annotated

from fastapi import APIRouter, Header, Request
from pydantic import BaseModel

from app.core.config import settings
from app.core.deps import DbSession, Tenant
from app.core.errors import NotAuthenticated, ValidationFailed
from app.integrations import github, github_oidc
from app.schemas.code_integration import (
    GitHubConnectOut,
    GitHubInstallationOut,
    GitHubLinkIn,
    GitHubStatusOut,
    IacIndexIn,
    IacIndexOut,
)
from app.schemas.common import ERROR_RESPONSES, Envelope, NoMeta, error_responses
from app.services import code_integrations as service
from app.services import pull_requests as pull_request_service

router = APIRouter(prefix="/integrations/github", tags=["integrations"], responses=ERROR_RESPONSES)
index_router = APIRouter(prefix="/iac-indexes", tags=["integrations"])


class UnlinkedOut(BaseModel):
    installation_id: int


class DeliveryOut(BaseModel):
    received: bool


@router.get("")
async def github_status(session: DbSession, tenant: Tenant) -> Envelope[GitHubStatusOut, NoMeta]:
    """Whether GitHub is offered here, and which installations this organization linked."""
    rows = await service.installations(session, tenant)
    return Envelope(
        data=GitHubStatusOut(
            available=settings.github_offered,
            installations=[GitHubInstallationOut.model_validate(row) for row in rows],
        ),
        meta=NoMeta(),
    )


@router.post("/connect", responses=error_responses(403, 404))
async def connect(tenant: Tenant) -> Envelope[GitHubConnectOut, NoMeta]:
    """Where an owner or an admin installs the App. GitHub sends them back to link it."""
    return Envelope(data=GitHubConnectOut(install_url=service.connect_url(tenant)), meta=NoMeta())


@router.post("/installations", responses=error_responses(403, 404, 409, 502))
async def link_installation(
    payload: GitHubLinkIn, session: DbSession, tenant: Tenant
) -> Envelope[GitHubInstallationOut, NoMeta]:
    """Link the installation GitHub sent the person back with.

    The installation id arrives in a query string anybody can edit, so it is
    linked only if GitHub lists it among the installations of the person's own
    token, exchanged from ``code``. ``200``: the installation already exists on
    GitHub, and this links it rather than creating it.
    """
    row = await service.link(session, tenant, payload)
    await session.commit()
    return Envelope(data=GitHubInstallationOut.model_validate(row), meta=NoMeta())


@router.delete("/installations/{installation_id}", responses=error_responses(403, 404))
async def unlink_installation(
    installation_id: int, session: DbSession, tenant: Tenant
) -> Envelope[UnlinkedOut, NoMeta]:
    """Unlink an installation. The App stays installed on GitHub until it is removed there."""
    await service.unlink(session, tenant, installation_id)
    await session.commit()
    return Envelope(data=UnlinkedOut(installation_id=installation_id), meta=NoMeta())


@router.post("/events", include_in_schema=False)
async def github_event(
    request: Request,
    x_github_event: Annotated[str | None, Header()] = None,
    x_hub_signature_256: Annotated[str | None, Header()] = None,
) -> Envelope[DeliveryOut, NoMeta]:
    """GitHub's deliveries to the App. An uninstalled App is unlinked everywhere."""
    body = await request.body()
    if not github.signed_by_github(body, x_hub_signature_256):
        raise NotAuthenticated("The delivery is not signed with the App's webhook secret")
    try:
        event = json.loads(body)
    except ValueError as exc:
        raise ValidationFailed("The delivery is not JSON") from exc
    if x_github_event == "installation" and event.get("action") == "deleted":
        await service.forget_installation(int(event["installation"]["id"]))
    elif x_github_event == "pull_request" and event.get("action") == "closed":
        # A merge claims the fix for what the pull request edited (§232).
        pull = event["pull_request"]
        await pull_request_service.pull_request_closed(
            int(event["repository"]["id"]), int(pull["number"]), merged=bool(pull.get("merged"))
        )
    return Envelope(data=DeliveryOut(received=True), meta=NoMeta())


@index_router.put("", include_in_schema=False)
async def put_index(
    payload: IacIndexIn,
    authorization: Annotated[str | None, Header()] = None,
) -> Envelope[IacIndexOut, NoMeta]:
    """A job's Terraform state index, authenticated by its own GitHub Actions token.

    Replaces the last index of the same repository, directory and workspace.
    """
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise NotAuthenticated("Send the job's GitHub Actions token as a bearer token")
    identity = await github_oidc.verify(token)
    return Envelope(data=await service.take_index(identity, payload), meta=NoMeta())
