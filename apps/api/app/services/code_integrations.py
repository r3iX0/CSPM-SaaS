"""Linking GitHub App installations to organizations, and taking their state indexes (§231).

Linking is proven, not asserted. After installing the App, GitHub sends the
person back with an ``installation_id`` in the query string, which anybody can
edit, so it is checked against the installations GitHub lists for that person's
own token, from the App's OAuth half, before it is linked. The ``state`` that
went out with them is signed, names its purpose, and is bound to this person in
this organization.

An index upload has no person behind it: its credential is the job's GitHub
Actions token. The repository it names must be covered by an installation some
organization linked, and the ref must be that repository's default branch. The
upload is then written through the owner connection, scoped to that
organization, as change events are. GitHub is asked first and the database
touched only after, so a stranger's token cannot hold a pooled connection while
GitHub answers (§158).
"""

import posixpath
import time
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import service_session
from app.core.deps import TenantContext
from app.core.enums import Role
from app.core.errors import ConflictError, NotFound, PermissionDenied, ValidationFailed
from app.core.signing import Purpose, SignedStateError, sign_state, verify_state
from app.integrations import github
from app.integrations.github_oidc import ActionsIdentity
from app.models.code_integration import CodeIntegration
from app.remediation.iac.index import InvalidIndex, entries_from_upload
from app.schemas.code_integration import GitHubLinkIn, IacIndexIn, IacIndexOut
from app.services import audit, iac_index

#: How long an installation may take, from Cleave's button back to Cleave.
INSTALL_STATE_TTL_SECONDS = 1800


def require_offered() -> None:
    if not settings.github_offered:
        raise NotFound("GitHub is not offered on this deployment")


async def installations(session: AsyncSession, tenant: TenantContext) -> list[CodeIntegration]:
    """The installations this organization has linked, oldest first."""
    rows = await session.execute(
        select(CodeIntegration)
        .where(CodeIntegration.organization_id == tenant.organization_id)
        .order_by(CodeIntegration.connected_at)
    )
    return list(rows.scalars())


def connect_url(tenant: TenantContext) -> str:
    """Where an owner or an admin installs the App, with a state bound to them."""
    tenant.require_role(Role.OWNER, Role.ADMIN)
    require_offered()
    state = sign_state(
        {
            "organization_id": str(tenant.organization_id),
            "user_id": str(tenant.user.id),
            "issued_at": int(time.time()),
        },
        purpose=Purpose.GITHUB_INSTALL,
    )
    return github.install_url(state)


async def link(
    session: AsyncSession, tenant: TenantContext, payload: GitHubLinkIn
) -> CodeIntegration:
    """Link the installation GitHub sent the person back with, once GitHub vouches for it."""
    tenant.require_role(Role.OWNER, Role.ADMIN)
    require_offered()
    try:
        claim = verify_state(
            payload.state,
            purpose=Purpose.GITHUB_INSTALL,
            max_age_seconds=INSTALL_STATE_TTL_SECONDS,
        )
    except SignedStateError as exc:
        raise ValidationFailed(str(exc)) from exc
    if claim.get("organization_id") != str(tenant.organization_id) or claim.get("user_id") != str(
        tenant.user.id
    ):
        raise PermissionDenied("This installation was started by someone else; start it again")

    token = await github.user_token(payload.code)
    installation = (await github.user_installations(token)).get(payload.installation_id)
    if installation is None:
        raise PermissionDenied("GitHub does not list this installation among yours")

    existing = (
        await session.execute(
            select(CodeIntegration).where(
                CodeIntegration.installation_id == installation.installation_id
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    row = CodeIntegration(
        organization_id=tenant.organization_id,
        installation_id=installation.installation_id,
        account_login=installation.account_login,
        account_type=installation.account_type,
        connected_by=tenant.user.id,
    )
    session.add(row)
    try:
        async with session.begin_nested():
            await session.flush()
    except IntegrityError as exc:
        # Unique on the installation, and invisible to this organization: so
        # another organization holds it.
        raise ConflictError("This installation is linked to another organization") from exc
    await audit.record(
        session,
        tenant,
        "github.linked",
        "code_integration",
        row.id,
        {"installation_id": row.installation_id, "account": row.account_login},
    )
    return row


async def unlink(session: AsyncSession, tenant: TenantContext, installation_id: int) -> None:
    """Unlink an installation. The App stays installed on GitHub until removed there."""
    tenant.require_role(Role.OWNER, Role.ADMIN)
    row = (
        await session.execute(
            select(CodeIntegration).where(
                CodeIntegration.organization_id == tenant.organization_id,
                CodeIntegration.installation_id == installation_id,
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise NotFound("No such GitHub installation is linked")
    await session.delete(row)
    await audit.record(
        session,
        tenant,
        "github.unlinked",
        "code_integration",
        row.id,
        {"installation_id": installation_id, "account": row.account_login},
    )
    await session.flush()


async def forget_installation(installation_id: int) -> None:
    """GitHub says the App was uninstalled: unlink it wherever it was linked."""
    async with service_session() as session:
        await session.execute(
            delete(CodeIntegration).where(CodeIntegration.installation_id == installation_id)
        )
        await session.commit()


def working_directory_in(given: str) -> str:
    """A working directory as a job names it, inside the repository; refused otherwise."""
    normalised = posixpath.normpath(given.strip().strip("/") or ".")
    if normalised == ".." or normalised.startswith("../") or normalised.startswith("/"):
        raise ValidationFailed("The working directory is outside the repository")
    return "" if normalised == "." else normalised


@dataclass(frozen=True)
class LinkedRepository:
    """A job's repository, proven to be covered by an installation this organization linked."""

    installation_id: int
    repository: github.Repository
    organization_id: UUID


async def linked_repository(identity: ActionsIdentity) -> LinkedRepository:
    """The organization a job's repository belongs to, on GitHub's word; refused otherwise.

    GitHub says which installation covers the token's repository, and that the
    repository's numeric id is the token's, so a renamed repository cannot stand
    in for another. The installation must be linked here. GitHub is asked before
    any session opens, so a stranger's token holds no pooled connection (§231).
    """
    installation_id = await github.repository_installation(identity.repository)
    if installation_id is None:
        raise PermissionDenied("Cleave's GitHub App is not installed on this repository")
    repository = await github.repository(identity.repository, installation_id)
    if repository.repository_id != identity.repository_id:
        raise PermissionDenied("The repository is not the one the token was issued for")
    async with service_session() as session:
        organization_id = (
            await session.execute(
                select(CodeIntegration.organization_id).where(
                    CodeIntegration.installation_id == installation_id
                )
            )
        ).scalar_one_or_none()
    if organization_id is None:
        raise PermissionDenied("This repository's installation is not linked to Cleave")
    return LinkedRepository(installation_id, repository, organization_id)


async def take_index(identity: ActionsIdentity, payload: IacIndexIn) -> IacIndexOut:
    """Store a job's state index under the organization its repository is linked to."""
    require_offered()
    try:
        entries = entries_from_upload([entry.model_dump() for entry in payload.entries])
    except InvalidIndex as exc:
        raise ValidationFailed(str(exc)) from exc
    working_directory = working_directory_in(payload.working_directory)

    linked = await linked_repository(identity)
    repository = linked.repository
    if identity.ref != f"refs/heads/{repository.default_branch}":
        raise PermissionDenied(
            f"Only {repository.default_branch}'s state is indexed, not {identity.ref}"
        )

    async with service_session() as session:
        await iac_index.replace_index(
            session,
            linked.organization_id,
            repository_id=repository.repository_id,
            repository=repository.full_name,
            working_directory=working_directory,
            workspace=payload.workspace,
            commit_sha=identity.sha,
            entries=entries,
        )
        await session.commit()
    return IacIndexOut(
        repository=repository.full_name,
        working_directory=working_directory,
        workspace=payload.workspace,
        commit_sha=identity.sha,
        entries=len(entries),
    )
