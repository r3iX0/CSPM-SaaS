"""FastAPI dependencies: identity, tenant context, and the RLS-bound session.

The chain is deliberate and one-directional:

    Bearer token -> user id -> membership lookup -> organization_id -> session

``organization_id`` is the *output* of authentication, never an input to it. A
client can name an organization it wants to act in, but the server only honours
it if the membership lookup confirms it -- and PostgreSQL re-checks the same
thing through RLS regardless.
"""

import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Header, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import rls_session
from app.core.enums import Role
from app.core.errors import (
    NotAuthenticated,
    OrganizationNotFound,
    PermissionDenied,
    RateLimited,
    SecondFactorRequired,
)
from app.core.middleware import over_limit
from app.core.security import AuthenticatedUser, decode_token
from app.models.organization import Organization, OrganizationMember

# Declared once so the published contract says how to authenticate: OpenAPI gets a ``bearerAuth``
# scheme and every route that depends on a user carries it. ``auto_error=False`` leaves the
# refusal to ``get_current_user``, so a missing token is still the envelope's NOT_AUTHENTICATED
# and not FastAPI's bare ``{"detail": "Not authenticated"}``.
bearer_scheme = HTTPBearer(
    scheme_name="bearerAuth",
    bearerFormat="JWT",
    description="A Supabase Auth access token, sent as `Authorization: Bearer <token>`.",
    auto_error=False,
)


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_scheme)],
) -> AuthenticatedUser:
    if credentials is None:
        raise NotAuthenticated("Missing bearer token")
    user = await decode_token(credentials.credentials.strip())
    # Counted per person, now that the token says who that is. The middleware
    # can only count per address, and one office is one address.
    await _within_limit("user", user.id, settings.rate_limit_per_user)
    return user


CurrentUser = Annotated[AuthenticatedUser, Depends(get_current_user)]


async def _within_limit(bucket: str, user_id: UUID, limit: int) -> None:
    window_seconds = settings.rate_limit_window_seconds
    window = int(time.time()) // window_seconds
    if await over_limit(f"ratelimit:{bucket}:{user_id}:{window}", limit, window_seconds):
        raise RateLimited(headers={"Retry-After": str(window_seconds)})


async def limit_costly(user: CurrentUser) -> None:
    """The smaller allowance, for requests that cost far more than a read.

    A scan queued against a customer's cloud, a PDF render (one at a time for
    the whole process), a plan simulated across the whole estate, a check that
    calls the provider. Each is a legitimate click, and none is something a
    person does twenty times a minute (DECISIONS.md section 161).
    """
    await _within_limit("costly", user.id, settings.rate_limit_costly_per_user)


# For a route's ``dependencies=[...]``: it returns nothing the handler reads.
Costly = Depends(limit_costly)


async def get_session(user: CurrentUser) -> AsyncIterator[AsyncSession]:
    """A database session PostgreSQL will constrain to this user's tenants.

    Refused to a session that skipped a second factor its user has set up. The
    sign-in page asks for the code, but a password alone is enough to get a
    one-factor token straight from Supabase's API, so the check that counts is
    this one (DECISIONS.md section 213).
    """
    async with rls_session(user.id, user.email) as session:
        if not user.second_factor:
            await refuse_a_skipped_second_factor(session)
        yield session


async def refuse_a_skipped_second_factor(session: AsyncSession) -> None:
    """Raise if the caller has a verified second factor this session did not use.

    Only asked of one-factor sessions: an ``aal2`` token has already passed it.
    """
    enrolled = (await session.execute(text("SELECT app.has_verified_factor()"))).scalar_one()
    if enrolled:
        raise SecondFactorRequired()


DbSession = Annotated[AsyncSession, Depends(get_session)]


@dataclass(frozen=True)
class TenantContext:
    """Everything downstream code is allowed to know about "who is asking"."""

    user: AuthenticatedUser
    organization_id: UUID
    role: Role
    # The shared demo organization. Read-only for everybody, checked here as
    # well as by role: joining the demo always grants VIEWER, but "nobody can
    # change the demo" should not rest on every membership row being right.
    is_demo: bool = False

    def _refuse_demo(self) -> None:
        if self.is_demo:
            raise PermissionDenied(
                "The demo organization is read-only. Create your own organization "
                "to connect a cloud and act on findings."
            )

    def require_role(self, *roles: Role) -> None:
        self._refuse_demo()
        if self.role not in roles:
            raise PermissionDenied(
                f"This action requires one of: {', '.join(sorted(r.value for r in roles))}"
            )

    @property
    def may_administer(self) -> bool:
        """Whether this caller may perform owner/admin actions.

        The same question ``require_role(OWNER, ADMIN)`` asks, answered rather
        than enforced. Used where the answer shapes a response instead of
        rejecting a request -- deciding whether to hand back a credential the
        holder could act with, which is a decision that must not be left to the
        frontend hiding a button.
        """
        return not self.is_demo and self.role in (Role.OWNER, Role.ADMIN)

    def require_write(self) -> None:
        """Anyone except VIEWER may change security workflow state -- never in the demo."""
        self._refuse_demo()
        if self.role == Role.VIEWER:
            raise PermissionDenied("Your role is read-only")


async def get_tenant(
    request: Request,
    user: CurrentUser,
    session: DbSession,
    x_organization_id: Annotated[str | None, Header()] = None,
) -> TenantContext:
    """Resolve the organization this request acts in.

    The ``X-Organization-Id`` header is a *preference*, not an authorization. It
    is only honoured when a membership row for this user backs it; otherwise the
    request is rejected rather than silently falling back to another tenant.
    """
    # Own organizations before the demo, oldest first: the fallback below takes
    # the first row, and somebody who has both must land in their own estate,
    # not in the sample they once opened.
    stmt = (
        select(OrganizationMember, Organization.is_demo)
        .join(Organization, Organization.id == OrganizationMember.organization_id)
        .where(OrganizationMember.user_id == user.id)
        .order_by(Organization.is_demo, Organization.created_at)
    )
    memberships = list((await session.execute(stmt)).all())
    if not memberships:
        raise OrganizationNotFound("You do not belong to any organization yet")

    # Keep the address colleagues see beside this membership in step with the
    # verified token. Written only when it differs, which is once per person
    # per change of address; ``app.record_member_email`` touches the caller's
    # own rows and nothing else (DECISIONS.md section 162).
    if user.email and any(m.email != user.email.lower() for m, _ in memberships):
        await session.execute(text("SELECT app.record_member_email()"))

    requested = x_organization_id or request.query_params.get("organization_id")
    if requested:
        try:
            wanted = UUID(requested)
        except ValueError as exc:
            raise OrganizationNotFound("Invalid organization id") from exc
        for m, is_demo in memberships:
            if m.organization_id == wanted:
                return TenantContext(
                    user=user, organization_id=wanted, role=Role(m.role), is_demo=is_demo
                )
        raise OrganizationNotFound("Organization not found")

    # Single-organization users -- the overwhelmingly common case -- never have
    # to send the header at all.
    chosen, is_demo = memberships[0]
    return TenantContext(
        user=user,
        organization_id=chosen.organization_id,
        role=Role(chosen.role),
        is_demo=is_demo,
    )


Tenant = Annotated[TenantContext, Depends(get_tenant)]
