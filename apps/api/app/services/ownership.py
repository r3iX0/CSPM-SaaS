"""Who owns the work on an asset: the person assigned, or the rule its place names (§236).

A task records ``assigned_to`` when a person hands it to somebody. Most work nobody hands out,
so an organization names owners by where assets sit: a default, a subscription, a resource
group, or an Azure tag such as ``owner=platform-team``. A task with nobody assigned is owned by
the most specific rule its asset matches -- a tag, then its resource group, then its
subscription, then the default.

Derived when the work is read, never written onto the task, as a policy's due date is (§225):
changing a rule reroutes every unassigned task at once, needs no batch write, and never
overwrites what a person chose. A rule whose owner has left the organization is skipped, so
the work falls to the next rule rather than to somebody who can no longer see it.
"""

import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import TenantContext
from app.core.enums import OrganizationMode, OwnershipScope, Role
from app.core.errors import ConflictError, NotFound, ValidationFailed
from app.models.cloud_account import CloudAccount
from app.models.organization import Organization, OrganizationMember
from app.models.ownership import OwnershipRule
from app.schemas.ownership import OwnershipRuleIn, OwnershipRuleUpdate
from app.services import audit

#: Enough for a rule per subscription and per team tag in a large estate.
MAX_RULES = 500

_RESOURCE_GROUP = re.compile(r"^/subscriptions/[^/]+/resourcegroups/([^/]+)", re.IGNORECASE)
_PRECEDENCE = (
    OwnershipScope.TAG,
    OwnershipScope.RESOURCE_GROUP,
    OwnershipScope.SUBSCRIPTION,
    OwnershipScope.DEFAULT,
)


@dataclass(frozen=True)
class Placement:
    """Where an asset sits, as far as ownership asks: its subscription, group and tags."""

    cloud_account_id: UUID | None = None
    resource_group: str | None = None
    tags: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Routed:
    owner_id: UUID
    scope: OwnershipScope
    rule_id: UUID


type Router = Callable[[Placement], Routed | None]


def placement_of(
    cloud_account_id: UUID | None, provider_resource_id: str | None, tags: Any
) -> Placement:
    """An asset's placement from its record; a directory object has none but the default."""
    group = _RESOURCE_GROUP.match(provider_resource_id or "")
    return Placement(
        cloud_account_id=cloud_account_id,
        resource_group=group.group(1) if group else None,
        tags={str(k): str(v) for k, v in tags.items()} if isinstance(tags, dict) else {},
    )


def route(
    placement: Placement, rules: Sequence[OwnershipRule], members: set[UUID]
) -> Routed | None:
    """The most specific rule this placement matches whose owner is still a member.

    Two tags of one asset can each have a rule; the one made first wins, so a rule added later
    never quietly takes work from an owner who already had it.
    """
    tags = {key.casefold(): value for key, value in placement.tags.items()}
    group = placement.resource_group.casefold() if placement.resource_group else None
    for scope in _PRECEDENCE:
        candidates = sorted(
            (rule for rule in rules if rule.scope is scope and rule.owner_id in members),
            key=lambda rule: (rule.created_at, str(rule.id)),
        )
        for rule in candidates:
            if _matches(rule, placement, tags, group):
                return Routed(rule.owner_id, scope, rule.id)
    return None


def _matches(
    rule: OwnershipRule, placement: Placement, tags: Mapping[str, str], group: str | None
) -> bool:
    if rule.scope is OwnershipScope.DEFAULT:
        return True
    if rule.scope is OwnershipScope.TAG:
        return rule.tag_key is not None and tags.get(rule.tag_key.casefold()) == rule.tag_value
    if rule.cloud_account_id != placement.cloud_account_id:
        return False
    if rule.scope is OwnershipScope.SUBSCRIPTION:
        return True
    return group is not None and (rule.resource_group or "").casefold() == group


async def members(session: AsyncSession, organization_id: UUID) -> set[UUID]:
    rows = await session.execute(
        select(OrganizationMember.user_id).where(
            OrganizationMember.organization_id == organization_id
        )
    )
    return set(rows.scalars())


async def router(session: AsyncSession, organization_id: UUID) -> Router:
    """Route any number of placements against the rules and members as they stand, read once."""
    rules = await list_rules(session, organization_id)
    current = await members(session, organization_id)

    def owner_of(placement: Placement) -> Routed | None:
        return route(placement, rules, current)

    return owner_of


async def list_rules(session: AsyncSession, organization_id: UUID) -> list[OwnershipRule]:
    return list(
        (
            await session.execute(
                select(OwnershipRule)
                .where(OwnershipRule.organization_id == organization_id)
                .order_by(OwnershipRule.scope, OwnershipRule.created_at)
            )
        )
        .scalars()
        .all()
    )


async def _require_owner(session: AsyncSession, tenant: TenantContext, owner_id: UUID) -> None:
    if owner_id not in await members(session, tenant.organization_id):
        raise ValidationFailed("The owner is not a member of this organization")


async def create_rule(
    session: AsyncSession, tenant: TenantContext, payload: OwnershipRuleIn
) -> OwnershipRule:
    """Name an owner for a scope. Owners and admins; one rule per scope (``409`` otherwise)."""
    tenant.require_role(Role.OWNER, Role.ADMIN)
    org = await session.get(Organization, tenant.organization_id)
    if org is not None and org.mode is OrganizationMode.SOLO:
        raise ConflictError("A solo organization's work is all its one person's")
    await _require_owner(session, tenant, payload.owner_id)
    if payload.cloud_account_id is not None:
        account = await session.get(CloudAccount, payload.cloud_account_id)
        if account is None or account.organization_id != tenant.organization_id:
            raise NotFound("Subscription not found")
    if len(await list_rules(session, tenant.organization_id)) >= MAX_RULES:
        raise ValidationFailed(f"An organization has at most {MAX_RULES} ownership rules")

    rule = OwnershipRule(
        organization_id=tenant.organization_id,
        scope=payload.scope,
        cloud_account_id=payload.cloud_account_id,
        resource_group=payload.resource_group,
        tag_key=payload.tag_key,
        tag_value=payload.tag_value,
        owner_id=payload.owner_id,
        created_by=tenant.user.id,
    )
    try:
        async with session.begin_nested():
            session.add(rule)
            await session.flush()
    except IntegrityError as exc:
        raise ConflictError("This scope already has an owner; change that rule instead") from exc
    await audit.record(
        session,
        tenant,
        "ownership_rule.created",
        "ownership_rule",
        rule.id,
        {"scope": rule.scope.value, "owner_id": str(rule.owner_id)},
    )
    return rule


async def _rule(session: AsyncSession, tenant: TenantContext, rule_id: UUID) -> OwnershipRule:
    rule = await session.get(OwnershipRule, rule_id)
    if rule is None or rule.organization_id != tenant.organization_id:
        raise NotFound("Ownership rule not found")
    return rule


async def update_rule(
    session: AsyncSession, tenant: TenantContext, rule_id: UUID, payload: OwnershipRuleUpdate
) -> OwnershipRule:
    """Hand a scope to another owner. Its scope is what the rule is, so it is not changed."""
    tenant.require_role(Role.OWNER, Role.ADMIN)
    rule = await _rule(session, tenant, rule_id)
    await _require_owner(session, tenant, payload.owner_id)
    previous, rule.owner_id = rule.owner_id, payload.owner_id
    await session.flush()
    await audit.record(
        session,
        tenant,
        "ownership_rule.updated",
        "ownership_rule",
        rule.id,
        {"owner_id": str(rule.owner_id), "previous_owner_id": str(previous)},
    )
    return rule


async def delete_rule(session: AsyncSession, tenant: TenantContext, rule_id: UUID) -> None:
    """Remove a rule; its scope's unassigned work falls to the next rule that matches."""
    tenant.require_role(Role.OWNER, Role.ADMIN)
    rule = await _rule(session, tenant, rule_id)
    scope, owner_id = rule.scope.value, str(rule.owner_id)
    await session.delete(rule)
    await session.flush()
    await audit.record(
        session,
        tenant,
        "ownership_rule.deleted",
        "ownership_rule",
        rule_id,
        {"scope": scope, "owner_id": owner_id},
    )


async def listing(session: AsyncSession, tenant: TenantContext) -> list[tuple[OwnershipRule, bool]]:
    """Every rule, with whether its owner is still a member."""
    current = await members(session, tenant.organization_id)
    return [
        (rule, rule.owner_id in current)
        for rule in await list_rules(session, tenant.organization_id)
    ]
