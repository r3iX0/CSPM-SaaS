"""Ownership rules: who owns the unassigned work on the assets of a scope (DECISIONS.md §236)."""

from uuid import UUID

from fastapi import APIRouter, Request, Response, status
from pydantic import BaseModel

from app.api.links import created
from app.core.deps import DbSession, Tenant
from app.schemas.common import ERROR_RESPONSES, Envelope, NoMeta, TotalMeta, error_responses
from app.schemas.ownership import OwnershipRuleIn, OwnershipRuleOut, OwnershipRuleUpdate
from app.services import ownership as service

router = APIRouter(prefix="/ownership-rules", tags=["remediation"], responses=ERROR_RESPONSES)


class OwnershipRuleDeletedOut(BaseModel):
    id: UUID


def _out(rule: object, owner_is_member: bool = True) -> OwnershipRuleOut:
    out = OwnershipRuleOut.model_validate(rule)
    out.owner_is_member = owner_is_member
    return out


@router.get("")
async def list_ownership_rules(
    session: DbSession, tenant: Tenant
) -> Envelope[list[OwnershipRuleOut], TotalMeta]:
    """Every rule, most general scope first. Not paged: at most 500 (``MAX_RULES``)."""
    rows = await service.listing(session, tenant)
    return Envelope(
        data=[_out(rule, is_member) for rule, is_member in rows], meta=TotalMeta(total=len(rows))
    )


@router.post("", status_code=status.HTTP_201_CREATED, responses=error_responses(403, 404, 409))
async def create_ownership_rule(
    payload: OwnershipRuleIn,
    request: Request,
    response: Response,
    session: DbSession,
    tenant: Tenant,
) -> Envelope[OwnershipRuleOut, NoMeta]:
    """Name an owner for a scope. Owners and admins. One rule per scope: a second is ``409``."""
    rule = await service.create_rule(session, tenant, payload)
    await session.commit()
    created(request, response, "update_ownership_rule", rule_id=rule.id)
    return Envelope(data=_out(rule), meta=NoMeta())


@router.patch("/{rule_id}", responses=error_responses(403, 404))
async def update_ownership_rule(
    rule_id: UUID, payload: OwnershipRuleUpdate, session: DbSession, tenant: Tenant
) -> Envelope[OwnershipRuleOut, NoMeta]:
    """Hand a scope to another member. Owners and admins."""
    rule = await service.update_rule(session, tenant, rule_id, payload)
    await session.commit()
    return Envelope(data=_out(rule), meta=NoMeta())


@router.delete("/{rule_id}", responses=error_responses(403, 404))
async def delete_ownership_rule(
    rule_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[OwnershipRuleDeletedOut, NoMeta]:
    """Remove a rule. Its scope's unassigned work falls to the next rule that matches."""
    await service.delete_rule(session, tenant, rule_id)
    await session.commit()
    return Envelope(data=OwnershipRuleDeletedOut(id=rule_id), meta=NoMeta())
