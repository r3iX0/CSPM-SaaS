"""Reading the rules table, which mirrors the registry for joins and the screen.

The registry in ``app/rules`` is the source of truth and ``rule_sync`` copies it into the table
at startup; these read the copy.
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import NotFound
from app.models.rule import Rule


async def list_rules(session: AsyncSession) -> list[Rule]:
    """Every rule, in id order."""
    return list((await session.execute(select(Rule).order_by(Rule.rule_id))).scalars().all())


async def get_rule(session: AsyncSession, rule_id: str) -> Rule:
    """One rule by its id, such as ``AZ-STO-001``."""
    rule = (await session.execute(select(Rule).where(Rule.rule_id == rule_id))).scalar_one_or_none()
    if rule is None:
        raise NotFound("Rule not found")
    return rule
