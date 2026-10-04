"""Guests: visitors who opened the demo without an account (DECISIONS.md section 219).

A guest is Supabase's anonymous user. It reads the demo and owns nothing, so the only thing
to look after is that guests do not pile up: each one is a row in ``auth.users`` and a
membership in the demo, and a link on the marketing site mints one per visitor.
"""

from datetime import datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


async def forget_stale(session: AsyncSession, created_before: datetime) -> int:
    """Delete the guests who signed in before ``created_before`` and never made an account.

    On the owner's session: the rows are in ``auth.users``, which belongs to Supabase, and in
    the demo's membership, which no tenant session may delete for somebody else. Returns how
    many were forgotten, at most one batch.
    """
    result = await session.execute(
        text("SELECT app.forget_guests(:before)"), {"before": created_before}
    )
    return int(result.scalar_one())
