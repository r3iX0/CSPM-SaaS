"""Reading the route ledger (DECISIONS.md section 244).

ANALYZE writes it (``services/scan/ledger.py``); this answers the page's
questions from it -- which routes are new, which closed and why, and how many
were open each day -- as reads, never as rebuilds. The live graph stays the
answer to "what is open now" and to every what-if.
"""

from collections import Counter
from collections.abc import Sequence
from datetime import UTC, date, datetime, time, timedelta
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import RouteEventKind
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection
from app.models.route_ledger import RouteEpisode, RouteEvent
from app.models.scan import Scan
from app.schemas.attack_path import (
    LedgerScanOut,
    LedgerStepOut,
    RouteEndOut,
    RouteEpisodeOut,
    RouteHistoryMeta,
    RouteHistoryOut,
    RouteLedgerStatus,
    RouteTargetEndOut,
    RouteTrendPointOut,
)


def ledger_status(episode: RouteEpisode) -> RouteLedgerStatus:
    """NEW when the open episode began in the scan that last saw it.

    Per route rather than against an organization's "last scan", which does not
    exist: connections scan on their own schedules, and a route seen again by a
    later scan of its own connection is no longer new.
    """
    if episode.closed_at is not None:
        return "CLOSED"
    if episode.opened_scan_id is not None and episode.opened_scan_id == episode.last_seen_scan_id:
        return "NEW"
    return "OPEN"


def open_each_day(
    episodes: Sequence[RouteEpisode], first: date, last: date
) -> list[RouteTrendPointOut]:
    """Routes open at the end of each day from ``first`` to ``last``.

    Counted from the episodes' own times rather than per scan: a scan may read
    part of one connection, so a per-scan count would rise and fall with what
    each scan covered rather than with the estate.
    """
    points = []
    day = first
    while day <= last:
        end = datetime.combine(day + timedelta(days=1), time.min, tzinfo=UTC)
        points.append(
            RouteTrendPointOut(
                day=day,
                open=sum(
                    1
                    for episode in episodes
                    if episode.opened_at < end
                    and (episode.closed_at is None or episode.closed_at >= end)
                ),
            )
        )
        day += timedelta(days=1)
    return points


def _steps(steps: list | None) -> list[LedgerStepOut]:
    return [LedgerStepOut.model_validate(step) for step in steps or []]


async def route_history(
    session: AsyncSession,
    organization_id: UUID,
    *,
    days: int,
    now: datetime | None = None,
) -> tuple[RouteHistoryOut, RouteHistoryMeta]:
    """Open episodes, those closed within ``days``, the trend, and the latest move."""
    now = now or datetime.now(UTC)
    since = now - timedelta(days=days)
    episodes = list(
        (
            await session.execute(
                select(RouteEpisode)
                .where(
                    RouteEpisode.organization_id == organization_id,
                    or_(RouteEpisode.closed_at.is_(None), RouteEpisode.closed_at >= since),
                )
                .order_by(RouteEpisode.opened_at.desc())
            )
        ).scalars()
    )
    keys = {episode.route_key for episode in episodes}
    # Which of these routes closed before and came back: an earlier episode of
    # the same route, closed, exists.
    closed_before = Counter(
        (
            await session.execute(
                select(RouteEpisode.route_key).where(
                    RouteEpisode.organization_id == organization_id,
                    RouteEpisode.closed_at.is_not(None),
                    RouteEpisode.route_key.in_(keys),
                )
            )
        ).scalars()
    )
    rerouted_from = await _rerouted_from(
        session, [episode.id for episode in episodes if episode.rerouted_at is not None]
    )

    routes = [
        RouteEpisodeOut(
            id=episode.id,
            key=episode.route_key,
            entry=RouteEndOut(id=episode.entry_id, name=episode.entry_name),
            target=RouteTargetEndOut(
                id=episode.target_id,
                name=episode.target_name,
                data_sensitivity=episode.target_sensitivity,
            ),
            hops=episode.hops,
            steps=_steps(episode.steps),
            status=ledger_status(episode),
            # A closed episode counts itself among the closed ones.
            reopened=closed_before[episode.route_key] > (1 if episode.closed_at is not None else 0),
            opened_at=episode.opened_at,
            opened_scan_id=episode.opened_scan_id,
            last_seen_at=episode.last_seen_at,
            last_seen_scan_id=episode.last_seen_scan_id,
            rerouted_at=episode.rerouted_at,
            rerouted_from=rerouted_from.get(episode.id),
            closed_at=episode.closed_at,
            closed_scan_id=episode.closed_scan_id,
            close_reason=episode.close_reason,
        )
        for episode in episodes
    ]
    recorded_since = (
        await session.execute(
            select(func.min(RouteEpisode.opened_at)).where(
                RouteEpisode.organization_id == organization_id
            )
        )
    ).scalar_one_or_none()
    trend = (
        open_each_day(episodes, max(since.date(), recorded_since.date()), now.date())
        if recorded_since
        else []
    )
    return (
        RouteHistoryOut(routes=routes, trend=trend, latest=await _latest(session, organization_id)),
        RouteHistoryMeta(days=days, recorded_since=recorded_since),
    )


async def _rerouted_from(
    session: AsyncSession, episode_ids: list[UUID]
) -> dict[UUID, list[LedgerStepOut]]:
    """The way each rerouted episode ran before its latest reroute."""
    if not episode_ids:
        return {}
    found: dict[UUID, list[LedgerStepOut]] = {}
    for episode_id, steps in (
        await session.execute(
            select(RouteEvent.episode_id, RouteEvent.steps_before)
            .where(
                RouteEvent.episode_id.in_(episode_ids),
                RouteEvent.kind == RouteEventKind.REROUTED,
            )
            .order_by(RouteEvent.observed_at)
        )
    ).all():
        # Later rows overwrite earlier ones: the latest reroute is the one read.
        found[episode_id] = _steps(steps)
    return found


async def _latest(session: AsyncSession, organization_id: UUID) -> LedgerScanOut | None:
    """The latest scan that moved the ledger, with what it moved and what it read."""
    row = (
        await session.execute(
            select(RouteEvent.scan_id, RouteEvent.observed_at)
            .where(RouteEvent.organization_id == organization_id)
            .order_by(RouteEvent.observed_at.desc())
            .limit(1)
        )
    ).first()
    if row is None:
        return None
    scan_id, observed_at = row
    # That reading's moves: every event written at its time.
    counts = Counter(
        (
            await session.execute(
                select(RouteEvent.kind).where(
                    RouteEvent.organization_id == organization_id,
                    RouteEvent.observed_at == observed_at,
                )
            )
        ).scalars()
    )
    return LedgerScanOut(
        scan_id=scan_id,
        observed_at=observed_at,
        scope_name=await _scope_name(session, scan_id),
        opened=counts[RouteEventKind.OPENED],
        closed=counts[RouteEventKind.CLOSED],
        rerouted=counts[RouteEventKind.REROUTED],
    )


async def _scope_name(session: AsyncSession, scan_id: UUID | None) -> str | None:
    """What a scan read, by the name the customer gave it."""
    if scan_id is None:
        return None
    row = (
        await session.execute(
            select(CloudConnection.name, CloudAccount.display_name, CloudAccount.account_name)
            .select_from(Scan)
            .outerjoin(CloudConnection, CloudConnection.id == Scan.connection_id)
            .outerjoin(CloudAccount, CloudAccount.id == Scan.cloud_account_id)
            .where(Scan.id == scan_id)
        )
    ).first()
    if row is None:
        return None
    connection, display, account = row
    return connection or display or account
