"""The route ledger, written by ANALYZE (DECISIONS.md §244).

Correlation turns the routes with something misconfigured on them into risks.
This records every route the scan's graph holds, misconfigured or not, as an
episode: opened by the scan that first saw it, carried by every scan that saw it
again, closed by the first scan that could have seen it and did not. The page
reads it to say what is new, what closed and whether there are fewer.

The rules are correlation's, because the question is the same one: a scan sees
only its own scope, so it closes only the routes wholly inside it, and an asset
with no row left is inside, because it is gone and so is every route through it.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import select

from app.core.enums import RouteCloseReason, RouteEventKind
from app.graph import AssetGraph, Path
from app.models.cloud_account import CloudAccount
from app.models.resource import ResourceRecord
from app.models.route_ledger import RouteEpisode, RouteEvent
from app.services.graph import route_key
from app.services.scan.context import AnalyzeContext
from app.services.scan.scope import asset_scope

type Shape = list[list[str]]


@dataclass(frozen=True)
class SeenRoute:
    """A route this scan's graph holds, with the links it crosses."""

    key: str
    path: Path
    shape: Shape


@dataclass(frozen=True)
class LedgerPlan:
    """What one reading does to the ledger, before any scope is consulted."""

    #: Routes with no open episode: each opens one.
    opened: tuple[SeenRoute, ...]
    #: Open episodes seen again, with the route as it runs now.
    seen_again: tuple[tuple[RouteEpisode, SeenRoute], ...]
    #: Open episodes this reading did not see. Closed only where in scope.
    unseen: tuple[RouteEpisode, ...]


def route_shape(graph: AssetGraph, path: Path) -> Shape:
    """The links a route crosses, keyed as the thing somebody removes.

    Keyed by ``removal_key`` rather than as drawn, so an escalation line beside
    its role line is one link here as it is one cut on the page (§127), and a
    route does not read as rerouted because the walk crossed the other of two
    lines that are the same assignment.
    """
    return [
        list(
            graph.removal_key(
                step.source.provider_resource_id,
                step.relationship,
                step.target.provider_resource_id,
            )
        )
        for step in path.steps
    ]


def observed_routes(graph: AssetGraph) -> list[SeenRoute]:
    """Every route the graph holds, as the ledger keys it."""
    return [
        SeenRoute(key=route_key(path), path=path, shape=route_shape(graph, path))
        for path in graph.attack_paths()
    ]


def plan_ledger(open_episodes: Mapping[str, RouteEpisode], seen: Sequence[SeenRoute]) -> LedgerPlan:
    """Sort this reading's routes against the open episodes, by key.

    Pure, so the rules -- a route seen again keeps its episode, a route not seen
    is a candidate to close -- are tested without a database.
    """
    seen_keys = {route.key for route in seen}
    return LedgerPlan(
        opened=tuple(route for route in seen if route.key not in open_episodes),
        seen_again=tuple(
            (open_episodes[route.key], route) for route in seen if route.key in open_episodes
        ),
        unseen=tuple(episode for key, episode in open_episodes.items() if key not in seen_keys),
    )


def stored_steps(path: Path) -> list[dict[str, str]]:
    """The route hop by hop, in the shape a risk stores its path."""
    return [
        {
            "source": step.source.name,
            "source_id": step.source.provider_resource_id,
            "relationship": step.relationship.value,
            "target": step.target.name,
            "target_id": step.target.provider_resource_id,
            "description": step.describe(),
        }
        for step in path.steps
    ]


def episode_nodes(episode: RouteEpisode) -> set[str]:
    """Every asset an episode's route passes through, by provider id."""
    nodes = {episode.entry_id, episode.target_id}
    for step in episode.steps or []:
        nodes.update(str(step[end]) for end in ("source_id", "target_id") if step.get(end))
    return nodes


def close_reason(nodes: set[str], absent: set[str]) -> RouteCloseReason:
    """Why a route in scope closed: an asset on it went, or a link did."""
    return RouteCloseReason.ASSET_GONE if nodes & absent else RouteCloseReason.LINK_REMOVED


def is_rerouted(episode: RouteEpisode, route: SeenRoute, scan_id: UUID) -> bool:
    """Whether a route seen again runs another way round than it last did.

    Never against a shape this same scan wrote: a retried ANALYZE reads back
    the episode the first attempt carried, and its shape is this scan's own.
    """
    return episode.shape != route.shape and episode.last_seen_scan_id != scan_id


async def record_routes(ctx: AnalyzeContext, graph: AssetGraph) -> None:
    """Open, carry and close this reading's episodes. Committed by the caller.

    Idempotent under a retried ANALYZE: the episodes a first attempt opened are
    open now and are carried rather than opened again, an episode it closed is
    no longer open, and a shape it recorded no longer differs. So a retry writes
    no event twice.
    """
    session, org_id, scan = ctx.session, ctx.org_id, ctx.scan
    at = ctx.observed_at
    open_episodes = {
        episode.route_key: episode
        for episode in (
            await session.execute(
                select(RouteEpisode).where(
                    RouteEpisode.organization_id == org_id,
                    RouteEpisode.closed_at.is_(None),
                )
            )
        ).scalars()
    }
    plan = plan_ledger(open_episodes, observed_routes(graph))
    connection_id = await _connection_of(ctx) if plan.opened else None

    for route in plan.opened:
        path = route.path
        episode = RouteEpisode(
            id=uuid4(),
            organization_id=org_id,
            route_key=route.key,
            connection_id=connection_id,
            entry_id=path.entry.provider_resource_id,
            entry_name=path.entry.name,
            target_id=path.target.provider_resource_id,
            target_name=path.target.name,
            target_sensitivity=path.target.data_sensitivity,
            hops=path.hops,
            steps=stored_steps(path),
            shape=route.shape,
            opened_scan_id=scan.id,
            opened_at=at,
            last_seen_scan_id=scan.id,
            last_seen_at=at,
        )
        session.add(episode)
        _event(ctx, episode.id, RouteEventKind.OPENED, at)

    for episode, route in plan.seen_again:
        path = route.path
        if is_rerouted(episode, route, scan.id):
            # The same ends by another way round. Recorded with the way it used
            # to run, because the episode holds only the way it runs now.
            _event(ctx, episode.id, RouteEventKind.REROUTED, at, steps_before=episode.steps)
            episode.rerouted_scan_id = scan.id
            episode.rerouted_at = at
        episode.entry_name = path.entry.name
        episode.target_name = path.target.name
        episode.target_sensitivity = path.target.data_sensitivity
        episode.hops = path.hops
        episode.steps = stored_steps(path)
        episode.shape = route.shape
        episode.last_seen_scan_id = scan.id
        episode.last_seen_at = at

    placed = await _placement(ctx, {node for e in plan.unseen for node in episode_nodes(e)})
    if placed is None:
        return
    outside, absent = placed
    for episode in plan.unseen:
        nodes = episode_nodes(episode)
        if outside & nodes:
            # Partly in a scope this scan did not read: its absence here says
            # only that the graph never held that part of the estate.
            continue
        reason = close_reason(nodes, absent)
        episode.closed_scan_id = scan.id
        episode.closed_at = at
        episode.close_reason = reason
        _event(ctx, episode.id, RouteEventKind.CLOSED, at, reason=reason)


def _event(
    ctx: AnalyzeContext,
    episode_id: UUID,
    kind: RouteEventKind,
    at: datetime,
    *,
    reason: RouteCloseReason | None = None,
    steps_before: list | None = None,
) -> None:
    values: dict[str, object] = {
        "id": uuid4(),
        "episode_id": episode_id,
        "scan_id": ctx.scan.id,
        "kind": kind.value,
        "observed_at": at,
    }
    # Only the columns an event of this kind sets: the writer groups rows by
    # the columns they carry, and an absent column keeps its default.
    if reason is not None:
        values["reason"] = reason.value
    if steps_before is not None:
        values["steps_before"] = steps_before
    ctx.writer.add(RouteEvent, **values)


async def _connection_of(ctx: AnalyzeContext) -> UUID | None:
    """The connection this scan reads through: the directory's, or its
    subscription's. None only for a subscription adopted before connections."""
    if ctx.connection_id is not None:
        return ctx.connection_id
    if not ctx.account_ids:
        return None
    return (
        await ctx.session.execute(
            select(CloudAccount.connection_id).where(CloudAccount.id == ctx.account_ids[0])
        )
    ).scalar_one_or_none()


async def _placement(ctx: AnalyzeContext, nodes: set[str]) -> tuple[set[str], set[str]] | None:
    """Of these assets, which sit in a scope this scan did not read, and which
    are gone. ``None`` when the scan covers nothing, which can close nothing.

    An asset with no row left counts as inside and gone, as correlation counts
    it (``correlation._outside_scope``). One marked absent is gone too: rows are
    kept when an asset disappears, so a later reappearance is one asset.
    """
    scope = asset_scope(ctx.account_ids, ctx.connection_id)
    if scope is None:
        return None
    if not nodes:
        return set(), set()
    known: set[str] = set()
    inside: set[str] = set()
    absent: set[str] = set()
    for provider_id, in_scope, absent_since in (
        await ctx.session.execute(
            select(ResourceRecord.provider_resource_id, scope, ResourceRecord.absent_since).where(
                ResourceRecord.organization_id == ctx.org_id,
                ResourceRecord.provider_resource_id.in_(nodes),
            )
        )
    ).all():
        known.add(provider_id)
        if in_scope:
            inside.add(provider_id)
        if absent_since is not None:
            absent.add(provider_id)
    return known - inside, absent | (nodes - known)
