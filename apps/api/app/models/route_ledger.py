"""The route ledger: which routes existed at each reading (DECISIONS.md §244).

The attack-path page rebuilds every route live from the stored graph, which
answers "what is open now" and nothing else. Whether a route is new, whether it
closed, and whether there are fewer than last week are questions about readings
over time, and nothing kept them: a route was a pure function of the graph, and
the graph is only ever the latest one.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import Level, RouteCloseReason, RouteEventKind
from app.models.base import Base, StrEnumType, TenantOwned, UUIDPrimaryKey


class RouteEpisode(UUIDPrimaryKey, TenantOwned, Base):
    """One stretch of time a route was open, from the scan that first saw it to
    the scan that no longer did.

    One row per episode rather than per route, so a route that closes and comes
    back opens a second row: the reopening is visible rather than overwritten,
    and "closed on the 3rd, back on the 9th" stays answerable.

    Written only by ANALYZE, through the scan's fenced writer, from the graph
    the scan already builds. Only the open episode of a route is ever updated.
    """

    __tablename__ = "route_episodes"
    __table_args__ = (
        # One open episode per route. A retried ANALYZE finds the one it opened
        # rather than opening a second.
        Index(
            "uq_route_episodes_open",
            "organization_id",
            "route_key",
            unique=True,
            postgresql_where=text("closed_at IS NULL"),
        ),
        # How the page reads it: what is open, and what closed recently.
        Index("ix_route_episodes_timeline", "organization_id", "closed_at", "opened_at"),
    )

    # The route's ends, as ``services.graph.route_key`` names them on the page.
    route_key: Mapped[str] = mapped_column(Text, nullable=False)
    # The connection whose scans see it. A deleted connection takes its routes'
    # history with it, so its routes never read as closed by a fix.
    connection_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cloud_connections.id", ondelete="CASCADE")
    )

    entry_id: Mapped[str] = mapped_column(Text, nullable=False)
    entry_name: Mapped[str] = mapped_column(String(400), nullable=False)
    target_id: Mapped[str] = mapped_column(Text, nullable=False)
    target_name: Mapped[str] = mapped_column(String(400), nullable=False)
    target_sensitivity: Mapped[Level] = mapped_column(StrEnumType(Level, 16), nullable=False)
    hops: Mapped[int] = mapped_column(Integer, nullable=False)
    # The route as last seen, hop by hop, in the shape a risk stores its path.
    # Kept so a closed route can still be read once its assets are gone.
    steps: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    # The links it crosses, each keyed as ``AssetGraph.removal_key`` keys it. A
    # route seen again with another shape was rerouted.
    shape: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    # SET NULL rather than CASCADE on every scan: pruning an execution log must
    # not rewrite history, the rule ``risk_history`` follows. The times stay.
    opened_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL")
    )
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL")
    )
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    rerouted_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL")
    )
    rerouted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL")
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    close_reason: Mapped[RouteCloseReason | None] = mapped_column(StrEnumType(RouteCloseReason, 16))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class RouteEvent(UUIDPrimaryKey, TenantOwned, Base):
    """One moment in a route's episode: opened, rerouted or closed.

    Append-only, written in bulk by the scan's writer. A REROUTED event keeps the
    way round the route used to take (``steps_before``), because the episode
    holds only the way it takes now, and "which way is left" is only half of
    what a customer who made a change wants to see.
    """

    __tablename__ = "route_events"
    __table_args__ = (Index("ix_route_events_episode", "episode_id", "observed_at"),)

    episode_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("route_episodes.id", ondelete="CASCADE"),
        nullable=False,
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="SET NULL")
    )
    kind: Mapped[RouteEventKind] = mapped_column(StrEnumType(RouteEventKind, 16), nullable=False)
    # When the provider was read, not when the row was written.
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    reason: Mapped[RouteCloseReason | None] = mapped_column(StrEnumType(RouteCloseReason, 16))
    steps_before: Mapped[list | None] = mapped_column(JSONB)
