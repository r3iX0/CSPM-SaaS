"""The asset inventory: which resources a scan saw, and how they are linked.

The first thing an analysis writes, because everything after it points at
these rows -- a finding is about an asset, and a route passes through them.
"""

from uuid import UUID

from sqlalchemy import select

from app.connectors.base import NormalizedState
from app.core.enums import AssetChange, RelationshipType
from app.domain.resource import CloudResource
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection
from app.models.history import AssetChangeEvent
from app.models.resource import ResourceRecord, ResourceRelationship
from app.services.scan.context import AnalyzeContext
from app.services.scan.scope import asset_scope
from app.services.scan.writer import ScanWriter


async def existing_resource_ids(ctx: AnalyzeContext) -> dict[str, UUID]:
    """Provider id -> database id, read without writing anything.

    The evaluation-only counterpart to ``persist_resources``. Resources in
    the snapshot that no longer have a row simply have no id, so the gaps
    they produce are recorded against the scan rather than against an asset
    -- which is accurate: there is no asset to point at any more.

    One query for every subscription, for the same reason its writing
    counterpart takes them all at once. Directory assets are read by
    connection in the same statement: they have no account, so an
    account-only filter would leave every identity gap unattributed.
    """
    scope = asset_scope(ctx.account_ids, ctx.connection_id)
    if scope is None:
        return {}
    rows = (
        (
            await ctx.session.execute(
                select(
                    ResourceRecord.provider_resource_id, ResourceRecord.id
                ).where(ResourceRecord.organization_id == ctx.org_id, scope)
            )
        )
        .tuples()
        .all()
    )
    return dict(rows)


async def persist_resources(
    ctx: AnalyzeContext,
    account_state: list[tuple[CloudAccount, NormalizedState]],
    *,
    directory: tuple[CloudConnection, NormalizedState] | None = None,
) -> dict[str, UUID]:
    """Upsert this scan's assets, returning provider id -> row id.

    Resources are updated rather than replaced so ``first_seen_at`` survives
    and a finding keeps pointing at the same asset row across scans.

    ``observed_at`` is when the state was *captured*, not when it was
    processed. The two are the same for a live scan and months apart for a
    replay, and ``last_seen_at`` means nothing if a replay of an old
    snapshot can report a deleted resource as seen today.

    Assets arrive in two scopes and are keyed differently because they are
    different things. A subscription's assets are keyed by (account,
    provider id); the directory's are keyed by (connection, provider id) and
    written once, which is the whole point -- keyed per account they became
    one row per subscription for every user in the tenant, and one finding
    per subscription for every administrator missing MFA.

    Every subscription is handled in one pass on purpose. Per-subscription
    this was one query for the existing rows, one more for *each newly
    created resource* to read back an id the flush had already assigned, and
    a scan of the organization's whole relationship table -- so a tenant of
    fifty subscriptions holding five hundred resources each issued tens of
    thousands of statements to write what is now four.

    The change events and edges go through the writer: neither is read back
    before the commit, and a large first scan produces one event for every
    asset it has never seen.
    """
    session, org_id, now = ctx.session, ctx.org_id, ctx.observed_at
    account_ids = [account.id for account, _ in account_state]
    scope = asset_scope(
        account_ids, directory[0].id if directory is not None else None
    )
    if scope is None:
        return {}

    existing = {
        (row.cloud_account_id, row.provider_resource_id): row
        for row in (
            await session.execute(
                select(ResourceRecord).where(
                    ResourceRecord.organization_id == org_id, scope
                )
            )
        )
        .scalars()
        .all()
    }

    # Held as objects rather than looked up again afterwards. The rows were
    # already in hand; the read-back loop existed only because this
    # reference was dropped.
    touched: dict[str, ResourceRecord] = {}
    # (row, what changed, before, after). Collected rather than written
    # inline because the rows are not flushed yet: a change event needs the
    # asset's primary key, and a new asset has none until the flush below.
    changes: list[tuple[ResourceRecord, AssetChange, str | None, str | None]] = []

    def upsert(
        resource: CloudResource,
        *,
        account_id: UUID | None,
        connection_id: UUID | None,
    ) -> None:
        row = existing.get((account_id, resource.provider_resource_id))
        if row is None:
            row = ResourceRecord(
                organization_id=org_id,
                cloud_account_id=account_id,
                connection_id=connection_id,
                provider=resource.provider,
                provider_resource_id=resource.provider_resource_id,
                first_seen_at=now,
            )
            session.add(row)
            changes.append((row, AssetChange.APPEARED, None, None))
        else:
            # Everything the risk engine multiplies a finding by, and
            # nothing else. Diffing whole payloads would produce a feed
            # nobody can read, and the drift that matters already arrives
            # as a finding.
            for change, before, after in (
                (
                    AssetChange.EXPOSURE_CHANGED,
                    row.public_exposure,
                    resource.public_exposure,
                ),
                (
                    AssetChange.SENSITIVITY_CHANGED,
                    row.data_sensitivity,
                    resource.data_sensitivity,
                ),
                (
                    AssetChange.CRITICALITY_CHANGED,
                    row.criticality,
                    resource.criticality,
                ),
            ):
                if before != after:
                    changes.append((row, change, before.value, after.value))
            if row.absent_since is not None:
                # It came back. One asset that vanished for a week, not two
                # assets -- which is why the row was kept rather than
                # deleted when it went.
                changes.append((row, AssetChange.APPEARED, None, None))
        row.absent_since = None

        row.resource_type = resource.resource_type
        row.name = resource.name
        row.region = resource.region
        row.environment = resource.environment
        row.criticality = resource.criticality
        row.data_sensitivity = resource.data_sensitivity
        row.public_exposure = resource.public_exposure
        # Written beside the values they explain, never separately. A row
        # holding CRITICAL with a source of 'none' would be a claim with no
        # author, which is worse than no source at all.
        row.criticality_source = resource.criticality_source
        row.data_sensitivity_source = resource.data_sensitivity_source
        row.environment_source = resource.environment_source
        row.resource_metadata = resource.metadata
        # Never moved backwards. A replay carries the capture's own
        # time, which is older than a detection already recorded
        # against a live scan -- and "last seen" going backwards would
        # be a lie in the one direction that matters, making a present
        # resource look stale.
        row.last_seen_at = max(row.last_seen_at or now, now)
        touched[resource.provider_resource_id] = row

    for account, state in account_state:
        for resource in state.resources:
            upsert(
                resource,
                account_id=account.id,
                connection_id=account.connection_id,
            )

    # The directory last, and the order is load-bearing. ``touched`` is
    # keyed by provider id alone, so if a scan run before this split left
    # per-account copies of a user behind, whichever scope is written second
    # is the row findings get attributed to. That has to be the tenant-scoped
    # one: it is the row that will still be here after the stale copies age
    # out, and attributing to a per-account copy would re-create the
    # duplicate finding this split exists to remove.
    if directory is not None:
        connection, directory_state = directory
        for resource in directory_state.resources:
            upsert(resource, account_id=None, connection_id=connection.id)

    # Assets this scan covered and did not find. Recorded as a transition
    # rather than left to be inferred: an absence derived from
    # ``last_seen_at`` would need a scan cadence nobody records, and would
    # re-report itself on every scan afterwards.
    for row in existing.values():
        if row.provider_resource_id in touched or row.absent_since is not None:
            continue
        row.absent_since = now
        changes.append((row, AssetChange.DISAPPEARED, None, None))

    # One flush assigns every pending primary key.
    await session.flush()
    for row, change, before, after in changes:
        ctx.writer.add(
            AssetChangeEvent,
            resource_id=row.id,
            scan_id=ctx.scan.id,
            change=change,
            previous_value=before,
            current_value=after,
            observed_at=now,
        )
    id_map = {provider_id: row.id for provider_id, row in touched.items()}

    edges = [edge for _account, state in account_state for edge in state.relationships]
    if directory is not None:
        edges.extend(directory[1].relationships)
    _persist_relationships(ctx.writer, edges, id_map)
    await ctx.writer.commit()
    return id_map


def _persist_relationships(
    writer: ScanWriter,
    edges: list[tuple[str, RelationshipType, str]],
    id_map: dict[str, UUID],
) -> None:
    """Record every edge between two assets this scan wrote.

    Without reading what is already recorded. The read was only ever there to
    skip edges that existed -- first across the organization's whole table,
    then narrowed to the sources being written -- and an edge is a fact that is
    either stored or not, so the writer's ``ON CONFLICT DO NOTHING`` on
    ``uq_resource_relationships_edge`` answers the same question inside the
    insert, for no read at all.

    Deduplicated here all the same: two subscriptions can report the same
    edge, and one row per edge is less to send.
    """
    wanted = {
        (id_map[s], rel, id_map[t])
        for s, rel, t in edges
        if s in id_map and t in id_map
    }
    for source, rel, target in wanted:
        writer.add(
            ResourceRelationship,
            source_resource_id=source,
            target_resource_id=target,
            relationship_type=rel,
        )


def group_edges(state: NormalizedState) -> dict[tuple[str, str], list[str]]:
    grouped: dict[tuple[str, str], list[str]] = {}
    for source, rel_type, target in state.relationships:
        grouped.setdefault((source, rel_type.value), []).append(target)
    return grouped
