"""Captures: how a reading is stored, and how it is read back.

Every scan writes a snapshot before anything is interpreted, so a scan can be
re-evaluated later against improved rules. This is both halves of that promise
-- the manifest a capture is stored as, and the reconstruction ANALYZE and
replay share -- so the two can never disagree about what a capture contains.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.base import NormalizedState, RawSnapshot
from app.connectors.evidence import EvidenceCategory
from app.connectors.registry import get_connector
from app.context import ContextDeclaration, resolve_resource
from app.core.enums import Provider, ScanStepKind
from app.core.errors import SnapshotUnavailable
from app.core.payloads import digest
from app.core.vocabulary import words
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection
from app.models.context import ContextDeclarationRecord
from app.models.scan import CloudSnapshot, EvidenceBlob, Scan, ScanStep


def manifest(snapshot: RawSnapshot) -> dict:
    """The capture, minus the bytes, plus where to find them.

    Everything ``to_json`` records except ``data``, and in its place the content
    hash of each reading. The payloads live once in ``evidence_blobs``, shared
    by every scan that read identical bytes -- so an estate that has not changed
    stores one copy rather than one per night.

    The hashes are computed the same way ``record_evidence`` computes them,
    from the same ``snapshot.payloads``, so a manifest and the evidence rows
    beside it can never name different bytes for one reading.
    """
    stored = snapshot.to_json()
    stored.pop("data", None)
    stored["payload_hashes"] = {
        key: digest(payload)[0] for key, payload in snapshot.payloads.items()
    }
    return stored


async def rebuild_capture(
    session: AsyncSession,
    organization_id: UUID,
    row: CloudSnapshot,
    payloads: dict[str, dict] | None = None,
) -> dict:
    """The stored form of a capture, whichever way it was written.

    A capture written before the manifest carries its payloads inline and is
    returned as it stands. A manifest is rebuilt by merging the blobs it names,
    which is exactly what ``TestCaptureReconstruction`` proves adds back up to
    what used to be stored.

    Merged rather than keyed by reading, and that is the case a careless version
    of this gets wrong: one task can produce several payload keys.
    ``authentication_methods`` has no task of its own -- the directory's
    role-map task reads it -- so a rebuild that assumed one key per reading
    would drop it, and the MFA rule would find nothing to judge while reporting
    no error at all.

    A missing blob is refused rather than silently skipped. Half a capture
    replays as an estate that has lost whatever was in the missing half, which
    is the same overclaim as a PASS nobody earned -- retention's interlock
    exists so this cannot happen, and this is what says so if it ever does.

    ``payloads`` is the readings already in hand, keyed by content hash. A
    tenant-wide scan rebuilds one capture per subscription and each rebuild was
    a query of its own, so a fifty-subscription analysis opened with fifty
    round trips before it read a rule -- see :func:`payloads_by_hash`,
    which fetches the lot in one. Absent, this asks for its own, which is what a
    single-capture caller wants.

    **The manifest decides which form this is, not ``data``.** This used to ask
    whether ``data`` was NULL, and that question could not be answered by the
    column: 0001 created it ``DEFAULT '{}'::jsonb`` and 0027 dropped only its
    NOT NULL, so a capture written as a manifest came back carrying an empty
    object and read as an inline capture of an estate with nothing in it. Every
    scan then failed in ANALYZE, on a capture that had been stored perfectly.
    0029 removes the default and clears those rows; asking about the manifest
    instead is what stops a column default ever answering "did anybody write
    this" again.
    """
    if row.manifest is None:
        if not row.data:
            raise SnapshotUnavailable(
                "this capture carries neither a manifest nor any inline "
                "readings, so there is nothing to replay it from"
            )
        return dict(row.data)

    manifest = dict(row.manifest)
    hashes = dict(manifest.pop("payload_hashes", {}) or {})
    held = payloads if payloads is not None else await payloads_by_hash(
        session, organization_id, set(hashes.values())
    )

    data: dict = {}
    for key, content_hash in hashes.items():
        payload = held.get(content_hash)
        if payload is None:
            raise SnapshotUnavailable(
                f"the stored reading for {key} is no longer held, so this "
                "capture cannot be replayed without describing an estate that "
                "is missing whatever it contained"
            )
        data.update(payload)

    manifest["data"] = data
    return manifest


def manifest_hashes(rows: Sequence[CloudSnapshot]) -> set[str]:
    """Every payload hash these captures name.

    Empty for a capture written before manifests, which carries its readings
    inline and needs nothing fetched.
    """
    return {
        content_hash
        for row in rows
        if row.manifest
        for content_hash in (row.manifest.get("payload_hashes") or {}).values()
    }


async def payloads_by_hash(
    session: AsyncSession, organization_id: UUID, hashes: set[str]
) -> dict[str, dict]:
    """The stored readings these hashes name, decompressed.

    One statement whatever the number of captures asking, which is the point of
    lifting it out of the per-capture rebuild: the hashes are content-addressed
    and a tenant's subscriptions share plenty of them, so a merged fetch is both
    fewer round trips and fewer decompressions than one query per capture.
    """
    if not hashes:
        return {}
    return {
        blob.content_hash: blob.content
        for blob in (
            await session.execute(
                select(EvidenceBlob).where(
                    EvidenceBlob.organization_id == organization_id,
                    EvidenceBlob.content_hash.in_(list(hashes)),
                )
            )
        )
        .scalars()
        .all()
    }


@dataclass
class ReconstructedScan:
    """A scan's captures, read back and normalized.

    What the single-task pipeline used to carry in memory between collection
    and evaluation. Reading it back from the captures is not a workaround for
    having split the two apart: everything after a capture is already a pure
    function of it -- the property replay depends on -- so this is the same
    operation the pipeline always performed.
    """

    merged: NormalizedState = field(default_factory=NormalizedState)
    account_state: list[tuple[CloudAccount, NormalizedState]] = field(
        default_factory=list
    )
    directory: tuple[CloudConnection, NormalizedState] | None = None
    errors: dict[str, str] = field(default_factory=dict)
    # Whether these captures are still CloudGuard's current picture. False when
    # any of them has been superseded, which is what forbids resolving a finding
    # from them.
    is_current: bool = True
    observed_at: datetime = field(default_factory=lambda: datetime.now(UTC))


def _scoped_key(
    account: CloudAccount, category: str, account_count: int
) -> str:
    """Category name, qualified by subscription when there is more than one.

    ``account_count`` counts *subscriptions*, not captures. A scan now
    stores a directory capture alongside them, and counting captures made a
    single-subscription scan look like two -- so its errors were qualified
    with a subscription id nobody needed, turning a plain "storage" into
    "00000000-0000-0000-0000-000000000001: storage" on the one screen whose
    job is to be readable.
    """
    if account_count == 1:
        return category
    return f"{account.display_name or account.subscription_id}: {category}"


async def reconstruct(
    session: AsyncSession,
    scan: Scan,
    stored: list[CloudSnapshot],
    *,
    check_freshness: bool = False,
) -> ReconstructedScan:
    """Read captures back into the state the rule engine evaluates.

    Shared verbatim by ANALYZE and by replay, and the sharing is the point.
    The two differ in one thing only -- whether the captures being read are
    this scan's own or an earlier scan's, which is what ``check_freshness``
    asks about -- and if the paths diverged, a replay would stop being
    evidence about the pipeline a real scan runs.

    ``check_freshness`` decides whether findings may be touched at all. A
    capture that has since been superseded describes an environment that has
    moved on, and resolving a finding from it would stamp "verified fixed"
    against something nobody looked at.
    """
    org_id = scan.organization_id
    state = ReconstructedScan(observed_at=min(row.created_at for row in stored))

    # Both lookups are done for the whole set rather than inside the loop:
    # one subscription's account and one subscription's newest capture are
    # two statements each, which a tenant-wide scan would multiply by every
    # subscription it covered.
    accounts = await _accounts_by_id(
        session,
        org_id,
        [row.cloud_account_id for row in stored if row.cloud_account_id],
    )
    newest_by_account = (
        await _newest_snapshot_ids(session, org_id, list(accounts))
        if check_freshness
        else {}
    )
    # What the customer has said about these subscriptions since the capture
    # was taken. Read here rather than at collection time on purpose: a
    # declaration is not part of the environment, so it must not be frozen
    # into the capture -- marking a subscription production today should
    # change how its findings rank today, including on a replay of an older
    # reading.
    declarations = await _declarations_for(session, org_id, list(accounts))
    # Every reading of every capture, in one statement. A rebuild used to
    # fetch its own, so an analysis of a tenant with fifty subscriptions
    # opened with fifty queries against the largest table in the schema
    # before a single rule ran -- and the captures share hashes, because
    # content addressing is the whole reason two subscriptions with the same
    # empty listing store it once.
    payloads = await payloads_by_hash(
        session, org_id, manifest_hashes(stored)
    )

    for row in stored:
        # The directory capture, read on its own terms. It is a reading of
        # the tenant, so it has no account to resolve and no
        # per-subscription staleness to check -- only whether a later scan
        # has since re-read the same directory through the same connection.
        if row.cloud_account_id is None:
            restored = await _restore_directory(
                session,
                org_id,
                row,
                check_freshness=check_freshness,
                payloads=payloads,
            )
            if restored is None:
                state.is_current = False
                continue
            state.directory, snapshot, current = restored
            state.is_current = state.is_current and current
            state.merged.resources.extend(state.directory[1].resources)
            state.merged.relationships.extend(state.directory[1].relationships)
            state.merged.collection_errors.update(
                state.directory[1].collection_errors
            )
            # Tenant defences. They come from the directory reading and are
            # about the whole tenant, so they merge once rather than per
            # subscription -- the same reason the directory is read once.
            state.merged.controls.update(state.directory[1].controls)
            state.errors.update(snapshot.errors)
            continue

        account = accounts.get(row.cloud_account_id)
        if account is None:
            # The subscription is gone. Its capture is still real history,
            # but there is nothing left to attribute the resources to, so it
            # cannot be re-evaluated.
            state.is_current = False
            continue

        if check_freshness and row.id != newest_by_account.get(account.id):
            state.is_current = False

        snapshot = RawSnapshot.from_json(
            await rebuild_capture(session, org_id, row, payloads)
        )
        connector = get_connector(
            account.provider,
            tenant_id=account.tenant_id,
            subscription_id=account.subscription_id,
            provider_ref=account.provider_ref,
        )
        account_state = connector.normalize(snapshot)
        # Normalization is a pure function of the capture, so this is where
        # the customer's own view of the subscription is applied: as a
        # floor over what was inferred, never as an override of it.
        declared = declarations.get(account.id)
        if declared is not None:
            account_state.resources = [
                resolve_resource(resource, declared)
                for resource in account_state.resources
            ]
        state.account_state.append((account, account_state))
        state.merged.resources.extend(account_state.resources)
        state.merged.relationships.extend(account_state.relationships)
        # Namespaced by subscription: two subscriptions can both fail to
        # read storage, and "storage: timeout" twice over tells a customer
        # nothing about which one to look at.
        for category, reason in snapshot.errors.items():
            state.errors[
                _scoped_key(account, category, len(accounts))
            ] = reason
        state.merged.collection_errors.update(account_state.collection_errors)

    return state


async def _declarations_for(
    session: AsyncSession, org_id: UUID, account_ids: list[UUID]
) -> dict[UUID, ContextDeclaration]:
    """Customer-declared context for the subscriptions this scan covers.

    One statement for the whole scan. A tenant-wide scan covers as many
    subscriptions as the customer has, and a lookup per subscription is the
    shape that turned every other batch read in this pipeline into a
    thousand statements.
    """
    if not account_ids:
        return {}
    rows = (
        (
            await session.execute(
                select(ContextDeclarationRecord).where(
                    ContextDeclarationRecord.organization_id == org_id,
                    ContextDeclarationRecord.cloud_account_id.in_(account_ids),
                )
            )
        )
        .scalars()
        .all()
    )
    return {
        row.cloud_account_id: ContextDeclaration(
            environment=row.environment,
            criticality=row.criticality,
            data_sensitivity=row.data_sensitivity,
            # Declared about the subscription, so every asset inside it
            # inherits the claim rather than being the subject of it. The
            # recorded source has to say which, or "you told us this" would
            # be shown against an asset nobody has ever looked at.
            inherited=True,
        )
        for row in rows
    }


async def directory_gap(
    session: AsyncSession, scan: Scan, state: ReconstructedScan
) -> dict[str, str]:
    """Why the identity checks have no directory, when they have none.

    A scan with no directory capture must not let its identity rules pass:
    failing to look is not the same as looking and finding nothing. The
    steps say which of the two happened -- a directory step that failed, or
    no directory step at all because there was no grant to read one through
    -- and the two need different sentences, because they send the customer
    to different places.

    Written into the rule-facing gaps keyed per evidence key, not per
    category. A category name there would match nothing a rule declares, and
    every identity check would quietly PASS over a directory nobody read.
    """
    if state.directory is not None:
        return {}

    step = (
        await session.execute(
            select(ScanStep).where(
                ScanStep.scan_id == scan.id,
                ScanStep.kind == ScanStepKind.COLLECT,
                ScanStep.cloud_account_id.is_(None),
            )
        )
    ).scalar_one_or_none()

    # The connection this scan runs through, for its words alone. A customer
    # reading "the tenant directory" about an AWS organization is reading a
    # product that has not noticed which cloud it is looking at.
    connection = (
        await session.get(CloudConnection, scan.connection_id)
        if scan.connection_id
        else None
    )
    scope_words = words(connection.provider if connection else None)
    if step is None:
        reason = (
            "This scan has no cloud connection behind it, so CloudGuard has "
            f"no grant to read its {scope_words.directory}. Reconnect it "
            "from the connections page."
        )
    else:
        reason = (
            f"The {scope_words.directory} could not be read for this scan, "
            "so no identity check could reach a verdict. "
            f"({step.error or 'unknown error'})"
        )

    # Asked of the connector rather than of Azure's key enum directly. The
    # pipeline is the provider-neutral half of this system, and a second
    # connector whose categories it could not ask would degrade nothing.
    provider = await _provider_of(session, scan)
    for key in get_connector(provider).evidence_keys_in(EvidenceCategory.IDENTITY):
        state.merged.collection_errors[key.value] = reason
    return {EvidenceCategory.IDENTITY.value: reason}


async def _provider_of(session: AsyncSession, scan: Scan) -> Provider:
    """Which cloud this scan is reading.

    Off the connection or the subscription, because a scan is scoped to one
    or the other and both name their provider. Not stored on the scan: it
    would be a third place the same fact lives, and the one most likely to
    disagree after a row is edited.
    """
    if scan.connection_id is not None:
        connection = await session.get(CloudConnection, scan.connection_id)
        if connection is not None:
            return connection.provider
    if scan.cloud_account_id is not None:
        account = await session.get(CloudAccount, scan.cloud_account_id)
        if account is not None:
            return account.provider
    # A scan scoped to neither cannot have collected anything, so nothing
    # downstream of this will be asked for a key. Azure is the fallback
    # rather than an error because raising here would turn "this scan had
    # no scope" into an exception in the code that explains gaps.
    return Provider.AZURE


async def snapshots_of(
    session: AsyncSession, org_id: UUID, scan_id: UUID
) -> list[CloudSnapshot]:
    """Every capture stored under one scan, oldest first.

    Scoped by organization as well as by scan. The id arrives on a scan row
    rather than from a request, but a tenant boundary enforced only where
    input is untrusted is one nobody can reason about.
    """
    return list(
        (
            await session.execute(
                select(CloudSnapshot)
                .where(
                    CloudSnapshot.scan_id == scan_id,
                    CloudSnapshot.organization_id == org_id,
                )
                .order_by(CloudSnapshot.created_at)
            )
        )
        .scalars()
        .all()
    )


async def stored_snapshots(
    session: AsyncSession, org_id: UUID, scan: Scan
) -> list[CloudSnapshot]:
    """Every snapshot the replayed scan stored, one per subscription.

    Scoped by organization as well as scan id: the id arrives on the scan
    row rather than from a request, but a tenant boundary that is only
    enforced where input is untrusted is one nobody can reason about.
    """
    if scan.replay_of_scan_id is None:
        return []
    return list(
        (
            await session.execute(
                select(CloudSnapshot)
                .where(
                    CloudSnapshot.scan_id == scan.replay_of_scan_id,
                    CloudSnapshot.organization_id == org_id,
                )
                .order_by(CloudSnapshot.created_at)
            )
        )
        .scalars()
        .all()
    )


async def _restore_directory(
    session: AsyncSession,
    org_id: UUID,
    row: CloudSnapshot,
    *,
    check_freshness: bool = False,
    payloads: dict[str, dict] | None = None,
) -> tuple[tuple[CloudConnection, NormalizedState], RawSnapshot, bool] | None:
    """Re-normalize a stored directory capture.

    Returns the state, the snapshot it came from, and whether that capture
    is still the newest directory read for its connection. ``None`` when
    the connection is gone -- the capture remains real history, but there is
    no tenant left to attribute directory assets to.

    The staleness question is the same one asked of a subscription, asked of
    the right thing. A directory capture from last month cannot resolve an
    MFA finding today, for exactly the reason a month-old subscription
    capture cannot resolve a storage finding: nothing was observed.
    """
    if row.connection_id is None:
        return None
    connection = await session.get(CloudConnection, row.connection_id)
    if connection is None or connection.organization_id != org_id:
        return None

    # Skipped when a scan is reading its own captures: they were taken
    # moments ago and are the newest by construction, so the query would be
    # a round trip to confirm what the caller already knows.
    newest = (
        (
            await session.execute(
                select(CloudSnapshot.id)
                .where(
                    CloudSnapshot.organization_id == org_id,
                    CloudSnapshot.connection_id == connection.id,
                    CloudSnapshot.cloud_account_id.is_(None),
                )
                .order_by(
                    CloudSnapshot.created_at.desc(), CloudSnapshot.id.desc()
                )
                .limit(1)
            )
        ).scalar_one_or_none()
        if check_freshness
        else row.id
    )

    snapshot = RawSnapshot.from_json(
        await rebuild_capture(session, org_id, row, payloads)
    )
    connector = get_connector(
        connection.provider,
        tenant_id=connection.tenant_id,
        subscription_id=None,
        provider_ref=connection.provider_ref,
    )
    state = connector.normalize(snapshot)
    return (connection, state), snapshot, row.id == newest


async def _accounts_by_id(
    session: AsyncSession, org_id: UUID, account_ids: list[UUID]
) -> dict[UUID, CloudAccount]:
    if not account_ids:
        return {}
    rows = (
        (
            await session.execute(
                select(CloudAccount).where(
                    CloudAccount.organization_id == org_id,
                    CloudAccount.id.in_(account_ids),
                )
            )
        )
        .scalars()
        .all()
    )
    return {account.id: account for account in rows}


async def _newest_snapshot_ids(
    session: AsyncSession, org_id: UUID, account_ids: list[UUID]
) -> dict[UUID, UUID]:
    """The most recent snapshot for each of these subscriptions.

    One grouped query rather than one per subscription. ``DISTINCT ON`` is
    PostgreSQL-specific and this application targets exactly one database
    (DECISIONS.md section 13), so the portable-but-slower alternative would
    be paying for a portability nothing asks for.
    """
    if not account_ids:
        return {}
    rows = (
        (
            await session.execute(
                select(CloudSnapshot.cloud_account_id, CloudSnapshot.id)
                .where(
                    CloudSnapshot.organization_id == org_id,
                    # Not merely redundant with the ``in_`` beside it. The
                    # column is nullable now -- a directory capture has no
                    # account -- and the NOT NULL is what lets the result be
                    # read as the account-keyed mapping this returns.
                    CloudSnapshot.cloud_account_id.is_not(None),
                    CloudSnapshot.cloud_account_id.in_(account_ids),
                )
                .distinct(CloudSnapshot.cloud_account_id)
                .order_by(
                    CloudSnapshot.cloud_account_id,
                    CloudSnapshot.created_at.desc(),
                    CloudSnapshot.id.desc(),
                )
            )
        )
        .tuples()
        .all()
    )
    # The NOT NULL in the query is what makes this narrowing sound; the
    # comprehension states it in a form the type checker can follow.
    return {
        account_id: snapshot_id
        for account_id, snapshot_id in rows
        if account_id is not None
    }
