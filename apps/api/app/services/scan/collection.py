"""Collection: reading one scope and storing what came back.

Interprets nothing. Everything after a capture is a pure function of it, which
is what lets ANALYZE -- and a replay months later -- read the capture back
instead of carrying state between steps.
"""

from collections.abc import Awaitable, Callable
from datetime import datetime
from uuid import UUID

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.base import NormalizedState, RawSnapshot
from app.connectors.planning import CollectionPlan
from app.connectors.registry import get_connector
from app.core.enums import TaskOutcome
from app.core.logging import get_logger
from app.core.payloads import digest
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection
from app.models.scan import CloudSnapshot, Evidence, EvidenceBlob, Scan
from app.services.cloud_connections import degraded_categories
from app.services.evidence_planner import plan_collection, required_evidence
from app.services.scan.capture import manifest
from app.services.scan.writer import ScanWriter

log = get_logger(__name__)


async def discard_prior_attempt(
    session: AsyncSession, scan: Scan, account_id: UUID | None
) -> None:
    """Clear what an earlier attempt at this scope stored.

    A capture is unique on (scan, scope), so a retry that simply wrote again
    would conflict; and a capture is supposed to be one reading rather than
    a merge of two, so clearing is also the honest thing rather than merely
    the convenient one. Evidence rows go with it, since they describe that
    reading.
    """
    scope = (
        CloudSnapshot.cloud_account_id == account_id
        if account_id is not None
        else CloudSnapshot.cloud_account_id.is_(None)
    )
    await session.execute(
        delete(CloudSnapshot).where(
            CloudSnapshot.organization_id == scan.organization_id,
            CloudSnapshot.scan_id == scan.id,
            scope,
        )
    )
    evidence_scope = (
        Evidence.cloud_account_id == account_id
        if account_id is not None
        else Evidence.cloud_account_id.is_(None)
    )
    await session.execute(
        delete(Evidence).where(
            Evidence.organization_id == scan.organization_id,
            Evidence.scan_id == scan.id,
            evidence_scope,
        )
    )


async def collect_directory(
    writer: ScanWriter,
    scan: Scan,
    connection: CloudConnection | None,
    heartbeat: Callable[[int, int], Awaitable[None]],
    observed_at: datetime,
    *,
    required: bool = False,
) -> tuple[NormalizedState, RawSnapshot] | None:
    """Read the tenant directory once, and store it as its own capture.

    Returns ``None`` when there is nothing to read it through, or when the
    read failed outright. Both cases end as a recorded gap rather than as a
    failed scan: a directory CloudGuard could not reach costs the identity
    rules their verdict and costs the subscription rules nothing.

    ``required`` raises instead, which is what its own step wants: a step
    that swallowed the failure would report SUCCEEDED, spend none of its
    retries, and leave the customer a silent gap where a transient Graph
    error deserved a second attempt.

    The capture is stored with a NULL ``cloud_account_id`` because it is not
    a reading of any subscription. That is also what makes it replayable on
    its own terms -- a replay reconstructs the tenant from this row and the
    subscriptions from theirs, exactly as the original scan saw them.
    """
    if connection is None or not connection.tenant_id:
        return None

    session = writer.session
    connector = get_connector(
        connection.provider,
        tenant_id=connection.tenant_id,
        subscription_id=None,
        provider_ref=connection.provider_ref,
    )
    plan = await plan_collection(
        session,
        organization_id=scan.organization_id,
        provider=connection.provider,
        required=required_evidence(
            connection.provider, connector.baseline_evidence()
        ),
        scan_id=scan.id,
        connection_id=connection.id,
        now=observed_at,
    )
    try:
        snapshot = await connector.collect_directory(heartbeat, plan)
    except Exception as exc:
        if required:
            raise
        # Never fatal. The same position collection takes on a single
        # failing ARM category, applied one level up: the directory is one
        # source among several, and losing it must cost the checks that
        # needed it and nothing else.
        log.warning(
            "scan.directory_collection_failed",
            scan_id=str(scan.id),
            connection_id=str(connection.id),
            error=str(exc),
        )
        return None

    session.add(
        CloudSnapshot(
            organization_id=scan.organization_id,
            cloud_account_id=None,
            connection_id=connection.id,
            scan_id=scan.id,
            snapshot_version=snapshot.version,
            manifest=manifest(snapshot),
        )
    )
    await record_evidence(
        writer,
        scan,
        snapshot,
        observed_at=observed_at,
        connection=connection,
        plan=plan,
    )
    return connector.normalize(snapshot), snapshot


async def collect_account(
    writer: ScanWriter,
    scan: Scan,
    account: CloudAccount,
    heartbeat: Callable[[int, int], Awaitable[None]],
    observed_at: datetime,
) -> None:
    """Read one subscription, and store it as its own capture.

    The counterpart of :func:`collect_directory` for a subscription, and like
    it this interprets nothing. The capture goes on the session and its
    evidence rows on ``writer``; both become durable at the step's commit.
    """
    session = writer.session
    connector = get_connector(
        account.provider,
        tenant_id=account.tenant_id,
        subscription_id=account.subscription_id,
        provider_ref=account.provider_ref,
    )
    # What this reading is for, decided before it is taken: every key
    # some enabled rule reads, plus the ones the product itself is
    # built from, minus whatever is already held fresh enough to stand
    # in for a new read.
    plan = await plan_collection(
        session,
        organization_id=scan.organization_id,
        provider=account.provider,
        required=required_evidence(
            account.provider, connector.baseline_evidence()
        ),
        scan_id=scan.id,
        cloud_account_id=account.id,
        connection_id=account.connection_id,
        now=observed_at,
    )
    snapshot = await connector.collect(heartbeat, plan)
    await explain_role_drift(session, account, snapshot)

    # Persisted before interpretation, always. One row per subscription,
    # so a tenant-wide scan can still be replayed subscription by
    # subscription.
    session.add(
        CloudSnapshot(
            organization_id=scan.organization_id,
            cloud_account_id=account.id,
            connection_id=account.connection_id,
            scan_id=scan.id,
            snapshot_version=snapshot.version,
            manifest=manifest(snapshot),
        )
    )
    await record_evidence(
        writer,
        scan,
        snapshot,
        observed_at=observed_at,
        account=account,
        plan=plan,
    )


async def resolve_connection(
    session: AsyncSession, scan: Scan, accounts: list[CloudAccount]
) -> CloudConnection | None:
    """The connection this scan reads through.

    Named on the scan for a tenant-wide run and reachable through the
    account for a single-subscription one. Both forms cover subscriptions
    beneath a single grant, so there is at most one connection either way --
    which is what makes "read the directory once" well defined.
    """
    if scan.connection_id is not None:
        return await session.get(CloudConnection, scan.connection_id)
    for account in accounts:
        if account.connection_id is not None:
            return await session.get(CloudConnection, account.connection_id)
    return None


async def record_evidence(
    writer: ScanWriter,
    scan: Scan,
    snapshot: RawSnapshot,
    *,
    observed_at: datetime,
    account: CloudAccount | None = None,
    connection: CloudConnection | None = None,
    plan: CollectionPlan | None = None,
) -> None:
    """One row per reading, and one stored copy of what it produced.

    The rows answer questions the snapshot cannot. The same facts travel
    inside the capture, which is the right home for them -- a replay has to
    see exactly what the original run saw -- but a fact buried in a JSONB
    payload can answer questions about one scan and none at all about a
    fleet, and "has storage been truncating in this subscription all week?"
    is the one that matters when deciding whether a customer has an outage
    or simply a large tenant.

    The payloads are stored by content hash, which is where the cost goes.
    A customer scanning daily whose network security groups have not changed
    in a month stored thirty identical copies of them. Keyed by hash they
    store one, and every later scan of an unchanged environment adds rows
    rather than megabytes.

    The rows are queued on the writer, which writes them in one statement at
    the step's commit. The payloads stay on the session: a blob is shared by
    every scan that read the same bytes, and whether one is already held is a
    question this has to ask before writing it.
    """
    connection_id = (
        connection.id if connection is not None else
        account.connection_id if account is not None else None
    )
    account_id = account.id if account is not None else None
    org_id = writer.organization_id
    digests = {
        key: digest(payload) for key, payload in snapshot.payloads.items()
    }
    # Readings this run did not take, and when they were taken. Read off
    # the plan rather than off the capture: the capture carries the same
    # fact as text for whoever reads a snapshot later, and a datetime that
    # never became a string cannot come back as a different one.
    carried_at = {
        key.value: reading.collected_at
        for key, reading in (plan.carried.items() if plan else ())
    }
    # And which scan made the call. Without it every row this scan writes
    # claims the reading as its own, and a citation followed back lands on
    # a scan that read nothing for that key.
    carried_from = {
        key.value: reading.source_scan_id
        for key, reading in (plan.carried.items() if plan else ())
    }

    await _store_blobs(writer.session, org_id, snapshot.payloads, digests, observed_at)

    for key, entry in snapshot.coverage.items():
        hashed = digests.get(key)
        writer.add(
            Evidence,
            scan_id=scan.id,
            cloud_account_id=account_id,
            connection_id=connection_id,
            provider=snapshot.provider,
            # The bare key, and the region beside it. ``key`` here is
            # the entry name, which for a regional reading is
            # ``security_groups@eu-west-1`` -- unique within a capture,
            # and not what a rule declares a dependency on. Captures
            # taken before regions existed carry no ``key`` field, and
            # their entry name is already the bare key, which is what
            # the fallback says.
            evidence_key=entry.get("key") or key,
            region=entry.get("region"),
            category=entry.get("category", ""),
            outcome=TaskOutcome(entry.get("outcome", TaskOutcome.FAILED.value)),
            detail=entry.get("detail") or None,
            item_count=int(entry.get("item_count", 0)),
            # When the provider was read, which for a carried reading
            # is not now. Recording it as now would make the freshness
            # question ask about the last scan that reused a reading
            # rather than about the read itself, and one reading could
            # then be carried for ever, each scan renewing it.
            collected_at=carried_at.get(key, observed_at),
            # NULL for a reading this scan took, which is the common
            # case and the honest one: the row is the reading.
            source_scan_id=carried_from.get(key),
            permissions=list(entry.get("permissions") or []),
            # `[]` for a reading taken before this was recorded, which
            # is a fact about CloudGuard's history rather than a claim
            # that the task called nothing.
            endpoints=list(entry.get("endpoints") or []),
            # NULL where a task produced nothing, which a failed one
            # did. A hash of an empty payload would claim there was
            # something to point at.
            content_hash=hashed[0] if hashed else None,
            byte_size=hashed[1] if hashed else 0,
        )


async def _store_blobs(
    session: AsyncSession,
    org_id: UUID,
    payloads: dict[str, dict],
    digests: dict[str, tuple[str, int]],
    observed_at: datetime,
) -> None:
    """Write the payloads this run produced that are not already stored.

    One query for what exists rather than one per payload: a scan produces
    a dozen readings and a tenant-wide one produces a dozen per
    subscription, and the whole point of content addressing is that most of
    them are already here.

    That query asks for the hashes alone. It used to load the rows, which
    meant a scan of an unchanged estate -- the case content addressing
    exists for, and the common one -- read every payload it already held
    back out of PostgreSQL, decompressed nothing, used none of it, and set
    a timestamp. The touch is a single UPDATE instead, guarded so it can
    only move ``last_seen_at`` forward: a replay of a capture collected in
    March must not make its payloads look freshly read.
    """
    if not digests:
        return

    hashes = {content_hash for content_hash, _size in digests.values()}
    held = set(
        (
            await session.execute(
                select(EvidenceBlob.content_hash).where(
                    EvidenceBlob.organization_id == org_id,
                    EvidenceBlob.content_hash.in_(hashes),
                )
            )
        )
        .scalars()
        .all()
    )

    if held:
        # Already here, byte for byte. Touched rather than rewritten, so
        # retention can tell a payload still in use from one whose last
        # reference was months ago.
        await session.execute(
            update(EvidenceBlob)
            .where(
                EvidenceBlob.organization_id == org_id,
                EvidenceBlob.content_hash.in_(held),
                EvidenceBlob.last_seen_at < observed_at,
            )
            .values(last_seen_at=observed_at)
        )

    for key, (content_hash, size) in digests.items():
        if content_hash in held:
            continue
        session.add(
            EvidenceBlob.of(
                organization_id=org_id,
                payload=payloads[key],
                content_hash=content_hash,
                byte_size=size,
                observed_at=observed_at,
            )
        )
        # Recorded immediately: two readings in one scan can produce
        # identical bytes -- two subscriptions with no storage accounts do
        # -- and a second insert of the same key would break on the
        # primary key.
        held.add(content_hash)


async def resolve_scope(
    session: AsyncSession, scan: Scan
) -> list[CloudAccount]:
    """Which subscriptions this scan covers.

    A connection-scoped scan resolves at execution time rather than at
    creation: a subscription discovered or excluded between queueing and
    running should be picked up or left out accordingly, and a queue that
    can sit for minutes makes that a real difference rather than a
    theoretical one.
    """
    if scan.connection_id is not None:
        rows = (
            (
                await session.execute(
                    select(CloudAccount)
                    .where(
                        CloudAccount.organization_id == scan.organization_id,
                        CloudAccount.connection_id == scan.connection_id,
                    )
                    .order_by(CloudAccount.display_name)
                )
            )
            .scalars()
            .all()
        )
        return [a for a in rows if a.is_scannable]

    if scan.cloud_account_id is None:
        return []
    account = await session.get(CloudAccount, scan.cloud_account_id)
    return [account] if account is not None else []


async def explain_role_drift(
    session: AsyncSession, account: CloudAccount, snapshot: RawSnapshot
) -> None:
    """Turn a 403 from an out-of-date role into an instruction.

    A customer whose deployed role predates a newer check sees that check's
    collection call fail with ``Forbidden``, which is true and useless. This
    rewrites the recorded reason for exactly those categories.

    It never *invents* a failure. A category that collected successfully is
    left alone even when the role is behind, because many customers also
    hold a broad Reader assignment that covers the new actions anyway --
    marking their working categories as gaps would degrade rules that had
    every right to a verdict.
    """
    if not snapshot.errors or account.connection_id is None:
        return

    connection = await session.get(CloudConnection, account.connection_id)
    if connection is None:
        return

    behind = degraded_categories(connection)
    for category, explanation in behind.items():
        if category.value in snapshot.errors:
            snapshot.errors[category.value] = (
                f"{explanation} (underlying error: {snapshot.errors[category.value]})"
            )
        # And every gap underneath it. ``errors`` is what the scan banner
        # reads; ``gaps`` is what a rule quotes when it reports UNKNOWN.
        # Rewriting only the first would leave the customer a useful
        # sentence on the banner and a bare "Forbidden" against the check
        # that actually lost its verdict -- which is the one they clicked
        # into to find out why.
        for key in get_connector(account.provider).evidence_keys_in(category):
            if key.value in snapshot.gaps:
                snapshot.gaps[key.value] = (
                    f"{explanation} (underlying error: {snapshot.gaps[key.value]})"
                )

    if behind:
        log.info(
            "scan.role_behind",
            connection_id=str(connection.id),
            deployed=connection.role_version,
            # ``.value``, because the keys are a StrEnum now and a log line
            # reading "[<EvidenceCategory.RESOURCES: 'resources'>]" is
            # noise where a category name was wanted.
            categories=sorted(category.value for category in behind),
        )
