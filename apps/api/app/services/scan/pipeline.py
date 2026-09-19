"""The scan pipeline.

    collect -> snapshot -> normalize -> persist assets -> evaluate
            -> findings -> risks -> verify fixes -> summarize

Two things here are the product, not plumbing:

* **Every scan writes a snapshot** before anything is interpreted, so a scan can
  be re-evaluated later against improved rules. :meth:`ScanPipeline.replay`
  is that promise being kept: it re-enters the pipeline at ``normalize`` with a
  stored capture and runs the identical remaining stages, so a rule written
  today can be applied to state collected months ago without asking the
  customer for anything.
* **A rescan verifies remediation by itself.** Where a previous scan produced
  FAIL and this one produces PASS, the finding is resolved automatically and
  stamped with the scan that proved it. Nobody clicks "verified"
  (RULE_ENGINE.md section 3).

The two combine into the one rule that constrains replay: **only the newest
snapshot for an account may write findings.** Verification means an observation
was made, and replaying an old capture makes none.

Runs in the Celery worker, which has no authenticated user, so it runs under
``scan_session`` -- held by RLS to the ``organization_id`` taken from the scan
record it was handed, never from client input -- and scopes every write by the
same id.

This module drives the steps and nothing else. The work lives beside it:
``collection`` reads one scope, ``capture`` stores and rebuilds what was read,
``analyze`` runs the stages in order, and ``writer`` is the one door every step
commits through -- in bulk for the rows nothing reads back, and only while the
step is still this attempt's (DECISIONS.md section 108).
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import scan_session, service_session
from app.core.enums import ScanStatus, ScanStepKind, ScanStepStatus
from app.core.logging import get_logger, log_context
from app.core.vocabulary import words
from app.models.cloud_account import CloudAccount
from app.models.scan import Scan, ScanStep
from app.rules.engine import RuleEngine
from app.services import orchestrator
from app.services.scan.analyze import evaluate
from app.services.scan.capture import (
    directory_gap,
    reconstruct,
    snapshots_of,
    stored_snapshots,
)
from app.services.scan.collection import (
    collect_account,
    collect_directory,
    discard_prior_attempt,
    resolve_connection,
    resolve_scope,
)
from app.services.scan.errors import (
    CollectionUnavailable,
    NothingToAnalyze,
    ScanScopeEmpty,
    ScanStepError,
    ScanVanished,
)
from app.services.scan.lease import (
    LeaseKeeper,
    PhaseReport,
    StepFence,
    _no_heartbeat,
    _no_phase,
    _PhaseReporter,
    _StepHeartbeat,
)
from app.services.scan.writer import ScanWriter

log = get_logger(__name__)


class ScanPipeline:
    def __init__(self, scan_id: UUID) -> None:
        self.scan_id = scan_id
        self.engine = RuleEngine()
        self._organization_id: UUID | None = None

    @asynccontextmanager
    async def _session(self) -> AsyncIterator[AsyncSession]:
        """A session PostgreSQL will hold to this scan's organization.

        Every read and write a scan makes goes through here. Before this, the
        pipeline ran on the owner connection -- RLS does not apply to it -- so
        the tenant boundary was whatever ``organization_id`` filter each query
        happened to carry. Those filters are all still there and still correct;
        what changed is that they are no longer the only thing standing between
        two customers' data.
        """
        organization_id = await self._organization()
        async with scan_session(organization_id) as session:
            yield session

    async def _organization(self) -> UUID:
        """Which organization this scan belongs to.

        The one read that cannot be scoped, because it is the read that
        establishes the scope. Deliberately narrow: one row by primary key,
        one column, cached for the life of the step -- and taken from the scan
        record rather than from the queue message, which is the same rule the
        pipeline has always followed about where a tenant boundary may come
        from.
        """
        if self._organization_id is None:
            async with service_session() as session:
                organization_id = (
                    await session.execute(
                        select(Scan.organization_id).where(Scan.id == self.scan_id)
                    )
                ).scalar_one_or_none()
            if organization_id is None:
                raise ScanVanished(
                    "This scan no longer exists, so there is nothing to run."
                )
            self._organization_id = organization_id
        return self._organization_id

    # ------------------------------------------------------------------ steps
    #
    # A scan used to be this class's ``run`` method: resolve the scope, read
    # every subscription in sequence, then interpret the lot, all inside one
    # Celery task with no retries. The three methods below are that method cut
    # at the seams it already had, so each becomes a durably recorded step that
    # can be claimed, retried and settled on its own
    # (``app/services/orchestrator.py``).
    #
    # The cut is not arbitrary. Collection writes captures and nothing else;
    # everything after a capture is a pure function of it. That was already
    # true -- it is what makes replay possible -- and it is what lets ANALYZE
    # reconstruct from the database exactly what the old in-memory pipeline
    # carried between its phases.

    async def run_step(self, step_id: UUID) -> ScanStepStatus:
        """Perform one claimed step and settle it. Returns how it went.

        The dispatch lives here rather than in the Celery task so that the
        thing under test and the thing in production are the same code. A test
        that drove the steps its own way would be testing its own driver.

        Which failures are retried is decided here too, and the distinction is
        between conditions the pipeline anticipated and ones it did not. "That
        subscription is gone" will be just as gone on the third attempt;
        a throttled API or a killed worker will not.
        """
        async with self._session() as session:
            step = await session.get(ScanStep, step_id)
            if step is None:
                log.error("scan.step_missing", step_id=str(step_id))
                return ScanStepStatus.FAILED
            kind = step.kind
            scope = step.cloud_account_id
            # The claim this worker is running under. Everything below is
            # fenced on it: the lease it renews, and the settle it writes at the
            # end. A step reclaimed while this attempt was working carries a
            # higher number, and this attempt then writes nothing.
            attempt = step.attempt

        # Bound here rather than in the Celery task, so a step driven by the
        # tests or by a future caller carries the same context a queued one
        # does. The scope is the id that matters when a tenant-wide scan has
        # fifty collections in flight and one of them is slow.
        with log_context(
            scan_id=str(self.scan_id),
            step_id=str(step_id),
            step_kind=kind.value,
            cloud_account_id=str(scope) if scope else None,
        ):
            organization_id = await self._organization()
            # Every commit the step makes is asked against this. The keeper
            # below finds out on a clock that the step was taken; the fence
            # finds out at the one moment it matters, before anything this
            # attempt did becomes visible.
            fence = StepFence(step_id, attempt)
            async with LeaseKeeper(step_id, organization_id, attempt) as keeper:
                try:
                    if kind == ScanStepKind.PLAN:
                        await self.plan(fence)
                    elif kind == ScanStepKind.COLLECT:
                        await self.collect(step_id, _StepHeartbeat(keeper), fence)
                    else:
                        await self.analyze(
                            _PhaseReporter(step_id, organization_id, attempt), fence
                        )
                except ScanStepError as exc:
                    return await self._settle(
                        step_id, str(exc), retryable=exc.retryable, attempt=attempt
                    )
                except Exception as exc:
                    log.exception("scan.step_failed")
                    return await self._settle(
                        step_id, str(exc), retryable=True, attempt=attempt
                    )

                return await self._settle(
                    step_id, None, retryable=False, attempt=attempt
                )

    def _log_step(self, step: ScanStep, outcome: ScanStepStatus) -> None:
        """One line per stage, carrying what it cost.

        The scan-level log said a scan finished and how many findings it held,
        which cannot distinguish a slow subscription from a slow evaluation.
        A stage names the scope it read and the seconds it took, which is the
        first thing anyone asks about a scan that took twice as long as usual.
        """
        started = step.started_at
        log.info(
            "scan.step_finished",
            scan_id=str(self.scan_id),
            stage=step.kind.value,
            scope=step.describe(),
            outcome=outcome.value,
            attempt=step.attempt,
            seconds=(
                round((datetime.now(UTC) - started).total_seconds(), 1)
                if started
                else None
            ),
        )

    async def _settle(
        self,
        step_id: UUID,
        error: str | None,
        *,
        retryable: bool,
        attempt: int | None = None,
    ) -> ScanStepStatus:
        """Record how this attempt went, if it is still this attempt's to record.

        ``attempt`` is the fence, and the case it closes is not exotic. A worker
        paused past its lease -- a container throttled, a database stall, a
        redeploy that took the process's CPU away for a quarter of an hour --
        has its step reclaimed and re-run elsewhere, and then comes back. What
        it wrote before is already discarded by the retry's own demolition; what
        it must not do is settle a step another worker is in the middle of,
        because ANALYZE waits on COLLECT settling and would then start on a
        collection still being written.
        """
        async with self._session() as session:
            step = await session.get(ScanStep, step_id)
            if step is None:
                return ScanStepStatus.FAILED
            if error is None:
                if not await orchestrator.finish(
                    session, step, ScanStepStatus.SUCCEEDED, attempt=attempt
                ):
                    return self._lost(step)
                self._log_step(step, ScanStepStatus.SUCCEEDED)
                return ScanStepStatus.SUCCEEDED
            if not retryable:
                if not await orchestrator.finish(
                    session, step, ScanStepStatus.FAILED, error, attempt=attempt
                ):
                    return self._lost(step)
                self._log_step(step, ScanStepStatus.FAILED)
                return ScanStepStatus.FAILED
            outcome = await orchestrator.fail_or_retry(
                session, step, error, attempt=attempt
            )
            if outcome is None:
                return self._lost(step)
            self._log_step(step, outcome)
            return outcome

    def _lost(self, step: ScanStep) -> ScanStepStatus:
        """What this attempt reports when the step was no longer its own.

        The step's real state is whatever the worker that took it says, so this
        returns what the row already holds rather than a verdict of its own. It
        is reported as this attempt's outcome only for the log line and the
        task's return value; nothing was written.
        """
        log.warning(
            "scan.step_settle_skipped",
            scan_id=str(self.scan_id),
            step_id=str(step.id),
            detail="another worker holds this step",
        )
        return step.status

    async def plan(self, fence: StepFence | None = None) -> list[CloudAccount]:
        """Resolve what this scan covers and create a step per scope.

        Scope is resolved here rather than when the scan was queued, and that
        is deliberate: a subscription discovered or excluded while the scan sat
        in the queue should be picked up or left out accordingly, and a queue
        that can be minutes deep makes that a real difference rather than a
        theoretical one.
        """
        async with self._session() as session:
            scan = await self._require_scan(session)
            if scan is None:
                return []

            accounts = await resolve_scope(session, scan)
            connection = await resolve_connection(session, scan, accounts)
            # The nouns this scan's messages are written in. A customer reading
            # "subscription" about an AWS account is reading a product that has
            # not noticed which cloud it is looking at. Resolved before the
            # scope check, because that message is one of the ones that needs
            # them and fires when there is no account left to ask.
            scope_words = words(connection.provider if connection else None)
            if not accounts:
                raise ScanScopeEmpty(
                    f"This scan has nothing in scope. Its {scope_words.accounts} "
                    "may have been removed, excluded from scanning, or never "
                    "discovered."
                )

            writer = ScanWriter(session, scan.organization_id, fence=fence)
            scan.started_at = scan.started_at or datetime.now(UTC)
            await orchestrator.create_collect_steps(
                session,
                scan,
                accounts,
                # No connection means no tenant-level grant to read a directory
                # through, so there is no step to create. ANALYZE records the
                # resulting gap rather than inventing a step that could only
                # fail.
                directory=connection is not None and bool(connection.tenant_id),
            )
            await writer.commit()
            log.info(
                "scan.planned",
                scan_id=str(scan.id),
                subscriptions=len(accounts),
                directory=connection is not None,
            )
            return accounts

    async def collect(
        self,
        step_id: UUID,
        heartbeat: _StepHeartbeat | None = None,
        fence: StepFence | None = None,
    ) -> None:
        """Read one scope and store what came back. Interprets nothing.

        ``heartbeat`` is how collection finds out it has lost the step. Optional
        so a test can drive one collection without a lease to hold, and passed
        by ``run_step`` in every other case.

        Idempotent by demolition: a retried step deletes whatever the previous
        attempt stored for this scope before storing again. The alternative is
        an upsert across two tables and a blob store, and a retry that half
        matched would be worse than one that starts clean -- a capture is
        supposed to be what the provider said in one reading, not a merge of
        two.
        """
        async with self._session() as session:
            scan = await self._require_scan(session)
            if scan is None:
                return
            step = await session.get(ScanStep, step_id)
            if step is None:
                log.error("scan.step_missing", step_id=str(step_id))
                return

            writer = ScanWriter(session, scan.organization_id, fence=fence)
            observed_at = datetime.now(UTC)
            connection = await resolve_connection(
                session, scan, await resolve_scope(session, scan)
            )
            scope_words = words(connection.provider if connection else None)
            await discard_prior_attempt(session, scan, step.cloud_account_id)

            if step.is_directory:
                if connection is None or not connection.tenant_id:
                    raise CollectionUnavailable(
                        f"This connection has no {scope_words.boundary} to read "
                        f"its {scope_words.directory} from."
                    )
                await collect_directory(
                    writer,
                    scan,
                    connection,
                    heartbeat or _no_heartbeat,
                    observed_at,
                    required=True,
                )
                await writer.commit()
                return

            account = await session.get(CloudAccount, step.cloud_account_id)
            if account is None:
                raise CollectionUnavailable(
                    f"This {scope_words.account} is no longer connected to "
                    "CloudGuard."
                )

            await collect_account(
                writer, scan, account, heartbeat or _no_heartbeat, observed_at
            )
            account.last_scan_at = observed_at
            await writer.commit()

    async def analyze(
        self,
        report_phase: PhaseReport = _no_phase,
        fence: StepFence | None = None,
    ) -> None:
        """Interpret every capture this scan stored.

        Reconstructs from the database what the old single-task pipeline held
        in memory between its phases. That is not a workaround: everything
        after a capture is already a pure function of it, which is the property
        replay depends on, so reading the captures back is the same operation
        the pipeline was always performing -- now with the collection that
        produced them separately durable.
        """
        async with self._session() as session:
            scan = await self._require_scan(session)
            if scan is None:
                return

            stored = await snapshots_of(session, scan.organization_id, scan.id)
            if not stored:
                raise NothingToAnalyze(
                    "This scan stored no readings, so there is nothing to "
                    "evaluate. Every subscription it covered failed to collect."
                )

            writer = ScanWriter(session, scan.organization_id, fence=fence)
            state = await reconstruct(session, scan, stored)
            state.errors.update(await directory_gap(session, scan, state))
            scan.collection_errors = state.errors
            await writer.commit()

            await evaluate(
                writer,
                scan,
                self.engine,
                state.account_state,
                state.merged,
                observed_at=state.observed_at,
                mutate_findings=True,
                degraded=bool(state.errors),
                directory=state.directory,
                # The orchestrator decides when a scan is finished and how,
                # from the steps. A stage writing its own terminal status would
                # be a second source of truth for it.
                finalize=False,
                on_phase=report_phase,
            )

    async def _require_scan(self, session: AsyncSession) -> Scan | None:
        """The scan, unless it has been cancelled or no longer exists.

        Checked at every step rather than only at the start. A scan runs across
        several steps and possibly several workers, and the cancel button is
        used in exactly the window between two of them -- carrying on would
        write findings somebody asked not to collect.
        """
        scan = await session.get(Scan, self.scan_id)
        if scan is None:
            log.error("scan.missing", scan_id=str(self.scan_id))
            return None
        if scan.status == ScanStatus.CANCELLED:
            log.info("scan.cancelled_before_step", scan_id=str(self.scan_id))
            return None
        return scan


    async def replay(self) -> None:
        """Re-evaluate an earlier scan's stored snapshots against today's rules.

        No collection, no Azure call, no consent required: everything after the
        snapshot is a pure function of it, which is what the raw capture was
        kept for. A tenant-wide scan stored one snapshot per subscription, and
        a replay re-reads all of them.

        The dangerous case is why ``evaluation_only`` exists. Replaying a
        month-old snapshot that now produces PASS where a finding was FAIL would
        otherwise reach the auto-resolve path and stamp that finding "verified
        fixed" -- on the strength of data collected before anyone was even told
        about it. Nothing was observed, so nothing may be resolved. Only a
        replay of the newest snapshots, which are CloudGuard's current picture
        of that environment, may touch findings at all; every older one writes
        coverage and reports counts, and stops there.

        For a multi-subscription scan that is all-or-nothing on purpose: if any
        subscription has been re-read since, the set as a whole no longer
        describes the present, and findings across it cannot be resolved from a
        picture that is partly stale.
        """
        async with self._session() as session:
            scan = await session.get(Scan, self.scan_id)
            if scan is None:
                log.error("scan.missing", scan_id=str(self.scan_id))
                return

            if scan.status == ScanStatus.CANCELLED:
                log.info("scan.cancelled_before_start", scan_id=str(self.scan_id))
                return

            scan.started_at = datetime.now(UTC)
            org_id = scan.organization_id
            # No fence: a replay is one task rather than a claimed step, so
            # there is no attempt for another worker to have taken over.
            writer = ScanWriter(session, org_id)

            try:
                stored = await stored_snapshots(session, org_id, scan)
                if not stored:
                    await self._fail(
                        session,
                        scan,
                        "That scan has no stored snapshot to replay. Snapshots are "
                        "written when collection succeeds, so a scan that failed "
                        "before that point has nothing to re-evaluate.",
                    )
                    return

                state = await reconstruct(
                    session, scan, stored, check_freshness=True
                )

                if not state.account_state and state.directory is None:
                    await self._fail(
                        session,
                        scan,
                        "None of the subscriptions this scan covered still exist, "
                        "so its snapshots cannot be re-evaluated.",
                    )
                    return

                scan.evaluation_only = not state.is_current
                scan.collection_errors = state.errors
                await writer.commit()

                await evaluate(
                    writer,
                    scan,
                    self.engine,
                    state.account_state,
                    state.merged,
                    # The observation happened when the snapshots were taken.
                    # Stamping findings with the replay time would date
                    # month-old evidence to today.
                    observed_at=state.observed_at,
                    mutate_findings=state.is_current,
                    degraded=bool(state.errors),
                    directory=state.directory,
                )

                # ``last_scan_at`` is deliberately left alone: it records when
                # Azure was last read, and a replay reads only the database.
                await writer.commit()

            except Exception as exc:
                log.exception("scan.replay_failed", scan_id=str(scan.id))
                await session.rollback()
                await self._fail(session, scan, str(exc))


    async def _fail(self, session: AsyncSession, scan: Scan, message: str) -> None:
        scan.status = ScanStatus.FAILED
        scan.error_message = message[:2000]
        scan.completed_at = datetime.now(UTC)
        # Terminal, so nothing should reclaim it. Released rather than left to
        # expire, so the reaper's index does not carry finished work.
        scan.lease_until = None
        await session.commit()
