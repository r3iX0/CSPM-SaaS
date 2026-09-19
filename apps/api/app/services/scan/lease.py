"""Holding a step while it runs, and letting go when it is taken.

Three pieces with one fence between them. :class:`LeaseKeeper` renews the
step's lease on a clock and notices when a renewal is refused; the heartbeat and
phase reporter are the callbacks a running step reports through; and
:class:`StepFence` is the same attempt number asked at the moment a step commits
what it did.
"""

import asyncio
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.db import scan_session
from app.core.enums import AnalyzePhase
from app.core.logging import get_logger
from app.models.scan import ScanStep
from app.services import orchestrator
from app.services.scan.errors import StepLeaseLost

log = get_logger(__name__)


class LeaseKeeper:
    """Holds a step's lease for as long as this worker is running it.

    A lease renewed only when collection reports progress covered exactly one
    of the three step kinds. PLAN is short enough not to need it, but ANALYZE
    is the longest thing a scan does -- reconstructing every capture,
    evaluating every rule, scoring every finding -- and it renewed nothing at
    all. A tenant whose analysis ran past ``ScanStep.LEASE_SECONDS`` had its
    step reaped mid-evaluation and started again on another worker, while the
    first was still writing findings for the same scan. The bigger the tenant,
    the more certain it was: the one case where the reaper reliably fired was
    the one where nothing had actually gone wrong.

    So the lease is held by the clock rather than by whatever the phase happens
    to report. A background task renews it on a fraction of the window, and a
    refused renewal -- the fence in ``orchestrator.renew`` -- means the step has
    been taken, which sets ``lost`` and makes the next heartbeat raise.
    """

    # Three renewals inside one lease window. Two would leave a single missed
    # renewal -- a slow query, a paused container -- looking exactly like a dead
    # worker; more would spend writes for no more safety.
    RENEW_EVERY = ScanStep.LEASE_SECONDS / 3

    def __init__(self, step_id: UUID, organization_id: UUID, attempt: int) -> None:
        self.step_id = step_id
        # Carried so the renewal runs on the same constrained session as the
        # step it is beating for. It writes one column on one row, and doing
        # that on the owner connection would be a small hole in an otherwise
        # closed boundary.
        self.organization_id = organization_id
        self.attempt = attempt
        self.lost = False
        self._task: asyncio.Task[None] | None = None

    async def __aenter__(self) -> "LeaseKeeper":
        self._task = asyncio.create_task(self._run())
        return self

    async def __aexit__(self, *_exc: object) -> None:
        if self._task is not None:
            self._task.cancel()
            with suppress(asyncio.CancelledError):
                await self._task

    async def _run(self) -> None:
        while True:
            await asyncio.sleep(self.RENEW_EVERY)
            try:
                async with scan_session(self.organization_id) as session:
                    held = await orchestrator.renew(
                        session, self.step_id, self.attempt
                    )
            except Exception as exc:  # pragma: no cover - never fatal in itself
                # A failed renewal is not proof the step was taken; the database
                # may simply have been unreachable for a moment. Losing enough
                # of them costs the lease, which the reaper handles -- and that
                # path ends in the same place, with this attempt fenced out of
                # its own settle.
                log.warning(
                    "scan.lease_renew_failed",
                    step_id=str(self.step_id),
                    error=str(exc),
                )
                continue
            if not held:
                log.warning(
                    "scan.lease_lost",
                    step_id=str(self.step_id),
                    attempt=self.attempt,
                )
                self.lost = True
                return


async def _no_heartbeat(done: int, total: int) -> None:
    """Progress reported by a collection with no step behind it.

    A direct ``collect`` call in a test has no lease to lose, and the collector
    always has somewhere to report progress rather than a callback it must
    check for None.
    """
    return None


class _StepHeartbeat:
    """The progress callback a step hands to collection.

    It no longer renews anything -- :class:`LeaseKeeper` does that on a clock,
    for every kind of step rather than only the one that reports progress. What
    is left is the half a callback is uniquely placed to do: stop the work.

    A step whose lease was lost is being run by somebody else, so every request
    this one still makes spends the customer's Azure quota to produce a capture
    that will be discarded. Raising at the next progress report ends it at the
    first opportunity the collector offers.
    """

    def __init__(self, keeper: "LeaseKeeper") -> None:
        self.keeper = keeper

    async def __call__(self, done: int, total: int) -> None:
        if self.keeper.lost:
            raise StepLeaseLost(
                "This step was taken over by another worker while it was "
                "running, so this attempt stopped."
            )


PhaseReport = Callable[[AnalyzePhase], Awaitable[None]]


async def _no_phase(phase: AnalyzePhase) -> None:
    """Analysis with no step behind it: a replay, or a direct call in a test.

    Replay is one task rather than a set of steps, so there is no step row to
    mark, and the evaluation it shares with a real scan still has somewhere to
    report rather than a callback it must check for None.
    """
    return None


class _PhaseReporter:
    """Writes where a running ANALYZE step is, on a session of its own.

    Its own session because the pipeline's is mid-transaction at two of the
    three seams, and a progress mark must not wait for -- or be rolled back
    with -- the work it describes. Fenced on the attempt through
    :func:`orchestrator.set_phase`, like the lease renewal beside it.

    Never fatal. A mark that fails to write costs the screen one phase label;
    failing the analysis over it would cost the scan.
    """

    def __init__(self, step_id: UUID, organization_id: UUID, attempt: int) -> None:
        self.step_id = step_id
        self.organization_id = organization_id
        self.attempt = attempt

    async def __call__(self, phase: AnalyzePhase) -> None:
        try:
            async with scan_session(self.organization_id) as session:
                await orchestrator.set_phase(session, self.step_id, self.attempt, phase)
        except Exception as exc:  # pragma: no cover - never fatal in itself
            log.warning(
                "scan.phase_report_failed",
                step_id=str(self.step_id),
                phase=phase.value,
                error=str(exc),
            )


@dataclass(frozen=True)
class StepFence:
    """The claim a step's writes are committed under.

    :class:`LeaseKeeper` finds out a step was taken on a clock, a third of a
    lease at a time, and everything this attempt committed in between was
    written by a worker that no longer owned the step -- findings, risks,
    resolutions, all of it duplicating or contradicting the attempt that took
    over. This closes that window: :class:`~app.services.scan.writer.ScanWriter`
    asks it inside every transaction it commits, and a step that is no longer
    this attempt's rolls the transaction back instead.
    """

    step_id: UUID
    attempt: int

    async def hold(self, session: AsyncSession) -> None:
        if not await orchestrator.hold(session, self.step_id, self.attempt):
            log.warning(
                "scan.write_fenced_out",
                step_id=str(self.step_id),
                attempt=self.attempt,
            )
            raise StepLeaseLost(
                "This step was taken over by another worker while it was "
                "running, so this attempt stopped without writing its results."
            )
