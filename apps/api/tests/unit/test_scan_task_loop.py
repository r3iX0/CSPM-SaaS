"""The worker runs each task in its own event loop.

asyncpg binds a connection to the loop that opened it, and the engines in
``app.core.db`` are cached for the life of the *process*. So a pooled
connection outlives the loop that created it, and the next task is handed
something belonging to a loop that has already closed:

    RuntimeError: got Future attached to a different loop
    RuntimeError: Event loop is closed

The failure is unusually good at hiding. The first scan in each worker child
succeeds, so a deployment looks healthy right up until the second one -- and
with prefork concurrency the number of free scans equals the number of
children, which reads like an intermittent fault rather than a certainty.
"""

import asyncio
from typing import ClassVar
from uuid import uuid4

import pytest

from app.workers import scan_tasks


class RecordingPipeline:
    """Stands in for the scan, and remembers which loop it ran on."""

    loops: ClassVar[list[asyncio.AbstractEventLoop]] = []

    def __init__(self, scan_id: object) -> None:
        self.scan_id = scan_id

    async def replay(self) -> None:
        RecordingPipeline.loops.append(asyncio.get_running_loop())


@pytest.fixture
def instrumented(monkeypatch: pytest.MonkeyPatch) -> dict:
    RecordingPipeline.loops = []
    disposals: list[asyncio.AbstractEventLoop] = []

    async def fake_dispose() -> None:
        disposals.append(asyncio.get_running_loop())

    monkeypatch.setattr(scan_tasks, "ScanPipeline", RecordingPipeline)
    monkeypatch.setattr(scan_tasks, "dispose_engines", fake_dispose)
    return {"disposals": disposals}


async def test_connections_are_released_before_the_loop_closes(instrumented) -> None:
    """Disposal has to happen *inside* the task's loop.

    Afterwards there would be no loop left to close the connections on, which
    is exactly the thing that has gone wrong.
    """
    await scan_tasks._replay_and_release(uuid4())

    assert len(instrumented["disposals"]) == 1
    assert instrumented["disposals"][0] is RecordingPipeline.loops[0]


async def test_a_failing_scan_still_releases_its_connections(
    instrumented, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Otherwise one bad scan poisons every later scan in that worker."""

    class FailingPipeline(RecordingPipeline):
        async def replay(self) -> None:
            await super().replay()
            raise RuntimeError("Azure exploded")

    monkeypatch.setattr(scan_tasks, "ScanPipeline", FailingPipeline)

    with pytest.raises(RuntimeError, match="Azure exploded"):
        await scan_tasks._replay_and_release(uuid4())

    assert len(instrumented["disposals"]) == 1


def test_consecutive_tasks_each_get_a_fresh_loop(instrumented) -> None:
    """The condition that made this a bug: every task is a new loop.

    Two runs, two loops, and a disposal inside each. Without the disposal the
    second would inherit the first loop's connections.
    """
    for _ in range(2):
        asyncio.run(scan_tasks._replay_and_release(uuid4()))

    assert len(RecordingPipeline.loops) == 2
    assert RecordingPipeline.loops[0] is not RecordingPipeline.loops[1]
    assert instrumented["disposals"] == RecordingPipeline.loops


def test_every_task_internal_releases_its_connections() -> None:
    """The invariant applies to all of them, not just the one tested above.

    Read from the ``asyncio.run`` call sites rather than from a list written
    here, because a hand-written list is what let the two beat sweeps --
    notifications and evidence pruning -- ship without disposal. They ran every
    five and every sixty minutes, and each one left a child holding connections
    from a dead loop, so the next task that child picked up died on it: in
    staging the reaper and the change-event sweep failed within the same minute
    as every notification sweep.
    """
    import ast
    import inspect

    entrypoints: set[str] = set()
    for node in ast.walk(ast.parse(inspect.getsource(scan_tasks))):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        run = node.func
        if not (
            isinstance(run, ast.Attribute)
            and run.attr == "run"
            and isinstance(run.value, ast.Name)
            and run.value.id == "asyncio"
        ):
            continue
        awaited = node.args[0]
        if isinstance(awaited, ast.Call) and isinstance(awaited.func, ast.Name):
            entrypoints.add(awaited.func.id)

    assert len(entrypoints) >= 8, "no asyncio.run call sites found to check"

    for name in sorted(entrypoints):
        source = inspect.getsource(getattr(scan_tasks, name))
        assert "finally:" in source and "dispose_engines()" in source, (
            f"{name} does not release its connections inside its own loop"
        )


# ------------------------------------------------- nudging what nothing owns
def test_the_reaper_nudges_every_scan_with_work_outstanding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The safety net that was written and never wired up.

    ``orchestrator.unfinished_scan_ids`` shipped with a docstring saying it
    exists for the case where a step's own advance message was lost -- and
    nothing called it. A lost message left the scan holding PENDING steps, which
    carry no lease to expire, and the scan reaper skips a scan with a live step
    because it has work waiting for a worker rather than work nobody is doing.
    Nothing else in the system would ever look at that scan again: it sat on
    screen at whatever percentage it had reached, and its connection answered
    "a scan is already running" for good.
    """
    reclaimed = uuid4()
    waiting = uuid4()
    nudged: list[str] = []

    async def fake_reap() -> tuple[list, list, list]:
        return [reclaimed], [], [waiting]

    monkeypatch.setattr(scan_tasks, "_reap_and_release", fake_reap)
    monkeypatch.setattr(
        scan_tasks.advance_scan, "delay", lambda scan_id: nudged.append(scan_id)
    )

    result = scan_tasks.reap_abandoned_scans()

    assert nudged == [str(reclaimed), str(waiting)]
    assert result["nudged"] == 2


def test_a_scan_is_nudged_once_however_many_ways_it_qualifies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A reclaimed step is also a step waiting for a worker, so the two lists
    overlap. Advancing twice is harmless -- the claim is atomic -- but a queue
    growing with every tick is not the shape to leave lying around."""
    scan_id = uuid4()
    nudged: list[str] = []

    async def fake_reap() -> tuple[list, list, list]:
        return [scan_id], [], [scan_id]

    monkeypatch.setattr(scan_tasks, "_reap_and_release", fake_reap)
    monkeypatch.setattr(
        scan_tasks.advance_scan, "delay", lambda scan_id: nudged.append(scan_id)
    )

    scan_tasks.reap_abandoned_scans()

    assert nudged == [str(scan_id)]


def test_a_scan_just_closed_is_not_nudged(monkeypatch: pytest.MonkeyPatch) -> None:
    """Closing it is the end of it. Advancing a scan the reaper has just failed
    would re-derive its status from steps it no longer has any use for."""
    closed = uuid4()
    nudged: list[str] = []

    async def fake_reap() -> tuple[list, list, list]:
        return [], [closed], []

    monkeypatch.setattr(scan_tasks, "_reap_and_release", fake_reap)
    monkeypatch.setattr(
        scan_tasks.advance_scan, "delay", lambda scan_id: nudged.append(scan_id)
    )

    scan_tasks.reap_abandoned_scans()

    assert nudged == []
