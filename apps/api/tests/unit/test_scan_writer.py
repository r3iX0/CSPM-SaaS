"""The scan writer: bulk rows, and the fence every step commits through.

Two promises, each held here without a database. The rows a scan never reads
back leave as one ``executemany`` per table, after the ORM objects they point
at; and a step whose lease was taken commits nothing, because the commit asks
the step row whether it is still this attempt's before it lands.

The fence is the one that matters. The lease keeper noticed a lost step on a
clock, a third of a lease at a time, and a worker that had lost its step went
on committing findings until then -- rows written by nobody entitled to write
them, beside the rows of the worker that took over.
"""

import ast
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy.dialects import postgresql

from app.connectors.base import NormalizedState
from app.core.enums import (
    AssetChange,
    FindingEvent,
    FindingStatus,
    RelationshipType,
    ScanStepStatus,
)
from app.models.finding import Finding
from app.models.history import AssetChangeEvent, FindingEventRecord
from app.models.resource import ResourceRelationship
from app.models.risk import RiskFinding
from app.models.scan import Scan
from app.rules.engine import RuleEngine
from app.services import orchestrator
from app.services.scan import analyze
from app.services.scan.errors import StepLeaseLost
from app.services.scan.lease import StepFence
from app.services.scan.writer import APPEND_ONLY, ScanWriter

ORG = uuid.uuid4()


class _Held:
    def __init__(self, value: object) -> None:
        self.value = value

    def scalar_one_or_none(self) -> object:
        return self.value


class FakeSession:
    """Records the order things happen in, which is most of what is under test."""

    def __init__(self, *, held: bool = True) -> None:
        self.log: list[tuple[str, Any]] = []
        self.held = held

    async def flush(self) -> None:
        self.log.append(("flush", None))

    async def execute(self, statement: Any, params: Any = None) -> _Held:
        if params is not None:
            self.log.append(("insert", (statement, params)))
            return _Held(None)
        self.log.append(("select", statement))
        return _Held(uuid.uuid4() if self.held else None)

    async def commit(self) -> None:
        self.log.append(("commit", None))

    async def rollback(self) -> None:
        self.log.append(("rollback", None))

    def kinds(self) -> list[str]:
        return [kind for kind, _ in self.log]

    def inserts(self) -> list[tuple[Any, list[dict]]]:
        return [payload for kind, payload in self.log if kind == "insert"]


def writer_over(session: FakeSession, fence: StepFence | None = None) -> ScanWriter:
    return ScanWriter(session, ORG, fence=fence)  # type: ignore[arg-type]


def sql(statement: Any) -> str:
    return str(statement.compile(dialect=postgresql.dialect()))


def event_row() -> dict[str, Any]:
    return {
        "finding_id": uuid.uuid4(),
        "event": FindingEvent.DETECTED,
        "current_status": FindingStatus.OPEN,
        "detail": "",
    }


# ---------------------------------------------------------------- what it takes
def test_a_table_the_scan_reads_back_is_refused() -> None:
    """Findings are updated in place and read back by the next stage, so they
    stay on the ORM. Accepting one here would leave two ways to write a row."""
    with pytest.raises(TypeError, match="Finding"):
        writer_over(FakeSession()).add(Finding, rule_id="X")


async def test_every_row_is_stamped_with_the_scans_organization() -> None:
    session = FakeSession()
    writer = writer_over(session)
    writer.add(RiskFinding, risk_id=uuid.uuid4(), finding_id=uuid.uuid4())
    await writer.flush()

    ((_, rows),) = session.inserts()
    assert rows[0]["organization_id"] == ORG


def test_a_row_for_another_organization_is_refused() -> None:
    """RLS would refuse it too, but as a policy violation on a statement
    carrying every row of the table. This refuses the one row, by name."""
    with pytest.raises(ValueError, match="organization"):
        writer_over(FakeSession()).add(
            RiskFinding,
            risk_id=uuid.uuid4(),
            finding_id=uuid.uuid4(),
            organization_id=uuid.uuid4(),
        )


def test_only_facts_are_idempotent() -> None:
    """An edge or a link is either recorded or not. An event recorded twice is
    a scan that did one thing twice, and must fail rather than be absorbed."""
    idempotent = {model for model, ignore in APPEND_ONLY.items() if ignore}
    assert idempotent == {ResourceRelationship, RiskFinding}


# ------------------------------------------------------------------ the flush
async def test_the_orm_is_flushed_before_any_row_that_points_at_it() -> None:
    """A finding event names its finding's id, which a new finding does not
    have until the ORM has flushed it."""
    session = FakeSession()
    writer = writer_over(session)
    writer.add(FindingEventRecord, **event_row())
    await writer.flush()
    assert session.kinds() == ["flush", "insert"]


async def test_one_statement_per_table_however_many_rows() -> None:
    session = FakeSession()
    writer = writer_over(session)
    for _ in range(250):
        writer.add(
            AssetChangeEvent, resource_id=uuid.uuid4(), change=AssetChange.APPEARED
        )
    await writer.flush()

    ((statement, rows),) = session.inserts()
    assert "INSERT INTO asset_change_events" in sql(statement)
    assert len(rows) == 250


async def test_rows_setting_different_columns_are_sent_apart() -> None:
    """One ``executemany`` compiles one statement from the first row's columns.
    A row leaving a column to its default, batched with one that sets it,
    would be sent an explicit NULL instead of the default."""
    session = FakeSession()
    writer = writer_over(session)
    writer.add(AssetChangeEvent, resource_id=uuid.uuid4(), change=AssetChange.APPEARED)
    writer.add(
        AssetChangeEvent,
        resource_id=uuid.uuid4(),
        change=AssetChange.EXPOSURE_CHANGED,
        previous_value="LOW",
        current_value="HIGH",
    )
    await writer.flush()
    assert len(session.inserts()) == 2


async def test_an_edge_already_recorded_is_skipped_by_the_insert_itself() -> None:
    """What the read of existing edges was for, answered inside the insert."""
    session = FakeSession()
    writer = writer_over(session)
    writer.add(
        ResourceRelationship,
        source_resource_id=uuid.uuid4(),
        target_resource_id=uuid.uuid4(),
        relationship_type=RelationshipType.HAS_IDENTITY,
    )
    writer.add(FindingEventRecord, **event_row())
    await writer.flush()

    compiled = {
        statement.table.name: sql(statement) for statement, _ in session.inserts()
    }
    assert "ON CONFLICT DO NOTHING" in compiled["resource_relationships"]
    assert "ON CONFLICT" not in compiled["finding_events"]


async def test_a_flush_sends_each_row_once() -> None:
    session = FakeSession()
    writer = writer_over(session)
    writer.add(RiskFinding, risk_id=uuid.uuid4(), finding_id=uuid.uuid4())
    await writer.flush()
    await writer.flush()
    assert len(session.inserts()) == 1
    assert writer.pending(RiskFinding) == 0


# ------------------------------------------------------------------ the fence
async def test_an_unfenced_commit_is_a_plain_commit() -> None:
    """A replay is one task, not a claimed step: nothing to have been taken."""
    session = FakeSession()
    await writer_over(session).commit()
    assert session.kinds() == ["flush", "commit"]


async def test_a_step_still_held_commits_after_asking() -> None:
    session = FakeSession(held=True)
    writer = writer_over(session, StepFence(uuid.uuid4(), 3))
    writer.add(RiskFinding, risk_id=uuid.uuid4(), finding_id=uuid.uuid4())
    await writer.commit()

    # Asked after every write, so the lock it takes lasts a commit, not a stage.
    assert session.kinds() == ["flush", "insert", "select", "commit"]


async def test_a_step_taken_over_commits_nothing() -> None:
    """The case this exists for. Everything the attempt wrote since its last
    commit is rolled back, and the step stops rather than carrying on to write
    more that would be rolled back in turn."""
    session = FakeSession(held=False)
    writer = writer_over(session, StepFence(uuid.uuid4(), 3))
    writer.add(RiskFinding, risk_id=uuid.uuid4(), finding_id=uuid.uuid4())

    with pytest.raises(StepLeaseLost):
        await writer.commit()

    assert "commit" not in session.kinds()
    assert session.kinds()[-1] == "rollback"


def test_a_lost_step_is_not_retried() -> None:
    """The step is already back in the queue or running elsewhere. A retry
    from here would be a third worker on it."""
    assert StepLeaseLost.retryable is False


async def test_the_fence_locks_the_row_it_asks_about() -> None:
    """``FOR SHARE`` is what makes the answer last until the commit. Without it
    the reaper could return the step to PENDING between the check and the
    commit, and the check would have fenced nothing."""
    session = FakeSession()
    step_id = uuid.uuid4()
    assert await orchestrator.hold(session, step_id, 7)  # type: ignore[arg-type]

    ((_, statement),) = [entry for entry in session.log if entry[0] == "select"]
    assert "FOR SHARE" in sql(statement)
    params = set(statement.compile().params.values())
    assert {step_id, 7, ScanStepStatus.RUNNING} <= params


# ------------------------------------------------------------- the one door
SCAN = Path(__file__).resolve().parents[2] / "app" / "services" / "scan"


def _commits(path: Path) -> list[str]:
    """Functions calling ``session.commit()`` or ``<x>.session.commit()``."""
    found: list[str] = []
    for node in ast.walk(ast.parse(path.read_text())):
        if not isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef):
            continue
        for call in ast.walk(node):
            if not (
                isinstance(call, ast.Call)
                and isinstance(call.func, ast.Attribute)
                and call.func.attr == "commit"
            ):
                continue
            target = call.func.value
            if (isinstance(target, ast.Name) and target.id == "session") or (
                isinstance(target, ast.Attribute) and target.attr == "session"
            ):
                found.append(f"{path.name}:{node.name}")
                break
    return found


def test_every_commit_in_the_pipeline_goes_through_the_writer() -> None:
    """A bare commit anywhere in the package is a write the fence never saw.

    ``ScanWriter.commit`` is the door, and a replay recording its own failure
    is the one other: a replay is no claimed step, so it has no attempt to be
    fenced on.
    """
    commits = sorted(c for path in SCAN.glob("*.py") for c in _commits(path))
    assert commits == ["pipeline.py:_fail", "writer.py:commit"]


async def test_an_analysis_that_lost_its_step_stops_at_its_first_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End to end through the driver: the first commit an analysis makes is the
    phase change before it persists anything, so a step taken over while it
    reconstructed its captures writes no asset, finding or risk at all."""
    ran: list[str] = []

    def stage(name: str):
        async def record(*_args: object, **_kwargs: object) -> dict:
            ran.append(name)
            return {}

        return record

    for name in ("persist_resources", "persist_coverage", "persist_findings"):
        monkeypatch.setattr(analyze, name, stage(name))

    session = FakeSession(held=False)
    scan = Scan(organization_id=ORG)
    with pytest.raises(StepLeaseLost):
        await analyze.evaluate(
            writer_over(session, StepFence(uuid.uuid4(), 2)),
            scan,
            RuleEngine(),
            [],
            NormalizedState(),
            observed_at=datetime.now(UTC),
            mutate_findings=True,
            degraded=False,
            finalize=False,
        )

    assert ran == []
    assert "commit" not in session.kinds()
