"""What moving a remediation task says about its finding (DECISIONS.md section 208).

The task is read through a stand-in session and the finding and verification
services are stubbed, so each transition is proven without a database: a field
sent as null clears it, a reopened task withdraws its claim, a cancelled task
gives its finding back to the untracked list, and a cancelled task stays
cancelled.
"""

from datetime import UTC, date, datetime
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import pytest

from app.core.enums import FindingStatus, RemediationStatus
from app.core.errors import ValidationFailed
from app.schemas.finding import RemediationUpdate
from app.services import remediation as service


class _Session:
    """Answers the one task lookup `update_task` makes."""

    def __init__(self, task: Any) -> None:
        self._task = task

    async def execute(self, _statement: object) -> Any:
        return SimpleNamespace(scalar_one_or_none=lambda: self._task)


def _task(status: RemediationStatus, **fields: Any) -> Any:
    return SimpleNamespace(
        id=uuid4(),
        finding_id=uuid4(),
        status=status,
        completed_at=fields.get("completed_at"),
        assigned_to=fields.get("assigned_to"),
        due_date=fields.get("due_date"),
        notes=fields.get("notes"),
    )


def _tenant() -> Any:
    return SimpleNamespace(organization_id=uuid4(), user=SimpleNamespace(id=uuid4()))


@pytest.fixture
def world(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """The finding every task is about, and what was asked of verification."""
    state: dict[str, Any] = {
        "finding": SimpleNamespace(status=FindingStatus.IN_PROGRESS),
        "abandoned": [],
        "opened": 0,
    }

    async def get_finding(session: object, tenant: object, finding_id: UUID) -> Any:
        return state["finding"]

    async def abandon(session: object, org: UUID, finding_id: UUID, *, reason: str) -> None:
        state["abandoned"].append(reason)

    async def open_verification(session: object, **kwargs: object) -> None:
        state["opened"] += 1

    async def record_audit(*args: object, **kwargs: object) -> None:
        return None

    async def is_member(*args: object) -> bool:
        return True

    monkeypatch.setattr(service.findings_service, "get_finding", get_finding)
    monkeypatch.setattr(service.findings_service, "record_audit", record_audit)
    monkeypatch.setattr(service.verification_service, "abandon", abandon)
    monkeypatch.setattr(service.verification_service, "open_verification", open_verification)
    monkeypatch.setattr(service.organizations_service, "is_member", is_member)
    return state


async def _update(task: Any, **body: Any) -> Any:
    payload = RemediationUpdate.model_validate(body)
    return await service.update_task(_Session(task), _tenant(), task.id, payload)  # type: ignore[arg-type]


async def test_null_clears_the_owner_and_the_due_date(world: dict[str, Any]) -> None:
    task = _task(RemediationStatus.TODO, assigned_to=uuid4(), due_date=date(2026, 10, 9))

    await _update(task, assigned_to=None, due_date=None)

    assert task.assigned_to is None
    assert task.due_date is None


async def test_a_field_left_out_is_left_alone(world: dict[str, Any]) -> None:
    owner = uuid4()
    task = _task(RemediationStatus.TODO, assigned_to=owner, due_date=date(2026, 10, 9))

    await _update(task, notes="Waiting on the network team")

    assert task.assigned_to == owner
    assert task.due_date == date(2026, 10, 9)
    assert task.notes == "Waiting on the network team"


async def test_starting_work_claims_nothing(world: dict[str, Any]) -> None:
    task = _task(RemediationStatus.TODO)

    await _update(task, status="IN_PROGRESS")

    assert task.status == RemediationStatus.IN_PROGRESS
    assert world["opened"] == 0
    assert world["abandoned"] == []


async def test_done_opens_the_claim(world: dict[str, Any]) -> None:
    task = _task(RemediationStatus.IN_PROGRESS)

    await _update(task, status="DONE")

    assert task.completed_at is not None
    assert world["opened"] == 1


async def test_reopening_withdraws_the_claim(world: dict[str, Any]) -> None:
    task = _task(RemediationStatus.DONE, completed_at=datetime(2026, 10, 3, tzinfo=UTC))

    await _update(task, status="TODO")

    assert task.status == RemediationStatus.TODO
    assert task.completed_at is None
    assert world["abandoned"] == ["The remediation task was reopened."]
    assert world["finding"].status == FindingStatus.IN_PROGRESS


async def test_cancelling_gives_the_finding_back(world: dict[str, Any]) -> None:
    task = _task(RemediationStatus.TODO)

    await _update(task, status="CANCELLED")

    assert world["abandoned"] == ["The remediation task was cancelled."]
    assert world["finding"].status == FindingStatus.OPEN


async def test_cancelling_leaves_a_resolved_finding_resolved(world: dict[str, Any]) -> None:
    world["finding"].status = FindingStatus.RESOLVED
    task = _task(RemediationStatus.DONE, completed_at=datetime(2026, 10, 3, tzinfo=UTC))

    await _update(task, status="CANCELLED")

    assert world["finding"].status == FindingStatus.RESOLVED


async def test_a_cancelled_task_is_not_reopened(world: dict[str, Any]) -> None:
    task = _task(RemediationStatus.CANCELLED)

    with pytest.raises(ValidationFailed, match="not reopened"):
        await _update(task, status="TODO")
