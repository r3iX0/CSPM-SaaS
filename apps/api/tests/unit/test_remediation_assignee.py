"""Remediation work is assigned only to members of the organization (DECISIONS.md section 159).

The refusal is checked before anything is read or written: the finding lookup
and the task are never reached, so these run with no session at all.
"""

from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import pytest

from app.api.routes import remediation as route
from app.core.errors import ValidationFailed
from app.schemas.finding import RemediationCreate, RemediationUpdate


def _tenant() -> Any:
    return SimpleNamespace(organization_id=uuid4(), require_write=lambda: None)


@pytest.fixture
def members(monkeypatch: pytest.MonkeyPatch) -> set[UUID]:
    """The organization's members, as ``is_member`` will report them."""
    known: set[UUID] = set()

    async def is_member(session: object, organization_id: UUID, user_id: UUID) -> bool:
        return user_id in known

    monkeypatch.setattr(route.organizations_service, "is_member", is_member)
    return known


async def test_a_task_for_a_stranger_is_refused(members: set[UUID]) -> None:
    payload = RemediationCreate(finding_id=uuid4(), assigned_to=uuid4())
    with pytest.raises(ValidationFailed, match="not a member"):
        await route.create_task(payload, session=None, tenant=_tenant())  # type: ignore[arg-type]


async def test_reassigning_to_a_stranger_is_refused(members: set[UUID]) -> None:
    payload = RemediationUpdate(assigned_to=uuid4())
    with pytest.raises(ValidationFailed, match="not a member"):
        await route.update_task(uuid4(), payload, session=None, tenant=_tenant())  # type: ignore[arg-type]


async def test_no_assignee_is_not_asked_about(monkeypatch: pytest.MonkeyPatch) -> None:
    async def is_member(*args: object) -> bool:
        raise AssertionError("an unassigned task has nobody to check")

    monkeypatch.setattr(route.organizations_service, "is_member", is_member)
    await route._require_assignee(None, _tenant(), None)  # type: ignore[arg-type]


async def test_a_member_passes(members: set[UUID]) -> None:
    colleague = uuid4()
    members.add(colleague)
    await route._require_assignee(None, _tenant(), colleague)  # type: ignore[arg-type]
