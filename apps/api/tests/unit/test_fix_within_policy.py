"""An organization's deadline policy is one statement, written whole (DECISIONS.md section 225).

``PATCH /organizations`` applies only the fields sent, but the policy inside it is sent whole: a
severity left out of it is cleared, null clears every severity, and the audit row records the
policy that resulted. A count outside 1 to 365 days is refused before it reaches the database.
"""

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.models.organization import Organization
from app.schemas.organization import OrganizationOut, OrganizationUpdate
from app.services import organizations as service


class _Session:
    def __init__(self, org: Organization) -> None:
        self.org = org

    async def get(self, _model: object, _id: object) -> Organization:
        return self.org


@pytest.fixture
def audited(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    async def record(*args: object) -> None:
        metadata = args[-1]
        assert isinstance(metadata, dict)
        rows.append(metadata)

    async def no_commit(_session: object) -> None:
        return None

    monkeypatch.setattr(service.audit, "record", record)
    monkeypatch.setattr(service, "commit_unless_externally_managed", no_commit)
    return rows


def _org(**days: int | None) -> Organization:
    org = Organization(name="Contoso", slug="contoso", is_demo=False)
    for severity in ("critical", "high", "medium", "low"):
        setattr(org, f"fix_within_days_{severity}", days.get(severity))
    return org


def _tenant() -> Any:
    return SimpleNamespace(organization_id=uuid4(), require_role=lambda *roles: None)


async def _update(org: Organization, body: dict[str, Any]) -> Organization:
    payload = OrganizationUpdate.model_validate(body)
    return await service.update_organization(_Session(org), _tenant(), payload)  # type: ignore[arg-type]


async def test_a_severity_left_out_of_the_policy_is_cleared(
    audited: list[dict[str, Any]],
) -> None:
    org = await _update(_org(critical=14, high=60, low=180), {"fix_within_days": {"critical": 7}})

    assert org.fix_within_days == {"critical": 7, "high": None, "medium": None, "low": None}
    assert audited[0]["changed"]["fix_within_days"] == org.fix_within_days


async def test_null_clears_every_deadline(audited: list[dict[str, Any]]) -> None:
    org = await _update(_org(critical=7, high=30), {"fix_within_days": None})
    assert set(org.fix_within_days.values()) == {None}


async def test_a_profile_edit_leaves_the_policy_alone(audited: list[dict[str, Any]]) -> None:
    org = await _update(_org(critical=7), {"name": "Contoso Security"})
    assert org.fix_within_days_critical == 7
    assert "fix_within_days" not in audited[0]["changed"]


@pytest.mark.parametrize("days", [0, 366, -1])
def test_a_count_outside_a_year_is_refused(days: int) -> None:
    with pytest.raises(ValidationError):
        OrganizationUpdate.model_validate({"fix_within_days": {"high": days}})


def test_an_unknown_severity_is_refused() -> None:
    with pytest.raises(ValidationError):
        OrganizationUpdate.model_validate({"fix_within_days": {"severe": 7}})


def test_the_organization_says_its_policy() -> None:
    org = _org(critical=7, high=30)
    org.id = uuid4()
    org.created_at = datetime(2026, 10, 8, tzinfo=UTC)
    out = OrganizationOut.model_validate(org)
    assert out.fix_within_days.model_dump() == {
        "critical": 7,
        "high": 30,
        "medium": None,
        "low": None,
    }
