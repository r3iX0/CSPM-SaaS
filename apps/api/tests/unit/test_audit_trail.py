"""The audit trail's writer and reader, without a database (DECISIONS.md section 163).

Every entry says where its change came from -- the address and the request --
because a trail that records what without whence cannot be joined to anything
else an investigator holds. And only owners and admins read it.
"""

import uuid
from datetime import UTC, datetime

import pytest

from app.api.routes.audit_log import _entry
from app.core.deps import TenantContext
from app.core.enums import Role
from app.core.errors import PermissionDenied
from app.core.request_context import bound
from app.core.security import AuthenticatedUser
from app.models.remediation import AuditLog
from app.services import audit

ORG = uuid.uuid4()


def tenant(role: Role = Role.OWNER) -> TenantContext:
    return TenantContext(
        user=AuthenticatedUser(id=uuid.uuid4(), email="a@example.com"),
        organization_id=ORG,
        role=role,
    )


class Collecting:
    def __init__(self) -> None:
        self.added: list[object] = []

    def add(self, row: object) -> None:
        self.added.append(row)


async def test_an_entry_says_where_its_change_came_from() -> None:
    session = Collecting()
    with bound("f" * 32, "203.0.113.9"):
        await audit.record(session, tenant(), "member.removed", "member", None, {"role": "VIEWER"})  # type: ignore[arg-type]

    (entry,) = session.added
    assert isinstance(entry, AuditLog)
    assert entry.ip_address == "203.0.113.9"
    assert entry.audit_metadata == {"role": "VIEWER", "request_id": "f" * 32}
    assert entry.organization_id == ORG


async def test_outside_a_request_nothing_is_invented() -> None:
    session = Collecting()
    await audit.record(session, tenant(), "scan.started", "scan", None)  # type: ignore[arg-type]
    (entry,) = session.added
    assert entry.ip_address is None  # type: ignore[attr-defined]
    assert entry.audit_metadata == {}  # type: ignore[attr-defined]


@pytest.mark.parametrize("role", [Role.VIEWER, Role.SECURITY_ANALYST, Role.IT_ADMIN, Role.ADVISOR])
async def test_only_owners_and_admins_read_the_trail(role: Role) -> None:
    with pytest.raises(PermissionDenied):
        await audit.list_entries(
            None,  # type: ignore[arg-type]
            tenant(role),
            action=None,
            actor=None,
            resource_type=None,
            limit=10,
            offset=0,
        )


def test_the_request_id_is_its_own_field_not_a_detail() -> None:
    row = AuditLog(
        id=uuid.uuid4(),
        organization_id=ORG,
        user_id=None,
        action="finding.acceptance_expired",
        resource_type="finding",
        resource_id=None,
        audit_metadata={"rule_id": "AZ-1", "request_id": "abc"},
        ip_address=None,
        created_at=datetime.now(UTC),
    )
    out = _entry(row, None)
    assert out.request_id == "abc"
    assert out.details == {"rule_id": "AZ-1"}
    assert out.actor_id is None
