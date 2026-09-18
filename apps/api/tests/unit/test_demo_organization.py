"""The demo organization is read-only for everybody, whatever their role.

Joining the demo always grants VIEWER, which ``require_write`` already refuses.
The flag is checked as well, so "nobody can change the demo" does not rest on
every membership row in it being right -- an OWNER row put there by hand, or by
a future bug, still cannot write.
"""

import uuid

import pytest

from app.core.deps import TenantContext
from app.core.enums import Role
from app.core.errors import PermissionDenied
from app.core.security import AuthenticatedUser


def tenant(role: Role, *, demo: bool) -> TenantContext:
    return TenantContext(
        user=AuthenticatedUser(id=uuid.uuid4()),
        organization_id=uuid.uuid4(),
        role=role,
        is_demo=demo,
    )


@pytest.mark.parametrize("role", list(Role))
def test_no_role_can_write_in_the_demo(role: Role) -> None:
    with pytest.raises(PermissionDenied, match="demo organization is read-only"):
        tenant(role, demo=True).require_write()


@pytest.mark.parametrize("role", list(Role))
def test_no_role_passes_a_role_check_in_the_demo(role: Role) -> None:
    with pytest.raises(PermissionDenied, match="demo organization is read-only"):
        tenant(role, demo=True).require_role(Role.OWNER, Role.ADMIN)


def test_an_ordinary_organization_is_unchanged() -> None:
    tenant(Role.OWNER, demo=False).require_write()
    tenant(Role.ADMIN, demo=False).require_role(Role.OWNER, Role.ADMIN)
    with pytest.raises(PermissionDenied, match="read-only"):
        tenant(Role.VIEWER, demo=False).require_write()


def test_the_flag_defaults_to_an_ordinary_organization() -> None:
    context = TenantContext(
        user=AuthenticatedUser(id=uuid.uuid4()),
        organization_id=uuid.uuid4(),
        role=Role.OWNER,
    )
    assert context.is_demo is False
    context.require_write()
