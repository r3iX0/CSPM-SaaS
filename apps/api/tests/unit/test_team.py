"""Members and invitations: the rules that live in Python rather than in policies.

The database decides who may touch a membership row at all (OWNER or ADMIN).
It cannot say that only an owner makes an owner, or that the last owner stays,
so ``services/team.py`` does -- and a rule that guards against locking a whole
organization out of itself is worth testing as a matrix (DECISIONS.md 162).
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.core.enums import Role
from app.core.errors import ConflictError, PermissionDenied
from app.schemas.team import InvitationCreate
from app.services import team

NOW = datetime(2026, 9, 29, tzinfo=UTC)


@pytest.mark.parametrize(
    ("actor", "current", "wanted"),
    [
        (Role.ADMIN, Role.VIEWER, Role.SECURITY_ANALYST),
        (Role.ADMIN, Role.VIEWER, Role.ADMIN),
        (Role.ADMIN, Role.IT_ADMIN, None),
        (Role.OWNER, Role.VIEWER, Role.OWNER),
        (Role.OWNER, Role.ADMIN, None),
    ],
)
def test_changes_an_admin_or_owner_may_make(actor: Role, current: Role, wanted: Role) -> None:
    team.check_role_change(actor, current, wanted, owners=1)


@pytest.mark.parametrize(
    ("current", "wanted"),
    [
        (Role.VIEWER, Role.OWNER),
        (Role.OWNER, Role.ADMIN),
        (Role.OWNER, None),
    ],
)
def test_only_an_owner_makes_or_unmakes_an_owner(current: Role, wanted: Role | None) -> None:
    with pytest.raises(PermissionDenied):
        team.check_role_change(Role.ADMIN, current, wanted, owners=3)


@pytest.mark.parametrize("wanted", [Role.ADMIN, Role.VIEWER, None])
def test_the_last_owner_stays(wanted: Role | None) -> None:
    with pytest.raises(ConflictError, match="needs an owner"):
        team.check_role_change(Role.OWNER, Role.OWNER, wanted, owners=1)


def test_an_owner_may_step_down_while_another_remains() -> None:
    team.check_role_change(Role.OWNER, Role.OWNER, Role.ADMIN, owners=2)
    team.check_role_change(Role.OWNER, Role.OWNER, None, owners=2)


def test_the_token_is_stored_only_as_its_hash() -> None:
    digest = team.token_hash("a-token-from-a-link-of-some-length")
    assert len(digest) == 64
    assert digest == team.token_hash("a-token-from-a-link-of-some-length")
    assert "token" not in digest


@pytest.mark.parametrize(
    ("fields", "status"),
    [
        ({}, "OPEN"),
        ({"expires_at": NOW - timedelta(seconds=1)}, "EXPIRED"),
        ({"revoked_at": NOW}, "REVOKED"),
        # Used before it expired is used, whatever the clock says now.
        ({"accepted_at": NOW, "expires_at": NOW - timedelta(days=1)}, "ACCEPTED"),
    ],
)
def test_an_invitation_says_where_it_stands(fields: dict, status: str) -> None:
    base = {"accepted_at": None, "revoked_at": None, "expires_at": NOW + timedelta(days=1)}
    invitation = SimpleNamespace(**{**base, **fields})
    assert team.invitation_status(invitation, NOW) == status  # type: ignore[arg-type]


def test_nobody_is_invited_straight_into_ownership() -> None:
    with pytest.raises(ValidationError, match="make them an owner"):
        InvitationCreate(email="new@example.com", role=Role.OWNER)
    assert InvitationCreate(email="new@example.com").role is Role.VIEWER


def test_the_link_carries_the_token_in_a_fragment() -> None:
    """Never in a path or query, where a Referer or an access log would keep it."""
    assert team.INVITATION_PATH.endswith("#")
