"""Who owns unassigned work: the most specific rule an asset's place matches (§236).

A tag, then the resource group, then the subscription, then the default. A rule whose owner
has left is skipped, and the work falls to the next one. Derived, never stored, so the person a
task was handed to always wins.
"""

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from app.core.enums import OwnershipScope, Priority, RemediationStatus
from app.models.ownership import OwnershipRule
from app.models.remediation import RemediationTask
from app.schemas.ownership import OwnershipRuleIn
from app.services.ownership import Placement, Routed, placement_of, route
from app.services.remediation import Owner, owner

SUB, OTHER_SUB = uuid4(), uuid4()
ALICE, BOB, CAROL, DAN = (uuid4() for _ in range(4))
MEMBERS = {ALICE, BOB, CAROL, DAN}
T0 = datetime(2026, 10, 1, tzinfo=UTC)


def _rule(
    scope: OwnershipScope, owner_id: UUID, *, minutes: int = 0, **scoped: object
) -> OwnershipRule:
    return OwnershipRule(
        id=uuid4(),
        scope=scope,
        owner_id=owner_id,
        created_by=owner_id,
        created_at=T0 + timedelta(minutes=minutes),
        **scoped,
    )


RULES = [
    _rule(OwnershipScope.DEFAULT, ALICE),
    _rule(OwnershipScope.SUBSCRIPTION, BOB, cloud_account_id=SUB),
    _rule(OwnershipScope.RESOURCE_GROUP, CAROL, cloud_account_id=SUB, resource_group="Payments"),
    _rule(OwnershipScope.TAG, DAN, tag_key="owner", tag_value="platform-team"),
]
ARM = f"/subscriptions/{SUB}/resourceGroups/payments/providers/Microsoft.Storage/storageAccounts/sa"


def _owner(placement: Placement, rules: list[OwnershipRule] = RULES, members: set[UUID] = MEMBERS):
    routed = route(placement, rules, members)
    return (routed.owner_id, routed.scope) if routed else None


def test_a_tag_is_the_most_specific() -> None:
    placement = placement_of(SUB, ARM, {"Owner": "platform-team"})
    assert _owner(placement) == (DAN, OwnershipScope.TAG)


def test_a_tag_value_is_compared_exactly() -> None:
    placement = placement_of(SUB, ARM, {"owner": "Platform-Team"})
    assert _owner(placement) == (CAROL, OwnershipScope.RESOURCE_GROUP)


def test_a_resource_group_is_matched_whatever_its_case() -> None:
    assert _owner(placement_of(SUB, ARM, {})) == (CAROL, OwnershipScope.RESOURCE_GROUP)


def test_a_resource_group_belongs_to_its_subscription() -> None:
    elsewhere = ARM.replace(str(SUB), str(OTHER_SUB))
    assert _owner(placement_of(OTHER_SUB, elsewhere, {})) == (ALICE, OwnershipScope.DEFAULT)


def test_another_group_falls_to_the_subscription() -> None:
    other = ARM.replace("payments", "logging")
    assert _owner(placement_of(SUB, other, None)) == (BOB, OwnershipScope.SUBSCRIPTION)


def test_a_directory_object_has_only_the_default() -> None:
    assert _owner(placement_of(None, None, None)) == (ALICE, OwnershipScope.DEFAULT)


def test_nobody_owns_what_no_rule_names() -> None:
    assert _owner(placement_of(None, None, None), rules=RULES[1:]) is None


def test_a_rule_whose_owner_left_is_skipped() -> None:
    placement = placement_of(SUB, ARM, {"owner": "platform-team"})
    assert _owner(placement, members=MEMBERS - {DAN}) == (CAROL, OwnershipScope.RESOURCE_GROUP)


def test_of_two_matching_tags_the_rule_made_first_wins() -> None:
    later = _rule(OwnershipScope.TAG, ALICE, minutes=5, tag_key="team", tag_value="data")
    placement = placement_of(SUB, ARM, {"team": "data", "owner": "platform-team"})
    assert _owner(placement, rules=[later, *RULES]) == (DAN, OwnershipScope.TAG)


def _task(assigned_to: UUID | None) -> RemediationTask:
    return RemediationTask(
        finding_id=uuid4(),
        assigned_to=assigned_to,
        status=RemediationStatus.TODO,
        priority=Priority.HIGH,
    )


def test_the_person_a_task_was_handed_to_wins_over_any_rule() -> None:
    routed = Routed(DAN, OwnershipScope.TAG, uuid4())
    assert owner(_task(BOB), routed) == Owner(BOB)


def test_an_unassigned_task_is_owned_by_its_rule_and_says_which() -> None:
    routed = Routed(DAN, OwnershipScope.TAG, uuid4())
    assert owner(_task(None), routed) == Owner(DAN, OwnershipScope.TAG)


@pytest.mark.parametrize(
    "body",
    [
        {"scope": "SUBSCRIPTION"},
        {"scope": "RESOURCE_GROUP", "cloud_account_id": str(SUB)},
        {"scope": "TAG", "tag_key": "owner"},
        {"scope": "DEFAULT", "tag_key": "owner", "tag_value": "x"},
        {"scope": "TAG", "tag_key": "owner", "tag_value": "x", "cloud_account_id": str(SUB)},
    ],
    ids=[
        "missing_account",
        "missing_group",
        "missing_value",
        "default_with_tag",
        "tag_with_account",
    ],
)
def test_a_rule_takes_exactly_the_fields_its_scope_needs(body: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        OwnershipRuleIn.model_validate({**body, "owner_id": str(ALICE)})


def test_a_complete_rule_validates() -> None:
    rule = OwnershipRuleIn.model_validate(
        {
            "scope": "RESOURCE_GROUP",
            "cloud_account_id": str(SUB),
            "resource_group": "rg",
            "owner_id": str(ALICE),
        }
    )
    assert rule.scope is OwnershipScope.RESOURCE_GROUP
