"""A cut as code: deleting the role assignment blocks it removes (DECISIONS.md section 257).

A block is deleted whole with the blank line after it; one under ``count`` or
``for_each`` only where every assignment it defines is in the cut; and what
cannot be deleted is declined with its reason.
"""

from app.remediation.iac.cut import AssignmentTarget, plan_removal
from app.remediation.iac.pull_request import block_key
from app.remediation.iac.terraform import Declined, Removed, remove_resource_block

SCOPE = "/subscriptions/00000000-0000-0000-0000-000000000001/resourcegroups/rg"
APP, OPS, MANY_0, MANY_1 = (
    f"{SCOPE}/providers/microsoft.authorization/roleassignments/{name}"
    for name in ("app", "ops", "many-0", "many-1")
)

MAIN = """\
resource "azurerm_role_assignment" "app" {
  scope                = azurerm_resource_group.rg.id
  role_definition_name = "Owner"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
}

resource "azurerm_role_assignment" "ops" {
  scope                = azurerm_resource_group.rg.id
  role_definition_name = "Reader"
  principal_id         = var.ops
}

resource "azurerm_role_assignment" "many" {
  count                = 2
  scope                = azurerm_resource_group.rg.id
  role_definition_name = "Contributor"
  principal_id         = var.principals[count.index]
}
"""
FILES = {"infra/main.tf": MAIN}


def target(address: str, assignment_id: str) -> AssignmentTarget:
    return AssignmentTarget(assignment_id, address, "infra")


def test_a_block_is_removed_whole_with_its_spacing() -> None:
    removed = remove_resource_block(MAIN, resource_type="azurerm_role_assignment", label="app")
    assert isinstance(removed, Removed)
    assert removed.line == 1
    assert removed.source.startswith('resource "azurerm_role_assignment" "ops" {')
    assert '"Owner"' not in removed.source
    assert '-  role_definition_name = "Owner"' in removed.diff("infra/main.tf")


def test_a_repeated_block_is_not_removed_unless_asked() -> None:
    declined = remove_resource_block(MAIN, resource_type="azurerm_role_assignment", label="many")
    assert isinstance(declined, Declined)
    assert declined.reason.value == "count_or_for_each"


def test_the_cut_deletes_its_assignment_and_leaves_the_rest() -> None:
    result = plan_removal(FILES, [target("azurerm_role_assignment.app", APP)], instances={})
    [outcome] = result.outcomes
    assert (outcome.removed, outcome.path, outcome.line) == (True, "infra/main.tf", 1)
    assert '"Reader"' in result.files["infra/main.tf"]
    assert '"Owner"' not in result.files["infra/main.tf"]
    assert "infra/main.tf" in result.diffs()


def test_two_removals_in_one_file_build_on_each_other() -> None:
    result = plan_removal(
        FILES,
        [target("azurerm_role_assignment.app", APP), target("azurerm_role_assignment.ops", OPS)],
        instances={},
    )
    assert all(outcome.removed for outcome in result.outcomes)
    text = result.files["infra/main.tf"]
    assert '"Owner"' not in text
    assert '"Reader"' not in text
    assert '"Contributor"' in text


def test_a_repeated_block_is_kept_while_any_assignment_it_defines_is_not_cut() -> None:
    key = block_key("infra", "azurerm_role_assignment.many")
    result = plan_removal(
        FILES,
        [target("azurerm_role_assignment.many[0]", MANY_0)],
        instances={key: {MANY_0, MANY_1}},
    )
    [outcome] = result.outcomes
    assert not outcome.removed
    assert outcome.reason == "count_or_for_each"
    assert result.files == {}


def test_a_repeated_block_goes_when_every_assignment_it_defines_is_cut() -> None:
    key = block_key("infra", "azurerm_role_assignment.many")
    result = plan_removal(
        FILES,
        [
            target("azurerm_role_assignment.many[0]", MANY_0),
            target("azurerm_role_assignment.many[1]", MANY_1),
        ],
        instances={key: {MANY_0, MANY_1}},
    )
    assert [outcome.removed for outcome in result.outcomes] == [True, True]
    assert '"Contributor"' not in result.files["infra/main.tf"]
