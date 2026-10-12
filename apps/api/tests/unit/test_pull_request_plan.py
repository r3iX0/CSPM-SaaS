"""Planning one rule's pull request over one repository (DECISIONS.md §232).

A block is edited only where every asset it defines fails the rule; two assets
in one block are one edit; edits to one file build on each other; and what the
engine cannot stand behind is declined with its reason, beside what it edited.
"""

from uuid import uuid4

from app.remediation.iac.pull_request import Target, block_key, plan
from app.remediation.iac.terraform import Change, RuleChanges

RULE = RuleChanges(
    resource_types=("azurerm_storage_account",),
    changes=(Change("min_tls_version", '"TLS1_2"'),),
)
SUB = "/subscriptions/00000000-0000-0000-0000-000000000001/resourcegroups/rg/providers/"
LOGS, DATA, SPARE = (
    f"{SUB}microsoft.storage/storageaccounts/{name}" for name in ("logs", "data", "spare")
)

FILES = {
    "infra/main.tf": """\
resource "azurerm_storage_account" "logs" {
  name            = "${var.prefix}logs"
  min_tls_version = "TLS1_0"
}

resource "azurerm_storage_account" "data" {
  name            = "${var.prefix}data"
  min_tls_version = "TLS1_0"
}

resource "azurerm_storage_account" "many" {
  count           = 2
  name            = "${var.prefix}${count.index}"
  min_tls_version = "TLS1_0"
}

module "vendored" {
  source = "Azure/avm-res-storage-storageaccount/azurerm"
}
""",
}


def _target(address: str, resource_id: str) -> Target:
    return Target(uuid4(), resource_id, address, "infra")


def _plan(*targets: Target, failing: set[str], instances: dict | None = None):
    return plan(FILES, targets, RULE, instances=instances or {}, failing=failing)


def test_a_block_named_by_an_expression_is_edited_by_its_address() -> None:
    result = _plan(_target("azurerm_storage_account.logs", LOGS), failing={LOGS})
    [outcome] = result.outcomes
    assert (outcome.edited, outcome.path, outcome.line) == (True, "infra/main.tf", 3)
    assert 'min_tls_version = "TLS1_2"' in result.files["infra/main.tf"]


def test_edits_to_one_file_build_on_each_other() -> None:
    result = _plan(
        _target("azurerm_storage_account.logs", LOGS),
        _target("azurerm_storage_account.data", DATA),
        failing={LOGS, DATA},
    )
    assert [outcome.edited for outcome in result.outcomes] == [True, True]
    assert result.files["infra/main.tf"].count('"TLS1_2"') == 2


def test_a_repeated_block_is_edited_where_every_instance_fails() -> None:
    first, second = (
        _target(f"azurerm_storage_account.many[{i}]", rid) for i, rid in enumerate((LOGS, DATA))
    )
    instances = {block_key("infra", "azurerm_storage_account.many[0]"): {LOGS, DATA}}
    result = _plan(first, second, failing={LOGS, DATA}, instances=instances)
    # One block, so one edit, and both findings are covered by it.
    assert [outcome.edited for outcome in result.outcomes] == [True, True]
    assert result.files["infra/main.tf"].count('"TLS1_2"') == 1


def test_a_repeated_block_with_a_passing_instance_is_declined() -> None:
    instances = {block_key("infra", "azurerm_storage_account.many[0]"): {LOGS, SPARE}}
    result = _plan(
        _target("azurerm_storage_account.many[0]", LOGS), failing={LOGS}, instances=instances
    )
    [outcome] = result.outcomes
    assert (outcome.edited, outcome.reason) == (False, "partial_instances")
    assert result.files == {}


def test_a_block_shared_by_workspaces_counts_every_workspaces_asset() -> None:
    # Not repeated in its address, but two workspaces' states place two assets in it.
    instances = {block_key("infra", "azurerm_storage_account.logs"): {LOGS, SPARE}}
    result = _plan(
        _target("azurerm_storage_account.logs", LOGS), failing={LOGS}, instances=instances
    )
    assert result.outcomes[0].reason == "partial_instances"


def test_what_the_engine_cannot_reach_is_declined_beside_what_it_edited() -> None:
    result = _plan(
        _target("azurerm_storage_account.logs", LOGS),
        _target("module.vendored.azurerm_storage_account.this", DATA),
        failing={LOGS, DATA},
    )
    assert [(o.edited, o.reason) for o in result.outcomes] == [
        (True, None),
        (False, "module_external"),
    ]
    assert len(result.edited) == 1
