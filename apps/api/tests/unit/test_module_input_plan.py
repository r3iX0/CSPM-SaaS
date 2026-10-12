"""A fix written through a module's inputs, and an edit in a module that other code calls (§233).

Where the argument in a module is written ``= var.x`` and nothing else in the
module uses ``x``, the edit is made on the module call that sets it, which
changes that call's assets only. A literal written in a module changes every
call of it, so each call must be in an index and fail the rule.
"""

from uuid import uuid4

from app.remediation.iac.pull_request import Plan, Target, block_key, plan
from app.remediation.iac.terraform import (
    Change,
    Decline,
    Declined,
    Passed,
    RuleChanges,
    edit_module_input,
)

RULE = RuleChanges(
    resource_types=("azurerm_storage_account",),
    changes=(Change("min_tls_version", '"TLS1_2"', ('"TLS1_3"',)),),
)
SUB = "/subscriptions/00000000-0000-0000-0000-000000000001/resourcegroups/rg/providers/"
LOGS, DATA, SPARE = (
    f"{SUB}microsoft.storage/storageaccounts/{name}" for name in ("logs", "data", "spare")
)

PASSED_THROUGH = """\
variable "prefix" {
  type = string
}

variable "tls" {
  type    = string
  default = "TLS1_0"
}

resource "azurerm_storage_account" "main" {
  name            = "${var.prefix}sa"
  min_tls_version = var.tls
}
"""
LITERAL = """\
resource "azurerm_storage_account" "main" {
  name            = "${var.prefix}sa"
  min_tls_version = "TLS1_0"
}
"""
ROOT = """\
module "logs" {
  source = "./modules/storage"
  prefix = "logs"
  tls    = "TLS1_0"
}

module "data" {
  source = "./modules/storage"
  prefix = "data"
}
"""


def _files(module: str = PASSED_THROUGH, root: str = ROOT, **more: str) -> dict[str, str]:
    return {"infra/main.tf": root, "infra/modules/storage/main.tf": module, **more}


def _address(call: str) -> str:
    return f"module.{call}.azurerm_storage_account.main"


def _plan(files: dict[str, str], *calls: tuple[str, str], failing: set[str]) -> Plan:
    """Plan the first call's target, with every call given indexed in ``infra``."""
    instances = {block_key("infra", _address(call)): {rid} for call, rid in calls}
    call, resource_id = calls[0]
    target = Target(uuid4(), resource_id, _address(call), "infra")
    return plan(files, [target], RULE, instances=instances, failing=failing)


def test_an_input_passed_straight_through_is_set_on_the_module_call() -> None:
    result = _plan(_files(), ("logs", LOGS), failing={LOGS})
    [outcome] = result.outcomes
    assert (outcome.edited, outcome.path, outcome.line) == (True, "infra/main.tf", 4)
    assert 'tls    = "TLS1_2"' in result.files["infra/main.tf"]
    # The module is left alone: the other call still gets its own value.
    assert "infra/modules/storage/main.tf" not in result.files


def test_an_input_left_to_its_default_is_added_to_the_call() -> None:
    result = _plan(_files(), ("data", DATA), failing={DATA})
    assert result.outcomes[0].edited
    assert '  prefix = "data"\n  tls = "TLS1_2"\n}' in result.files["infra/main.tf"]


def test_a_default_that_already_meets_the_rule_is_not_added() -> None:
    files = _files(PASSED_THROUGH.replace('default = "TLS1_0"', 'default = "TLS1_3"'))
    result = _plan(files, ("data", DATA), failing={DATA})
    assert result.outcomes[0].reason == Decline.ALREADY_SET.value


def test_a_variable_the_module_uses_elsewhere_declines() -> None:
    module = PASSED_THROUGH + 'output "tls" {\n  value = var.tls\n}\n'
    result = _plan(_files(module), ("logs", LOGS), failing={LOGS})
    assert result.outcomes[0].reason == Decline.VARIABLE_SHARED.value
    assert result.files == {}


def test_a_validated_variable_declines() -> None:
    module = PASSED_THROUGH.replace(
        '  default = "TLS1_0"\n',
        '  default = "TLS1_0"\n  validation {\n    condition     = var.tls != ""\n'
        '    error_message = "Set it."\n  }\n',
    )
    result = _plan(_files(module), ("logs", LOGS), failing={LOGS})
    assert result.outcomes[0].reason == Decline.VARIABLE_VALUE.value


def test_a_value_from_the_root_modules_variables_declines() -> None:
    root = ROOT.replace('tls    = "TLS1_0"', "tls    = var.logs_tls")
    result = _plan(_files(root=root), ("logs", LOGS), failing={LOGS})
    [outcome] = result.outcomes
    assert outcome.reason == Decline.VARIABLE_VALUE.value
    assert outcome.detail is not None and ".tfvars" in outcome.detail


def test_an_input_is_followed_up_through_two_modules() -> None:
    wrapper = (
        'variable "tls" {\n  type = string\n}\n\n'
        'module "inner" {\n  source = "../storage"\n  prefix = "logs"\n  tls    = var.tls\n}\n'
    )
    root = 'module "outer" {\n  source = "./modules/wrapper"\n  tls    = "TLS1_0"\n}\n'
    files = _files(root=root, **{"infra/modules/wrapper/main.tf": wrapper})
    address = "module.outer.module.inner.azurerm_storage_account.main"
    instances = {block_key("infra", address): {LOGS}}
    result = plan(
        files,
        [Target(uuid4(), LOGS, address, "infra")],
        RULE,
        instances=instances,
        failing={LOGS},
    )
    assert result.outcomes[0].edited
    assert set(result.files) == {"infra/main.tf"}
    assert 'tls    = "TLS1_2"' in result.files["infra/main.tf"]


def test_a_literal_in_a_module_two_failing_calls_share_is_one_edit() -> None:
    result = plan(
        _files(LITERAL),
        [
            Target(uuid4(), LOGS, _address("logs"), "infra"),
            Target(uuid4(), DATA, _address("data"), "infra"),
        ],
        RULE,
        instances={
            block_key("infra", _address("logs")): {LOGS},
            block_key("infra", _address("data")): {DATA},
        },
        failing={LOGS, DATA},
    )
    assert [outcome.edited for outcome in result.outcomes] == [True, True]
    assert result.files["infra/modules/storage/main.tf"].count('"TLS1_2"') == 1


def test_a_literal_in_a_module_another_passing_call_uses_declines() -> None:
    result = _plan(_files(LITERAL), ("logs", LOGS), ("data", SPARE), failing={LOGS})
    assert result.outcomes[0].reason == Decline.PARTIAL_INSTANCES.value
    assert result.files == {}


def test_a_literal_in_a_module_unindexed_code_calls_declines() -> None:
    example = 'module "example" {\n  source = "../infra/modules/storage"\n}\n'
    files = _files(LITERAL, **{"examples/main.tf": example})
    result = _plan(files, ("logs", LOGS), ("data", DATA), failing={LOGS, DATA})
    [outcome] = result.outcomes
    assert outcome.reason == Decline.UNINDEXED_CALLER.value
    assert outcome.detail is not None and "examples/main.tf" in outcome.detail


def test_an_input_edit_is_not_held_back_by_other_calls_of_the_module() -> None:
    # The call is the edit's place, so what else runs the module is unchanged.
    example = 'module "example" {\n  source = "../infra/modules/storage"\n}\n'
    result = _plan(_files(**{"examples/main.tf": example}), ("logs", LOGS), failing={LOGS})
    assert result.outcomes[0].edited


def test_a_repeated_module_call_is_edited_only_where_every_instance_fails() -> None:
    root = ROOT.replace('  prefix = "logs"\n', '  count  = 2\n  prefix = "logs"\n')
    address = "module.logs[0].azurerm_storage_account.main"
    instances = {block_key("infra", address): {LOGS, SPARE}}
    target = Target(uuid4(), LOGS, address, "infra")
    declined = plan(_files(root=root), [target], RULE, instances=instances, failing={LOGS})
    assert declined.outcomes[0].reason == Decline.PARTIAL_INSTANCES.value
    edited = plan(_files(root=root), [target], RULE, instances=instances, failing={LOGS, SPARE})
    assert edited.outcomes[0].edited


def test_a_call_mixing_its_own_and_passed_values_is_left_to_a_person() -> None:
    passed = (Passed("tls", RULE.changes[0]), Passed("extra", Change("x", "true")))
    root = 'module "logs" {\n  source = "./m"\n  tls    = "TLS1_0"\n  extra  = var.extra\n}\n'
    declined = edit_module_input(
        root, module="logs", inputs=passed, defaults={"tls": None, "extra": None}
    )
    assert isinstance(declined, Declined) and declined.reason is Decline.VARIABLE_VALUE
    assert not declined.passed
