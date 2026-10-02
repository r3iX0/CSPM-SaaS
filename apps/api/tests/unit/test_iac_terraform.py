"""The Terraform edit engine: one value changed in the customer's own HCL, or a
reason why not (DECISIONS.md §190).

Every case here is one a real repository has. The engine's job is less to make
the edit than to know when it must not: a guess written into somebody's
Terraform is a ``plan`` that fails, or worse, one that succeeds on the wrong
resource.
"""

import pytest

from app.remediation.iac import Change, Decline, Declined, Patched, edit_terraform

STORAGE = ("azurerm_storage_account",)
WEB = ("azurerm_linux_web_app", "azurerm_windows_web_app")
TLS = Change("min_tls_version", '"TLS1_2"')

ACCOUNT = """\
# Logs for prod. Do not rename.
resource "azurerm_storage_account" "logs" {
  name                     = "prodlogs"   # fixed by policy
  resource_group_name      = azurerm_resource_group.main.name
  account_tier             = "Standard"
  min_tls_version          = "TLS1_0"

  network_rules {
    default_action = "Allow"
  }
}
"""


def edit(source: str, *changes: Change, name: str = "prodlogs", types=STORAGE, **kw):
    return edit_terraform(source, resource_types=types, name=name, changes=changes or (TLS,), **kw)


def declined(result) -> Decline:
    assert isinstance(result, Declined), result
    return result.reason


# ------------------------------------------------------------------ the edit
def test_replaces_only_the_value() -> None:
    result = edit(ACCOUNT)
    assert isinstance(result, Patched)
    assert result.source == ACCOUNT.replace('"TLS1_0"', '"TLS1_2"')


def test_says_what_it_changed_and_where() -> None:
    result = edit(ACCOUNT)
    assert isinstance(result, Patched)
    (change,) = result.edits
    assert (change.attribute, change.before, change.after, change.line) == (
        "min_tls_version",
        '"TLS1_0"',
        '"TLS1_2"',
        6,
    )


def test_a_nested_attribute_is_replaced_inside_its_block() -> None:
    result = edit(ACCOUNT, Change("network_rules.default_action", '"Deny"'))
    assert isinstance(result, Patched)
    assert result.source == ACCOUNT.replace('"Allow"', '"Deny"')


def test_a_missing_optional_argument_is_added_beside_its_siblings() -> None:
    result = edit(ACCOUNT, Change("cross_tenant_replication_enabled", "false"))
    assert isinstance(result, Patched)
    assert result.source == ACCOUNT.replace(
        '  min_tls_version          = "TLS1_0"\n',
        '  min_tls_version          = "TLS1_0"\n  cross_tenant_replication_enabled = false\n',
    )
    assert result.edits[0].before is None


def test_an_added_argument_reports_its_own_line() -> None:
    result = edit(ACCOUNT, Change("cross_tenant_replication_enabled", "false"))
    assert isinstance(result, Patched)
    (added,) = result.edits
    assert (added.after, added.line) == ("false", 7)
    assert result.source.splitlines()[6].strip() == "cross_tenant_replication_enabled = false"


def test_a_web_app_site_config_setting_is_added_inside_its_block() -> None:
    source = """\
resource "azurerm_linux_web_app" "api" {
  name                = "orders-api"
  https_only          = false

  site_config {
    always_on = true
  }
}
"""
    result = edit(
        source,
        Change("https_only", "true"),
        Change("site_config.minimum_tls_version", '"1.2"'),
        name="orders-api",
        types=WEB,
    )
    assert isinstance(result, Patched)
    assert result.source == source.replace("= false", "= true").replace(
        "    always_on = true\n", '    always_on = true\n    minimum_tls_version = "1.2"\n'
    )


def test_a_value_the_rule_also_accepts_is_not_downgraded() -> None:
    # TLS 1.3 satisfies a rule asking for 1.2; rewriting it to 1.2 is a regression.
    source = ACCOUNT.replace('"TLS1_0"', '"TLS1_3"')
    change = Change("min_tls_version", '"TLS1_2"', accepts=('"TLS1_3"',))
    assert declined(edit(source, change)) is Decline.ALREADY_SET


def test_an_accepted_value_does_not_stop_a_failing_one_being_fixed() -> None:
    change = Change("min_tls_version", '"TLS1_2"', accepts=('"TLS1_3"',))
    result = edit(ACCOUNT, change)
    assert isinstance(result, Patched)
    assert result.edits[0].after == '"TLS1_2"'


@pytest.mark.parametrize(
    "source",
    [
        'resource "azurerm_storage_account" "x" { name = "prodlogs" }',
        'resource "azurerm_storage_account" "x" { name = "prodlogs" }\n',
    ],
    ids=["no-final-newline", "final-newline"],
)
def test_a_one_line_block_declines_rather_than_breaking(source: str) -> None:
    # Adding an argument means splitting the line; that is reformatting, not an edit.
    assert declined(edit(source)) is Decline.SINGLE_LINE_BLOCK


def test_a_one_line_nested_block_declines() -> None:
    source = ACCOUNT.replace(
        'network_rules {\n    default_action = "Allow"\n  }', "network_rules { bypass = [] }"
    )
    change = Change("network_rules.default_action", '"Deny"')
    assert declined(edit(source, change)) is Decline.SINGLE_LINE_BLOCK


def test_two_arguments_on_one_line_decline_cleanly() -> None:
    # Not valid HCL -- one argument per line -- so it must decline, not crash.
    source = 'resource "azurerm_storage_account" "x" { name = "prodlogs", min_tls_version = "a" }'
    assert declined(edit(source)) is Decline.PARSE_ERROR


def test_an_added_line_keeps_the_files_line_endings() -> None:
    source = ACCOUNT.replace("\n", "\r\n")
    result = edit(source, Change("cross_tenant_replication_enabled", "false"))
    assert isinstance(result, Patched)
    assert "cross_tenant_replication_enabled = false\r\n" in result.source
    assert "\n" not in result.source.replace("\r\n", "")


def test_several_changes_land_in_one_block() -> None:
    result = edit(ACCOUNT, TLS, Change("https_traffic_only_enabled", "true"))
    assert isinstance(result, Patched)
    assert [e.attribute for e in result.edits] == ["min_tls_version", "https_traffic_only_enabled"]
    assert '"TLS1_2"' in result.source
    assert "https_traffic_only_enabled = true" in result.source


def test_a_value_already_right_is_left_alone() -> None:
    result = edit(ACCOUNT.replace('"TLS1_0"', '"TLS1_2"'), TLS, Change("x_enabled", "false"))
    assert isinstance(result, Patched)
    assert [e.attribute for e in result.edits] == ["x_enabled"]


def test_nothing_to_change_is_its_own_answer() -> None:
    assert declined(edit(ACCOUNT.replace('"TLS1_0"', '"TLS1_2"'))) is Decline.ALREADY_SET


def test_the_resource_name_matches_whatever_its_case() -> None:
    # Azure resource names are case-insensitive; the portal shows one casing,
    # the HCL may hold another.
    assert isinstance(edit(ACCOUNT, name="ProdLogs"), Patched)


def test_the_diff_is_unified_and_names_the_file() -> None:
    result = edit(ACCOUNT)
    assert isinstance(result, Patched)
    diff = result.diff("storage.tf")
    assert diff.startswith("--- a/storage.tf\n+++ b/storage.tf\n")
    assert '-  min_tls_version          = "TLS1_0"\n' in diff
    assert '+  min_tls_version          = "TLS1_2"\n' in diff


# ------------------------------------------------------------ finding the block
def test_no_block_of_that_name() -> None:
    assert declined(edit(ACCOUNT, name="other")) is Decline.NO_MATCH


def test_a_block_of_another_type_is_not_a_match() -> None:
    assert declined(edit(ACCOUNT, types=("azurerm_key_vault",))) is Decline.NO_MATCH


def test_two_blocks_with_the_name_decline() -> None:
    twice = ACCOUNT + ACCOUNT.replace('"logs"', '"logs2"')
    assert declined(edit(twice)) is Decline.MULTIPLE_MATCHES


def test_an_interpolated_name_declines() -> None:
    source = ACCOUNT.replace('"prodlogs"', '"${var.env}logs"')
    assert declined(edit(source)) is Decline.INTERPOLATED_NAME


def test_an_interpolated_neighbour_makes_a_literal_match_ambiguous() -> None:
    # The interpolated one may render to the same name; which is deployed is a guess.
    other = ACCOUNT.replace('"logs"', '"other"').replace('"prodlogs"', "var.name")
    assert declined(edit(ACCOUNT + other)) is Decline.INTERPOLATED_NAME


# ------------------------------------------ the only block, in a file chosen for it
# An upload is a person saying "this file defines the asset". Where the name is
# built from an expression but the file holds one block of the type, that block
# is the one they meant -- and the answer says it was matched that way, so the
# reviewer checks it. Opt-in: a file CloudGuard chose itself says nothing of the kind.
INTERPOLATED = ACCOUNT.replace('"prodlogs"', '"${var.env}logs"')


def test_the_only_block_in_an_uploaded_file_is_matched_and_says_so() -> None:
    result = edit(INTERPOLATED, sole_block=True)
    assert isinstance(result, Patched)
    assert result.matched_by == "sole_block"
    assert '"TLS1_2"' in result.source


def test_a_literal_name_is_matched_by_name() -> None:
    result = edit(ACCOUNT, sole_block=True)
    assert isinstance(result, Patched)
    assert result.matched_by == "name"


def test_without_the_upload_the_only_block_is_still_a_guess() -> None:
    assert declined(edit(INTERPOLATED)) is Decline.INTERPOLATED_NAME


def test_two_interpolated_blocks_are_not_a_sole_block() -> None:
    other = INTERPOLATED.replace('"logs"', '"other"')
    assert declined(edit(INTERPOLATED + other, sole_block=True)) is Decline.INTERPOLATED_NAME


def test_an_interpolated_block_beside_another_of_its_kind_is_not_the_only_one() -> None:
    # "The only block of its kind" is what the reviewer is told; a second block
    # of the type, whatever its name, makes that untrue.
    other = ACCOUNT.replace('"logs"', '"other"').replace('"prodlogs"', '"zzz"')
    result = edit(INTERPOLATED + other, sole_block=True)
    assert declined(result) is Decline.INTERPOLATED_NAME


def test_the_only_block_named_something_else_is_another_resource() -> None:
    assert declined(edit(ACCOUNT, name="elsewhere", sole_block=True)) is Decline.NO_MATCH


def test_the_only_block_is_matched_across_the_rules_types() -> None:
    # A web app is Linux or Windows; one of either is still the only one.
    source = (
        'resource "azurerm_windows_web_app" "w" {\n  name = var.name\n  https_only = false\n}\n'
    )
    result = edit(source, Change("https_only", "true"), name="orders", types=WEB, sole_block=True)
    assert isinstance(result, Patched)


def test_the_only_block_under_count_still_declines() -> None:
    source = INTERPOLATED.replace("  account_tier", "  count = 2\n  account_tier")
    assert declined(edit(source, sole_block=True)) is Decline.COUNT_OR_FOR_EACH


@pytest.mark.parametrize("meta", ["count = 2", 'for_each = toset(["a"])'])
def test_a_repeated_resource_declines(meta: str) -> None:
    source = ACCOUNT.replace("  account_tier", f"  {meta}\n  account_tier")
    assert declined(edit(source)) is Decline.COUNT_OR_FOR_EACH


# ------------------------------------------------------------- the value itself
def test_a_value_from_a_variable_declines() -> None:
    source = ACCOUNT.replace('"TLS1_0"', "var.tls")
    assert declined(edit(source)) is Decline.VARIABLE_VALUE


def test_one_unsafe_change_declines_them_all() -> None:
    source = ACCOUNT.replace('"TLS1_0"', "var.tls")
    assert declined(edit(source, Change("x_enabled", "false"), TLS)) is Decline.VARIABLE_VALUE


# ----------------------------------------------------------------- nested blocks
def test_a_missing_nested_block_is_not_created() -> None:
    source = ACCOUNT.replace('  network_rules {\n    default_action = "Allow"\n  }\n', "")
    change = Change("network_rules.default_action", '"Deny"')
    assert declined(edit(source, change)) is Decline.NESTED_BLOCK_MISSING


def test_an_empty_nested_block_declines() -> None:
    block = 'network_rules {\n    default_action = "Allow"\n  }'
    source = ACCOUNT.replace(block, "network_rules {}")
    change = Change("network_rules.bypass", '["AzureServices"]')
    assert declined(edit(source, change)) is Decline.EMPTY_BLOCK


def test_a_dynamic_nested_block_declines() -> None:
    source = ACCOUNT.replace("network_rules {", 'dynamic "network_rules" {\n    for_each = []')
    change = Change("network_rules.default_action", '"Deny"')
    assert declined(edit(source, change)) is Decline.DYNAMIC_BLOCK


def test_two_nested_blocks_decline() -> None:
    block = '  network_rules {\n    default_action = "Allow"\n  }\n'
    source = ACCOUNT.replace(block, block + block)
    change = Change("network_rules.default_action", '"Deny"')
    assert declined(edit(source, change)) is Decline.MULTIPLE_MATCHES


# -------------------------------------------------------------- the file itself
def test_a_file_that_does_not_parse_declines() -> None:
    assert declined(edit(ACCOUNT.replace("}\n", "", 1))) is Decline.PARSE_ERROR


def test_an_oversized_file_declines_before_parsing() -> None:
    assert declined(edit(ACCOUNT + "#" * 300_000)) is Decline.TOO_LARGE


# ---------------------------------------------------------- the provider release
def providers(constraint: str) -> str:
    return (
        "terraform {\n  required_providers {\n"
        f'    azurerm = {{ source = "hashicorp/azurerm", version = "{constraint}" }}\n'
        "  }\n}\n"
    )


def lock(version: str) -> str:
    return (
        'provider "registry.terraform.io/hashicorp/azurerm" {\n'
        f'  version     = "{version}"\n  constraints = "~> 4.0"\n}}\n'
    )


@pytest.mark.parametrize("constraint", ["~> 3.0", "~> 4.0", "4.10.0", ">= 3.0"])
def test_a_release_the_attributes_were_checked_for_is_accepted(constraint: str) -> None:
    result = edit(providers(constraint) + ACCOUNT)
    assert isinstance(result, Patched)


@pytest.mark.parametrize(
    "constraint", ["~> 2.0", "= 2.99.0", "~> 5.0", ">= 5.0", "< 3.100", "<= 3.116.9"]
)
def test_a_pinned_release_outside_the_range_declines(constraint: str) -> None:
    result = edit(providers(constraint) + ACCOUNT)
    assert declined(result) is Decline.PROVIDER_VERSION_OUT_OF_RANGE


@pytest.mark.parametrize("version", ["3.117.1", "4.81.0", "4.99.1"])
def test_a_locked_release_in_range_is_accepted_and_reported(version: str) -> None:
    result = edit(ACCOUNT, lockfile=lock(version))
    assert isinstance(result, Patched)
    assert result.provider_version == version


@pytest.mark.parametrize("version", ["3.116.0", "2.99.0", "5.0.0"])
def test_a_locked_release_outside_the_range_declines(version: str) -> None:
    result = edit(ACCOUNT, lockfile=lock(version))
    assert declined(result) is Decline.PROVIDER_VERSION_OUT_OF_RANGE


def test_no_version_anywhere_is_reported_as_unknown() -> None:
    result = edit(ACCOUNT)
    assert isinstance(result, Patched)
    assert result.provider_version is None
