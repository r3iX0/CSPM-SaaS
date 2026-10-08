"""The state index: what an upload may hold, and how an address finds its block (§229).

The Action sends four fields per resource and nothing else, because state holds
secrets in plain text; anything more refuses the upload. An address is followed
from the directory Terraform ran in, through each module's local source, to the
one ``resource "<type>" "<label>"`` block, which the edit engine then changes by
its label rather than by a name an expression renders.
"""

import pytest

from app.remediation.iac.index import (
    MAX_ENTRIES,
    InvalidIndex,
    entries_from_upload,
    parse_address,
)
from app.remediation.iac.terraform import (
    Change,
    Decline,
    Declined,
    FoundBlock,
    ModuleCall,
    Patched,
    edit_terraform,
    find_resource_block,
)

SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"
ACCOUNT_ID = f"{SUB}/resourceGroups/RG/providers/Microsoft.Storage/storageAccounts/ProdLogs"


def _entry(**fields: object) -> dict[str, object]:
    return {
        "address": "module.storage.azurerm_storage_account.main",
        "type": "azurerm_storage_account",
        "index": None,
        "id": ACCOUNT_ID,
    } | fields


# ------------------------------------------------------------------ addresses
def test_an_address_names_its_modules_type_and_label() -> None:
    address = parse_address('module.app["eu"].module.data.azurerm_storage_account.logs[0]')
    assert address.modules == ("app", "data")
    assert (address.type, address.name, address.repeated) == (
        "azurerm_storage_account",
        "logs",
        True,
    )


def test_a_plain_resource_is_not_repeated() -> None:
    address = parse_address("azurerm_key_vault.main")
    assert (address.modules, address.repeated) == ((), False)


def test_a_repeated_module_repeats_what_it_holds() -> None:
    assert parse_address("module.region[1].azurerm_key_vault.main").repeated


@pytest.mark.parametrize(
    "address",
    ["data.azurerm_client_config.current", "aws_s3_bucket.logs", "azurerm_key_vault", ""],
)
def test_anything_but_a_managed_azurerm_resource_is_refused(address: str) -> None:
    with pytest.raises(InvalidIndex):
        parse_address(address)


# --------------------------------------------------------------------- upload
def test_an_upload_keeps_four_fields_and_lowers_the_id() -> None:
    [entry] = entries_from_upload([_entry(index=0)])
    assert entry.resource_id == ACCOUNT_ID.lower()
    assert entry.index == "0"


@pytest.mark.parametrize(
    "fields",
    [
        {"values": {"primary_access_key": "secret"}},
        {"id": "https://vault.vault.azure.net/secrets/db"},
        {"type": "azurerm_key_vault"},
        {"index": True},
        {"address": None},
    ],
    ids=["extra_field", "not_an_arm_id", "wrong_type", "bool_index", "no_address"],
)
def test_an_upload_holding_anything_else_is_refused_whole(fields: dict[str, object]) -> None:
    with pytest.raises(InvalidIndex):
        entries_from_upload([_entry(), _entry(address="azurerm_storage_account.b") | fields])


def test_what_the_actions_filter_sends_is_accepted() -> None:
    # The output of tools/iac/github/cleave-index.sh's jq filter over a state
    # holding a resource group, a storage account under count in a module, a data
    # source, a random_string and a key vault secret: the last three are left out.
    sent = [
        {
            "address": "azurerm_resource_group.rg",
            "type": "azurerm_resource_group",
            "index": None,
            "id": f"{SUB}/resourceGroups/rg",
        },
        {
            "address": "module.storage.azurerm_storage_account.main[0]",
            "type": "azurerm_storage_account",
            "index": 0,
            "id": ACCOUNT_ID,
        },
    ]
    assert [entry.address for entry in entries_from_upload(sent)] == [
        "azurerm_resource_group.rg",
        "module.storage.azurerm_storage_account.main[0]",
    ]


def test_one_address_twice_is_refused() -> None:
    with pytest.raises(InvalidIndex):
        entries_from_upload([_entry(), _entry()])


def test_an_upload_has_a_ceiling() -> None:
    with pytest.raises(InvalidIndex):
        entries_from_upload([_entry()] * (MAX_ENTRIES + 1))


# --------------------------------------------------------------------- blocks
ROOT = """\
module "storage" {
  source = "./modules/storage"
  prefix = var.prefix
}
"""
MODULE = """\
resource "azurerm_storage_account" "main" {
  name            = "${var.prefix}logs"
  min_tls_version = "TLS1_0"
}
"""
FILES = {
    "infra/main.tf": ROOT,
    "infra/modules/storage/main.tf": MODULE,
    "infra/modules/storage/README.md": "resource in prose",
}


def _find(files: dict[str, str] = FILES, modules: tuple[str, ...] = ("storage",)):
    return find_resource_block(files, "infra", modules, "azurerm_storage_account", "main")


def test_an_address_is_followed_through_a_local_module() -> None:
    assert _find() == FoundBlock(
        path="infra/modules/storage/main.tf",
        label="main",
        calls=(ModuleCall("infra/main.tf", "storage", "infra/modules/storage"),),
    )


def test_a_registry_module_is_not_in_the_repository() -> None:
    files = {"infra/main.tf": ROOT.replace("./modules/storage", "Azure/avm-res-storage/azurerm")}
    found = _find(files)
    assert isinstance(found, Declined) and found.reason is Decline.MODULE_EXTERNAL


def test_a_source_that_leaves_the_repository_is_refused() -> None:
    files = {"main.tf": ROOT.replace("./modules/storage", "../../elsewhere")}
    found = find_resource_block(files, "", ("storage",), "azurerm_storage_account", "main")
    assert isinstance(found, Declined) and found.reason is Decline.MODULE_EXTERNAL


def test_code_that_moved_since_the_upload_is_stale() -> None:
    files = {**FILES, "infra/modules/storage/main.tf": MODULE.replace('"main"', '"logs"')}
    found = _find(files)
    assert isinstance(found, Declined) and found.reason is Decline.INDEX_STALE


def test_a_module_no_longer_called_is_stale() -> None:
    found = _find(modules=("network",))
    assert isinstance(found, Declined) and found.reason is Decline.INDEX_STALE


def test_the_block_is_edited_by_its_label_whatever_its_name_renders_to() -> None:
    # The name is an expression: a name search declines it, the label does not.
    patched = edit_terraform(
        MODULE,
        resource_types=("azurerm_storage_account",),
        name="prodlogs",
        changes=[Change("min_tls_version", '"TLS1_2"')],
        label="main",
    )
    assert isinstance(patched, Patched)
    assert patched.matched_by == "address"
    assert [(edit.before, edit.after) for edit in patched.edits] == [('"TLS1_0"', '"TLS1_2"')]


def test_a_labelled_block_under_count_still_declines() -> None:
    source = MODULE.replace("{\n", "{\n  count = 2\n", 1)
    declined = edit_terraform(
        source,
        resource_types=("azurerm_storage_account",),
        name="prodlogs",
        changes=[Change("min_tls_version", '"TLS1_2"')],
        label="main",
    )
    assert isinstance(declined, Declined) and declined.reason is Decline.COUNT_OR_FOR_EACH
