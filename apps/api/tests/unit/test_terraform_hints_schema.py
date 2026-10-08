"""Every Terraform attribute a rule names, checked against the provider itself.

``terraform_hints`` hands a customer the line to change, and Fix-as-Code writes
that line into their own HCL (DECISIONS.md §190). An argument the provider does
not have -- or has under another name in this major version, or will not accept
a value of this type for -- fails their ``terraform plan``, which is worse than
no hint: they trusted it enough to try. So each name is held to the schema of
every azurerm release the edit engine claims, dumped by ``terraform providers
schema -json`` and trimmed by ``tools/iac/trim_azurerm_schema.py``.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from app.remediation import Comparison
from app.remediation.spec import UNSET, ExpectedState
from app.rules.registry import RULE_REGISTRY

FIXTURES = Path(__file__).parents[1] / "fixtures/terraform"
SCHEMAS = {
    path.stem.removeprefix("azurerm-"): json.loads(path.read_text())["resource_types"]
    for path in sorted(FIXTURES.glob("azurerm-*.json"))
    if not path.stem.endswith("-docs")
}
# What the provider's documentation says of each argument, from
# ``tools/iac/trim_azurerm_docs.py``: which exist, and which replace the resource.
DOCS = {
    path.stem.removeprefix("azurerm-").removesuffix("-docs"): json.loads(path.read_text())[
        "resource_types"
    ]
    for path in sorted(FIXTURES.glob("azurerm-*-docs.json"))
}

AZURE_HINTED = [
    rule
    for rule in RULE_REGISTRY
    if rule.provider == "azure"
    and rule.remediation_spec is not None
    and any(state.terraform_attribute for state in rule.remediation_spec.expected)
]

# The value a rule's hint writes, as Terraform types it.
_HCL_TYPES = {bool: "bool", str: "string", int: "number"}


def _hinted(rule) -> list[ExpectedState]:
    return [state for state in rule.remediation_spec.expected if state.terraform_attribute]


def _written(state: ExpectedState) -> Any:
    return state.equals if state.terraform_value is UNSET else state.terraform_value


def _attribute(schema: dict[str, Any], resource_type: str, path: str) -> dict[str, Any] | None:
    block = schema[resource_type]
    *nested, leaf = path.split(".")
    for index, name in enumerate(nested):
        nested_block = block["block_types"].get(name)
        if nested_block is None:
            # azurerm declares some blocks as attributes that files write in
            # block form (``network_rule_set``): a list of one object type.
            return _object_attribute(block["attributes"].get(name), nested[index + 1 :], leaf)
        # One block at most, or "the" block the edit changes is a guess.
        if nested_block.get("max_items") != 1:
            return None
        block = nested_block["block"]
    return block["attributes"].get(leaf)


def _object_attribute(
    attribute: dict[str, Any] | None, nested: list[str], leaf: str
) -> dict[str, Any] | None:
    # Only the plain shape: a list of objects, the field one level down. The
    # engine declines a second block of the name, so a list of one is not assumed.
    if attribute is None or nested or not attribute.get("optional"):
        return None
    collection, element = attribute["type"]
    if collection != "list" or element[0] != "object" or leaf not in element[1]:
        return None
    return {"type": element[1][leaf], "optional": True}


def test_both_major_versions_are_fixtures() -> None:
    assert sorted(version.split(".")[0] for version in SCHEMAS) == ["3", "4"]


def test_the_fixture_is_not_empty() -> None:
    # Guards the parametrised tests below against passing by collecting nothing.
    assert len(AZURE_HINTED) >= 10


@pytest.mark.parametrize("rule", AZURE_HINTED, ids=lambda r: r.rule_id)
def test_a_hinted_rule_names_the_resources_it_edits(rule) -> None:
    types = rule.remediation_spec.terraform_resource_types
    assert types, "a Terraform attribute means nothing without the resource it sits on"
    assert all(t.startswith("azurerm_") for t in types)


@pytest.mark.parametrize("rule", AZURE_HINTED, ids=lambda r: r.rule_id)
def test_every_declared_resource_type_is_in_every_fixture(rule) -> None:
    for version, schema in SCHEMAS.items():
        missing = set(rule.remediation_spec.terraform_resource_types) - set(schema)
        assert not missing, f"azurerm {version}: rerun tools/iac/trim_azurerm_schema.py"


@pytest.mark.parametrize("rule", AZURE_HINTED, ids=lambda r: r.rule_id)
def test_every_attribute_is_a_settable_argument_in_every_version(rule) -> None:
    for state in _hinted(rule):
        for resource_type in rule.remediation_spec.terraform_resource_types:
            for version, schema in SCHEMAS.items():
                found = _attribute(schema, resource_type, state.terraform_attribute)
                where = f"{resource_type}.{state.terraform_attribute} in azurerm {version}"
                assert found is not None, f"{where} does not exist"
                assert found.get("optional") or found.get("required"), f"{where} is read-only"


@pytest.mark.parametrize("rule", AZURE_HINTED, ids=lambda r: r.rule_id)
def test_every_hinted_value_has_the_argument_type(rule) -> None:
    for state in _hinted(rule):
        written = _HCL_TYPES[type(_written(state))]
        for resource_type in rule.remediation_spec.terraform_resource_types:
            for version, schema in SCHEMAS.items():
                found = _attribute(schema, resource_type, state.terraform_attribute)
                assert found is not None
                assert found["type"] == written, (
                    f"{resource_type}.{state.terraform_attribute} in azurerm {version} "
                    f"is {found['type']}, the hint writes {written}"
                )


@pytest.mark.parametrize("rule", AZURE_HINTED, ids=lambda r: r.rule_id)
def test_only_a_scalar_state_is_hinted(rule) -> None:
    # A collection state is a structural edit, not a line to change (§190).
    assert all(state.comparison is Comparison.EQUALS for state in _hinted(rule))


def test_the_documentation_is_of_the_releases_the_schema_is() -> None:
    assert sorted(DOCS) == sorted(SCHEMAS)


@pytest.mark.parametrize("rule", AZURE_HINTED, ids=lambda r: r.rule_id)
def test_every_attribute_is_documented_in_every_version(rule) -> None:
    # Guards the test below: an argument the trimmer missed would read as safe.
    for state in _hinted(rule):
        for resource_type in rule.remediation_spec.terraform_resource_types:
            for version, docs in DOCS.items():
                # The name this release is written with: a renamed argument's old
                # name may be undocumented once the new one is (§230).
                attribute, _ = _named_for(state, version)
                documented = docs[resource_type]["arguments"]
                assert _documented_as(attribute, documented), (
                    f"{resource_type}.{attribute} is not in azurerm {version}'s "
                    "documentation; rerun tools/iac/trim_azurerm_docs.py"
                )


@pytest.mark.parametrize("rule", AZURE_HINTED, ids=lambda r: r.rule_id)
def test_an_attribute_that_replaces_the_resource_says_so(rule) -> None:
    # A fix that recreates a storage account is not a fix (DECISIONS.md §228).
    for state in _hinted(rule):
        replaces = {
            f"{resource_type} in azurerm {version}"
            for resource_type in rule.remediation_spec.terraform_resource_types
            for version, docs in DOCS.items()
            if _documented_as(_named_for(state, version)[0], docs[resource_type]["replaces"])
        }
        assert state.terraform_replaces == bool(replaces), (
            f"{state.terraform_attribute}: the documentation says it replaces the resource in "
            f"{sorted(replaces)}, the hint says {state.terraform_replaces}"
            if replaces
            else f"{state.terraform_attribute} is flagged as replacing but nothing documents it"
        )


def _documented_as(attribute: str, documented: list[str]) -> bool:
    # The documentation names a nested argument by its own block only:
    # ``site_config.minimum_tls_version`` is ``minimum_tls_version`` under
    # "The `site_config` block", so the last two parts are what match.
    return ".".join(attribute.split(".")[-2:]) in documented


RENAMED = [rule for rule in AZURE_HINTED if any(state.terraform_renamed for state in _hinted(rule))]


def _named_for(state: ExpectedState, version: str) -> tuple[str, Any]:
    """The argument and value a file for this release is written with (§230)."""
    major = int(version.split(".")[0])
    later = [rename for rename in state.terraform_renamed if rename.since <= major]
    if not later:
        return state.terraform_attribute or "", _written(state)
    newest = max(later, key=lambda rename: rename.since)
    return newest.attribute, newest.value


def test_a_renamed_argument_is_declared_somewhere() -> None:
    assert RENAMED, "AZ-COS-002 renames its argument in azurerm 4"


@pytest.mark.parametrize("rule", RENAMED, ids=lambda r: r.rule_id)
def test_every_later_name_is_an_argument_of_the_releases_that_use_it(rule) -> None:
    for state in _hinted(rule):
        for resource_type in rule.remediation_spec.terraform_resource_types:
            for version, schema in SCHEMAS.items():
                attribute, value = _named_for(state, version)
                found = _attribute(schema, resource_type, attribute)
                where = f"{resource_type}.{attribute} in azurerm {version}"
                assert found is not None, f"{where} does not exist"
                assert found.get("optional") or found.get("required"), f"{where} is read-only"
                assert found["type"] == _HCL_TYPES[type(value)], f"{where} is {found['type']}"


@pytest.mark.parametrize("rule", RENAMED, ids=lambda r: r.rule_id)
def test_a_rename_comes_after_the_oldest_checked_release(rule) -> None:
    # The original name is what a file with no lock file gets, so it must be one
    # every checked release accepts; a rename at or below the oldest is a typo.
    oldest = min(int(version.split(".")[0]) for version in SCHEMAS)
    for state in _hinted(rule):
        assert all(rename.since > oldest for rename in state.terraform_renamed)
