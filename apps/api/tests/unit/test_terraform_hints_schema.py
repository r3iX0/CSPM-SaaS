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

SCHEMAS = {
    path.stem.removeprefix("azurerm-"): json.loads(path.read_text())["resource_types"]
    for path in sorted((Path(__file__).parents[1] / "fixtures/terraform").glob("azurerm-*.json"))
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
