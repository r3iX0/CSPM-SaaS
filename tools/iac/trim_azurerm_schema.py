"""Trim a ``terraform providers schema -json`` dump to the azurerm resources the
rules edit, for the test that holds every ``terraform_attribute`` to the provider.

    # az4/main.tf pins the major version the fixture is for:
    #   terraform { required_providers {
    #     azurerm = { source = "hashicorp/azurerm", version = "~> 4.0" } } }
    cd az4 && terraform init && terraform providers schema -json > schema.json && cd ..
    python tools/iac/trim_azurerm_schema.py az4/schema.json az4/.terraform.lock.hcl

Run it once per major version the edit engine claims (DECISIONS.md §190). The
output lands in ``apps/api/tests/fixtures/terraform/azurerm-<version>.json``,
named for the exact provider release the lock file resolved, because an
attribute is verified against a release rather than against a range someone
remembered.

The full dump is several megabytes of resources no rule touches; what is kept is
the attribute tree of each type in ``RESOURCE_TYPES``, with the flags that say
whether an argument can be set at all. Add a type here when a rule starts to
declare it, and rerun -- the test fails on a type the fixture does not carry.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

PROVIDER = "registry.terraform.io/hashicorp/azurerm"
OUT = Path(__file__).resolve().parents[2] / "apps/api/tests/fixtures/terraform"

RESOURCE_TYPES = (
    "azurerm_container_registry",
    "azurerm_cosmosdb_account",
    "azurerm_databricks_workspace",
    "azurerm_key_vault",
    "azurerm_kubernetes_cluster",
    "azurerm_linux_virtual_machine",
    "azurerm_linux_web_app",
    "azurerm_mssql_server",
    "azurerm_postgresql_flexible_server",
    "azurerm_search_service",
    "azurerm_storage_account",
    "azurerm_windows_web_app",
)

_ATTRIBUTE_FLAGS = ("type", "required", "optional", "computed")
_BLOCK_FLAGS = ("nesting_mode", "min_items", "max_items")


def _trim(block: dict[str, Any]) -> dict[str, Any]:
    return {
        "attributes": {
            name: {flag: attribute[flag] for flag in _ATTRIBUTE_FLAGS if flag in attribute}
            for name, attribute in sorted(block.get("attributes", {}).items())
        },
        "block_types": {
            name: {
                **{flag: nested[flag] for flag in _BLOCK_FLAGS if flag in nested},
                "block": _trim(nested["block"]),
            }
            for name, nested in sorted(block.get("block_types", {}).items())
        },
    }


def _version(lock_file: Path) -> str:
    match = re.search(
        rf'provider "{re.escape(PROVIDER)}" {{\s*version\s*=\s*"([^"]+)"',
        lock_file.read_text(),
    )
    if match is None:
        raise SystemExit(f"{lock_file}: no azurerm version")
    return match.group(1)


def main(schema_file: str, lock_file: str) -> None:
    schemas = json.loads(Path(schema_file).read_text())["provider_schemas"][PROVIDER]
    resources = schemas["resource_schemas"]
    missing = [name for name in RESOURCE_TYPES if name not in resources]
    if missing:
        raise SystemExit(f"not in this provider release: {', '.join(missing)}")

    version = _version(Path(lock_file))
    trimmed = {
        "provider": PROVIDER,
        "version": version,
        "resource_types": {name: _trim(resources[name]["block"]) for name in RESOURCE_TYPES},
    }
    OUT.mkdir(parents=True, exist_ok=True)
    target = OUT / f"azurerm-{version}.json"
    target.write_text(json.dumps(trimmed, indent=1, sort_keys=True) + "\n")
    print(f"wrote {target.relative_to(OUT.parents[4])}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit(__doc__)
    main(sys.argv[1], sys.argv[2])
