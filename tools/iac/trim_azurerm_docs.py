"""Record which azurerm arguments make Terraform replace the resource when they change.

    python tools/iac/trim_azurerm_docs.py 3.117.1 4.81.0

``terraform providers schema -json`` says whether an argument can be set, not what
setting it costs. Some arguments are ``ForceNew``: changing one makes ``terraform
apply`` destroy the resource and create another, and for a storage account that is
its data. A fix that edits one of those is not a fix (DECISIONS.md §228). The
provider's documentation says it of each such argument, as "Changing this forces a
new ... to be created", so this reads the documentation of the release the schema
fixture was dumped from and keeps, per resource type, every argument it documents
and the ones it says force a new resource. A sentence that forces a new resource
only for some changes ("from Continuous to Periodic") is recorded as forcing one:
the edit is then declined, which is the safe side.

An argument is written as ``block.argument`` under the nearest "A `block` block
supports" heading, or bare at the top level. The output lands beside the schema
fixtures as ``azurerm-<version>-docs.json``. Add a type to
``trim_azurerm_schema.RESOURCE_TYPES`` and rerun both.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request

from trim_azurerm_schema import OUT, RESOURCE_TYPES

SOURCE = (
    "https://raw.githubusercontent.com/hashicorp/terraform-provider-azurerm/"
    "v{version}/website/docs/r/{name}.html.markdown"
)

_BLOCK = re.compile(r"^(?:An?|The) `(\w+)` block (?:supports|exports|contains)")
_ARGUMENT = re.compile(r"^\* `(\w+)` - ")
_REPLACES = re.compile(r"forces? (?:a )?new", re.IGNORECASE)


def _fetch(version: str, resource_type: str) -> str:
    url = SOURCE.format(version=version, name=resource_type.removeprefix("azurerm_"))
    with urllib.request.urlopen(url, timeout=30) as response:
        return response.read().decode("utf-8")


def _arguments(markdown: str) -> dict[str, bool]:
    """Every documented argument, and whether changing it forces a new resource."""
    found: dict[str, bool] = {}
    block: str | None = None
    current: str | None = None
    in_arguments = False
    for line in markdown.splitlines():
        if line.startswith("## "):
            in_arguments = line.strip() in ("## Arguments Reference", "## Argument Reference")
            block = current = None
            continue
        if not in_arguments:
            continue
        if heading := _BLOCK.match(line):
            block, current = heading.group(1), None
            continue
        if argument := _ARGUMENT.match(line):
            current = f"{block}.{argument.group(1)}" if block else argument.group(1)
            found.setdefault(current, False)
        elif not line.strip() or line.startswith("---"):
            current = None
            continue
        if current is not None and _REPLACES.search(line):
            found[current] = True
    return found


def main(versions: list[str]) -> None:
    for version in versions:
        trimmed = {}
        for resource_type in RESOURCE_TYPES:
            arguments = _arguments(_fetch(version, resource_type))
            if not arguments:
                raise SystemExit(f"{resource_type} {version}: no arguments read")
            trimmed[resource_type] = {
                "arguments": sorted(arguments),
                "replaces": sorted(name for name, replaces in arguments.items() if replaces),
            }
        target = OUT / f"azurerm-{version}-docs.json"
        target.write_text(
            json.dumps({"version": version, "resource_types": trimmed}, indent=1, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        print(f"wrote {target.relative_to(OUT.parents[4])}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    main(sys.argv[1:])
