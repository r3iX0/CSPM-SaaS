"""How often the Terraform edit engine can write a fix into real HCL.

    APP_ENV=test apps/api/.venv/bin/python tools/iac/hit_rate.py [--sole-block] <dir> [<dir> ...]

Walks every ``*.tf`` under the directories, and for every resource block of a
type an Azure rule edits, asks the engine to apply that rule's fix to it --
named by its own ``name`` where that is a literal, as a finding would name it.
Prints the share of each outcome per rule and overall.

This is the number Phase 2 (pull requests) waits on (docs/FIX_AS_CODE.md): if
most real files decline, a PR integration mostly opens nothing. A decline is
counted by reason, because each reason is a different piece of work --
``interpolated_name`` wants a Terraform state address, ``variable_value``
wants the edit made where the variable is set.

``--sole-block`` measures the upload flow, where a file chosen for the asset
may be matched by holding the only block of the type (DECISIONS.md §190). An
interpolated block is then tried under a name no literal carries, which is what
a finding about it would look like to the engine.
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "apps/api"))

from app.remediation import terraform_hints
from app.remediation.iac import Change, Declined, edit_terraform
from app.remediation.iac.terraform import (
    _attributes,
    _blocks,
    _body,
    _child,
    _keyword,
    _labels,
    _literal_string,
    _parse,
    _Refused,
    _value,
)
from app.rules.registry import RULE_REGISTRY

RULES = [
    rule
    for rule in RULE_REGISTRY
    if rule.provider == "azure"
    and rule.remediation_spec is not None
    and rule.remediation_spec.terraform_resource_types
    and terraform_hints(rule.remediation_spec)
]


def _names(source: bytes, resource_type: str) -> list[str | None]:
    """Each block's literal name, or ``None`` for an interpolated one."""
    try:
        root = _parse(source)
    except _Refused:
        return []
    names: list[str | None] = []
    for block in _blocks(_child(root, "body")):
        labels = _labels(block, source)
        if _keyword(block, source) == "resource" and labels[:1] == [resource_type]:
            named = _attributes(_body(block), source).get("name")
            if named is not None:
                names.append(_literal_string(_value(named), source))
    return names


# A name no literal block carries: what an interpolated block's asset looks like.
_UNSEEN = "asset-named-by-an-expression"


def main(roots: list[str], sole_block: bool) -> None:
    per_rule: dict[str, Counter[str]] = {rule.rule_id: Counter() for rule in RULES}
    files = [path for root in roots for path in Path(root).rglob("*.tf")]
    for path in files:
        try:
            text = path.read_text()
        except (UnicodeDecodeError, OSError):
            continue
        data = text.encode()
        for rule in RULES:
            spec = rule.remediation_spec
            assert spec is not None
            changes = [Change(h["attribute"], h["value"]) for h in terraform_hints(spec)]
            for resource_type in spec.terraform_resource_types:
                for name in _names(data, resource_type):
                    if name is None and not sole_block:
                        per_rule[rule.rule_id]["interpolated_name"] += 1
                        continue
                    result = edit_terraform(
                        text,
                        resource_types=spec.terraform_resource_types,
                        name=_UNSEEN if name is None else name,
                        changes=changes,
                        sole_block=sole_block,
                    )
                    outcome = result.reason.value if isinstance(result, Declined) else "patched"
                    per_rule[rule.rule_id][outcome] += 1

    total: Counter[str] = Counter()
    print(f"{len(files)} .tf files\n")
    for rule_id, counts in per_rule.items():
        total.update(counts)
        seen = sum(counts.values())
        if seen:
            shares = ", ".join(f"{k} {v / seen:.0%}" for k, v in counts.most_common())
            print(f"{rule_id:12} {seen:5} blocks  {shares}")
    seen = sum(total.values())
    print(f"\n{'all':12} {seen:5} attempts")
    for outcome, count in total.most_common():
        print(f"  {outcome:32} {count:5}  {count / seen:.0%}")


if __name__ == "__main__":
    arguments = sys.argv[1:]
    sole = "--sole-block" in arguments
    roots = [a for a in arguments if a != "--sole-block"]
    if not roots:
        raise SystemExit(__doc__)
    main(roots, sole)
