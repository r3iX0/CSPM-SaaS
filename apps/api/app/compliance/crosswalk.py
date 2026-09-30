"""Controls a native rule answers in frameworks it does not map itself.

A rule's own ``compliance_mappings`` were written by hand against the frameworks
CloudGuard had when the rule was written. The frameworks kept in
``data/frameworks.json`` came later -- NIS2, HIPAA, the current CIS benchmarks
-- and a question a rule already answers is evidence toward their controls too.
``data/crosswalk.json`` records which, per rule. It was carried over from the
Prowler checks that asked the same questions as each rule when the second
engine was removed (DECISIONS.md section 168), and is edited by hand since.

Two limits keep it from overclaiming, and :func:`compliance_mappings_for`
applies the first. A framework a rule maps itself keeps its hand-written
mapping: that was a judgement, and this is not. And a rule known to ask a
slightly different question than its Prowler counterpart inherited nothing
(``divergence_notes`` in section 150), so it has no entry here.
"""

import json
from collections.abc import Mapping, Sequence
from functools import lru_cache
from pathlib import Path

CROSSWALK_PATH = Path(__file__).resolve().parent / "data" / "crosswalk.json"


@lru_cache(maxsize=1)
def crosswalk() -> dict[str, dict[str, list[str]]]:
    """Every rule's derived mappings, parsed once per process."""
    raw = json.loads(CROSSWALK_PATH.read_text())
    return {
        rule_id: {framework: list(controls) for framework, controls in mappings.items()}
        for rule_id, mappings in raw["mappings"].items()
    }


def compliance_mappings_for(
    rule_id: str, own: Mapping[str, Sequence[str]]
) -> dict[str, list[str]]:
    """A rule's mappings as the compliance view should see them.

    Its own, plus what the crosswalk gives it for the frameworks it does not
    map itself.
    """
    merged = {framework: list(ids) for framework, ids in own.items()}
    for framework, controls in crosswalk().get(rule_id, {}).items():
        merged.setdefault(framework, list(controls))
    return merged
