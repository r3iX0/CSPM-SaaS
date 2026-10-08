"""Plan one rule's fix over one repository: which blocks to edit, and why not the rest (§232).

Pure: the worker reads the repository's Terraform and the organization's state
index, and passes them in; nothing here calls GitHub or the database, so every
decision is proven by a unit test.

Each failing asset the index places in this repository is a target. Its block
is found from its state address (``find_resource_block``) and edited by its
label (``edit_terraform``). A block under ``count`` or ``for_each``, or shared
by several workspaces, defines more than one asset, and is edited only where
every asset it defines fails the rule: otherwise the pull request would change
assets nobody asked about. Two targets in one block are one edit, and edits to
one file build on each other.
"""

import posixpath
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from uuid import UUID

from app.remediation.iac.index import parse_address
from app.remediation.iac.terraform import (
    Decline,
    Declined,
    RuleChanges,
    edit_terraform,
    find_resource_block,
)

_KEYS = re.compile(r'\[(?:\d+|"(?:[^"\\]|\\.)*")\]')


@dataclass(frozen=True)
class Target:
    """A failing asset, where the state index says it is defined."""

    finding_id: UUID
    resource_id: str
    address: str
    working_directory: str


@dataclass(frozen=True)
class Outcome:
    finding_id: UUID
    edited: bool
    reason: str | None = None
    detail: str | None = None
    path: str | None = None
    line: int | None = None


@dataclass
class Plan:
    #: Path to the file's new text, for every file the pull request changes.
    files: dict[str, str] = field(default_factory=dict)
    outcomes: list[Outcome] = field(default_factory=list)

    @property
    def edited(self) -> list[Outcome]:
        return [outcome for outcome in self.outcomes if outcome.edited]


def block_key(working_directory: str, address: str) -> tuple[str, str]:
    """One block of code: an address with every instance key taken out.

    ``module.app["eu"].azurerm_storage_account.logs[0]`` and ``...logs[1]`` are
    one block, and so is the same address in another workspace of the same
    directory, since a workspace is the same code with other state.
    """
    return working_directory, _KEYS.sub("", address)


def plan(
    files: Mapping[str, str],
    targets: Sequence[Target],
    rule: RuleChanges,
    *,
    instances: Mapping[tuple[str, str], set[str]],
    failing: set[str],
) -> Plan:
    """Decide every target's edit over ``files``.

    ``instances`` holds, per block, the resource ids every uploaded index of this
    repository places in it; ``failing`` the resource ids failing the rule.
    """
    result = Plan()
    done: dict[tuple[str, str], Outcome] = {}
    for target in targets:
        key = block_key(target.working_directory, target.address)
        if key not in done:
            defined = instances.get(key, {target.resource_id})
            done[key] = _edit_one(files, result.files, target, rule, defined, failing)
        prior = done[key]
        result.outcomes.append(
            Outcome(
                finding_id=target.finding_id,
                edited=prior.edited,
                reason=prior.reason,
                detail=prior.detail,
                path=prior.path,
                line=prior.line,
            )
        )
    return result


def _edit_one(
    files: Mapping[str, str],
    edited: dict[str, str],
    target: Target,
    rule: RuleChanges,
    defined: set[str],
    failing: set[str],
) -> Outcome:
    address = parse_address(target.address)
    repeated = address.repeated or len(defined) > 1
    if repeated and not defined <= failing:
        return Outcome(
            target.finding_id,
            edited=False,
            reason=Decline.PARTIAL_INSTANCES.value,
            detail=(
                f"The block defines {len(defined)} assets and {len(defined - failing)} of them "
                "pass, so editing it would change those too."
            ),
        )

    found = find_resource_block(
        {**files, **edited},
        target.working_directory,
        address.modules,
        address.type,
        address.name,
    )
    if isinstance(found, Declined):
        return Outcome(target.finding_id, False, found.reason.value, found.detail)

    patched = edit_terraform(
        edited.get(found.path, files[found.path]),
        resource_types=rule.resource_types,
        name=address.name,
        changes=rule.changes,
        lockfile=files.get(posixpath.join(target.working_directory, ".terraform.lock.hcl")),
        label=found.label,
        allow_repeated=repeated,
    )
    if isinstance(patched, Declined):
        return Outcome(target.finding_id, False, patched.reason.value, patched.detail, found.path)
    edited[found.path] = patched.source
    return Outcome(
        target.finding_id,
        edited=True,
        path=found.path,
        line=patched.edits[0].line if patched.edits else None,
    )
