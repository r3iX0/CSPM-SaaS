"""Plan a cut as code: which role assignment blocks to delete (DECISIONS.md section 257).

A cut is usually a role assignment, and removing one in Terraform means deleting
its ``azurerm_role_assignment`` block -- a different edit from the arguments a
rule's fix changes (section 232). Pure, as the rule planner is: the caller reads
the repository's files and the state index, and nothing here calls GitHub or the
database.

Each assignment the cut removes is a target where the state index places it. A
block under ``count`` or ``for_each`` defines several assignments and is deleted
only where every one it defines is being removed, the rule section 232 applies
to an edit; otherwise the change would take away access nobody asked to remove.
"""

import difflib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from app.remediation.iac.index import InvalidIndex, parse_address
from app.remediation.iac.pull_request import BlockKey, block_key
from app.remediation.iac.terraform import (
    Decline,
    Declined,
    Repository,
    remove_resource_block,
)


@dataclass(frozen=True)
class AssignmentTarget:
    """A role assignment the cut removes, where the state index says it is defined."""

    assignment_id: str
    address: str
    working_directory: str


@dataclass(frozen=True)
class RemovalOutcome:
    assignment_id: str
    removed: bool
    reason: str | None = None
    detail: str | None = None
    path: str | None = None
    line: int | None = None


@dataclass
class Removal:
    #: Path to the file's new text, for every file the change touches.
    files: dict[str, str] = field(default_factory=dict)
    #: Each changed file as it was before, for its diff.
    originals: dict[str, str] = field(default_factory=dict)
    outcomes: list[RemovalOutcome] = field(default_factory=list)

    def diffs(self) -> dict[str, str]:
        """Every changed file's unified diff, from before the first removal in it."""
        return {
            path: "".join(
                difflib.unified_diff(
                    self.originals[path].splitlines(keepends=True),
                    text.splitlines(keepends=True),
                    fromfile=f"a/{path}",
                    tofile=f"b/{path}",
                )
            )
            for path, text in self.files.items()
        }


def plan_removal(
    files: Mapping[str, str],
    targets: Sequence[AssignmentTarget],
    *,
    instances: Mapping[BlockKey, set[str]],
) -> Removal:
    """Delete each target's block over ``files``, or say why not.

    ``instances`` holds, per block, the resource ids every index of this
    repository places in it, so a block defining assignments outside the cut is
    left alone. Two targets in one block are one deletion.
    """
    result = Removal()
    repository = Repository(files)
    removing = {target.assignment_id.lower() for target in targets}
    done: dict[BlockKey, RemovalOutcome] = {}
    for target in targets:
        key = block_key(target.working_directory, target.address)
        if key not in done:
            done[key] = _remove(repository, files, result, target, instances.get(key), removing)
        shared = done[key]
        result.outcomes.append(
            RemovalOutcome(
                assignment_id=target.assignment_id,
                removed=shared.removed,
                reason=shared.reason,
                detail=shared.detail,
                path=shared.path,
                line=shared.line,
            )
        )
    return result


def _remove(
    repository: Repository,
    files: Mapping[str, str],
    result: Removal,
    target: AssignmentTarget,
    defined_here: set[str] | None,
    removing: set[str],
) -> RemovalOutcome:
    def declined(reason: str, detail: str) -> RemovalOutcome:
        return RemovalOutcome(target.assignment_id, removed=False, reason=reason, detail=detail)

    try:
        address = parse_address(target.address)
    except InvalidIndex as exc:
        return declined(Decline.NO_MATCH.value, str(exc))
    defined = {each.lower() for each in (defined_here or {target.assignment_id})}
    others = defined - removing
    if others:
        return declined(
            Decline.COUNT_OR_FOR_EACH.value,
            f"The block defines {len(defined)} assignments; {len(others)} are not in the cut.",
        )
    found = repository.find_resource_block(
        target.working_directory, address.modules, address.type, address.name
    )
    if isinstance(found, Declined):
        return declined(found.reason.value, found.detail)
    before = result.files.get(found.path, files[found.path])
    removed = remove_resource_block(
        before, resource_type=address.type, label=found.label, allow_repeated=len(defined) > 1
    )
    if isinstance(removed, Declined):
        return declined(removed.reason.value, removed.detail)
    result.originals.setdefault(found.path, files[found.path])
    result.files[found.path] = removed.source
    return RemovalOutcome(target.assignment_id, removed=True, path=found.path, line=removed.line)
