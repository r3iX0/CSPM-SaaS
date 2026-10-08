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

Through modules (§233): where the block's argument is written ``= var.x`` and
the module uses ``x`` for nothing else, the module call that sets ``x`` is
edited instead, one level up at a time, so only that call's assets change. An
edit inside a module reaches every call of it, so the assets every reaching
address defines are counted, and a call no index passes through declines
``unindexed_caller``: what it deployed is unknown.
"""

import posixpath
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from uuid import UUID

from app.remediation.iac.index import parse_address
from app.remediation.iac.terraform import (
    Decline,
    Declined,
    FoundBlock,
    ModuleCall,
    Patched,
    Repository,
    RuleChanges,
    edit_module_input,
    edit_terraform,
)

_KEYS = re.compile(r'\[(?:\d+|"(?:[^"\\]|\\.)*")\]')

#: One block of code an edit is written into: its file, and ``<type>.<label>``
#: for a resource or ``module.<label>`` for a module call.
type Site = tuple[str, str]
type BlockKey = tuple[str, str]


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
    instances: Mapping[BlockKey, set[str]],
    failing: set[str],
) -> Plan:
    """Decide every target's edit over ``files``.

    ``instances`` holds, per block, the resource ids every uploaded index of this
    repository places in it; ``failing`` the resource ids failing the rule.
    """
    result = Plan()
    planner = _Planner(files, rule, instances, failing, result.files)
    done: dict[BlockKey, Outcome] = {}
    for target in targets:
        key = block_key(target.working_directory, target.address)
        if key not in done:
            outcome, covered = planner.edit(target)
            # Every block key the edit reaches shares its answer: two calls of
            # one module, edited once in the module, are one edit (§233).
            for reached in (key, *covered):
                done.setdefault(reached, outcome)
        result.outcomes.append(replace(done[key], finding_id=target.finding_id))
    return result


class _Planner:
    """One plan's view of the repository: where each indexed block is written, and who calls it."""

    def __init__(
        self,
        files: Mapping[str, str],
        rule: RuleChanges,
        instances: Mapping[BlockKey, set[str]],
        failing: set[str],
        edited: dict[str, str],
    ) -> None:
        self.files = files
        self.rule = rule
        self.instances = instances
        self.failing = failing
        self.edited = edited
        # Resolved against the files as read: an edit changes values, never a
        # module's source or a block's label, so the answers hold after it.
        self.repository = Repository(files)
        self._chains: dict[BlockKey, tuple[Site, ...] | None] = {}
        self._reached: set[Site] | None = None

    def text(self, path: str) -> str:
        return self.edited.get(path, self.files[path])

    def edit(self, target: Target) -> tuple[Outcome, list[BlockKey]]:
        """The target's edit, and the other block keys it reaches."""
        address = parse_address(target.address)
        found = self.repository.find_resource_block(
            target.working_directory, address.modules, address.type, address.name
        )
        if isinstance(found, Declined):
            return Outcome(target.finding_id, False, found.reason.value, found.detail), []
        lockfile = self.files.get(posixpath.join(target.working_directory, ".terraform.lock.hcl"))
        written = self._write(found, address.type, lockfile)
        if isinstance(written, Declined):
            return Outcome(target.finding_id, False, written.reason.value, written.detail), []
        site, path, patched = written

        end = _resource_site(found, address.type)
        covered = [key for key in self.instances if self._through(key, site, end)]
        defined = {target.resource_id}.union(*(self.instances[key] for key in covered))
        if passing := defined - self.failing:
            return Outcome(
                target.finding_id,
                edited=False,
                reason=Decline.PARTIAL_INSTANCES.value,
                detail=(
                    f"The edit reaches {len(defined)} assets and {len(passing)} of them "
                    "pass, so it would change those too."
                ),
            ), covered
        unreached = self._unreached(posixpath.dirname(path), set())
        if isinstance(unreached, Declined):
            return Outcome(target.finding_id, False, unreached.reason.value, unreached.detail), []
        if unreached is not None:
            return Outcome(
                target.finding_id,
                edited=False,
                reason=Decline.UNINDEXED_CALLER.value,
                detail=(
                    f"Module {unreached.label!r} in {unreached.path} also runs this code, and "
                    "no uploaded state index says what it deployed."
                ),
            ), covered

        self.edited[path] = patched.source
        return Outcome(
            target.finding_id,
            edited=True,
            path=path,
            line=patched.edits[0].line if patched.edits else None,
        ), covered

    def _write(
        self, found: FoundBlock, resource_type: str, lockfile: str | None
    ) -> tuple[Site, str, Patched] | Declined:
        """Edit the resource block, or the module call that passes its value in (§233).

        Repetition is allowed at every level: whether every asset an edit
        reaches fails the rule is checked once the edit's place is known.
        """
        patched = edit_terraform(
            self.text(found.path),
            resource_types=self.rule.resource_types,
            name=found.label,
            changes=self.rule.changes,
            lockfile=lockfile,
            label=found.label,
            allow_repeated=True,
            through_inputs=bool(found.calls),
        )
        site, path = _resource_site(found, resource_type), found.path
        for call in reversed(found.calls):
            if not isinstance(patched, Declined) or not patched.passed:
                break
            defaults: dict[str, str | None] = {}
            for passed in patched.passed:
                variable = self.repository.variable(call.directory, passed.variable)
                if isinstance(variable, Declined):
                    return variable
                defaults[passed.variable] = variable.default
            patched = edit_module_input(
                self.text(call.path),
                module=call.label,
                inputs=patched.passed,
                defaults=defaults,
                lockfile=lockfile,
                allow_repeated=True,
            )
            site, path = (call.path, f"module.{call.label}"), call.path
        if isinstance(patched, Declined):
            if patched.passed:
                first = patched.passed[0]
                return Declined(
                    Decline.VARIABLE_VALUE,
                    f"{first.change.attribute} comes from var.{first.variable} of the root "
                    "module, whose value is set outside this code (a .tfvars file or the "
                    "pipeline); change it there.",
                )
            return patched
        return site, path, patched

    def _chain(self, key: BlockKey) -> tuple[Site, ...] | None:
        """The calls and the block a block key's address is written through, or ``None``."""
        if key not in self._chains:
            working_directory, address = key
            parsed = parse_address(address)
            found = (
                self.repository.find_resource_block(
                    working_directory, parsed.modules, parsed.type, parsed.name
                )
                if parsed.type in self.rule.resource_types
                else None
            )
            self._chains[key] = (
                None
                if found is None or isinstance(found, Declined)
                else (
                    *(_call_site(call) for call in found.calls),
                    _resource_site(found, parsed.type),
                )
            )
        return self._chains[key]

    def _through(self, key: BlockKey, site: Site, end: Site) -> bool:
        chain = self._chain(key)
        return chain is not None and chain[-1] == end and site in chain

    def _unreached(self, directory: str, seen: set[str]) -> ModuleCall | Declined | None:
        """A call of ``directory``'s code, at any depth, that no indexed address passes through.

        An edit in a module changes every call of it. Each call's assets must be
        in an index, or nobody can say whether they fail the rule too.
        """
        if directory in seen:
            return None
        seen.add(directory)
        callers = self.repository.callers(directory)
        if isinstance(callers, Declined):
            return callers
        for call in callers:
            if _call_site(call) not in self._reached_calls():
                return call
            further = self._unreached(posixpath.dirname(call.path), seen)
            if further is not None:
                return further
        return None

    def _reached_calls(self) -> set[Site]:
        """Every module call some indexed address of this repository passes through."""
        if self._reached is None:
            reached: set[Site] = set()
            for working_directory, address in self.instances:
                calls = self.repository.module_calls(
                    working_directory, parse_address(address).modules
                )
                if not isinstance(calls, Declined):
                    reached.update(_call_site(call) for call in calls)
            self._reached = reached
        return self._reached


def _resource_site(found: FoundBlock, resource_type: str) -> Site:
    return found.path, f"{resource_type}.{found.label}"


def _call_site(call: ModuleCall) -> Site:
    return call.path, f"module.{call.label}"
