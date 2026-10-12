"""A pull request's Terraform plan, judged before it is applied (DECISIONS.md §234).

The customer's pipeline runs ``terraform plan`` on a pull request, and the
Action keeps, for each azurerm resource the plan creates or updates, only the
arguments Cleave's rules read: the allowlist below, built from the rules' own
Terraform hints. A plan holds every attribute in plain text, secrets included,
so nothing else leaves the runner, and an upload holding anything else is
refused whole, as a state index is (§229).

Judged by the same expected values the fix writes (``rule_edit``'s changes),
over planned values rather than a scan's capture. The rule engine itself is not
run: it reads Azure's own JSON, and a plan is Terraform's, so translating one
into the other would be a guess per resource type. A rule with no Terraform
hint is not judged here; the scan still judges what is deployed.

Deterministic and pure: no network, no database, no clock.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from app.remediation.iac.index import InvalidIndex, parse_address
from app.remediation.iac.terraform import Change, RuleChanges

#: As many resources as a state index holds, for the same request limit (§231).
MAX_RESOURCES = 4_000
MAX_VALUE_LENGTH = 1_000
_ACTIONS = frozenset({"create", "update", "delete", "no-op", "read"})
_FIELDS = frozenset({"address", "type", "actions", "after", "before", "unknown"})

type Scalar = str | bool | int | float | None


class InvalidPlan(ValueError):
    """An upload that is not what the Action sends, refused whole."""


class Verdict(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    # The plan cannot say: the value is known only after apply, or the argument
    # is absent and the provider's default is not in the plan. Never a pass.
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class GuardedRule:
    """A rule the guardrail judges: its id, and the arguments its fix writes."""

    rule_id: str
    name: str
    severity: str
    changes: RuleChanges


@dataclass(frozen=True)
class PlannedResource:
    address: str
    type: str
    actions: tuple[str, ...]
    #: Allowlisted arguments as planned, by dotted path; absent where not set.
    after: Mapping[str, Scalar]
    #: The same arguments before the change; empty for a resource being created.
    before: Mapping[str, Scalar]
    #: Allowlisted arguments whose planned value is known only after apply.
    unknown: frozenset[str]


@dataclass(frozen=True)
class Judged:
    rule_id: str
    address: str
    verdict: Verdict
    #: A failure this plan brings: the resource is new, or passed before it.
    introduced: bool
    #: The argument that decided, under the name the plan uses, and its planned value.
    attribute: str
    planned: str | None
    expected: str


def allowlist(rules: Sequence[GuardedRule]) -> dict[str, list[str]]:
    """Per resource type, every argument path the Action may send: each name a rule reads."""
    paths: dict[str, set[str]] = {}
    for rule in rules:
        names = {
            name for change in rule.changes.changes for name, _value, _accepts in _names(change)
        }
        for resource_type in rule.changes.resource_types:
            paths.setdefault(resource_type, set()).update(names)
    return {resource_type: sorted(names) for resource_type, names in sorted(paths.items())}


def resources_from_upload(
    raw: Sequence[Mapping[str, Any]], allowed: Mapping[str, Sequence[str]]
) -> list[PlannedResource]:
    """The planned resources an upload holds, checked; ``InvalidPlan`` refuses it whole."""
    if len(raw) > MAX_RESOURCES:
        raise InvalidPlan(f"A plan upload holds at most {MAX_RESOURCES} resources.")
    resources: list[PlannedResource] = []
    seen: set[str] = set()
    for item in raw:
        if set(item) - _FIELDS:
            raise InvalidPlan(f"A resource holds only {', '.join(sorted(_FIELDS))}.")
        address, resource_type = item.get("address"), item.get("type")
        if not isinstance(address, str) or not isinstance(resource_type, str):
            raise InvalidPlan("Every resource has a string address and type.")
        try:
            parsed = parse_address(address)
        except InvalidIndex as exc:
            raise InvalidPlan(str(exc)) from exc
        if parsed.type != resource_type:
            raise InvalidPlan(f"{address[:200]!r} is not of type {resource_type[:80]!r}.")
        if address in seen:
            raise InvalidPlan(f"{address[:200]!r} appears twice.")
        seen.add(address)
        permitted = frozenset(allowed.get(resource_type, ()))
        actions = item.get("actions")
        if (
            not isinstance(actions, list)
            or not actions
            or not all(isinstance(a, str) and a in _ACTIONS for a in actions)
        ):
            raise InvalidPlan(f"{address[:200]!r} has no plan actions Terraform writes.")
        unknown = item.get("unknown", [])
        if not isinstance(unknown, list) or not all(
            isinstance(path, str) and path in permitted for path in unknown
        ):
            raise InvalidPlan(f"{address[:200]!r} names an argument Cleave does not read.")
        resources.append(
            PlannedResource(
                address=address,
                type=resource_type,
                actions=tuple(actions),
                after=_values(item.get("after", {}), permitted, address),
                before=_values(item.get("before", {}), permitted, address),
                unknown=frozenset(unknown),
            )
        )
    return resources


def _values(raw: Any, permitted: frozenset[str], address: str) -> dict[str, Scalar]:
    if not isinstance(raw, dict):
        raise InvalidPlan(f"{address[:200]!r} has values that are not an object.")
    for path, value in raw.items():
        if path not in permitted:
            raise InvalidPlan(f"{address[:200]!r} sends {str(path)[:100]!r}, which no rule reads.")
        if value is not None and not isinstance(value, str | bool | int | float):
            raise InvalidPlan(f"{address[:200]!r} sends a {path} that is not one value.")
        if isinstance(value, str) and len(value) > MAX_VALUE_LENGTH:
            raise InvalidPlan(f"{address[:200]!r} sends a {path} longer than one value.")
    return dict(raw)


def judge(resources: Sequence[PlannedResource], rules: Sequence[GuardedRule]) -> list[Judged]:
    """Every rule over every resource the plan creates or updates.

    A resource left as it is, or only deleted, is the scan's to judge: a pull
    request that does not touch it neither fixed nor broke it.
    """
    judged: list[Judged] = []
    for resource in resources:
        if not {"create", "update"} & set(resource.actions):
            continue
        for rule in rules:
            if resource.type not in rule.changes.resource_types:
                continue
            verdict, attribute, planned, expected = _verdict(
                rule.changes.changes, resource.after, resource.unknown
            )
            before = _verdict(rule.changes.changes, resource.before, frozenset())[0]
            judged.append(
                Judged(
                    rule_id=rule.rule_id,
                    address=resource.address,
                    verdict=verdict,
                    introduced=verdict is Verdict.FAIL
                    and ("create" in resource.actions or before is not Verdict.FAIL),
                    attribute=attribute,
                    planned=planned,
                    expected=expected,
                )
            )
    return judged


type _Reading = tuple[Verdict, str, str | None, str]


def _verdict(
    changes: Sequence[Change], values: Mapping[str, Scalar], unknown: frozenset[str]
) -> _Reading:
    """The worst of a rule's arguments: one failing fails it, one unreadable leaves it unknown."""
    found = [_one(change, values, unknown) for change in changes]
    for wanted in (Verdict.FAIL, Verdict.UNKNOWN):
        for reading in found:
            if reading[0] is wanted:
                return reading
    return found[0]


def _one(change: Change, values: Mapping[str, Scalar], unknown: frozenset[str]) -> _Reading:
    # The newest name the plan carries a value under decides: azurerm 4 plans
    # both names of a renamed argument, each in its own terms (§230).
    names = _names(change)
    for name, expected, accepts in names:
        if name in unknown:
            return Verdict.UNKNOWN, name, None, expected
        value = values.get(name)
        if value is None:
            continue
        written = _hcl(value)
        met = written in (expected, *accepts)
        return (Verdict.PASS if met else Verdict.FAIL), name, written, expected
    name, expected, _accepts = names[0]
    return Verdict.UNKNOWN, name, None, expected


def _names(change: Change) -> list[tuple[str, str, tuple[str, ...]]]:
    """Each name of the argument, newest first, with its value and what else meets it."""
    renamed = sorted(change.renamed, key=lambda rename: rename.since, reverse=True)
    return [
        *((rename.attribute, rename.value, ()) for rename in renamed),
        (change.attribute, change.value, change.accepts),
    ]


def _hcl(value: str | bool | int | float) -> str:
    """A planned JSON value written as the HCL the hints compare against."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return f'"{value}"'
    return str(value)


def conclusion(judged: Sequence[Judged]) -> str:
    """The check run's conclusion: a failure only for one this plan brings."""
    return "failure" if any(item.introduced for item in judged) else "success"
