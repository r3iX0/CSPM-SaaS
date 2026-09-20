"""Routes that are the same route said many times.

Twelve machines in a scale set, each running as the same identity, which holds
one role over the subscription the customer data sits in. That is twelve attack
paths by the graph's count and it is one sentence, one cause and one fix -- and
a page that prints it twelve times has buried every other shape in the estate
under a repetition of one.

Two shapes fan, and they fan in opposite directions:

- **Many ways in, one thing reached.** The routes differ only in where they
  start. The fix is at the far end of every one of them.
- **One way in, many things reached.** The routes differ only in what they end
  at -- one over-privileged identity and everything its role covers. The fix is
  the role, and the count is how much rests on it.

Grouped only where the routes are *identical* apart from that one end, so a
group is a claim anybody can check by reading its members. Similar is not the
same: two routes passing through different identities are two problems, and
folding them because they end alike would hide one of them.

A route belongs to at most one group, and to the larger one where it could join
either. Both readings are true at once -- an estate can fan in and out around
the same middle -- but a route counted twice makes the totals beneath the two
groups add up to more than the estate has, and a total nobody can reconcile is
worse than the second reading is useful.
"""

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum

from app.graph.model import Path


class PatternKind(StrEnum):
    """Which end of the routes fans out."""

    #: Same route, many starting points. "Twelve machines all reach it this way."
    MANY_ENTRIES = "many_entries"
    #: Same start and middle, many things reached. One role, everything under it.
    MANY_TARGETS = "many_targets"


@dataclass(frozen=True)
class RoutePattern:
    """Routes that differ at one end and agree everywhere else."""

    kind: PatternKind
    #: The routes themselves, shortest first. Always two or more: one route is
    #: not a pattern, it is a route.
    members: tuple[Path, ...]
    #: The route to read as the group's -- the shortest, and the one whose
    #: steps are drawn for it.
    exemplar: Path

    @property
    def size(self) -> int:
        return len(self.members)

    def describe(self) -> str:
        """The group as one sentence, with the count where the fan is."""
        if self.kind is PatternKind.MANY_ENTRIES:
            kind = _plural(self.exemplar.entry.resource_type.value)
            return f"{self.size} {kind} reach {self.exemplar.target.name} the same way"
        kind = _plural(self.exemplar.target.resource_type.value)
        return f"{self.exemplar.entry.name} reaches {self.size} {kind} the same way"


def route_patterns(paths: Sequence[Path]) -> tuple[list[RoutePattern], list[Path]]:
    """The groups worth collapsing, and the routes that belong to none.

    Returned together because the page needs both and must not double-count:
    the groups and the loose routes partition the list exactly.
    """
    candidates = [
        (PatternKind.MANY_ENTRIES, members)
        for members in _group(paths, _tail_key).values()
    ] + [
        (PatternKind.MANY_TARGETS, members)
        for members in _group(paths, _head_key).values()
    ]

    claimed: set[int] = set()
    patterns: list[RoutePattern] = []
    # Largest group first, so a route that could join either lands in the one
    # saying the most. Ties settle on the kind, so the answer does not move
    # between two identical readings of one estate.
    for kind, members in sorted(
        candidates, key=lambda item: (-len(item[1]), item[0].value)
    ):
        free = [path for path in members if id(path) not in claimed]
        if len(free) < 2:
            continue
        claimed.update(id(path) for path in free)
        ordered = tuple(
            sorted(free, key=lambda p: (p.hops, p.entry.name, p.target.name))
        )
        patterns.append(RoutePattern(kind=kind, members=ordered, exemplar=ordered[0]))

    patterns.sort(key=lambda pattern: (-pattern.size, pattern.describe()))
    loose = [path for path in paths if id(path) not in claimed]
    return patterns, loose


def _plural(resource_type: str) -> str:
    words = resource_type.replace("_", " ")
    return words if words.endswith("s") else f"{words}s"


def _tail_key(path: Path) -> tuple:
    """Everything but where the route starts.

    The kind of the entry is part of it: a machine and a user account arriving
    at the same identity are not one sentence, however alike the rest reads.
    """
    return (
        path.entry.resource_type,
        tuple(
            (step.relationship, step.target.provider_resource_id) for step in path.steps
        ),
    )


def _head_key(path: Path) -> tuple:
    """Everything but what the route ends at."""
    return (
        path.entry.provider_resource_id,
        path.target.resource_type,
        tuple(
            (step.relationship, step.target.provider_resource_id)
            for step in path.steps[:-1]
        ),
        path.steps[-1].relationship if path.steps else None,
    )


def _group(
    paths: Sequence[Path], key: Callable[[Path], tuple]
) -> dict[tuple, list[Path]]:
    grouped: dict[tuple, list[Path]] = {}
    for path in paths:
        grouped.setdefault(key(path), []).append(path)
    return {shape: members for shape, members in grouped.items() if len(members) > 1}
