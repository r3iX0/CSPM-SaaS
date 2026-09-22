"""The graph, and the two questions worth asking of it.

Built per scan from the same normalized state the rule engine sees, so a path
and a finding are always statements about one reading of one environment. A
graph assembled from a different scan's edges would let CloudGuard describe a
route through an environment nobody looked at in one go.
"""

from collections import deque
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import StrEnum

from app.core.enums import Level, RelationshipType, ResourceType
from app.domain.resource import CloudResource
from app.graph.access import (
    SCOPES,
    AccessGrant,
    AccessHolder,
    Lens,
    grants,
    holders,
    lens_for,
)
from app.graph.facts import edge_facts
from app.graph.identity import join
from app.graph.severance import EdgeKey, removable, severed_pairs

# Exposure at or above which a node is somewhere an attacker could start.
#
# A predicate over an attribute the normalizer already computes, rather than an
# edge from a synthetic INTERNET node. UNKNOWN is deliberately *not* an entry
# point: it means CloudGuard could not work the exposure out, and treating that
# as "reachable from the internet" would manufacture attack paths out of gaps in
# collection -- the same overclaim as a PASS nobody earned, pointed the other
# way.
ENTRY_EXPOSURE = {Level.HIGH, Level.CRITICAL}

# Sensitivity at or above which reaching a node actually costs the customer
# something. UNKNOWN is excluded for the mirror-image reason.
SENSITIVE_DATA = {Level.HIGH, Level.CRITICAL}

# How far a path may run before it stops being a description of anything.
# Every real Azure path this graph can express is three to five hops -- host,
# perhaps the host beside it, identity, scope, resource -- and a longer one is
# a containment chain being walked for its own sake.
MAX_DEPTH = 6

# How one hop reads in a sentence. Shared by a route's steps and by the edges of
# a neighbourhood, so a link is worded the same way in the list and on the canvas.
RELATIONSHIP_VERBS = {
    RelationshipType.HAS_IDENTITY: "runs as",
    RelationshipType.GRANTS_ROLE: "can act over",
    RelationshipType.CAN_GRANT_ROLES: "can grant itself any role over",
    RelationshipType.CONTAINS: "contains",
    RelationshipType.NETWORK_ACCESS: "can reach over the network",
    RelationshipType.MEMBER_OF: "is a member of",
    RelationshipType.CAN_ACT_AS: "can sign in as",
    RelationshipType.CAN_TAKE_OVER: "can take ownership of",
}

# Where a walk stands: a node, and the lens it arrived through -- None where it
# holds the node (see ``AssetGraph._moves``).
State = tuple[str, Lens | None]

# The edges a walk crosses with a lens rather than holding what it lands on.
_ROLE_EDGES = frozenset(
    {
        RelationshipType.GRANTS_ROLE,
        RelationshipType.CAN_GRANT_ROLES,
        RelationshipType.CAN_TAKE_OVER,
    }
)

# How many neighbours one asset may contribute to a neighbourhood before the
# rest are folded into a counted group. A subscription contains every resource
# group under it, and drawing four hundred of them as boxes answers nothing.
NEIGHBOURHOOD_FAN_OUT = 12

# How many assets one neighbourhood may draw. Past this the canvas stops being
# something a person reads, and the traversal stops rather than growing it.
NEIGHBOURHOOD_MAX_NODES = 150


@dataclass(frozen=True)
class PathStep:
    """One hop, and why it exists."""

    source: CloudResource
    relationship: RelationshipType
    target: CloudResource

    def describe(self) -> str:
        verb = RELATIONSHIP_VERBS.get(self.relationship, self.relationship.value)
        return f"{self.source.name} {verb} {self.target.name}"

    def key(self) -> EdgeKey:
        """This hop as a link, named the way a query string names one."""
        return (
            self.source.provider_resource_id,
            self.relationship.value,
            self.target.provider_resource_id,
        )

    @property
    def facts(self) -> tuple[str, ...]:
        """What this link is beyond its kind -- the role, the network, the kind
        of identity -- read off the two assets it joins (``graph/facts.py``)."""
        return edge_facts(self.source, self.relationship, self.target)

    def detail(self) -> str:
        """The sentence with its evidence in it.

        "mi-app can act over sub-prod" names no role, and the role is the only
        thing anybody can go and change. Beside :meth:`describe` rather than
        replacing it, because the plain sentence is what a risk is titled by,
        and a title that moved when a second assignment appeared would read as
        a different route.
        """
        facts = self.facts
        return f"{self.describe()} ({', '.join(facts)})" if facts else self.describe()


@dataclass(frozen=True)
class Path:
    """A route from somewhere an attacker could start to something worth taking.

    Carries the whole route rather than its endpoints. "This storage account is
    reachable" is an alarm; "it is reachable *because* this internet-facing VM
    runs as an identity holding Contributor over the subscription" is a thing
    somebody can go and fix, and it names three places they could cut it.
    """

    entry: CloudResource
    target: CloudResource
    steps: tuple[PathStep, ...]

    @property
    def hops(self) -> int:
        return len(self.steps)

    def describe(self) -> list[str]:
        return [step.describe() for step in self.steps]

    def node_ids(self) -> frozenset[str]:
        """Every asset on the route, endpoints included."""
        ids = {self.entry.provider_resource_id, self.target.provider_resource_id}
        for step in self.steps:
            ids.add(step.source.provider_resource_id)
            ids.add(step.target.provider_resource_id)
        return frozenset(ids)

    def cheapest_break(self) -> PathStep | None:
        """The hop to cut first.

        The capability hops, in preference to the structural ones: removing a
        role assignment, detaching an identity or closing a network security
        group between two machines severs the route, while
        "contains" describes where a resource lives and cannot be removed at
        all. Among those, the earliest -- closing the way in beats containing
        what someone reaches once inside.
        """
        for step in self.steps:
            if removable(step.relationship):
                return step
        return None


class DeadEndReason(StrEnum):
    """Why a way in leads nowhere worth reaching. Each asks for a different fix."""

    # Nothing leads out of it at all: a machine that runs as no identity and
    # reaches no other machine, a user or principal holding no role over
    # anything this scan saw.
    REACHES_NOTHING = "reaches_nothing"
    # It runs as an identity, and the identity holds no role over anything this
    # scan saw.
    IDENTITY_WITHOUT_ROLE = "identity_without_role"
    # It runs as an identity that does hold roles, and none of them controls
    # anything: they read configuration, were not read, or carry a condition
    # CloudGuard cannot evaluate (DECISIONS.md section 125). Distinct from the
    # case above because the fix is not "this identity is harmless" -- a role
    # is there, and it is one change away from mattering.
    ROLES_WITHOUT_CONTROL = "roles_without_control"
    # It reaches assets, and none of them is classified as sensitive. The one
    # case where the answer may be wrong rather than reassuring, because
    # sensitivity is only what tags and names declare.
    NOTHING_SENSITIVE = "nothing_sensitive"


@dataclass(frozen=True)
class DeadEnd:
    """A way in with no route out of it, and where it stops."""

    entry: CloudResource
    reason: DeadEndReason
    #: How many assets it does reach, for the nothing-sensitive case.
    reached: int


@dataclass(frozen=True)
class ChokePoint:
    """One removable link, and the routes that stop existing without it.

    The question the attack-path list cannot answer however carefully it is
    sorted. Fifty routes are fifty things to read; "remove this one role
    assignment and thirty-seven of them close" is one thing to do, and it is
    frequently not the fix any single route would have suggested on its own --
    the shared hop is usually in the middle, while each route's own cheapest
    break is at its start.
    """

    step: PathStep
    #: Routes that no longer exist once this link is gone. The real answer.
    severed: tuple[Path, ...]
    #: Routes this link sits on, which is larger whenever another way round
    #: exists. Kept because the gap between the two is the interesting part:
    #: a link on twenty routes that closes three is a link with alternates.
    on_routes: int

    @property
    def severs(self) -> int:
        return len(self.severed)

    def describe(self) -> str:
        return self.step.describe()


@dataclass(frozen=True)
class CutOutcome:
    """What happens to the attack paths if one link is removed.

    Asked of one link somebody picked, rather than ranked like
    :class:`ChokePoint`: the question is "what if I do this", and a link that
    closes nothing is a real answer to it -- the way round is the finding.
    """

    step: PathStep
    #: Routes that no longer exist without the link.
    closed: tuple[Path, ...]
    #: How many routes exist before and after, across the organization.
    before: int
    after: int


@dataclass(frozen=True)
class FoldedGroup:
    """Neighbours of one asset that were counted rather than drawn.

    Folded rather than dropped. A canvas that silently stopped at twelve would
    say an identity reaches twelve things when it reaches four hundred -- the
    same overclaim as a PASS nobody earned, pointed at the size of the answer.
    """

    parent: str
    relationship: RelationshipType
    #: Where the group sits: positive when the parent reaches its members,
    #: negative when the members reach the parent.
    layer: int
    members: tuple[CloudResource, ...]


@dataclass(frozen=True)
class Neighborhood:
    """One asset, what reaches it, and what it reaches, a few hops each way."""

    focus: str
    #: Provider id to layer: 0 for the focus, negative for what reaches it,
    #: positive for what it reaches. Each asset sits once, at its shortest
    #: distance, downstream on a tie -- reach from the focus is the question the
    #: canvas is opened to ask.
    layers: dict[str, int]
    edges: tuple[tuple[str, RelationshipType, str], ...]
    groups: tuple[FoldedGroup, ...]
    #: Whether the node cap stopped the walk before ``depth`` was reached. The
    #: neighbours it had in hand are folded, not lost; the assets beyond them
    #: were never looked at, and the canvas has to say so.
    truncated: bool


@dataclass
class AssetGraph:
    """Assets and the edges between them, for one scan.

    Directed. ``CONTAINS`` runs from the container downward and
    ``GRANTS_ROLE`` from the principal to the scope, so following edges forward
    is following reach -- which is what makes a traversal from an entry point
    mean what it looks like it means.
    """

    nodes: dict[str, CloudResource] = field(default_factory=dict)
    _out: dict[str, list[tuple[RelationshipType, str]]] = field(
        default_factory=dict, repr=False
    )
    # The same edges indexed by target, for asking what reaches a node rather
    # than what it reaches. Only the neighbourhood reads it.
    _in: dict[str, list[tuple[RelationshipType, str]]] = field(
        default_factory=dict, repr=False
    )
    # Attack paths by depth, worked out once per graph. A graph is cached per
    # tenant (``services/graph.py``) and never changed after it is built --
    # ``_without`` makes a new one -- so the routes are a fixed property of it,
    # and the asset list asks for them on every page it serves.
    _paths: dict[int, list["Path"]] = field(
        default_factory=dict, repr=False, compare=False
    )
    # And what each link is holding up, worked out once for the same reason:
    # the ranked list, the what-if on one link and the number drawn on a line
    # are three readings of one analysis, and recomputing it per caller is how
    # they would come to disagree.
    _severance: dict[int, dict[EdgeKey, tuple["Path", ...]]] = field(
        default_factory=dict, repr=False, compare=False
    )
    # A stand-in's id to the node it was folded into, so a page opened on the
    # stand-in is answered about the identity it stood for.
    _aliases: dict[str, str] = field(default_factory=dict, repr=False, compare=False)
    # What each role edge controls, read off the principal's metadata once.
    _lenses: dict[tuple[str, RelationshipType, str], Lens] = field(
        default_factory=dict, repr=False, compare=False
    )

    @classmethod
    def build(
        cls,
        resources: list[CloudResource],
        relationships: list[tuple[str, RelationshipType, str]],
        *,
        derive: bool = True,
    ) -> "AssetGraph":
        """The graph, with the edges the nodes imply drawn in.

        ``derive=False`` takes the edges exactly as given. For rebuilding an
        estate from another graph's own :meth:`links`, which already carry the
        derived edges -- re-deriving them would put back the very link a
        what-if removed.
        """
        # Each identity one node, whichever capture each half of it came from
        # (``graph/identity.py``, DECISIONS.md section 126).
        joined = join(resources, relationships, derive=derive)
        graph = cls(nodes={r.provider_resource_id: r for r in joined.resources})
        graph._aliases = joined.aliases
        for source, relationship, target in joined.relationships:
            # Both ends have to be nodes. A dangling edge is not a shorter path,
            # it is a path through something CloudGuard never saw -- and a
            # traversal that followed one would describe reach it cannot
            # support.
            if source in graph.nodes and target in graph.nodes:
                graph._out.setdefault(source, []).append((relationship, target))
                graph._in.setdefault(target, []).append((relationship, source))
        return graph

    # ---------------------------------------------------------------- queries
    def resolve(self, node_id: str) -> str:
        """The node an id names: itself, or the identity a stand-in was folded
        into when the graph was built."""
        return self._aliases.get(node_id, node_id)

    def links(self) -> Iterator[tuple[str, RelationshipType, str]]:
        """Every edge, source first, in a stable order."""
        for source in sorted(self._out):
            for relationship, target in sorted(self._out[source]):
                yield source, relationship, target

    def entry_points(self) -> list[CloudResource]:
        """Assets an attacker could plausibly start from."""
        return [
            node for node in self.nodes.values() if node.public_exposure in ENTRY_EXPOSURE
        ]

    def sensitive_targets(self) -> list[CloudResource]:
        """Assets where reaching them costs the customer something."""
        return [
            node for node in self.nodes.values() if node.data_sensitivity in SENSITIVE_DATA
        ]

    def reachable_from(self, start: str, max_depth: int = MAX_DEPTH) -> dict[str, Path]:
        """Everything reachable from one node, with the route to each.

        Breadth-first, so the route recorded for a node is the shortest one --
        which is also the most useful, because a shorter path is a smaller thing
        to explain and usually a cheaper thing to break.

        Only capability edges are followed. An NSG protecting a VM is a fact
        about the VM's configuration, not a way to get anywhere from the NSG,
        and walking it would produce routes that read as attack paths while
        describing nothing an attacker could do.

        And a role edge only as far as the role reaches (``graph/access.py``).
        The walk descends through the scope a role lands on, but an asset under
        it counts as reached -- and is walked on from -- only when the role
        controls it. Reader over a subscription reaches the subscription and
        nothing in it.
        """
        start = self.resolve(start)
        if start not in self.nodes:
            return {}

        found: dict[str, Path] = {}
        origin = self._holding(start)
        queue: deque[tuple[State, tuple[PathStep, ...]]] = deque([(origin, ())])
        seen = {origin}

        while queue:
            state, steps = queue.popleft()
            if len(steps) >= max_depth:
                continue

            current = state[0]
            for relationship, target, ahead in self._moves(state):
                if ahead in seen:
                    continue
                seen.add(ahead)
                route = (
                    *steps,
                    PathStep(self.nodes[current], relationship, self.nodes[target]),
                )
                if target != start and target not in found and self._reached(ahead):
                    found[target] = Path(
                        entry=self.nodes[start], target=self.nodes[target], steps=route
                    )
                queue.append((ahead, route))

        return found

    # ------------------------------------------------------------- the walk
    #
    # A state is ``(node, lens)``. A lens of None means the walk holds the
    # node -- it started there, or took it -- and may leave by any capability
    # edge. A lens means the walk arrived through a role and is passing through
    # the scope it landed on: it may only descend, and an asset below becomes
    # held when the lens controls it.

    def _moves(self, state: State) -> Iterator[tuple[RelationshipType, str, State]]:
        """Every way on from a state: the edge taken, where it lands, and how."""
        node, lens = state
        if lens is None:
            for relationship, target in self._out.get(node, []):
                if not relationship.is_capability:
                    continue
                if relationship in _ROLE_EDGES:
                    carried = self._lens(node, relationship, target)
                    if carried.empty:
                        continue
                    yield relationship, target, self._arrive(target, carried)
                else:
                    yield relationship, target, (target, None)
            return
        for relationship, target in self._out.get(node, []):
            if relationship is RelationshipType.CONTAINS:
                yield relationship, target, self._arrive(target, lens)

    def _arrive(self, node: str, lens: Lens) -> State:
        resource = self.nodes[node]
        if resource.resource_type in SCOPES:
            return (node, lens)
        return (node, None) if lens.controls(resource) else (node, lens)

    def conveys(self, source: str, relationship: RelationshipType, target: str) -> bool:
        """Whether a link is reach, for drawing it as reach.

        A capability edge, and for a role edge one whose roles control
        something. Reader over a group is a fact the access view lists; drawn
        on a canvas of reach it would say the opposite of what the walk says.
        """
        if not relationship.is_capability:
            return False
        if relationship in _ROLE_EDGES and source in self.nodes:
            return not self._lens(source, relationship, target).empty
        return True

    def _reached(self, state: State) -> bool:
        """Whether standing here reaches the node: held, or a scope a role
        landed on. An asset the walk only passed beneath is not reached."""
        node, lens = state
        return lens is None or self.nodes[node].resource_type in SCOPES

    def _lens(self, source: str, relationship: RelationshipType, target: str) -> Lens:
        key = (source, relationship, target)
        if key not in self._lenses:
            self._lenses[key] = lens_for(self.nodes[source], relationship, target)
        return self._lenses[key]

    def _successors(self, state: State) -> Iterator[tuple[EdgeKey | None, State]]:
        """The walk as severance reads it: the removable link, or None."""
        node = state[0]
        for relationship, target, ahead in self._moves(state):
            link = self.removal_key(node, relationship, target) if removable(relationship) else None
            yield link, ahead

    def removal_key(
        self, source: str, relationship: RelationshipType, target: str
    ) -> EdgeKey:
        """The one thing somebody removes to take this link away.

        Itself, for every link but one. An identity that may grant roles over a
        scope is drawn twice between the same two nodes -- what its roles do
        there, and that it can grant itself the rest -- and both lines are the
        same role assignments. Counted as two links, each was a way round the
        other: removing an Owner assignment, the fix a customer most often
        makes, severed nothing on either line, and the choke points offered
        "detach the identity" instead (DECISIONS.md section 127). So the
        escalation line is keyed as the assignment it comes from.
        """
        if relationship is RelationshipType.CAN_GRANT_ROLES and (
            RelationshipType.GRANTS_ROLE,
            target,
        ) in self._out.get(source, []):
            return (source, RelationshipType.GRANTS_ROLE.value, target)
        return (source, relationship.value, target)

    @staticmethod
    def _holding(node: str) -> State:
        """Standing on a node the walk holds -- where every walk starts."""
        return (node, None)

    def _reached_node(self, state: State) -> str | None:
        return state[0] if self._reached(state) else None

    def attack_paths(self, max_depth: int = MAX_DEPTH) -> list[Path]:
        """Routes from somewhere an attacker could start to something worth taking.

        The question no rule can answer, and the reason the graph exists. Sorted
        shortest-first: a two-hop path is both more likely and easier to
        explain than a five-hop one, and a list that buried it under longer
        routes would be a worse answer to the same question.
        """
        if max_depth not in self._paths:
            self._paths[max_depth] = self._find_attack_paths(max_depth)
        # A copy, so a caller that sorts or trims its answer cannot change the
        # next caller's.
        return list(self._paths[max_depth])

    def _find_attack_paths(self, max_depth: int) -> list[Path]:
        targets = {t.provider_resource_id for t in self.sensitive_targets()}
        if not targets:
            return []

        paths: list[Path] = []
        for entry in self.entry_points():
            reachable = self.reachable_from(entry.provider_resource_id, max_depth)
            for target_id, path in reachable.items():
                if target_id in targets and target_id != entry.provider_resource_id:
                    paths.append(path)

        return sorted(paths, key=lambda p: (p.hops, p.target.name))

    def dead_ends(self, max_depth: int = MAX_DEPTH) -> list[DeadEnd]:
        """Every way in that no route leaves, and why.

        The answer to an empty attack-path list. "Nothing exposed can reach
        anything sensitive" is a verdict a customer cannot check; "vm-web runs
        as no identity" and "vm-api reaches four assets, none classified" are
        things they can look at and disagree with. Machines and apps first, then
        people, because an estate has far more accounts than machines and the
        machines are what the customer came to ask about.
        """
        targets = {t.provider_resource_id for t in self.sensitive_targets()}
        identities = {ResourceType.SERVICE_PRINCIPAL, ResourceType.USER, ResourceType.GROUP}
        ends: list[DeadEnd] = []
        for entry in self.entry_points():
            start = entry.provider_resource_id
            reached = self.reachable_from(start, max_depth)
            if any(node in targets for node in reached if node != start):
                continue
            if not reached:
                reason = DeadEndReason.REACHES_NOTHING
            elif entry.resource_type not in identities and all(
                self.nodes[node].resource_type in identities for node in reached
            ):
                holding = any(
                    relationship is RelationshipType.GRANTS_ROLE
                    for node in reached
                    for relationship, _ in self._out.get(node, [])
                )
                reason = (
                    DeadEndReason.ROLES_WITHOUT_CONTROL
                    if holding
                    else DeadEndReason.IDENTITY_WITHOUT_ROLE
                )
            else:
                reason = DeadEndReason.NOTHING_SENSITIVE
            ends.append(DeadEnd(entry=entry, reason=reason, reached=len(reached)))
        return sorted(
            ends,
            key=lambda end: (
                end.entry.resource_type in identities,
                end.entry.resource_type.value,
                end.entry.name,
            ),
        )

    def route_members(self, max_depth: int = MAX_DEPTH) -> frozenset[str]:
        """Every asset on at least one attack path, wherever on it."""
        return frozenset(
            node for path in self.attack_paths(max_depth) for node in path.node_ids()
        )

    def paths_through(
        self, resource_id: str, max_depth: int = MAX_DEPTH
    ) -> list[Path]:
        """The attack paths this asset is part of, wherever on them it sits.

        Wherever on them, deliberately. A storage account at the end of a route
        and the jump box at the start of it are on the same route, and a person
        looking at one finding on either asset is looking at the same problem --
        so membership is asked of the whole route rather than of its endpoints.
        """
        resource_id = self.resolve(resource_id)
        return [
            path
            for path in self.attack_paths(max_depth)
            if resource_id in path.node_ids()
        ]

    def escalation_chains(self, max_depth: int = MAX_DEPTH) -> list[Path]:
        """Routes from somewhere an attacker could start to an identity that can
        grant itself more.

        A different question from :meth:`attack_paths`, not a variation on it.
        That one asks what an attacker reaches; this asks what they could be
        *given* once they arrive -- and the answer changes the shape of the
        problem, because a principal that may write role assignments over a
        scope has an effective permission of "whatever exists", regardless of
        the role it currently holds. Fixing the reachable asset does not shrink
        that; only the assignment does.

        The route ends at the scope rather than at the identity, because the
        scope is the size of the answer. "This VM runs as an identity that can
        grant itself Owner" is alarming; naming the subscription it can do that
        over is what makes it actionable.

        Requires an entry point, deliberately. A directory administrator who can
        hand out roles is over-privileged and is not a *chain* -- there is no
        route from outside to them here, and reporting one would be inventing
        the half of the story that makes it urgent.
        """
        chains: list[Path] = []
        for entry in self.entry_points():
            reachable = self.reachable_from(entry.provider_resource_id, max_depth)
            for node_id, path in reachable.items():
                for relationship, scope_id in self._out.get(node_id, []):
                    if relationship is not RelationshipType.CAN_GRANT_ROLES:
                        continue
                    if scope_id not in self.nodes:
                        continue
                    if self._already_controls(path, scope_id):
                        # The route took full control of this scope, or of one
                        # above it, before it got here: granting roles over it
                        # now is a loop, not an escalation (section 128).
                        continue
                    hop = PathStep(
                        self.nodes[node_id],
                        RelationshipType.CAN_GRANT_ROLES,
                        self.nodes[scope_id],
                    )
                    chains.append(
                        Path(
                            entry=entry,
                            target=self.nodes[scope_id],
                            steps=(*path.steps, hop),
                        )
                    )

        # Shortest first, and by scope name for stability. A two-hop chain -- an
        # exposed host whose own identity can grant roles -- is both likelier and
        # cheaper to explain than one that arrives through three intermediaries.
        return sorted(chains, key=lambda p: (p.hops, p.target.name))

    def _already_controls(self, path: Path, scope_id: str) -> bool:
        """Whether a route already holds everything over a scope by the time it
        ends: it crossed a line that controls everything -- an escalation, or a
        directory role taking the subscription -- onto the scope or a container
        of it. A narrower role over the same scope does not count; an identity
        with Virtual Machine Contributor that reaches a machine able to grant
        roles over the group has escalated, and the chain is real."""
        whole = {RelationshipType.CAN_GRANT_ROLES, RelationshipType.CAN_TAKE_OVER}
        held = {s.target.provider_resource_id for s in path.steps if s.relationship in whole}
        if not held:
            return False
        above = {scope_id}
        queue: deque[str] = deque([scope_id])
        while queue:
            current = queue.popleft()
            for relationship, parent in self._in.get(current, []):
                if relationship is RelationshipType.CONTAINS and parent not in above:
                    above.add(parent)
                    queue.append(parent)
        return bool(held & above)

    def link_severance(self, max_depth: int = MAX_DEPTH) -> dict[EdgeKey, tuple[Path, ...]]:
        """Every removable link, and the routes that close without it.

        Exact, and for every link rather than for a shortlist -- see
        ``graph/severance.py`` for why one forward walk per entry point answers
        it. A link absent from the answer closes nothing: every route through it
        has another way round, which is a real answer to "what if I cut this"
        and the reason the number on a line is worth drawing at all.

        Attack paths only. Escalation chains answer a different question, and a
        single count covering both would make "routes" mean two things in one
        sentence.
        """
        if max_depth in self._severance:
            return self._severance[max_depth]

        paths = self.attack_paths(max_depth)
        by_pair = {
            (p.entry.provider_resource_id, p.target.provider_resource_id): p for p in paths
        }
        closes = severed_pairs(
            self._successors,
            self._reached_node,
            # The ways in that lead somewhere, rather than every way in. An
            # entry point with no route has nothing to lose, and a directory
            # full of accounts is mostly those -- walking each of them again
            # would double the cost of the page to learn nothing.
            [(entry, self._holding(entry)) for entry in sorted({pair[0] for pair in by_pair})],
            {pair[1] for pair in by_pair},
            max_depth,
        )
        severance = {
            link: tuple(
                by_pair[pair] for pair in sorted(pairs) if pair in by_pair
            )
            for link, pairs in closes.items()
        }
        self._severance[max_depth] = severance
        return severance

    def links_on_routes(self, max_depth: int = MAX_DEPTH) -> dict[EdgeKey, int]:
        """How many routes each removable link sits on.

        Carried beside severance rather than instead of it, because the gap
        between the two is the useful part: a link on twenty routes that closes
        three is a link with a way round, and a customer who cut it expecting
        twenty would rightly stop trusting the next number.
        """
        on: dict[EdgeKey, int] = {}
        for path in self.attack_paths(max_depth):
            for step in path.steps:
                if not removable(step.relationship):
                    continue
                source, _, target = step.key()
                link = self.removal_key(source, step.relationship, target)
                on[link] = on.get(link, 0) + 1
        return on

    def choke_points(
        self, *, limit: int = 5, max_depth: int = MAX_DEPTH
    ) -> list["ChokePoint"]:
        """The links worth cutting first, ranked by how much closes with them.

        The top of :meth:`link_severance`, and nothing more than that. It used
        to be a ranking by containment followed by a verification pass over the
        leaders, because each verification was a whole re-traversal and only a
        handful were affordable; now every link is answered for exactly, so the
        ranked list is a sort rather than a search and cannot miss a choke point
        that sat below whatever the cut-off happened to be.

        A link that closes nothing is not offered: every route through it has
        another way round, so cutting it changes nothing a customer would see.
        """
        severance = self.link_severance(max_depth)
        if not severance:
            return []

        on_routes = self.links_on_routes(max_depth)
        # Keyed as severance keys them, and drawn as the assignment where the
        # escalation line was folded into it: "can act over rg (Owner)" is the
        # thing somebody removes.
        steps = {
            step.key(): step for path in self.attack_paths(max_depth) for step in path.steps
        }
        found = [
            ChokePoint(
                step=steps.get(link) or self._step(link),
                severed=severed,
                # Never smaller than ``severs``, and not by an accident of
                # ordering: a link is severing only when *every* walk to the
                # target uses it, and the enumerated route is one of those
                # walks -- so a link that severs a route is always drawn on it.
                on_routes=on_routes.get(link, 0),
            )
            for link, severed in severance.items()
            if severed
        ]
        return sorted(found, key=lambda c: (-c.severs, c.describe()))[:limit]

    def cut(
        self,
        source: str,
        relationship: RelationshipType,
        target: str,
        max_depth: int = MAX_DEPTH,
    ) -> CutOutcome | None:
        """What happens to the attack paths if one link is removed.

        The same answer :meth:`choke_points` ranks by, for a link somebody
        chose -- read from the one analysis rather than recomputed, so the
        number on the ranked list and the number on the what-if can never
        disagree. None for a link that is not there, and for one nobody can
        remove: containment is where a resource lives, so offering to cut it
        would be a recommendation nobody can take.

        A route closes only when no route between the same two ends remains.
        One that merely moves to another way round is not closed, and counting
        it as closed would promise a customer a result they will not get.
        """
        if not removable(relationship):
            return None
        source, target = self.resolve(source), self.resolve(target)
        if (relationship, target) not in self._out.get(source, []):
            return None

        link = self.removal_key(source, relationship, target)
        closed = self.link_severance(max_depth).get(link, ())
        before = len(self.attack_paths(max_depth))
        return CutOutcome(
            step=self._step(link),
            closed=closed,
            before=before,
            after=before - len(closed),
        )

    def _step(self, link: EdgeKey) -> PathStep:
        source, relationship, target = link
        return PathStep(
            self.nodes[source], RelationshipType(relationship), self.nodes[target]
        )

    def neighborhood(
        self,
        focus: str,
        depth: int = 2,
        *,
        fan_out: int = NEIGHBOURHOOD_FAN_OUT,
        max_nodes: int = NEIGHBOURHOOD_MAX_NODES,
        expand: frozenset[tuple[str, RelationshipType, int]] = frozenset(),
    ) -> Neighborhood | None:
        """The assets around one, for drawing rather than for ranking.

        Walks capability edges both ways from the focus -- forward for what it
        reaches, backward for what reaches it -- one hop at a time, alternating,
        so an asset lands at its shortest distance whichever side that is on.
        Only the edges :meth:`reachable_from` follows: an NSG protecting a VM is
        configuration, and drawing it beside a role assignment would make it
        read as reach.

        Bounded twice, and both bounds fold rather than drop. More than
        ``fan_out`` new neighbours of one asset are counted into a group, except
        that entry points and sensitive assets among them are drawn first --
        "412 resources" hides the one that matters, "3 sensitive of 412" does
        not. Past ``max_nodes`` every remaining neighbour is folded and the walk
        stops, and ``truncated`` says the far side went unread.

        ``expand`` names folds somebody asked to open, as ``(parent,
        relationship, layer)`` -- the same triple a :class:`FoldedGroup`
        carries. Their members are drawn whatever ``fan_out`` says and walked
        on from like any other asset; only ``max_nodes`` still applies, because
        opening a fold of four thousand must not draw four thousand boxes.
        """
        focus = self.resolve(focus)
        if focus not in self.nodes:
            return None

        layers: dict[str, int] = {focus: 0}
        folded: dict[tuple[str, RelationshipType, int], list[str]] = {}
        truncated = False
        frontiers = {1: [focus], -1: [focus]}

        for hop in range(1, depth + 1):
            for sign, adjacency in ((1, self._out), (-1, self._in)):
                layer = sign * hop
                reached: list[str] = []
                for current in frontiers[sign]:
                    fresh = sorted(
                        {
                            (relationship, other)
                            for relationship, other in adjacency.get(current, [])
                            if other not in layers
                            and (
                                self.conveys(current, relationship, other)
                                if sign > 0
                                else self.conveys(other, relationship, current)
                            )
                        },
                        key=lambda edge: self._drawing_order(edge[1]),
                    )
                    opened = [e for e in fresh if (current, e[0], layer) in expand]
                    folding = [e for e in fresh if (current, e[0], layer) not in expand]
                    if len(folding) > fan_out:
                        folding = [e for e in folding if self._is_notable(e[1])][:fan_out]
                    drawn = set(opened) | set(folding)
                    for relationship, other in fresh:
                        if other in layers:
                            continue
                        if (relationship, other) in drawn and len(layers) < max_nodes:
                            layers[other] = layer
                            reached.append(other)
                            continue
                        if len(layers) >= max_nodes:
                            truncated = True
                        folded.setdefault((current, relationship, layer), []).append(other)
                frontiers[sign] = reached

        groups = []
        for (parent, relationship, layer), candidates in sorted(
            folded.items(), key=lambda item: (item[0][2], item[0][0], item[0][1].value)
        ):
            # A neighbour folded here may have been drawn anyway, reached by
            # another route; counting it twice would inflate the group.
            members = tuple(
                self.nodes[other]
                for other in dict.fromkeys(candidates)
                if other not in layers
            )
            if members:
                groups.append(FoldedGroup(parent, relationship, layer, members))

        edges = sorted(
            (source, relationship, target)
            for source in layers
            for relationship, target in self._out.get(source, [])
            if target in layers and self.conveys(source, relationship, target)
        )
        return Neighborhood(
            focus=focus,
            layers=layers,
            edges=tuple(edges),
            groups=tuple(groups),
            truncated=truncated,
        )

    def _is_notable(self, node_id: str) -> bool:
        node = self.nodes[node_id]
        return (
            node.public_exposure in ENTRY_EXPOSURE or node.data_sensitivity in SENSITIVE_DATA
        )

    def _drawing_order(self, node_id: str) -> tuple[bool, str, str, str]:
        """Notable assets first, then by kind and name, so a fold is stable."""
        node = self.nodes[node_id]
        return (not self._is_notable(node_id), node.resource_type.value, node.name, node_id)

    def contained_by(self, scope_id: str, max_depth: int = MAX_DEPTH) -> list[CloudResource]:
        """Everything that sits under a scope.

        What an escalation at that scope would be an escalation *over*.

        Containment only, unlike :meth:`blast_radius`, and the difference is the
        point rather than an optimization. Reach spreads through identities --
        a host under this subscription runs as a principal, and that principal
        is reachable from here -- but a managed identity is not something the
        subscription *holds*. Counting it would answer "what could be taken from
        here" while being asked "what is in here", and the two diverge exactly
        where the answer matters.
        """
        scope_id = self.resolve(scope_id)
        structural = {ResourceType.SUBSCRIPTION, ResourceType.RESOURCE_GROUP}
        held: list[CloudResource] = []
        queue: deque[tuple[str, int]] = deque([(scope_id, 0)])
        seen = {scope_id}

        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for relationship, target in self._out.get(current, []):
                if relationship is not RelationshipType.CONTAINS or target in seen:
                    continue
                seen.add(target)
                node = self.nodes[target]
                if node.resource_type not in structural:
                    held.append(node)
                queue.append((target, depth + 1))
        return held

    def access_to(self, resource_id: str) -> list[AccessHolder]:
        """Every role that reaches this asset, and what each lets its holder do.

        Whether or not anything exposed leads to the holder -- the question an
        attack path cannot answer, because it needs a way in (``graph/access.py``).
        """
        return holders(self.nodes, self._in, self.resolve(resource_id))

    def access_of(self, principal_id: str) -> list[AccessGrant]:
        """Every role one identity holds, and the assets each one controls."""
        return grants(self.nodes, self._out, self.resolve(principal_id))

    def blast_radius(self, principal_id: str, max_depth: int = MAX_DEPTH) -> list[CloudResource]:
        """What one identity can act on.

        Answers the question a customer asks about an over-privileged
        principal, which is never "is this role too broad" in the abstract but
        "what would go if this were taken". Scopes are excluded from the answer
        for the same reason a folder is not a file: a subscription is where the
        reach lands, and the resources beneath it are what the reach is *of*.
        """
        structural = {ResourceType.SUBSCRIPTION, ResourceType.RESOURCE_GROUP}
        return [
            path.target
            for path in self.reachable_from(principal_id, max_depth).values()
            if path.target.resource_type not in structural
        ]
