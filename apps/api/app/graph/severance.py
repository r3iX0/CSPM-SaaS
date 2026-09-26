"""Which routes each link is holding up -- for every link, exactly, in one pass.

The question the attack-path list cannot answer however carefully it is sorted.
Fifty routes are fifty things to read; "remove this one role assignment and
thirty-seven of them close" is one thing to do.

The first implementation answered it by removing a link and re-asking the whole
question, once per candidate, over every entry point in the tenant. That is
correct, and it costs a full traversal per candidate -- so it could only afford
to check the links sitting on the most routes, ranking by containment first and
trusting that severance agreed. Containment does bound severance, so the
ranking is sound as far as it goes. What it cannot do is say anything at all
about the links it never checked, and those are most of them.

This answers for every link at once, and exactly.

**How.** From one entry point, walk forward layer by layer to the depth bound,
carrying with each node the set of removable links that appear on *every* walk
of that length to it:

    necessary(entry, 0)  = {}
    necessary(v, d+1)    = intersection over each u with an edge u->v of
                           necessary(u, d) + {that edge, when removable}
    necessary(v)         = intersection over every d at which v is reached

A link is in ``necessary(v)`` exactly when no walk from the entry to ``v``
within the bound avoids it -- which is exactly when removing it puts ``v`` out
of reach. The severed set of a link is then read off the targets rather than
searched for, and one walk per entry answers for every link in the graph.

**Layers, not a visited set.** The traversal that enumerates routes stops at a
node it has already seen, because it wants the shortest route to it. This must
not: a longer way round is the whole reason a link might *not* be worth
cutting, and a walk that stopped at the first arrival would call every link on
the shortest route necessary and promise closures that never happen. Keeping
the layers is affordable for the same reason the routes are short -- a set
carried here can never hold more links than the walk has hops.

**The same bound as everything else.** Reach is "within ``MAX_DEPTH`` hops"
throughout CloudGuard, so severance is too: a way round that takes nine hops
does not keep a route alive here, because a nine-hop route was never claimed to
exist in the first place. One definition, shared by the ranked list, by the
what-if on a single link, and by the number drawn on a line.

**Over walk states, not over nodes.** A role edge is walked with what the
role controls (``graph/access.py``), so arriving at a resource group through
Reader and arriving through Owner are different places to stand even though
they are one node. The walk carries states; the links it names are still the
graph's own, because a state is a way of standing on a node and never a link
anybody could cut.
"""

from collections import defaultdict
from collections.abc import Callable, Hashable, Iterable

from app.core.enums import RelationshipType

#: A link, named the way a query string and a drawn edge both name it.
EdgeKey = tuple[str, str, str]

#: Every way on from a state -- a place a walk can stand: a node, and whatever
#: the walk carries with it -- as the link taken and where it leads. The link
#: is None where it is not one anybody could remove.
type Successors[S: Hashable] = Callable[[S], Iterable[tuple[EdgeKey | None, S]]]

#: The node a state counts as having reached, or None where standing there is
#: not reaching anything -- passing beneath an asset a role cannot touch.
type Reached[S: Hashable] = Callable[[S], str | None]


def removable(relationship: RelationshipType) -> bool:
    """Whether a link is one somebody could actually remove.

    Containment is where a resource lives -- a storage account has to sit in
    some resource group -- so offering to cut it would be a recommendation
    nobody can take.
    """
    return relationship.is_capability and relationship is not RelationshipType.CONTAINS


def necessary_links[S: Hashable](
    successors: Successors[S], entry: S, max_depth: int
) -> dict[S, frozenset[EdgeKey]]:
    """For each state reached from ``entry``, the links every walk to it uses.

    Empty for a state reached by a walk with nothing removable on it, and
    absent altogether for one not reached within the bound. The entry is
    reached by the empty walk, so nothing is necessary to it.
    """
    necessary: dict[S, frozenset[EdgeKey]] = {entry: frozenset()}
    layer: dict[S, frozenset[EdgeKey]] = {entry: frozenset()}

    for _ in range(max_depth):
        ahead: dict[S, frozenset[EdgeKey]] = {}
        for state, carried in layer.items():
            for link, other in successors(state):
                through = carried | {link} if link is not None else carried
                # Intersected, never unioned: a link is necessary to a state
                # only when it is on every way of getting there.
                reached = ahead.get(other)
                ahead[other] = through if reached is None else reached & through
        if not ahead:
            break
        for state, through in ahead.items():
            # A state reached at this depth and at a shallower one is one state
            # with two ways to it, and only what both use is necessary.
            settled = necessary.get(state)
            necessary[state] = through if settled is None else settled & through
        layer = ahead

    return necessary


def severed_pairs[S: Hashable](
    successors: Successors[S],
    reached: Reached[S],
    entries: list[tuple[str, S]],
    targets: set[str],
    max_depth: int,
) -> dict[EdgeKey, set[tuple[str, str]]]:
    """Every link, and the (entry, target) routes that close without it.

    One walk per entry point whatever the number of links -- the cost the route
    list already pays, rather than a traversal per candidate on top of it.
    ``entries`` pairs each entry's node with the state its walk starts in.
    """
    closes: dict[EdgeKey, set[tuple[str, str]]] = defaultdict(set)
    for entry, start in entries:
        # A node can be stood on in several states, and it stays reached while
        # any of them is -- so what is necessary to the node is what every one
        # of its reaching states needs.
        per_node: dict[str, frozenset[EdgeKey]] = {}
        for state, links in necessary_links(successors, start, max_depth).items():
            node = reached(state)
            if node is None:
                continue
            settled = per_node.get(node)
            per_node[node] = links if settled is None else settled & links
        # Over what this entry reached rather than over every sensitive asset
        # in the tenant. A directory has far more administrators than any one
        # machine reaches, and asking about each of them per entry point is a
        # multiplication of two large numbers to answer "no" almost every time.
        for target in per_node.keys() & targets:
            if target == entry:
                continue
            for link in per_node[target]:
                closes[link].add((entry, target))
    return dict(closes)
