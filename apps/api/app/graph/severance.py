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
"""

from collections import defaultdict

from app.core.enums import RelationshipType

#: A link, named the way a query string and a drawn edge both name it.
EdgeKey = tuple[str, str, str]

#: Reach out of one node, as the graph indexes it.
Adjacency = dict[str, list[tuple[RelationshipType, str]]]


def removable(relationship: RelationshipType) -> bool:
    """Whether a link is one somebody could actually remove.

    Containment is where a resource lives -- a storage account has to sit in
    some resource group -- so offering to cut it would be a recommendation
    nobody can take.
    """
    return relationship.is_capability and relationship is not RelationshipType.CONTAINS


def necessary_links(
    out: Adjacency, entry: str, max_depth: int
) -> dict[str, frozenset[EdgeKey]]:
    """For each node reached from ``entry``, the links every route to it uses.

    Empty for a node reached by a route with nothing removable on it, and
    absent altogether for a node not reached within the bound. The entry is
    reached by the empty walk, so nothing is necessary to it.
    """
    necessary: dict[str, frozenset[EdgeKey]] = {entry: frozenset()}
    layer: dict[str, frozenset[EdgeKey]] = {entry: frozenset()}

    for _ in range(max_depth):
        ahead: dict[str, frozenset[EdgeKey]] = {}
        for node, carried in layer.items():
            for relationship, other in out.get(node, ()):
                if not relationship.is_capability:
                    continue
                through = (
                    carried | {(node, relationship.value, other)}
                    if removable(relationship)
                    else carried
                )
                # Intersected, never unioned: a link is necessary to a node
                # only when it is on every way of getting there.
                reached = ahead.get(other)
                ahead[other] = through if reached is None else reached & through
        if not ahead:
            break
        for node, through in ahead.items():
            # A node reached at this depth and at a shallower one is one node
            # with two ways to it, and only what both use is necessary.
            settled = necessary.get(node)
            necessary[node] = through if settled is None else settled & through
        layer = ahead

    return necessary


def severed_pairs(
    out: Adjacency,
    entries: list[str],
    targets: set[str],
    max_depth: int,
) -> dict[EdgeKey, set[tuple[str, str]]]:
    """Every link, and the (entry, target) routes that close without it.

    One walk per entry point whatever the number of links -- the cost the route
    list already pays, rather than a traversal per candidate on top of it.
    """
    closes: dict[EdgeKey, set[tuple[str, str]]] = defaultdict(set)
    for entry in entries:
        necessary = necessary_links(out, entry, max_depth)
        # Over what this entry reached rather than over every sensitive asset
        # in the tenant. A directory has far more administrators than any one
        # machine reaches, and asking about each of them per entry point is a
        # multiplication of two large numbers to answer "no" almost every time.
        for target in necessary.keys() & targets:
            if target == entry:
                continue
            for link in necessary[target]:
                closes[link].add((entry, target))
    return dict(closes)
