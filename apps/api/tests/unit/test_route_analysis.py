"""What each link holds up, what each hop actually is, and what a fan of routes
is really one of.

Three readings of one graph the attack-path page depends on being exact:

- severance, which must answer for *every* link rather than for the handful an
  older ranking could afford to verify;
- the evidence on a hop, which is the difference between "can act over" and the
  role somebody has to go and remove;
- the shape of a fan, because twelve machines reaching one storage account the
  same way is one sentence and was printed as twelve.

Pure: a graph is built from resources and edges and asked. No database, no
Azure, no scan.
"""

from app.core.enums import Level, RelationshipType, ResourceType
from app.domain.resource import CloudResource
from app.graph import AssetGraph, PathStep
from app.graph.facts import edge_facts
from app.graph.patterns import PatternKind, route_patterns
from app.services.graph import serialize_route_map

GROUP = "/subscriptions/s/resourceGroups/data"
RECORDS = f"{GROUP}/providers/storage/records"
LEDGER = "/storage/ledger"
HOP_A = "/vm/hop-a"
HOP_B = "/vm/hop-b"
WEB = "/vm/web"
IDENTITY = "/principals/mi-hop"
VNET = "/subscriptions/s/resourceGroups/net/providers/virtualNetworks/core"


def node(
    resource_id: str,
    kind: ResourceType,
    *,
    metadata: dict | None = None,
    **levels: Level,
) -> CloudResource:
    return CloudResource(
        provider_resource_id=resource_id,
        resource_type=kind,
        name=resource_id.rsplit("/", 1)[-1],
        metadata=metadata or {},
        **levels,
    )


def diamond() -> AssetGraph:
    """One way in, two ways across, one identity beyond both.

    ``web`` reaches ``hop-a`` and ``hop-b`` over the network; either runs as the
    same identity, which holds a role over the group the records sit in. No
    single network hop is worth cutting -- the other one is still there -- and
    the identity's role is, because everything passes through it.
    """
    return AssetGraph.build(
        [
            node(WEB, ResourceType.VIRTUAL_MACHINE, public_exposure=Level.CRITICAL),
            node(HOP_A, ResourceType.VIRTUAL_MACHINE),
            node(HOP_B, ResourceType.VIRTUAL_MACHINE),
            node(IDENTITY, ResourceType.SERVICE_PRINCIPAL),
            node(GROUP, ResourceType.RESOURCE_GROUP),
            node(
                RECORDS, ResourceType.STORAGE_ACCOUNT, data_sensitivity=Level.CRITICAL
            ),
        ],
        [
            (WEB, RelationshipType.NETWORK_ACCESS, HOP_A),
            (WEB, RelationshipType.NETWORK_ACCESS, HOP_B),
            (HOP_A, RelationshipType.HAS_IDENTITY, IDENTITY),
            (HOP_B, RelationshipType.HAS_IDENTITY, IDENTITY),
            (IDENTITY, RelationshipType.GRANTS_ROLE, GROUP),
            (GROUP, RelationshipType.CONTAINS, RECORDS),
        ],
    )


def test_a_link_with_a_longer_way_round_severs_nothing() -> None:
    """The first hop of the shortest route is not always worth cutting.

    ``web -> hop-a`` is on the route the list draws, because it is the shortest
    one. Removing it leaves ``web -> hop-b``, which arrives at the same identity
    -- so the route does not close, and a page offering this link as the fix
    would be selling an afternoon's work for nothing.
    """
    graph = diamond()
    severance = graph.link_severance()

    assert (WEB, "network_access", HOP_A) not in severance
    assert (WEB, "network_access", HOP_B) not in severance

    outcome = graph.cut(WEB, RelationshipType.NETWORK_ACCESS, HOP_A)
    assert outcome is not None
    assert outcome.closed == ()
    assert outcome.before == outcome.after


def test_the_link_every_way_round_shares_is_the_one_offered() -> None:
    graph = diamond()

    chokes = graph.choke_points()

    assert [choke.step.key() for choke in chokes] == [(IDENTITY, "grants_role", GROUP)]
    assert chokes[0].severs == 1
    # It sits on the one drawn route and it closes it: no way round to admit.
    assert chokes[0].on_routes == 1


def test_severance_and_the_what_if_are_one_analysis() -> None:
    """The ranked number and the number for a single link cannot disagree.

    They used to be two computations of the same thing, one of them a ranking
    that could only afford to check its leaders.
    """
    graph = diamond()
    choke = graph.choke_points()[0]

    outcome = graph.cut(
        choke.step.source.provider_resource_id,
        choke.step.relationship,
        choke.step.target.provider_resource_id,
    )

    assert outcome is not None
    assert len(outcome.closed) == choke.severs
    assert outcome.after == outcome.before - choke.severs


def test_containment_is_never_offered_as_a_cut() -> None:
    graph = diamond()

    assert (GROUP, "contains", RECORDS) not in graph.link_severance()
    assert graph.cut(GROUP, RelationshipType.CONTAINS, RECORDS) is None


def roled() -> AssetGraph:
    """One route, with the evidence the connector already collects on it."""
    return AssetGraph.build(
        [
            node(
                WEB,
                ResourceType.VIRTUAL_MACHINE,
                public_exposure=Level.CRITICAL,
                metadata={"subnets": [f"{VNET}/subnets/web"]},
            ),
            node(
                HOP_A,
                ResourceType.VIRTUAL_MACHINE,
                metadata={"subnets": [f"{VNET}/subnets/app"]},
            ),
            node(
                IDENTITY,
                ResourceType.SERVICE_PRINCIPAL,
                metadata={
                    "principal_type": "ManagedIdentity",
                    "roles": [
                        # Spelled in another case, the way an assignment made in
                        # the portal routinely spells the scope it is over.
                        {
                            "role": "Contributor",
                            "scope": GROUP.upper(),
                            "grants_role_assignment": False,
                        },
                        {
                            "role": "Owner",
                            "scope": GROUP,
                            "grants_role_assignment": True,
                        },
                        {
                            "role": "Reader",
                            "scope": "/subscriptions/other",
                            "grants_role_assignment": False,
                        },
                    ],
                },
            ),
            node(GROUP, ResourceType.RESOURCE_GROUP),
            node(
                RECORDS, ResourceType.STORAGE_ACCOUNT, data_sensitivity=Level.CRITICAL
            ),
        ],
        [
            (WEB, RelationshipType.NETWORK_ACCESS, HOP_A),
            (HOP_A, RelationshipType.HAS_IDENTITY, IDENTITY),
            (IDENTITY, RelationshipType.GRANTS_ROLE, GROUP),
            (IDENTITY, RelationshipType.CAN_GRANT_ROLES, GROUP),
            (GROUP, RelationshipType.CONTAINS, RECORDS),
        ],
    )


def hops(graph: AssetGraph) -> dict[str, PathStep]:
    return {step.relationship.value: step for step in graph.attack_paths()[0].steps}


def test_a_role_hop_names_the_roles_it_is_made_of() -> None:
    step = hops(roled())["grants_role"]

    assert step.facts == ("Contributor", "Owner")
    assert step.detail() == f"{step.describe()} (Contributor, Owner)"


def test_an_escalation_hop_names_only_what_escalates() -> None:
    """Reader beside "can grant itself any role" would put the harmless
    assignment's name on the dangerous claim."""
    graph = roled()

    assert edge_facts(
        graph.nodes[IDENTITY], RelationshipType.CAN_GRANT_ROLES, graph.nodes[GROUP]
    ) == ("Owner",)


def test_a_network_hop_names_the_network_and_an_identity_hop_its_kind() -> None:
    walked = hops(roled())

    assert walked["network_access"].facts == ("same virtual network (core)",)
    assert walked["has_identity"].facts == ("managed identity",)


def test_a_hop_with_nothing_collected_says_only_its_kind() -> None:
    step = hops(diamond())["grants_role"]

    assert step.facts == ()
    assert step.detail() == step.describe()


def fan() -> AssetGraph:
    """Three machines, one identity, one storage account. One sentence."""
    machines = [f"/vm/worker-{index}" for index in range(3)]
    return AssetGraph.build(
        [
            *(
                node(machine, ResourceType.VIRTUAL_MACHINE, public_exposure=Level.HIGH)
                for machine in machines
            ),
            node(IDENTITY, ResourceType.SERVICE_PRINCIPAL),
            node(GROUP, ResourceType.RESOURCE_GROUP),
            node(RECORDS, ResourceType.STORAGE_ACCOUNT, data_sensitivity=Level.HIGH),
        ],
        [
            *(
                (machine, RelationshipType.HAS_IDENTITY, IDENTITY)
                for machine in machines
            ),
            (IDENTITY, RelationshipType.GRANTS_ROLE, GROUP),
            (GROUP, RelationshipType.CONTAINS, RECORDS),
        ],
    )


def test_routes_that_differ_only_in_where_they_start_are_one_pattern() -> None:
    patterns, loose = route_patterns(fan().attack_paths())

    assert loose == []
    assert len(patterns) == 1
    assert patterns[0].kind is PatternKind.MANY_ENTRIES
    assert patterns[0].size == 3
    assert patterns[0].describe() == "3 virtual machines reach records the same way"


def test_routes_that_differ_only_in_what_they_reach_are_one_pattern() -> None:
    graph = AssetGraph.build(
        [
            node(WEB, ResourceType.VIRTUAL_MACHINE, public_exposure=Level.HIGH),
            node(IDENTITY, ResourceType.SERVICE_PRINCIPAL),
            node(RECORDS, ResourceType.STORAGE_ACCOUNT, data_sensitivity=Level.HIGH),
            node(LEDGER, ResourceType.STORAGE_ACCOUNT, data_sensitivity=Level.HIGH),
        ],
        [
            (WEB, RelationshipType.HAS_IDENTITY, IDENTITY),
            (IDENTITY, RelationshipType.GRANTS_ROLE, RECORDS),
            (IDENTITY, RelationshipType.GRANTS_ROLE, LEDGER),
        ],
    )

    patterns, loose = route_patterns(graph.attack_paths())

    assert loose == []
    assert [pattern.kind for pattern in patterns] == [PatternKind.MANY_TARGETS]
    assert patterns[0].size == 2
    assert patterns[0].describe() == "web reaches 2 storage accounts the same way"


def rebuilt_without(graph: AssetGraph, link: tuple[str, str, str]) -> AssetGraph:
    """The same estate with one link removed, assembled from the outside."""
    gone = (link[0], RelationshipType(link[1]), link[2])
    return AssetGraph.build(
        list(graph.nodes.values()), [edge for edge in graph.links() if edge != gone]
    )


def test_every_severance_answer_survives_being_checked_the_slow_way() -> None:
    """The independent oracle for the whole analysis.

    `link_severance` derives its answer once, forward, and everything else on
    the page reads that one derivation -- which is what keeps the ranked list,
    the what-if and the number on a line from disagreeing, and also what makes
    them all wrong together if the derivation is. So each answer is re-checked
    against the definition it claims to mean: remove the link, enumerate the
    routes again from resources and edges, and see what is actually gone.
    """
    for estate in (diamond(), fan(), roled()):
        before = {
            (path.entry.provider_resource_id, path.target.provider_resource_id)
            for path in estate.attack_paths()
        }
        severance = estate.link_severance()

        for link in {step.key() for path in estate.attack_paths() for step in path.steps}:
            if link[1] == RelationshipType.CONTAINS.value:
                continue
            after = {
                (path.entry.provider_resource_id, path.target.provider_resource_id)
                for path in rebuilt_without(estate, link).attack_paths()
            }
            claimed = {
                (path.entry.provider_resource_id, path.target.provider_resource_id)
                for path in severance.get(link, ())
            }
            assert claimed == before - after, link


def test_the_drawn_map_counts_a_cut_against_every_route_not_the_drawn_ones() -> None:
    """One claim, one denominator.

    The map is capped, the severance behind a link is not, and the risks queue
    leads with the same links under its own endpoint. A map saying "1 of 1
    routes close" beside a queue saying "1 of 3" would be the same sentence
    with two answers, in two places one person reads in one sitting.
    """
    graph = fan()
    every = graph.attack_paths()
    drawn = every[:1]

    payload = serialize_route_map(graph, drawn, {}, {}, total_routes=len(every))

    assert len(payload["routes"]) == 1
    assert all(
        choke["total_routes"] == len(every) for choke in payload["choke_points"]
    )
    # And the severance itself is over every route, not over the drawn one: the
    # role the three machines share closes all three.
    assert payload["choke_points"][0]["severs"] == len(every)


def test_a_route_belongs_to_one_pattern_and_the_totals_add_up() -> None:
    """Both readings are true of a fan that opens at both ends. Counting a
    route in both would make the groups total more than the estate holds."""
    paths = fan().attack_paths()

    patterns, loose = route_patterns(paths)

    assert sum(pattern.size for pattern in patterns) + len(loose) == len(paths)
