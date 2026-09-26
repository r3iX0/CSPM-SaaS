"""What an edge *is*, beyond what kind of edge it is.

``RELATIONSHIP_VERBS`` turns an edge into a sentence: "mi-app can act over
sub-prod". True, and it is the sentence a customer cannot act on, because the
one thing they would have to change to make it false -- the role -- is the one
thing it does not name. CloudGuard collected the role. It stored the role. It
drew a line for it and then declined to say it.

Derived here rather than carried on the edge, and that is the whole design.
An edge is ``(source, kind, target)`` in the payload the normalizer produces,
in the table it is stored in, and in every traversal that walks it; threading a
fourth element through all of that would mean a column, a migration, an
``ON CONFLICT`` that updates it, and a producer change per provider -- to
restate facts that are *already* on the two assets the edge joins. A
principal's roles are on the principal. A machine's subnets are on the machine.
So the facts are read back off the nodes, which makes them exactly as fresh as
the assets are and impossible to leave stale behind them.

Nothing here guesses. A fact appears when the asset states it and is absent
otherwise -- an unresolved role is already "Unknown role" by the time it
reaches metadata, and an edge whose evidence was never collected says nothing
rather than something plausible.
"""

from app.core.enums import RelationshipType
from app.domain.resource import CloudResource
from app.graph.access import control_pairs, role_entries
from app.graph.identity import directory_reason

# Metadata a normalizer writes for the facts below to be readable. Neutral
# keys, written by whichever connector has the answer: ``roles`` is a list of
# role entries on a principal (``graph/access.py`` spells them out), ``subnets``
# a list of subnet ids on a machine, ``principal_type`` a string on a minted
# identity.
ROLES = "roles"
SUBNETS = "subnets"
PRINCIPAL_TYPE = "principal_type"

# How many roles one hop names before the rest are counted. A principal holding
# nine roles over one scope is a fact about the principal, not about the hop,
# and the hop is a label on a line.
_MAX_ROLES = 3


def edge_facts(
    source: CloudResource, relationship: RelationshipType, target: CloudResource
) -> tuple[str, ...]:
    """What is known about this one link, in the words a person would use.

    Short phrases, each true on its own, ordered so the first is the one worth
    reading if only one fits: the role over the scope, the kind of identity,
    the network both machines sit in. Empty when the assets carry nothing -- an
    edge that cannot say more than its kind says its kind and stops.
    """
    if relationship in {RelationshipType.GRANTS_ROLE, RelationshipType.CAN_GRANT_ROLES}:
        return _roles(
            source, target, escalating=relationship is RelationshipType.CAN_GRANT_ROLES
        )
    if relationship is RelationshipType.HAS_IDENTITY:
        return _identity_kind(target)
    if relationship is RelationshipType.NETWORK_ACCESS:
        return _shared_network(source, target)
    if relationship in {RelationshipType.CAN_ACT_AS, RelationshipType.CAN_TAKE_OVER}:
        # The directory role, the ownership or the credential -- whichever of
        # them somebody would remove (DECISIONS.md section 128).
        reason = directory_reason(source, relationship)
        return (reason,) if reason else ()
    return ()


def _roles(
    principal: CloudResource, scope: CloudResource, *, escalating: bool
) -> tuple[str, ...]:
    """The roles this principal holds over this scope, by name.

    Matched on where the edge was drawn, case-insensitively, for the reason the
    normalizer joins scopes that way: an assignment's scope is spelled by
    whoever made it, and ``resourcegroups/lab-rg`` over a group whose id says
    ``resourceGroups/LAB-RG`` is the same scope. An assignment inherited from a
    management group is drawn to the subscription and says where it came from.

    For an escalation edge, only the assignments that carry the escalation. For
    a role edge, the roles that control something first: the principal may hold
    Reader over the same scope too, and naming Reader first on a hop the walk
    took because of Owner would put the harmless assignment's name on the
    dangerous claim (DECISIONS.md section 125).
    """
    ranked: list[tuple[bool, str]] = []
    for entry in role_entries(principal, scope.provider_resource_id):
        if escalating and not entry.get("grants_role_assignment"):
            continue
        name = entry.get("role")
        if not isinstance(name, str) or not name:
            continue
        origin = entry.get("inherited_from")
        if isinstance(origin, str) and origin:
            name = f"{name} from {_ancestor_name(origin)}"
        controlling = "access" not in entry or bool(
            entry.get("grants_role_assignment")
        ) or any(True for _ in control_pairs(entry.get("access")))
        ranked.append((not controlling, name))

    names: list[str] = []
    for _, name in sorted(ranked, key=lambda item: item[0]):
        if name not in names:
            names.append(name)

    if len(names) > _MAX_ROLES:
        return (*names[:_MAX_ROLES], f"and {len(names) - _MAX_ROLES} more")
    return tuple(names)


def _ancestor_name(scope: str) -> str:
    """A management group by its name, or the root by what it is."""
    trimmed = scope.rstrip("/")
    if not trimmed:
        return "the tenant root"
    return f"management group {trimmed.rsplit('/', 1)[-1]}"


def _identity_kind(identity: CloudResource) -> tuple[str, ...]:
    """Whether the workload runs as a managed identity or as something else.

    Which decides who can take it: a managed identity is handed to that
    workload by the platform, while a service principal with a secret is
    reachable by anyone holding the secret.
    """
    kind = identity.metadata.get(PRINCIPAL_TYPE)
    if not isinstance(kind, str) or not kind:
        return ()
    if kind.lower() == "managedidentity":
        return ("managed identity",)
    return (kind.lower(),)


def _shared_network(source: CloudResource, target: CloudResource) -> tuple[str, ...]:
    """The virtual network both machines sit in.

    The edge exists *because* they share one and nothing between them stops
    traffic, so the network is the fact that makes the hop what it is -- and
    separating them is the change that removes it.
    """
    shared = _networks(source) & _networks(target)
    if not shared:
        return ()
    name = sorted(shared)[0].rsplit("/", 1)[-1]
    return (f"same virtual network ({name})",) if name else ()


def _networks(machine: CloudResource) -> set[str]:
    subnets = machine.metadata.get(SUBNETS)
    if not isinstance(subnets, list):
        return set()
    return {
        str(subnet).lower().split("/subnets/", 1)[0]
        for subnet in subnets
        if isinstance(subnet, str) and subnet
    }
