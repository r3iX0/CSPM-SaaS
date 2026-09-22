"""One identity, one node -- whichever capture each half of it came from.

A scan reads the directory once and each subscription separately, and each
reading is normalized on its own (DECISIONS.md section 108). So the same person
arrived as two nodes: ``/users/<id>`` from the directory, carrying the account
-- its MFA, its sign-ins, its exposure as a way in -- and a stand-in minted from
a subscription's role assignment, carrying the roles. Nothing joined them. The
account was an entry point that reached nothing; the roles belonged to an
identity nothing could reach. A phished administrator with Owner was, in every
production scan, not a route.

The same split hid in plainer form. A principal holding roles in two
subscriptions was minted once per subscription, and building the graph kept
whichever copy came last -- with only that subscription's roles on it.

This joins them, when the graph is built and nowhere earlier, because it is
only here that both readings are in one place:

* Copies of one node are merged, their roles combined.
* A stand-in (``stub``) is folded into the directory's record of the same
  identity (``identity_id``). Its roles move onto that record, and its edges
  are redrawn from it. The stand-in's id still resolves, so a page opened on it
  is answered about the identity it stood for.
* A group's recorded members become ``MEMBER_OF`` edges, from whichever node
  holds each member's identity. A member no node holds is still listed by the
  access view, by name. It just cannot be walked through, because nothing about
  it was read.
* The directory's say over the estate becomes edges too (section 128). An
  application registration's owners, and the registration itself where it
  holds a credential, ``CAN_ACT_AS`` the service principal it signs in as. An
  account whose directory role manages every application can act as every one
  of those principals. An account whose directory role can make it owner of
  every subscription ``CAN_TAKE_OVER`` each subscription in the graph.

Neutral: it reads metadata keys and no provider id.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any

from app.core.enums import RelationshipType, ResourceType
from app.domain.resource import CloudResource

#: The directory object a node is, however it arrived.
IDENTITY_ID = "identity_id"
#: Set on a node a connector minted to stand in for an identity it did not
#: read itself -- from a role assignment, or a workload's identity block.
STUB = "stub"
#: On a group: ``[{"id", "kind", "name"}]``, or None when not read.
MEMBERS = "members"
ROLES = "roles"
#: On a node whose name was made up from its id because nothing read named it.
UNNAMED = "unnamed"
#: On an identity: ``[{"power", "via"}]``. ``control_all_scopes`` can make
#: itself owner of every subscription; ``act_as_any_application`` can sign in as
#: any application's service principal. ``via`` names the directory role.
POWERS = "directory_powers"
#: The same, for directory roles the identity could activate under PIM rather
#: than holds; and the Azure roles it could activate. Drawn as ``ELIGIBLE_FOR``,
#: never walked (section 130).
ELIGIBLE_POWERS = "eligible_directory_powers"
ELIGIBLE_ROLES = "eligible_roles"
CONTROL_ALL_SCOPES = "control_all_scopes"
ACT_AS_ANY_APPLICATION = "act_as_any_application"
#: On an application registration: the identity it signs in as, who can add a
#: credential to it (None when not read), and whether it holds one itself.
ACTS_AS = "acts_as"
CONTROLLERS = "controllers"
CAN_SIGN_IN = "can_sign_in"

Edge = tuple[str, RelationshipType, str]


@dataclass
class Joined:
    """The graph's nodes and edges once each identity is one node."""

    resources: list[CloudResource]
    relationships: list[Edge]
    #: Stand-in id to the id of the node it was folded into.
    aliases: dict[str, str] = field(default_factory=dict)


def join(
    resources: Iterable[CloudResource],
    relationships: Iterable[Edge],
    *,
    derive: bool = True,
) -> Joined:
    merged = _merge_copies(resources)
    aliases = _fold_stubs(merged)
    for alias in aliases:
        merged.pop(alias, None)

    edges: list[Edge] = []
    seen: set[Edge] = set()
    for source, relationship, target in relationships:
        edge = (aliases.get(source, source), relationship, aliases.get(target, target))
        if edge[0] != edge[2] and edge not in seen:
            seen.add(edge)
            edges.append(edge)
    derived = (*_memberships(merged), *_directory_reach(merged)) if derive else ()
    for edge in derived:
        if edge not in seen:
            seen.add(edge)
            edges.append(edge)
    return Joined(resources=list(merged.values()), relationships=edges, aliases=aliases)


def _merge_copies(resources: Iterable[CloudResource]) -> dict[str, CloudResource]:
    """One node per id, with every copy's roles and powers on it.

    The directory's own record of an identity keeps its fields over a stand-in
    minted with the same id, whichever arrived first: a principal a
    subscription minted as "ServicePrincipal 1a2b3c4d" is the one the directory
    names and knows the powers of (section 129). A key only one copy has is
    kept; roles and powers are combined.
    """
    merged: dict[str, CloudResource] = {}
    for resource in resources:
        key = resource.provider_resource_id
        existing = merged.get(key)
        if existing is None:
            merged[key] = resource
            continue
        base, other = (
            (resource, existing)
            if existing.metadata.get(STUB) and not resource.metadata.get(STUB)
            else (existing, resource)
        )
        merged[key] = _absorb(base, other)
    return merged


def _absorb(base: CloudResource, other: CloudResource) -> CloudResource:
    """``base``, with what ``other`` knows about the same identity added.

    ``base`` keeps its fields; a key only ``other`` has is kept; a name a
    reading gave beats one made up from an id; and roles, powers and eligible
    roles are combined -- every list another copy of the identity carries.
    """
    metadata = {**other.metadata, **base.metadata}
    if not base.metadata.get(STUB):
        # The directory's record stays one, whatever the stand-in said.
        metadata.pop(STUB, None)
    name = base.name
    if base.metadata.get(UNNAMED) and not other.metadata.get(UNNAMED):
        name = other.name
        metadata.pop(UNNAMED, None)
    for listed in (POWERS, ELIGIBLE_POWERS, ELIGIBLE_ROLES):
        combined = [*_listed(base, listed), *_listed(other, listed)]
        if combined:
            metadata[listed] = list({repr(sorted(p.items())): p for p in combined}.values())
    return _with_roles(replace(base, name=name, metadata=metadata), _roles(other))


def _listed(resource: CloudResource, key: str) -> list[Any]:
    value = resource.metadata.get(key)
    if not isinstance(value, list):
        return []
    return [entry for entry in value if isinstance(entry, Mapping)]


def _fold_stubs(nodes: dict[str, CloudResource]) -> dict[str, str]:
    """Stand-ins to the node each is folded into, with roles moved across."""
    by_identity: dict[str, list[str]] = {}
    for node_id, node in nodes.items():
        identity = node.metadata.get(IDENTITY_ID)
        if isinstance(identity, str) and identity:
            by_identity.setdefault(identity.lower(), []).append(node_id)

    aliases: dict[str, str] = {}
    for ids in by_identity.values():
        if len(ids) < 2:
            continue
        # The directory's own record where there is one; a stand-in only
        # stands in for something CloudGuard did not otherwise read.
        canonical = next((i for i in ids if not nodes[i].metadata.get(STUB)), ids[0])
        for other in ids:
            if other == canonical:
                continue
            nodes[canonical] = _absorb(nodes[canonical], nodes[other])
            aliases[other] = canonical
    return aliases


def _memberships(nodes: Mapping[str, CloudResource]) -> Iterable[Edge]:
    index = _identity_index(nodes)
    for group_id, group in nodes.items():
        for member in members_of(group):
            holder = index.get(member["id"].lower())
            if holder is not None and holder != group_id:
                yield (holder, RelationshipType.MEMBER_OF, group_id)


def _identity_index(nodes: Mapping[str, CloudResource]) -> dict[str, str]:
    index: dict[str, str] = {}
    for node_id, node in nodes.items():
        identity = node.metadata.get(IDENTITY_ID)
        if isinstance(identity, str) and identity:
            index.setdefault(identity.lower(), node_id)
    return index


def _directory_reach(nodes: Mapping[str, CloudResource]) -> Iterable[Edge]:
    """What the directory lets an identity do to the estate, as edges.

    Only to nodes the graph holds. A principal that holds no Azure role never
    reached a subscription's graph, and acting as it reaches nothing here.
    """
    index = _identity_index(nodes)
    principals: set[str] = set()
    for app_id, app in nodes.items():
        acts_as = app.metadata.get(ACTS_AS)
        principal = index.get(acts_as.lower()) if isinstance(acts_as, str) else None
        if principal is None or principal == app_id:
            continue
        principals.add(principal)
        if app.metadata.get(CAN_SIGN_IN) is True:
            yield (app_id, RelationshipType.CAN_ACT_AS, principal)
        controllers = app.metadata.get(CONTROLLERS)
        for owner in controllers if isinstance(controllers, list) else []:
            holder = index.get(str(owner).lower())
            if holder is not None and holder != principal:
                yield (holder, RelationshipType.CAN_ACT_AS, principal)

    subscriptions = sorted(
        node_id
        for node_id, node in nodes.items()
        if node.resource_type is ResourceType.SUBSCRIPTION
    )
    for node_id, node in nodes.items():
        for key, act_as, take_over in (
            (POWERS, RelationshipType.CAN_ACT_AS, RelationshipType.CAN_TAKE_OVER),
            # What an eligible role would give, drawn for the access view and
            # not walked: activating it is a step CloudGuard cannot see into.
            (ELIGIBLE_POWERS, RelationshipType.ELIGIBLE_FOR, RelationshipType.ELIGIBLE_FOR),
        ):
            held = {entry["power"] for entry in powers_of(node, key)}
            if ACT_AS_ANY_APPLICATION in held:
                for principal in sorted(principals - {node_id}):
                    yield (node_id, act_as, principal)
            if CONTROL_ALL_SCOPES in held:
                for subscription in subscriptions:
                    yield (node_id, take_over, subscription)


def directory_reason(source: CloudResource, relationship: RelationshipType) -> str | None:
    """Why the directory lets ``source`` cross a derived edge, in a phrase.

    Named for what somebody removes: the directory role, the ownership, or the
    registration's own credential. None for an edge the directory did not draw.
    """
    if relationship is RelationshipType.CAN_TAKE_OVER:
        roles = [p["via"] for p in powers_of(source) if p["power"] == CONTROL_ALL_SCOPES]
        return ", ".join(dict.fromkeys(roles)) or None
    if relationship is not RelationshipType.CAN_ACT_AS:
        return None
    if source.metadata.get(ACTS_AS):
        return "its own credentials"
    roles = [p["via"] for p in powers_of(source) if p["power"] == ACT_AS_ANY_APPLICATION]
    if roles:
        return ", ".join(dict.fromkeys(roles))
    return "owner of its application registration"


def powers_of(node: CloudResource, key: str = POWERS) -> list[dict[str, str]]:
    """An identity's directory powers -- or, with ``ELIGIBLE_POWERS``, the ones
    it could activate -- as ``{"power", "via"}``."""
    recorded = node.metadata.get(key)
    if not isinstance(recorded, list):
        return []
    return [
        {"power": str(entry["power"]), "via": str(entry.get("via") or "")}
        for entry in recorded
        if isinstance(entry, Mapping) and entry.get("power")
    ]


def members_of(group: CloudResource) -> list[dict[str, str]]:
    """A group's recorded members, as ``{"id", "kind", "name"}``; empty when
    none were recorded or the list was not read."""
    recorded = group.metadata.get(MEMBERS)
    if not isinstance(recorded, list):
        return []
    return [
        {
            "id": str(member["id"]),
            "kind": str(member.get("kind") or ""),
            "name": str(member.get("name") or ""),
        }
        for member in recorded
        if isinstance(member, Mapping) and member.get("id")
    ]


def _roles(resource: CloudResource) -> list[Any]:
    held = resource.metadata.get(ROLES)
    return list(held) if isinstance(held, list) else []


def _with_roles(resource: CloudResource, extra: list[Any]) -> CloudResource:
    """The resource with ``extra`` roles appended, repeats dropped.

    A copy, never a mutation: the same object may be a scan's normalized state
    or a cached row, and neither may change because a graph was built from it.
    """
    if not extra:
        return resource
    held = _roles(resource)
    keys = {_role_key(entry) for entry in held}
    for entry in extra:
        key = _role_key(entry)
        if key not in keys:
            keys.add(key)
            held.append(entry)
    return replace(resource, metadata={**resource.metadata, ROLES: held})


def _role_key(entry: Any) -> tuple[str, ...]:
    if not isinstance(entry, Mapping):
        return (repr(entry),)
    return (
        str(entry.get("role") or ""),
        str(entry.get("target") or entry.get("scope") or "").lower(),
        str(entry.get("inherited_from") or ""),
        str(entry.get("conditional") or ""),
    )
