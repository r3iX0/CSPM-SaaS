"""What a role assignment actually lets its holder reach, and who holds what.

Two things, both read off the same per-role answer the connector writes
(``connectors/azure/access.py``) and both neutral.

**The lens a role edge is walked with.** A ``GRANTS_ROLE`` edge lands on a
scope, and the traversal descends from the scope through ``CONTAINS``. It used
to descend as though the holder controlled everything underneath, which made
Reader over a subscription a route to every sensitive asset in it. Now the edge
carries a :class:`Lens`: the resource types the holder's roles at that scope
actually control. The walk still descends through the scope -- a resource group
is where the reach lands -- but an asset under it is *reached* only when the
lens controls it, and only a reached asset is walked on from. A machine is
reached by a role that runs code on it, a storage account by one that reads its
data; neither is reached by one that reads its configuration.

**Who holds access to an asset, and what an identity holds.** The question the
route list cannot answer, because a route needs a way in: an administrator with
Owner over the subscription is on no route until something exposed runs as
them, and is still the first thing a person asks about when they open the
payments ledger. :func:`holders` answers it from the asset's side, walking up
its containers; :func:`grants` from the identity's.

**Nothing inferred from absence.** A role whose definition was not read
reaches nothing and is listed as unread. A role recorded before this analysis
existed -- stored metadata with no ``access`` key -- is walked as it always
was, because a stored scan must not lose its routes to a deploy; the next scan
replaces it with a verdict (DECISIONS.md section 125).
"""

from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any

from app.core.enums import AccessKind, RelationshipType, ResourceType
from app.domain.resource import CloudResource
from app.graph.identity import (
    ACT_AS_ANY_APPLICATION,
    CONTROL_ALL_SCOPES,
    ELIGIBLE_POWERS,
    ELIGIBLE_ROLES,
    IDENTITY_ID,
    MEMBERS,
    directory_reason,
    members_of,
    powers_of,
)

#: Metadata a normalizer writes on a principal: a list of role entries, each
#: ``{"role", "scope", "target", "inherited_from", "conditional",
#: "grants_role_assignment", "access"}``. ``access`` maps a ResourceType value
#: to a list of AccessKind values, or is None for a definition never read.
ROLES = "roles"

#: Metadata on a resource whose own access list decides who reads it -- a vault
#: on access policies. True, False, or absent when the resource did not say.
GOVERNED_BY_OWN_POLICY = "governed_by_own_policy"

#: The containers a role can be assigned at. Reaching one is where a role's
#: reach lands, not a thing it controls.
SCOPES = frozenset({ResourceType.SUBSCRIPTION, ResourceType.RESOURCE_GROUP})

# The kinds a lens carries: the ones that can make an asset reached.
_CONTROLLING = frozenset({AccessKind.READ_DATA, AccessKind.EXECUTE, AccessKind.EDIT_POLICY})


@dataclass(frozen=True)
class Lens:
    """What a walk arriving through one role edge controls below it.

    ``everything`` for an edge that controls whatever it lands on: a principal
    that can grant itself roles, and a role recorded before its access was
    evaluated. Otherwise the (type, kind) pairs its roles grant that amount to
    control.
    """

    everything: bool = False
    grants: frozenset[tuple[ResourceType, AccessKind]] = frozenset()

    @property
    def empty(self) -> bool:
        return not self.everything and not self.grants

    def controls(self, resource: CloudResource) -> bool:
        """Whether a holder arriving with this lens holds what this asset holds."""
        if self.everything:
            return True
        kind = resource.resource_type
        if (kind, AccessKind.READ_DATA) in self.grants or (kind, AccessKind.EXECUTE) in self.grants:
            return True
        return (kind, AccessKind.EDIT_POLICY) in self.grants and _governed_by_own_policy(
            resource
        )


EVERYTHING = Lens(everything=True)
NOTHING = Lens()


def _governed_by_own_policy(resource: CloudResource) -> bool:
    return resource.metadata.get(GOVERNED_BY_OWN_POLICY) is True


def role_entries(
    principal: CloudResource, target: str, key: str = ROLES
) -> list[Mapping[str, Any]]:
    """The role entries a principal holds at one node, matched case-insensitively.

    ``target`` is where the edge was drawn; an entry written before the
    normalizer recorded it is matched on its scope, which was the same thing
    for every assignment it drew an edge for. ``key`` reads the roles it could
    activate instead (``eligible_roles``, section 130).
    """
    held = principal.metadata.get(key)
    if not isinstance(held, list):
        return []
    wanted = target.lower()
    return [
        entry
        for entry in held
        if isinstance(entry, Mapping)
        and str(entry.get("target") or entry.get("scope") or "").lower() == wanted
    ]


def lens_for(
    principal: CloudResource, relationship: RelationshipType, target: str
) -> Lens:
    """The lens a walk takes across one role edge.

    Every role the principal holds at the target contributes, because the edge
    is the principal's access there and removing it removes all of them. An
    escalation edge controls everything: the holder can grant itself the rest.
    """
    if relationship in {RelationshipType.CAN_GRANT_ROLES, RelationshipType.CAN_TAKE_OVER}:
        return EVERYTHING
    entries = role_entries(principal, target)
    if not entries:
        # An edge with no entry behind it was drawn by something that never
        # recorded roles. Walked as edges always were, rather than silently
        # dropped: the gap is in the recording, not in the estate.
        return EVERYTHING
    grants: set[tuple[ResourceType, AccessKind]] = set()
    for entry in entries:
        if "access" not in entry:
            return EVERYTHING
        grants.update(control_pairs(entry.get("access")))
    return Lens(grants=frozenset(grants))


def control_pairs(access: Any) -> Iterable[tuple[ResourceType, AccessKind]]:
    """The (type, kind) pairs in an ``access`` value that can make an asset reached."""
    for resource_type, kind in _pairs(access):
        if kind in _CONTROLLING:
            yield resource_type, kind


def _pairs(access: Any) -> Iterable[tuple[ResourceType, AccessKind]]:
    """Every (type, kind) an ``access`` value states, skipping what is not one."""
    if not isinstance(access, Mapping):
        return
    for type_value, kinds in access.items():
        try:
            resource_type = ResourceType(type_value)
        except ValueError:
            continue
        for kind_value in kinds if isinstance(kinds, list) else ():
            try:
                yield resource_type, AccessKind(kind_value)
            except ValueError:
                continue


# ------------------------------------------------------------------ the views


@dataclass(frozen=True)
class AccessHolder:
    """One role one principal holds that reaches one asset."""

    principal: CloudResource
    role: str
    #: The node the assignment applies at: the asset itself or a container of it.
    at: CloudResource
    #: The management group or root it was actually made at, when above ``at``.
    inherited_from: str | None
    #: What the role lets the principal do to the asset asked about. Empty for
    #: a container, which is a scope rather than a thing with contents.
    kinds: tuple[AccessKind, ...]
    #: Whether the principal holds what the asset holds.
    controls: bool
    conditional: bool
    #: False when the role's definition was not read, or was recorded before
    #: CloudGuard evaluated definitions: nothing about it is known.
    resolved: bool
    #: Workloads that run as the principal, which is how most identities are
    #: taken -- and so what reaches the asset through this role.
    runs_on: tuple[CloudResource, ...] = field(default=())
    #: For a group: the members the graph holds a node for, and the names of
    #: those it does not (read, but never read as accounts). None for anything
    #: that is not a group, and for a group whose membership was not read.
    members: tuple[CloudResource, ...] | None = None
    unlisted_members: tuple[str, ...] = ()
    #: Held through the directory rather than an Azure role assignment: a
    #: directory role that takes over subscriptions, or the ability to sign in
    #: as the identity asked about (section 128).
    through_directory: bool = False
    #: Could be activated under PIM rather than held. ``kinds`` says what
    #: activating it would give; ``controls`` is False, because nothing is
    #: held until it is activated (section 130).
    eligible: bool = False


@dataclass(frozen=True)
class AccessGrant:
    """One role an identity holds, and what it amounts to."""

    role: str
    at: CloudResource | None
    #: The scope exactly as the assignment names it.
    scope: str
    inherited_from: str | None
    conditional: bool
    resolved: bool
    grants_access: bool
    #: Resource types the role acts on, and what it does to each.
    access: tuple[tuple[ResourceType, tuple[AccessKind, ...]], ...]
    #: Assets under ``at`` (``at`` included) this one role controls.
    controlled: tuple[CloudResource, ...]
    #: The group the identity holds this role through, when not its own --
    #: or the identity it can sign in as.
    via: CloudResource | None = None
    through_directory: bool = False
    eligible: bool = False


def _kinds(access: Any, resource_type: ResourceType) -> tuple[AccessKind, ...]:
    return tuple(
        sorted({kind for kind_type, kind in _pairs(access) if kind_type is resource_type})
    )


def _controls(
    entry: Mapping[str, Any], resource: CloudResource, kinds: tuple[AccessKind, ...]
) -> bool:
    if entry.get("grants_role_assignment"):
        return True
    if AccessKind.READ_DATA in kinds or AccessKind.EXECUTE in kinds:
        return True
    return AccessKind.EDIT_POLICY in kinds and _governed_by_own_policy(resource)


def _holder_order(holder: AccessHolder) -> tuple[bool, bool, bool, bool, str, str]:
    return (
        not holder.controls,
        holder.eligible,
        AccessKind.MANAGE not in holder.kinds,
        not holder.resolved,
        holder.principal.name.lower(),
        holder.role.lower(),
    )


def holders(
    nodes: Mapping[str, CloudResource],
    incoming: Mapping[str, list[tuple[RelationshipType, str]]],
    resource_id: str,
) -> list[AccessHolder]:
    """Every role that reaches this asset, directly or from a container above it.

    Walks up ``CONTAINS`` from the asset, and at each level reads the role
    edges landing there. Holders that control the asset first, then those that
    can change it, then those that only read it, then the roles nobody could
    read: the order a person looking for "who could take this" reads in.
    """
    focus = nodes.get(resource_id)
    if focus is None:
        return []

    chain: list[str] = [resource_id]
    seen = {resource_id}
    queue: deque[str] = deque([resource_id])
    while queue:
        current = queue.popleft()
        for relationship, parent in incoming.get(current, []):
            if relationship is RelationshipType.CONTAINS and parent not in seen:
                seen.add(parent)
                chain.append(parent)
                queue.append(parent)

    found: list[AccessHolder] = []
    for level in chain:
        principals = sorted(
            {
                source
                for relationship, source in incoming.get(level, [])
                if relationship is RelationshipType.GRANTS_ROLE and source in nodes
            }
        )
        for principal_id in principals:
            principal = nodes[principal_id]
            runs_on = tuple(
                sorted(
                    (
                        nodes[source]
                        for relationship, source in incoming.get(principal_id, [])
                        if relationship is RelationshipType.HAS_IDENTITY and source in nodes
                    ),
                    key=lambda workload: workload.name.lower(),
                )
            )
            # An edge with no role recorded behind it -- drawn by a connector
            # that never wrote roles, or stored before it did -- is still a
            # holder, of a role nobody can name.
            entries = role_entries(principal, level) or [{"role": "Unknown role"}]
            members, unlisted = _members(nodes, incoming, principal)
            for entry in entries:
                access = entry.get("access")
                resolved = "access" in entry and access is not None
                kinds = (
                    () if focus.resource_type in SCOPES else _kinds(access, focus.resource_type)
                )
                if entry.get("grants_role_assignment"):
                    kinds = (*kinds, AccessKind.GRANT_ACCESS)
                found.append(
                    AccessHolder(
                        principal=principal,
                        role=str(entry.get("role") or "Unknown role"),
                        at=nodes[level],
                        inherited_from=_optional(entry.get("inherited_from")),
                        kinds=kinds,
                        controls=focus.resource_type not in SCOPES
                        and resolved
                        and _controls(entry, focus, kinds),
                        conditional=bool(entry.get("conditional")),
                        resolved=resolved,
                        runs_on=runs_on,
                        members=members,
                        unlisted_members=unlisted,
                    )
                )
    found.extend(_directory_holders(nodes, incoming, focus, chain))
    found.extend(_eligible_holders(nodes, incoming, focus, chain))
    return sorted(found, key=_holder_order)


def _eligible_holders(
    nodes: Mapping[str, CloudResource],
    incoming: Mapping[str, list[tuple[RelationshipType, str]]],
    focus: CloudResource,
    chain: list[str],
) -> list[AccessHolder]:
    """Who could activate a role that reaches this asset (section 130).

    An Azure role eligible at the asset or a container above it, and a
    directory role eligible to take over its subscription or, on a principal,
    to sign in as it. Listed with what activating would give, and never as
    control: nothing is held until the role is activated.
    """
    found: list[AccessHolder] = []
    for level in chain:
        for kind, source in sorted(incoming.get(level, []), key=lambda e: e[1]):
            if kind is not RelationshipType.ELIGIBLE_FOR or source not in nodes:
                continue
            principal = nodes[source]
            entries = role_entries(principal, level, ELIGIBLE_ROLES)
            for entry in entries:
                access = entry.get("access")
                kinds = (
                    () if focus.resource_type in SCOPES else _kinds(access, focus.resource_type)
                )
                if entry.get("grants_role_assignment"):
                    kinds = (*kinds, AccessKind.GRANT_ACCESS)
                found.append(
                    AccessHolder(
                        principal=principal,
                        role=str(entry.get("role") or "Unknown role"),
                        at=nodes[level],
                        inherited_from=_optional(entry.get("inherited_from")),
                        kinds=kinds,
                        controls=False,
                        conditional=bool(entry.get("conditional")),
                        resolved=access is not None,
                        eligible=True,
                    )
                )
            if entries:
                continue
            # No Azure eligibility here, so a directory role drew this edge.
            wanted = (
                CONTROL_ALL_SCOPES
                if nodes[level].resource_type is ResourceType.SUBSCRIPTION
                else ACT_AS_ANY_APPLICATION
                if level == focus.provider_resource_id
                else None
            )
            vias = [
                power["via"]
                for power in powers_of(principal, ELIGIBLE_POWERS)
                if power["power"] == wanted
            ]
            if vias:
                found.append(
                    AccessHolder(
                        principal=principal,
                        role=", ".join(dict.fromkeys(vias)),
                        at=nodes[level],
                        inherited_from=None,
                        kinds=(AccessKind.GRANT_ACCESS,)
                        if wanted == CONTROL_ALL_SCOPES
                        else (AccessKind.ACT_AS,),
                        controls=False,
                        conditional=False,
                        resolved=True,
                        through_directory=True,
                        eligible=True,
                    )
                )
    return found


def _directory_holders(
    nodes: Mapping[str, CloudResource],
    incoming: Mapping[str, list[tuple[RelationshipType, str]]],
    focus: CloudResource,
    chain: list[str],
) -> list[AccessHolder]:
    """Who the directory lets take this asset, or sign in as it.

    A directory role that takes over every subscription holds everything in
    them, and an application's owner holds its service principal -- neither by
    an Azure role assignment, so neither was on this list (section 128).
    """
    found: list[AccessHolder] = []
    wanted = {
        # Taking over lands on a subscription: the asset's own, or itself.
        RelationshipType.CAN_TAKE_OVER: [
            level for level in chain if nodes[level].resource_type is ResourceType.SUBSCRIPTION
        ],
        RelationshipType.CAN_ACT_AS: [focus.provider_resource_id],
    }
    for relationship, levels in wanted.items():
        for level in levels:
            for kind, source in sorted(incoming.get(level, []), key=lambda e: e[1]):
                if kind is not relationship or source not in nodes:
                    continue
                holder = nodes[source]
                taking_over = relationship is RelationshipType.CAN_TAKE_OVER
                found.append(
                    AccessHolder(
                        principal=holder,
                        role=directory_reason(holder, relationship) or relationship.value,
                        at=nodes[level],
                        inherited_from=None,
                        kinds=(AccessKind.GRANT_ACCESS,) if taking_over else (AccessKind.ACT_AS,),
                        controls=focus.resource_type not in SCOPES,
                        conditional=False,
                        resolved=True,
                        through_directory=True,
                    )
                )
    return found


def _members(
    nodes: Mapping[str, CloudResource],
    incoming: Mapping[str, list[tuple[RelationshipType, str]]],
    principal: CloudResource,
) -> tuple[tuple[CloudResource, ...] | None, tuple[str, ...]]:
    """Who a group's role reaches: the members drawn in the graph, then the
    names of the ones read only as names."""
    if principal.resource_type is not ResourceType.GROUP:
        return None, ()
    if not isinstance(principal.metadata.get(MEMBERS), list):
        return None, ()
    drawn = sorted(
        (
            nodes[source]
            for relationship, source in incoming.get(principal.provider_resource_id, [])
            if relationship is RelationshipType.MEMBER_OF and source in nodes
        ),
        key=lambda member: member.name.lower(),
    )
    drawn_ids = {
        str(member.metadata.get(IDENTITY_ID) or "").lower() for member in drawn
    }
    unlisted = sorted(
        member["name"] or member["id"]
        for member in members_of(principal)
        if member["id"].lower() not in drawn_ids
        and member["kind"] != ResourceType.GROUP.value
    )
    return tuple(drawn), tuple(unlisted)


def grants(
    nodes: Mapping[str, CloudResource],
    outgoing: Mapping[str, list[tuple[RelationshipType, str]]],
    principal_id: str,
) -> list[AccessGrant]:
    """Every role this identity holds, and what each amounts to.

    Per role rather than per scope, because a role is what somebody removes;
    the assets it controls are counted under it, containers excluded, so
    "Contributor over sub-prod" arrives with the forty assets it is actually
    Contributor *of*.
    """
    principal = nodes.get(principal_id)
    if principal is None:
        return []

    # Its own roles, then every group's it is in -- a role held through a group
    # is held all the same, and removing the person from the group is a fix.
    sources: list[tuple[CloudResource | None, list[Any]]] = [
        (None, _held(principal))
    ]
    for relationship, other in outgoing.get(principal_id, []):
        # Through a group it is in, or an identity it can sign in as: either
        # way the role is held, and the membership or the sign-in is a fix.
        if (
            relationship in {RelationshipType.MEMBER_OF, RelationshipType.CAN_ACT_AS}
            and other in nodes
        ):
            sources.append((nodes[other], _held(nodes[other])))

    found = [
        _grant(nodes, outgoing, entry, via)
        for via, held in sources
        for entry in held
        if isinstance(entry, Mapping)
    ]
    # Roles it could activate under PIM, Azure and directory alike (section 130).
    eligible = principal.metadata.get(ELIGIBLE_ROLES)
    found.extend(
        replace(_grant(nodes, outgoing, entry, None), eligible=True)
        for entry in (eligible if isinstance(eligible, list) else [])
        if isinstance(entry, Mapping)
    )
    take_over = [
        power["via"]
        for power in powers_of(principal, ELIGIBLE_POWERS)
        if power["power"] == CONTROL_ALL_SCOPES
    ]
    for relationship, subscription in outgoing.get(principal_id, []):
        if (
            take_over
            and relationship is RelationshipType.ELIGIBLE_FOR
            and subscription in nodes
            and nodes[subscription].resource_type is ResourceType.SUBSCRIPTION
            and not role_entries(principal, subscription, ELIGIBLE_ROLES)
        ):
            at = nodes[subscription]
            found.append(
                AccessGrant(
                    role=", ".join(dict.fromkeys(take_over)),
                    at=at,
                    scope=at.provider_resource_id,
                    inherited_from=None,
                    conditional=False,
                    resolved=True,
                    grants_access=True,
                    access=(),
                    controlled=tuple(
                        resource
                        for resource in _under(nodes, outgoing, subscription)
                        if resource.resource_type not in SCOPES
                    ),
                    through_directory=True,
                    eligible=True,
                )
            )
    # A directory role that can make the identity owner of each subscription.
    for relationship, subscription in outgoing.get(principal_id, []):
        if relationship is RelationshipType.CAN_TAKE_OVER and subscription in nodes:
            at = nodes[subscription]
            found.append(
                AccessGrant(
                    role=directory_reason(principal, relationship) or relationship.value,
                    at=at,
                    scope=at.provider_resource_id,
                    inherited_from=None,
                    conditional=False,
                    resolved=True,
                    grants_access=True,
                    access=(),
                    controlled=tuple(
                        resource
                        for resource in _under(nodes, outgoing, subscription)
                        if resource.resource_type not in SCOPES
                    ),
                    through_directory=True,
                )
            )
    return sorted(
        found,
        key=lambda grant: (
            not grant.grants_access,
            -len(grant.controlled),
            not grant.resolved,
            grant.role.lower(),
            grant.scope.lower(),
        ),
    )


def _held(principal: CloudResource) -> list[Any]:
    held = principal.metadata.get(ROLES)
    return held if isinstance(held, list) else []


def _grant(
    nodes: Mapping[str, CloudResource],
    outgoing: Mapping[str, list[tuple[RelationshipType, str]]],
    entry: Mapping[str, Any],
    via: CloudResource | None,
) -> AccessGrant:
    target = _optional(entry.get("target"))
    at = nodes.get(target) if target else None
    access = entry.get("access")
    resolved = "access" in entry and access is not None
    by_type: dict[ResourceType, set[AccessKind]] = {}
    for resource_type, kind in _pairs(access):
        by_type.setdefault(resource_type, set()).add(kind)

    controlled: tuple[CloudResource, ...] = ()
    if at is not None and resolved:
        lens = Lens(
            everything=bool(entry.get("grants_role_assignment")),
            grants=frozenset(control_pairs(access)),
        )
        controlled = tuple(
            resource
            for resource in _under(nodes, outgoing, at.provider_resource_id)
            if resource.resource_type not in SCOPES and lens.controls(resource)
        )

    return AccessGrant(
        role=str(entry.get("role") or "Unknown role"),
        at=at,
        scope=str(entry.get("scope") or ""),
        inherited_from=_optional(entry.get("inherited_from")),
        conditional=bool(entry.get("conditional")),
        resolved=resolved,
        grants_access=bool(entry.get("grants_role_assignment")),
        access=tuple(
            (resource_type, tuple(sorted(kinds)))
            for resource_type, kinds in sorted(by_type.items(), key=lambda item: item[0].value)
        ),
        controlled=controlled,
        via=via,
    )


def _under(
    nodes: Mapping[str, CloudResource],
    outgoing: Mapping[str, list[tuple[RelationshipType, str]]],
    root: str,
) -> list[CloudResource]:
    """The node and everything contained beneath it."""
    found = [nodes[root]]
    seen = {root}
    queue: deque[str] = deque([root])
    while queue:
        current = queue.popleft()
        for relationship, child in outgoing.get(current, []):
            if relationship is RelationshipType.CONTAINS and child not in seen and child in nodes:
                seen.add(child)
                found.append(nodes[child])
                queue.append(child)
    return found


def _optional(value: Any) -> str | None:
    return str(value) if isinstance(value, str) and value else None
