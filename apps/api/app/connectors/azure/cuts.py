"""How to make a cut in Azure, as commands (DECISIONS.md section 246).

A cut is a link on the attack-path page: a role assignment, a group membership,
a managed identity, a network path. The page says each one in neutral words; the
command that removes it is Azure's own, so it lives here, behind the connector,
and the neutral half asks for it without knowing which cloud it is holding
(``CloudConnector.cut_commands``).

Only where the link names exactly one thing to remove. A role edge names the
principal, the scope and the roles it holds there, read off the principal's own
record of each assignment, so ``az role assignment delete`` can be written
exactly. A group membership names the group and the member. Everything else --
detaching a managed identity, closing a network path -- has more than one right
way to do it, and a command that guessed would be worse than none: those links
are answered with the findings on their two ends instead.
"""

import shlex
from collections.abc import Mapping
from typing import Any

from app.core.enums import RelationshipType
from app.domain.resource import CloudResource
from app.graph.access import role_entries


def cut_commands(
    source: CloudResource, relationship: RelationshipType, target: CloudResource
) -> list[str]:
    """The ``az`` commands that remove this link, or none where no one command does."""
    if relationship in {RelationshipType.GRANTS_ROLE, RelationshipType.CAN_GRANT_ROLES}:
        return _role_assignment_deletes(source, target)
    if relationship is RelationshipType.MEMBER_OF:
        return _group_member_remove(source, target)
    return []


def _object_id(principal: CloudResource) -> str | None:
    """The principal's object id in Entra, which every command names it by."""
    for key in ("principal_id", "identity_id"):
        value = principal.metadata.get(key)
        if isinstance(value, str) and value:
            return value
    return None


def _role_assignment_deletes(principal: CloudResource, scope: CloudResource) -> list[str]:
    """One delete per role the principal holds at this scope.

    Every role counts, because the edge is the principal's whole access there
    and the walk crossed it with all of them (``graph/access.lens_for``). An
    assignment inherited from a management group is deleted at that management
    group, where it was made, which removes it from every subscription beneath:
    the command says so by naming the scope it acts on.
    """
    assignee = _object_id(principal)
    if assignee is None:
        return []
    commands: list[str] = []
    for entry in role_entries(principal, scope.provider_resource_id):
        command = _role_delete(assignee, entry)
        if command and command not in commands:
            commands.append(command)
    return commands


def _role_delete(assignee: str, entry: Mapping[str, Any]) -> str | None:
    role = entry.get("role")
    where = entry.get("scope")
    if not isinstance(role, str) or not role or role == "Unknown role":
        return None
    if not isinstance(where, str) or not where:
        return None
    return (
        f"az role assignment delete --assignee {shlex.quote(assignee)} "
        f"--role {shlex.quote(role)} --scope {shlex.quote(where)}"
    )


def _group_member_remove(member: CloudResource, group: CloudResource) -> list[str]:
    member_id, group_id = _object_id(member), _object_id(group)
    if member_id is None or group_id is None:
        return []
    return [
        f"az ad group member remove --group {shlex.quote(group_id)} "
        f"--member-id {shlex.quote(member_id)}"
    ]
