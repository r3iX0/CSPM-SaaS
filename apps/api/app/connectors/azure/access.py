"""What an Azure role lets its holder do, per kind of resource.

The graph used to know one thing about a role assignment: that it exists. A
principal holding Reader over a subscription and one holding Owner over it drew
the same edge, and the traversal walked both down into every storage account
underneath -- so a monitoring identity with Reader was an attack path to the
payments ledger, and a machine running as Storage Blob Data Reader "reached"
every virtual machine in its group, and through them every identity those
machines run as. Neither is true. Reader cannot read a blob; a blob reader
cannot run anything on a machine.

This reads the role definition's own actions and says what they amount to for
each neutral resource type, in :class:`~app.core.enums.AccessKind` terms. The
graph reads only that answer, so the provider's vocabulary stops here
(DECISIONS.md section 125).

**Evaluated, not named.** A role is judged by its permission blocks -- actions
less not-actions, data actions less not-data-actions, wildcards matched the way
ARM matches them -- never by its name. Owner and Contributor both say
``actions: ["*"]``; Storage Blob Data Reader says nothing in ``actions`` that
reaches data and everything it grants is in ``dataActions``; a tenant's custom
role is invisible to any list of well-known names and is exactly the thing
worth reading.

**The strings below are matched, never deployed.** Unlike ``rbac.py``, nothing
here reaches ARM: an action that is not a real operation cannot fail a
customer's deployment. It can still make this silently wrong -- a misspelled
action matches nothing, and a role that grants it reads as granting less than
it does -- so each is a documented operation, and the tests hold the built-in
roles to what Microsoft documents them as doing.

**A condition narrows what CloudGuard can claim.** Azure ABAC conditions are
evaluated on data actions (and on role-assignment writes), against request
attributes CloudGuard never sees. An assignment carrying one keeps the control
actions it grants -- conditions do not apply there -- and loses every kind it
would have had only through a data action, because the condition may well be
the thing that stops it. What cannot be established is not claimed, the same
rule that keeps UNKNOWN from reading as PASS, pointed at reach.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from app.connectors.azure.rbac import action_matches
from app.core.enums import AccessKind, ResourceType


@dataclass(frozen=True)
class Requirement:
    """The operations that amount to one kind of access over one type.

    Any one of them suffices. ``control`` are ARM management operations,
    checked against ``actions``/``notActions``; ``data`` are data-plane
    operations, checked against ``dataActions``/``notDataActions``.
    """

    control: tuple[str, ...] = ()
    data: tuple[str, ...] = ()


def _config(namespace: str) -> dict[AccessKind, Requirement]:
    """Read and change a resource's configuration, and nothing more."""
    return {
        AccessKind.READ: Requirement(control=(f"{namespace}/read",)),
        AccessKind.MANAGE: Requirement(control=(f"{namespace}/write",)),
    }


_STORAGE = "Microsoft.Storage/storageAccounts"
_VAULT = "Microsoft.KeyVault/vaults"
_SQL = "Microsoft.Sql/servers"
_POSTGRES_FLEXIBLE = "Microsoft.DBforPostgreSQL/flexibleServers"
_POSTGRES_SINGLE = "Microsoft.DBforPostgreSQL/servers"
_VM = "Microsoft.Compute/virtualMachines"
_SITE = "Microsoft.Web/sites"

REQUIREMENTS: Mapping[ResourceType, Mapping[AccessKind, Requirement]] = {
    ResourceType.STORAGE_ACCOUNT: {
        **_config(_STORAGE),
        AccessKind.READ_DATA: Requirement(
            # The account keys open every container, share, queue and table,
            # whatever the data-plane roles say. An account with shared-key
            # access switched off is no defence against this holder: the same
            # ``write`` that comes with ``*`` switches it back on.
            control=(f"{_STORAGE}/listKeys/action",),
            data=(
                f"{_STORAGE}/blobServices/containers/blobs/read",
                f"{_STORAGE}/fileServices/fileshares/files/read",
                f"{_STORAGE}/queueServices/queues/messages/read",
                f"{_STORAGE}/tableServices/tables/entities/read",
            ),
        ),
    },
    ResourceType.KEY_VAULT: {
        **_config(_VAULT),
        AccessKind.READ_DATA: Requirement(data=(f"{_VAULT}/secrets/getSecret/action",)),
        # Only control over a vault that uses access policies -- which the
        # normalizer states per vault, because a role cannot know which model
        # the vault it lands on uses.
        AccessKind.EDIT_POLICY: Requirement(control=(f"{_VAULT}/accessPolicies/write",)),
    },
    ResourceType.SQL_SERVER: {
        **_config(_SQL),
        # Writing the server resets its administrator password; writing its
        # Entra administrator makes the holder one. Either is every database
        # on it.
        AccessKind.READ_DATA: Requirement(
            control=(f"{_SQL}/write", f"{_SQL}/administrators/write")
        ),
    },
    ResourceType.SQL_DATABASE: {
        **_config(f"{_SQL}/databases"),
        AccessKind.READ_DATA: Requirement(control=(f"{_SQL}/databases/export/action",)),
    },
    ResourceType.POSTGRESQL_SERVER: {
        AccessKind.READ: Requirement(
            control=(f"{_POSTGRES_FLEXIBLE}/read", f"{_POSTGRES_SINGLE}/read")
        ),
        AccessKind.MANAGE: Requirement(
            control=(f"{_POSTGRES_FLEXIBLE}/write", f"{_POSTGRES_SINGLE}/write")
        ),
        # The administrator password is part of the server's own resource.
        AccessKind.READ_DATA: Requirement(
            control=(
                f"{_POSTGRES_FLEXIBLE}/write",
                f"{_POSTGRES_SINGLE}/write",
                f"{_POSTGRES_FLEXIBLE}/administrators/write",
            )
        ),
    },
    ResourceType.VIRTUAL_MACHINE: {
        **_config(_VM),
        AccessKind.EXECUTE: Requirement(
            control=(
                f"{_VM}/runCommand/action",
                f"{_VM}/runCommands/write",
                f"{_VM}/extensions/write",
            )
        ),
    },
    ResourceType.APP_SERVICE: {
        **_config(_SITE),
        # Writing the site sets what it runs -- the image, the package URL,
        # the startup command -- and the publishing profile and credentials
        # are a deployment by another name.
        AccessKind.EXECUTE: Requirement(
            control=(
                f"{_SITE}/write",
                f"{_SITE}/publishxml/action",
                f"{_SITE}/config/list/action",
            )
        ),
    },
    ResourceType.NETWORK_SECURITY_GROUP: _config("Microsoft.Network/networkSecurityGroups"),
    ResourceType.VIRTUAL_NETWORK: _config("Microsoft.Network/virtualNetworks"),
    ResourceType.SUBNET: _config("Microsoft.Network/virtualNetworks/subnets"),
    ResourceType.NETWORK_INTERFACE: _config("Microsoft.Network/networkInterfaces"),
    ResourceType.PUBLIC_IP: _config("Microsoft.Network/publicIPAddresses"),
}


@dataclass(frozen=True)
class _Block:
    """One permission block of a role definition, as ARM evaluates it."""

    actions: tuple[str, ...]
    not_actions: tuple[str, ...]
    data_actions: tuple[str, ...]
    not_data_actions: tuple[str, ...]

    def allows_control(self, action: str) -> bool:
        return _any_match(self.actions, action) and not _any_match(self.not_actions, action)

    def allows_data(self, action: str) -> bool:
        return _any_match(self.data_actions, action) and not _any_match(
            self.not_data_actions, action
        )


def _any_match(patterns: Iterable[str], action: str) -> bool:
    return any(action_matches(pattern, action) for pattern in patterns)


def _strings(value: Any) -> tuple[str, ...]:
    return tuple(str(item) for item in (value or []) if item)


def _blocks(definition: Mapping[str, Any]) -> list[_Block]:
    """The definition's permission blocks.

    Each is evaluated on its own: a not-action removes an action only within
    the block that states it, and a definition's grant is the union of its
    blocks. Built-in roles have one block; the distinction matters for a custom
    role written with several.
    """
    properties = definition.get("properties") or {}
    return [
        _Block(
            actions=_strings(block.get("actions")),
            not_actions=_strings(block.get("notActions")),
            data_actions=_strings(block.get("dataActions")),
            not_data_actions=_strings(block.get("notDataActions")),
        )
        for block in (properties.get("permissions") or [])
        if isinstance(block, Mapping)
    ]


def access_profile(
    definition: Mapping[str, Any] | None, *, conditional: bool = False
) -> dict[str, list[str]] | None:
    """What this role lets its holder do, per resource type.

    Keyed by :class:`ResourceType` value, each a sorted list of
    :class:`AccessKind` values; a type the role grants nothing over is absent.
    ``None`` when the definition was not read -- not ``{}``, which is the
    answer "this role was read and grants nothing", and the two must not be
    confused downstream: the first is a gap, the second a verdict.

    ``conditional`` drops whatever was granted only through a data action (see
    the module docstring).
    """
    if not definition:
        return None
    blocks = _blocks(definition)

    profile: dict[str, list[str]] = {}
    for resource_type, kinds in REQUIREMENTS.items():
        granted = sorted(
            kind.value
            for kind, requirement in kinds.items()
            if _satisfied(requirement, blocks, conditional=conditional)
        )
        if granted:
            profile[resource_type.value] = granted
    return profile


def _satisfied(requirement: Requirement, blocks: list[_Block], *, conditional: bool) -> bool:
    for block in blocks:
        if any(block.allows_control(action) for action in requirement.control):
            return True
        if not conditional and any(block.allows_data(action) for action in requirement.data):
            return True
    return False
