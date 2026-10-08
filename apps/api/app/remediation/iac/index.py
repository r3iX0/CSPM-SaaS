"""What the customer's own Terraform state says each asset is (DECISIONS.md §229).

A GitHub Action in the customer's pipeline reads ``terraform show -json`` and
uploads, for each managed azurerm resource whose ``id`` is an Azure Resource
Manager id, four fields: its state ``address``, its ``type``, its instance
``index`` and that ``id``. The id is the asset's own id, so an asset is matched
to the block that defines it exactly, through variables, ``count``, ``for_each``
and local modules, where a literal-name search reaches about 1% of blocks (§190).

Nothing else is accepted: state carries every attribute in plain text, secrets
included, and the Action drops the rest on the runner. This module checks that
what arrived is only that, and reads an address into the parts that find its
block.
"""

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

#: What fits the 1 MiB request limit at about 250 bytes an entry. A root managing
#: more is uploaded per workspace or split, rather than the limit raised for it.
MAX_ENTRIES = 4_000

# The Action keeps only ids under a subscription: a key vault secret's id is a
# URL naming the secret, and nothing else is an asset Cleave reads.
_ARM_ID = re.compile(r"^/subscriptions/[0-9a-fA-F-]{36}/[!-~]{1,1000}$")
_NAME = r"[A-Za-z_][A-Za-z0-9_-]*"
# ``[0]`` or ``["eu"]``: a count index or a for_each key.
_KEY = r'\[(?:\d+|"(?:[^"\\]|\\.)*")\]'
_ADDRESS = re.compile(
    rf"^(?P<modules>(?:module\.{_NAME}(?:{_KEY})?\.)*)"
    rf"(?P<type>azurerm_[a-z0-9_]+)\.(?P<name>{_NAME})(?P<key>{_KEY})?$"
)
_MODULE = re.compile(rf"module\.({_NAME})(?:{_KEY})?\.")


class InvalidIndex(ValueError):
    """An upload that is not what the Action sends, refused whole."""


@dataclass(frozen=True)
class Address:
    """A managed resource's state address, read into the parts that find its block."""

    #: The module calls on the way, outermost first, without instance keys.
    modules: tuple[str, ...]
    type: str
    #: The resource block's label: ``resource "<type>" "<name>"``.
    name: str
    #: Whether this is one instance of a ``count``, a ``for_each`` or a module
    #: repeated by either, so its block defines more than this asset.
    repeated: bool


@dataclass(frozen=True)
class IndexEntry:
    address: str
    type: str
    #: The instance key as state wrote it (``0``, ``eu``); ``None`` for a
    #: resource that is not repeated.
    index: str | None
    #: Lower-cased: Azure Resource Manager ids are case-insensitive, and the
    #: casing of one depends on which API wrote it.
    resource_id: str


def parse_address(address: str) -> Address:
    """Read a managed azurerm resource's address; ``InvalidIndex`` for anything else."""
    match = _ADDRESS.match(address)
    if match is None:
        raise InvalidIndex(f"Not a managed azurerm resource address: {address[:200]!r}")
    modules = match.group("modules")
    return Address(
        modules=tuple(_MODULE.findall(modules)),
        type=match.group("type"),
        name=match.group("name"),
        repeated=match.group("key") is not None or "[" in modules,
    )


def entries_from_upload(raw: Sequence[Mapping[str, Any]]) -> list[IndexEntry]:
    """The entries an upload holds, checked; ``InvalidIndex`` refuses the whole upload.

    Refused whole rather than filtered, because an Action that sends something
    else has been changed, and taking the part that looks right would hide that.
    """
    if len(raw) > MAX_ENTRIES:
        raise InvalidIndex(f"An index holds at most {MAX_ENTRIES} resources.")
    entries: list[IndexEntry] = []
    seen: set[str] = set()
    for item in raw:
        if set(item) - {"address", "type", "index", "id"}:
            raise InvalidIndex("An entry holds only address, type, index and id.")
        address, resource_type = item.get("address"), item.get("type")
        index, resource_id = item.get("index"), item.get("id")
        if not isinstance(address, str) or not isinstance(resource_type, str):
            raise InvalidIndex("Every entry has a string address and type.")
        if parse_address(address).type != resource_type:
            raise InvalidIndex(f"{address[:200]!r} is not of type {resource_type[:80]!r}.")
        if not isinstance(resource_id, str) or not _ARM_ID.match(resource_id):
            raise InvalidIndex(f"{address[:200]!r} has no Azure Resource Manager id.")
        if index is not None and (isinstance(index, bool) or not isinstance(index, int | str)):
            raise InvalidIndex(f"{address[:200]!r} has an index that is not a number or a key.")
        if address in seen:
            raise InvalidIndex(f"{address[:200]!r} appears twice.")
        seen.add(address)
        entries.append(
            IndexEntry(
                address=address,
                type=resource_type,
                index=None if index is None else str(index),
                resource_id=resource_id.lower(),
            )
        )
    return entries
