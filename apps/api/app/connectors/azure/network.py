"""Which machines an internet-facing machine can open a connection to.

A helper of the normalizer, split out because it is a small evaluator of its
own rather than a reading of one payload: it answers "does anything on either
side stop traffic between these two machines" from the network security groups
the scan collected, and the attack-path graph turns each yes into a
``NETWORK_ACCESS`` edge (DECISIONS.md section 119).

Deliberately narrow, because a false edge is a route CloudGuard would describe
through an estate that does not have it:

- **Same virtual network only.** Peering is not collected, so a machine in a
  peered network is not reached rather than guessed at.
- **Machine to machine only.** Reaching a storage account or a database over
  the network is not reaching its data -- that still takes a key or a role, and
  the role is already an edge. Reaching another machine is different: it is a
  second foothold, running as whatever identity that machine has.
- **"Some traffic gets through", not "this port is open".** The question an
  attacker asks of the box next door is whether anything answers, and the
  default ``AllowVnetInBound`` means something almost always does.
- **Unknown is no edge.** A machine whose interfaces or guarding groups were not
  collected, or a deny rule naming an application security group this reading
  cannot resolve, produces nothing rather than a route through a gap.
"""

import ipaddress
from dataclasses import dataclass
from typing import Any

from app.core.enums import Level, ResourceType
from app.domain.resource import CloudResource

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Prefixes that cover every address of the virtual network both machines sit
# in. ``VirtualNetwork`` is Azure's service tag for the network's own address
# space (plus peers and on-premises ranges, which only widen it).
WHOLE_NETWORK = {"*", "any", "virtualnetwork"}


@dataclass(frozen=True)
class _Rule:
    priority: int
    allow: bool
    sources: tuple[str, ...]
    destinations: tuple[str, ...]
    # Whether the rule applies to every port and protocol. Only a deny that
    # does closes the machine off entirely; one that denies port 22 leaves the
    # rest answering.
    total: bool
    # Names an application security group, whose members this reading does not
    # hold. Such a rule can neither be matched nor ruled out.
    opaque: bool


# Azure's own rules, beneath every group's and impossible to remove. Written
# out rather than read from ``defaultSecurityRules``, because not every capture
# carries them and their content is fixed.
_DEFAULTS = (
    _Rule(65000, True, ("VirtualNetwork",), ("VirtualNetwork",), True, False),
    _Rule(65500, False, ("*",), ("*",), True, False),
)


def _prefixes(props: dict[str, Any], single: str, plural: str) -> tuple[str, ...]:
    values = [props.get(single), *(props.get(plural) or [])]
    return tuple(str(v) for v in values if v)


def _rules(nsg: dict[str, Any], direction: str) -> list[_Rule]:
    """One group's rules for one direction, its own and Azure's, in order."""
    rules = list(_DEFAULTS)
    for raw in (nsg.get("properties") or {}).get("securityRules") or []:
        props = raw.get("properties") or {}
        if str(props.get("direction", "")).lower() != direction:
            continue
        ports = _prefixes(props, "destinationPortRange", "destinationPortRanges")
        rules.append(
            _Rule(
                priority=int(props.get("priority") or 0),
                allow=str(props.get("access", "")).lower() == "allow",
                sources=_prefixes(props, "sourceAddressPrefix", "sourceAddressPrefixes"),
                destinations=_prefixes(
                    props, "destinationAddressPrefix", "destinationAddressPrefixes"
                ),
                total=(
                    str(props.get("protocol", "*")).lower() in {"*", "any"}
                    and any(p.strip() in {"*", "0-65535"} for p in ports)
                ),
                opaque=bool(
                    props.get("sourceApplicationSecurityGroups")
                    or props.get("destinationApplicationSecurityGroups")
                ),
            )
        )
    return sorted(rules, key=lambda rule: rule.priority)


def _covers(prefixes: tuple[str, ...], addresses: tuple[IPAddress, ...]) -> bool:
    """Whether a rule's prefixes include one of this machine's addresses.

    A service tag other than the network's own -- ``Internet``,
    ``AzureLoadBalancer`` -- does not cover a machine talking to its neighbour,
    and an address range covers it only if the machine's private address is in
    it.
    """
    for prefix in prefixes:
        text = prefix.strip()
        if text.lower() in WHOLE_NETWORK:
            return True
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            continue
        if any(address in network for address in addresses):
            return True
    return False


def admits(
    nsg: dict[str, Any],
    direction: str,
    sources: tuple[IPAddress, ...],
    destinations: tuple[IPAddress, ...],
) -> bool | None:
    """Whether this group lets some traffic between the two machines through.

    ``direction`` is ``"inbound"`` or ``"outbound"``. Azure applies a group's
    rules lowest priority number first and stops at the first match. The first
    allow covering both ends means something gets through; a deny covering both
    ends on every port and protocol first means nothing does. A deny that only
    closes some ports is passed over, because the ports it leaves are still an
    answer. ``None`` when a deny naming an application security group comes
    before any answer: it may close the machine off, and this reading cannot
    tell.
    """
    for rule in _rules(nsg, direction):
        if rule.opaque:
            if not rule.allow and rule.total:
                return None
            continue
        if not (_covers(rule.sources, sources) and _covers(rule.destinations, destinations)):
            continue
        if rule.allow:
            return True
        if rule.total:
            return False
    return False


def _network(subnet_id: str) -> str:
    """The virtual network a subnet belongs to, from the subnet's own id."""
    return subnet_id.lower().split("/subnets/", 1)[0]


def _addresses(machine: CloudResource) -> tuple[IPAddress, ...]:
    found: list[IPAddress] = []
    for text in machine.metadata.get("private_ips") or []:
        try:
            found.append(ipaddress.ip_address(str(text)))
        except ValueError:
            continue
    return tuple(found)


def network_access(
    machines: list[CloudResource], nsgs: dict[str, dict[str, Any]]
) -> list[tuple[str, str]]:
    """Every (from, to) pair where an exposed machine can reach another.

    Drawn only from machines with a public address, because that is where a
    route starts: an edge between every pair of machines in a network would be
    quadratic in its size and would describe nothing an attacker does before
    they have a foothold. ``nsgs`` is keyed by lower-cased id, because a
    machine's interfaces spell the group's resource group in whatever case ARM
    returned that day.
    """
    placed = [
        m
        for m in machines
        if m.resource_type is ResourceType.VIRTUAL_MACHINE and m.metadata.get("subnets")
    ]
    edges: list[tuple[str, str]] = []
    for source in placed:
        if source.public_exposure not in {Level.HIGH, Level.CRITICAL}:
            continue
        networks = {_network(s) for s in source.metadata["subnets"]}
        for target in placed:
            if target is source:
                continue
            if not networks & {_network(s) for s in target.metadata["subnets"]}:
                continue
            if _reachable(source, target, nsgs):
                edges.append((source.provider_resource_id, target.provider_resource_id))
    return edges


def _reachable(
    source: CloudResource, target: CloudResource, nsgs: dict[str, dict[str, Any]]
) -> bool:
    """Whether every group on the way lets something through.

    Out through each group guarding the source, in through each guarding the
    target -- Azure evaluates a subnet's group and an interface's group both,
    and either can stop the traffic. A group the scan did not collect is not
    assumed to be permissive.
    """
    from_ips, to_ips = _addresses(source), _addresses(target)
    for guards, direction in (
        (source.metadata.get("guarding_nsgs") or [], "outbound"),
        (target.metadata.get("guarding_nsgs") or [], "inbound"),
    ):
        for nsg_id in guards:
            nsg = nsgs.get(str(nsg_id).lower())
            if nsg is None or admits(nsg, direction, from_ips, to_ips) is not True:
                return False
    return True
