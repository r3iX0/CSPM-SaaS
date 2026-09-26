"""Routes a lab estate has and the graph used to miss (DECISIONS.md section 119).

An internet-facing machine that runs as no identity used to be a dead end, even
when the machine beside it on the same network runs as one with a role. Four
things stood between that estate and its route: no network hop, identities
assigned by the user rather than the system, and two joins that compared ARM
ids case-sensitively.
"""

import ipaddress

from app.connectors.azure.network import admits
from app.connectors.azure.normalizer import AzureNormalizer
from app.connectors.base import RawSnapshot
from app.core.enums import Level, Provider, RelationshipType, ResourceType
from app.domain.resource import CloudResource
from app.graph import AssetGraph, DeadEndReason

SUB_ID = "00000000-0000-0000-0000-000000000001"
SUB = f"/subscriptions/{SUB_ID}"
# ARM's own inconsistency, reproduced: the machines' records spell the group in
# capitals, everything else in lower case.
UPPER = f"{SUB}/resourceGroups/LAB-RG"
LOWER = f"{SUB}/resourceGroups/lab-rg"
VNET = f"{LOWER}/providers/Microsoft.Network/virtualNetworks/lab-vnet"
SUBNET = f"{VNET}/subnets/default"
OTHER_SUBNET = f"{LOWER}/providers/Microsoft.Network/virtualNetworks/other/subnets/default"
NSG = f"{LOWER}/providers/Microsoft.Network/networkSecurityGroups/lab-nsg"
UAI = f"{LOWER}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/app-id"
VAULT = f"{LOWER}/providers/Microsoft.KeyVault/vaults/lab-kv"
CONTRIBUTOR = f"{SUB}/providers/Microsoft.Authorization/roleDefinitions/b24988ac"


def vm(name: str, ip: str, *, subnet: str = SUBNET, identity: dict | None = None) -> dict:
    return {
        "id": f"{UPPER}/providers/Microsoft.Compute/virtualMachines/{name}",
        "name": name,
        "location": "westeurope",
        "identity": identity,
        "properties": {
            "networkProfile": {
                # Upper case here, lower case in the interface listing.
                "networkInterfaces": [
                    {"id": f"{UPPER}/providers/Microsoft.Network/networkInterfaces/{name}-nic"}
                ]
            }
        },
        "_nic": {
            "id": f"{LOWER}/providers/Microsoft.Network/networkInterfaces/{name}-nic",
            "properties": {
                "networkSecurityGroup": {"id": NSG.replace("lab-rg", "LAB-RG")},
                "ipConfigurations": [
                    {
                        "properties": {
                            "privateIPAddress": ip,
                            "subnet": {"id": subnet},
                            **(
                                {"publicIPAddress": {"id": f"{LOWER}/pip/{name}"}}
                                if name.startswith("open")
                                else {}
                            ),
                        }
                    }
                ],
            },
        },
    }


def rule(name: str, priority: int, access: str, **props: object) -> dict:
    return {
        "name": name,
        "properties": {
            "priority": priority,
            "access": access,
            "direction": props.pop("direction", "Inbound"),
            "protocol": props.pop("protocol", "*"),
            "sourceAddressPrefix": props.pop("source", "*"),
            "destinationAddressPrefix": props.pop("destination", "*"),
            "destinationPortRange": props.pop("ports", "*"),
            **props,
        },
    }


def snapshot(machines: list[dict], rules: list[dict] | None = None) -> RawSnapshot:
    nics = [m.pop("_nic") for m in machines]
    return RawSnapshot(
        provider=Provider.AZURE,
        tenant_id="tenant-1",
        subscription_id=SUB_ID,
        data={
            "virtual_machines": machines,
            "network_interfaces": nics,
            "public_ip_addresses": [
                {"id": f"{LOWER}/pip/{m['name']}", "properties": {"ipAddress": "20.0.0.1"}}
                for m in machines
                if m["name"].startswith("open")
            ],
            "network_security_groups": [
                {
                    "id": NSG,
                    "name": "lab-nsg",
                    "properties": {
                        "securityRules": [
                            rule("ssh", 100, "Allow", source="Internet", ports="22"),
                            *(rules or []),
                        ]
                    },
                }
            ],
            "key_vaults": [
                {"id": VAULT, "name": "lab-kv", "properties": {"publicNetworkAccess": "Disabled"}}
            ],
            "role_definitions": [
                {
                    "id": CONTRIBUTOR,
                    "properties": {
                        "roleName": "Contributor",
                        "permissions": [{"actions": ["*"]}],
                    },
                }
            ],
            "role_assignments": [
                {
                    "properties": {
                        "principalId": "uai-principal",
                        "principalType": "ServicePrincipal",
                        "roleDefinitionId": CONTRIBUTOR,
                        # Written by hand, in a third casing.
                        "scope": f"{SUB}/resourcegroups/Lab-Rg",
                    }
                }
            ],
        },
    )


def lab(rules: list[dict] | None = None, *, subnet: str = SUBNET):
    return AzureNormalizer().normalize(
        snapshot(
            [
                vm("open-web", "10.0.0.4"),
                vm(
                    "app",
                    "10.0.0.5",
                    subnet=subnet,
                    identity={
                        "type": "UserAssigned",
                        "userAssignedIdentities": {
                            UAI: {"principalId": "uai-principal", "clientId": "c"}
                        },
                    },
                ),
            ],
            rules,
        )
    )


def edges(state, relationship: RelationshipType) -> set[tuple[str, str]]:
    return {(s, t) for s, r, t in state.relationships if r is relationship}


def by_name(state, name: str) -> CloudResource:
    return next(r for r in state.resources if r.name == name)


# ------------------------------------------------------------------ casing
def test_a_machine_whose_interface_is_spelled_differently_is_still_exposed() -> None:
    """The join that left an open machine UNKNOWN, and so no entry point."""
    state = lab()
    assert by_name(state, "open-web").public_exposure is Level.HIGH
    assert by_name(state, "open-web").metadata["subnets"] == [SUBNET]


def test_one_resource_group_is_one_node_whatever_its_casing() -> None:
    state = lab()
    groups = [r for r in state.resources if r.resource_type is ResourceType.RESOURCE_GROUP]
    assert len(groups) == 1
    contained = {
        t for s, t in edges(state, RelationshipType.CONTAINS)
        if s == groups[0].provider_resource_id
    }
    assert VAULT in contained
    assert by_name(state, "app").provider_resource_id in contained


def test_a_role_over_a_group_in_another_casing_still_reaches_it() -> None:
    state = lab()
    group = next(r for r in state.resources if r.resource_type is ResourceType.RESOURCE_GROUP)
    assert ("/principals/uai-principal", group.provider_resource_id) in edges(
        state, RelationshipType.GRANTS_ROLE
    )


def test_an_nsg_edge_in_another_casing_lands_on_the_machine() -> None:
    state = lab()
    ids = {r.provider_resource_id for r in state.resources}
    protects = edges(state, RelationshipType.PROTECTS)
    assert protects
    for source, target in protects:
        assert source in ids and target in ids


# --------------------------------------------------------------- identities
def test_a_user_assigned_identity_is_one_the_machine_runs_as() -> None:
    state = lab()
    app = by_name(state, "app")
    assert (app.provider_resource_id, "/principals/uai-principal") in edges(
        state, RelationshipType.HAS_IDENTITY
    )
    assert by_name(state, "app-id (user-assigned identity)")


# ------------------------------------------------------------------ network
def test_an_open_machine_reaches_the_one_beside_it() -> None:
    state = lab()
    assert (
        by_name(state, "open-web").provider_resource_id,
        by_name(state, "app").provider_resource_id,
    ) in edges(state, RelationshipType.NETWORK_ACCESS)


def test_only_exposed_machines_are_where_a_network_hop_starts() -> None:
    state = lab()
    app = by_name(state, "app").provider_resource_id
    assert all(source != app for source, _ in edges(state, RelationshipType.NETWORK_ACCESS))


def test_another_network_is_not_reached() -> None:
    state = lab(subnet=OTHER_SUBNET)
    assert not edges(state, RelationshipType.NETWORK_ACCESS)


def test_a_group_that_denies_the_network_closes_the_hop() -> None:
    state = lab([rule("no-lateral", 200, "Deny", source="VirtualNetwork")])
    assert not edges(state, RelationshipType.NETWORK_ACCESS)


def test_a_deny_on_one_port_leaves_the_rest_answering() -> None:
    state = lab([rule("no-rdp", 200, "Deny", source="VirtualNetwork", ports="3389")])
    assert edges(state, RelationshipType.NETWORK_ACCESS)


def test_a_deny_this_reading_cannot_place_is_no_edge() -> None:
    state = lab(
        [
            rule(
                "asg",
                200,
                "Deny",
                source=None,
                sourceApplicationSecurityGroups=[{"id": "asg-1"}],
            )
        ]
    )
    assert not edges(state, RelationshipType.NETWORK_ACCESS)


def test_address_ranges_are_matched_against_private_addresses() -> None:
    web = (ipaddress.ip_address("10.0.0.4"),)
    app = (ipaddress.ip_address("10.0.0.5"),)
    nsg = {
        "properties": {
            "securityRules": [
                rule("other-range", 100, "Deny", source="10.1.0.0/16"),
                rule("this-range", 200, "Deny", source="10.0.0.0/24"),
            ]
        }
    }
    assert admits(nsg, "inbound", web, app) is False
    assert admits({"properties": {}}, "inbound", web, app) is True
    outbound = {
        "properties": {
            "securityRules": [rule("egress", 100, "Deny", direction="Outbound")]
        }
    }
    assert admits(outbound, "outbound", web, app) is False
    assert admits(outbound, "inbound", web, app) is True


# -------------------------------------------------------------------- route
def test_the_lab_route_runs_through_the_machine_next_door() -> None:
    """Open box, box beside it, its identity, the group, the vault."""
    state = lab()
    graph = AssetGraph.build(state.resources, state.relationships)
    paths = [p for p in graph.attack_paths() if p.target.provider_resource_id == VAULT]

    assert paths, "the open machine reaches the vault through its neighbour"
    path = paths[0]
    assert path.entry.name == "open-web"
    # Through the escalation edge rather than the role edge beside it. The
    # fixture's role is ``actions: ["*"]`` with no not-actions -- Owner in all
    # but name -- and nothing in it reads a secret: it reaches the vault only
    # because it can grant itself the role that does (DECISIONS.md section 125).
    assert [s.relationship for s in path.steps] == [
        RelationshipType.NETWORK_ACCESS,
        RelationshipType.HAS_IDENTITY,
        RelationshipType.CAN_GRANT_ROLES,
        RelationshipType.CONTAINS,
    ]
    cut = path.cheapest_break()
    assert cut is not None and cut.relationship is RelationshipType.NETWORK_ACCESS
    assert cut.describe() == "open-web can reach over the network app"


# ----------------------------------------------------------------- dead ends
def node(
    rid: str, kind: ResourceType, *, exposure: Level = Level.LOW, sensitivity: Level = Level.LOW
) -> CloudResource:
    return CloudResource(
        provider_resource_id=rid,
        resource_type=kind,
        name=rid,
        provider=Provider.AZURE,
        public_exposure=exposure,
        data_sensitivity=sensitivity,
    )


def test_each_way_in_says_where_it_stops() -> None:
    graph = AssetGraph.build(
        [
            node("bare", ResourceType.VIRTUAL_MACHINE, exposure=Level.HIGH),
            node("roleless", ResourceType.VIRTUAL_MACHINE, exposure=Level.HIGH),
            node("mi", ResourceType.SERVICE_PRINCIPAL),
            node("scoped", ResourceType.VIRTUAL_MACHINE, exposure=Level.HIGH),
            node("mi2", ResourceType.SERVICE_PRINCIPAL),
            node("rg", ResourceType.RESOURCE_GROUP),
            node("blob", ResourceType.STORAGE_ACCOUNT),
            node("admin", ResourceType.USER, exposure=Level.HIGH, sensitivity=Level.HIGH),
        ],
        [
            ("roleless", RelationshipType.HAS_IDENTITY, "mi"),
            ("scoped", RelationshipType.HAS_IDENTITY, "mi2"),
            ("mi2", RelationshipType.GRANTS_ROLE, "rg"),
            ("rg", RelationshipType.CONTAINS, "blob"),
        ],
    )
    assert graph.attack_paths() == []
    ends = {end.entry.provider_resource_id: end for end in graph.dead_ends()}

    assert ends["bare"].reason is DeadEndReason.REACHES_NOTHING
    assert ends["roleless"].reason is DeadEndReason.IDENTITY_WITHOUT_ROLE
    assert ends["scoped"].reason is DeadEndReason.NOTHING_SENSITIVE
    assert ends["scoped"].reached == 3
    assert ends["admin"].reason is DeadEndReason.REACHES_NOTHING
    # Machines before people.
    assert graph.dead_ends()[-1].entry.provider_resource_id == "admin"


def test_a_way_in_with_a_route_is_not_a_dead_end() -> None:
    graph = AssetGraph.build(
        [
            node("vm", ResourceType.VIRTUAL_MACHINE, exposure=Level.HIGH),
            node("mi", ResourceType.SERVICE_PRINCIPAL),
            node("blob", ResourceType.STORAGE_ACCOUNT, sensitivity=Level.HIGH),
        ],
        [
            ("vm", RelationshipType.HAS_IDENTITY, "mi"),
            ("mi", RelationshipType.GRANTS_ROLE, "blob"),
        ],
    )
    assert graph.attack_paths()
    assert graph.dead_ends() == []
