"""A role edge reaches only what the role controls (DECISIONS.md section 125).

The graph used to treat every role assignment as control over everything under
its scope. Reader over a subscription was a route to the payments ledger; a
blob reader "reached" the machines beside the account, and through them every
identity those machines run as. These pin the evaluation of a role's actions,
the walk that uses it, the severance that must agree with the walk, and the
access view that reads the same evaluation from the other side.
"""

from typing import Any

from app.connectors.azure.access import access_profile
from app.connectors.azure.normalizer import AzureNormalizer
from app.connectors.base import NormalizedState, RawSnapshot
from app.core.enums import AccessKind, Level, Provider, RelationshipType, ResourceType
from app.domain.resource import CloudResource
from app.graph import AssetGraph, DeadEndReason
from app.graph.facts import edge_facts

# ------------------------------------------------------------ the definitions
_BLOBS = "Microsoft.Storage/storageAccounts/blobServices/containers/blobs"

OWNER: dict[str, Any] = {"actions": ["*"], "notActions": []}
CONTRIBUTOR: dict[str, Any] = {
    "actions": ["*"],
    "notActions": [
        "Microsoft.Authorization/*/Delete",
        "Microsoft.Authorization/*/Write",
        "Microsoft.Authorization/elevateAccess/Action",
    ],
}
READER: dict[str, Any] = {"actions": ["*/read"]}
BLOB_READER: dict[str, Any] = {
    "actions": ["Microsoft.Storage/storageAccounts/blobServices/containers/read"],
    "dataActions": [f"{_BLOBS}/read"],
}
SECRETS_USER: dict[str, Any] = {
    "actions": [],
    "dataActions": ["Microsoft.KeyVault/vaults/secrets/getSecret/action"],
}
VM_CONTRIBUTOR: dict[str, Any] = {
    "actions": [
        "Microsoft.Compute/virtualMachines/*",
        "Microsoft.Network/networkInterfaces/read",
    ],
}


def definition(*blocks: dict[str, Any]) -> dict[str, Any]:
    return {"id": "role", "properties": {"roleName": "Role", "permissions": list(blocks)}}


def kinds(profile: dict[str, list[str]] | None, resource_type: ResourceType) -> set[str]:
    assert profile is not None
    return set(profile.get(resource_type.value, []))


def test_reader_reads_configuration_and_nothing_else() -> None:
    profile = access_profile(definition(READER))
    assert profile
    for granted in profile.values():
        assert granted == [AccessKind.READ.value]


def test_contributor_takes_keys_and_runs_code_but_reads_no_secret() -> None:
    profile = access_profile(definition(CONTRIBUTOR))
    assert AccessKind.READ_DATA.value in kinds(profile, ResourceType.STORAGE_ACCOUNT)
    assert AccessKind.EXECUTE.value in kinds(profile, ResourceType.VIRTUAL_MACHINE)
    assert AccessKind.EXECUTE.value in kinds(profile, ResourceType.APP_SERVICE)
    assert AccessKind.READ_DATA.value in kinds(profile, ResourceType.SQL_SERVER)
    # A secret is a data action, and ``*`` in actions is no data action. What
    # Contributor has over a vault is its access policies.
    vault = kinds(profile, ResourceType.KEY_VAULT)
    assert AccessKind.READ_DATA.value not in vault
    assert AccessKind.EDIT_POLICY.value in vault


def test_a_data_role_is_read_from_its_data_actions() -> None:
    profile = access_profile(definition(BLOB_READER))
    assert kinds(profile, ResourceType.STORAGE_ACCOUNT) == {AccessKind.READ_DATA.value}
    assert ResourceType.VIRTUAL_MACHINE.value not in (profile or {})
    assert kinds(access_profile(definition(SECRETS_USER)), ResourceType.KEY_VAULT) == {
        AccessKind.READ_DATA.value
    }


def test_not_actions_take_away_what_the_wildcard_gave() -> None:
    no_run = {
        **VM_CONTRIBUTOR,
        "notActions": [
            "Microsoft.Compute/virtualMachines/*/action",
            "Microsoft.Compute/virtualMachines/runCommands/*",
            "Microsoft.Compute/virtualMachines/extensions/*",
        ],
    }
    granted = kinds(access_profile(definition(no_run)), ResourceType.VIRTUAL_MACHINE)
    assert AccessKind.EXECUTE.value not in granted
    assert AccessKind.MANAGE.value in granted

    no_blobs = {**BLOB_READER, "notDataActions": [f"{_BLOBS}/*"]}
    profile = access_profile(definition(no_blobs))
    assert AccessKind.READ_DATA.value not in (profile or {}).get(
        ResourceType.STORAGE_ACCOUNT.value, []
    )


def test_a_not_action_applies_only_inside_its_own_block() -> None:
    """ARM evaluates each permission block on its own and unions them."""
    split = definition(
        {"actions": ["Microsoft.Compute/virtualMachines/runCommand/action"]},
        {"actions": ["*/read"], "notActions": ["Microsoft.Compute/*"]},
    )
    assert AccessKind.EXECUTE.value in kinds(
        access_profile(split), ResourceType.VIRTUAL_MACHINE
    )


def test_a_condition_withholds_only_what_came_through_data_actions() -> None:
    assert access_profile(definition(BLOB_READER), conditional=True) == {}
    conditioned = access_profile(definition(CONTRIBUTOR), conditional=True)
    assert AccessKind.READ_DATA.value in kinds(conditioned, ResourceType.STORAGE_ACCOUNT)


def test_an_unread_definition_is_a_gap_not_a_verdict() -> None:
    assert access_profile(None) is None
    assert access_profile(definition()) == {}


# --------------------------------------------------------------- normalizer
SUB_ID = "00000000-0000-0000-0000-00000000000a"
SUB = f"/subscriptions/{SUB_ID}"
RG = f"{SUB}/resourceGroups/rg-data"
STORAGE = f"{RG}/providers/Microsoft.Storage/storageAccounts/ledger"
VAULT = f"{RG}/providers/Microsoft.KeyVault/vaults/kv-data"
MG = "/providers/Microsoft.Management/managementGroups/contoso-root"


def role_def(key: str, name: str, block: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": f"{SUB}/providers/Microsoft.Authorization/roleDefinitions/{key}",
        "properties": {"roleName": name, "type": "BuiltInRole", "permissions": [block]},
    }


def assignment(principal_id: str, key: str, scope: str, **extra: Any) -> dict[str, Any]:
    return {
        "properties": {
            "principalId": principal_id,
            "principalType": "ServicePrincipal",
            "roleDefinitionId": f"{SUB}/providers/Microsoft.Authorization/roleDefinitions/{key}",
            "scope": scope,
            **extra,
        }
    }


def normalize(
    assignments: list[dict[str, Any]], *, vault_rbac: bool | None = None
) -> NormalizedState:
    vault_props: dict[str, Any] = {"publicNetworkAccess": "Disabled"}
    if vault_rbac is not None:
        vault_props["enableRbacAuthorization"] = vault_rbac
    return AzureNormalizer().normalize(
        RawSnapshot(
            provider=Provider.AZURE,
            tenant_id="tenant-1",
            subscription_id=SUB_ID,
            data={
                "storage_accounts": [
                    {"id": STORAGE, "name": "ledger", "location": "westeurope", "properties": {}}
                ],
                "key_vaults": [{"id": VAULT, "name": "kv-data", "properties": vault_props}],
                "role_definitions": [
                    role_def("owner", "Owner", OWNER),
                    role_def("reader", "Reader", READER),
                    role_def("contributor", "Contributor", CONTRIBUTOR),
                ],
                "role_assignments": assignments,
            },
        )
    )


def principal(state: NormalizedState, principal_id: str) -> CloudResource:
    return next(
        r for r in state.resources if r.provider_resource_id == f"/principals/{principal_id}"
    )


def test_each_role_is_recorded_with_what_it_amounts_to() -> None:
    state = normalize([assignment("p1", "reader", RG)])
    entry = principal(state, "p1").metadata["roles"][0]
    assert entry["role"] == "Reader"
    assert entry["target"].lower() == RG.lower()
    assert entry["conditional"] is False
    assert entry["inherited_from"] is None
    assert entry["access"][ResourceType.STORAGE_ACCOUNT.value] == [AccessKind.READ.value]


def test_an_assignment_at_a_management_group_reaches_the_subscription() -> None:
    state = normalize([assignment("p1", "owner", MG)])
    edges = set(state.relationships)
    assert ("/principals/p1", RelationshipType.GRANTS_ROLE, SUB) in edges
    assert ("/principals/p1", RelationshipType.CAN_GRANT_ROLES, SUB) in edges
    entry = principal(state, "p1").metadata["roles"][0]
    assert entry["inherited_from"] == MG
    assert entry["target"] == SUB


def test_a_conditioned_delegation_is_not_drawn_as_an_escalation() -> None:
    condition = "((!(ActionMatches{'Microsoft.Authorization/roleAssignments/write'})))"
    state = normalize([assignment("p1", "owner", RG, condition=condition)])
    drawn = {r for s, r, _ in state.relationships if s == "/principals/p1"}
    assert drawn == {RelationshipType.GRANTS_ROLE}
    entry = principal(state, "p1").metadata["roles"][0]
    assert entry["conditional"] is True
    assert entry["grants_role_assignment"] is False


def test_a_vault_says_whether_its_own_policies_govern_it() -> None:
    def governed(rbac: bool | None) -> Any:
        state = normalize([], vault_rbac=rbac)
        vault = next(r for r in state.resources if r.provider_resource_id == VAULT)
        return vault.metadata["governed_by_own_policy"]

    assert governed(False) is True
    assert governed(True) is False
    assert governed(None) is None


# --------------------------------------------------------------------- walk
def node(
    rid: str,
    kind: ResourceType,
    *,
    exposure: Level = Level.LOW,
    sensitivity: Level = Level.LOW,
    **metadata: Any,
) -> CloudResource:
    return CloudResource(
        provider_resource_id=rid,
        resource_type=kind,
        name=rid.rsplit("/", 1)[-1],
        public_exposure=exposure,
        data_sensitivity=sensitivity,
        metadata=dict(metadata),
    )


def role(name: str, target: str, block: dict[str, Any] | None, **extra: Any) -> dict[str, Any]:
    access = access_profile(definition(block)) if block is not None else None
    return {
        "role": name,
        "scope": target,
        "target": target,
        "grants_role_assignment": False,
        "conditional": False,
        "inherited_from": None,
        "access": access,
        **extra,
    }


G_SUB = "/sub"
G_RG = "/sub/rg"
G_WEB = "/sub/rg/vm-web"
G_APP = "/sub/rg/vm-app"
G_LEDGER = "/sub/rg/ledger"
G_KV = "/sub/rg/kv"
G_WEB_ID = "/principals/web"
G_APP_ID = "/principals/app"


def estate(
    web_roles: list[dict[str, Any]],
    app_roles: list[dict[str, Any]] | None = None,
    *,
    vault: dict[str, Any] | None = None,
) -> AssetGraph:
    """An exposed machine and a quiet one, each with its identity, in one group
    beside a sensitive ledger and a sensitive vault."""
    app_roles = app_roles or []
    resources = [
        node(G_SUB, ResourceType.SUBSCRIPTION),
        node(G_RG, ResourceType.RESOURCE_GROUP),
        node(G_WEB, ResourceType.VIRTUAL_MACHINE, exposure=Level.HIGH),
        node(G_APP, ResourceType.VIRTUAL_MACHINE),
        node(G_LEDGER, ResourceType.STORAGE_ACCOUNT, sensitivity=Level.CRITICAL),
        node(G_KV, ResourceType.KEY_VAULT, sensitivity=Level.CRITICAL, **(vault or {})),
        node(G_WEB_ID, ResourceType.SERVICE_PRINCIPAL, roles=web_roles),
        node(G_APP_ID, ResourceType.SERVICE_PRINCIPAL, roles=app_roles),
    ]
    edges = [
        (G_SUB, RelationshipType.CONTAINS, G_RG),
        *((G_RG, RelationshipType.CONTAINS, child) for child in (G_WEB, G_APP, G_LEDGER, G_KV)),
        (G_WEB, RelationshipType.HAS_IDENTITY, G_WEB_ID),
        (G_APP, RelationshipType.HAS_IDENTITY, G_APP_ID),
    ]
    for principal_id, held in ((G_WEB_ID, web_roles), (G_APP_ID, app_roles)):
        for entry in held:
            scope = entry.get("target") or entry["scope"]
            edges.append((principal_id, RelationshipType.GRANTS_ROLE, scope))
            if entry.get("grants_role_assignment"):
                edges.append((principal_id, RelationshipType.CAN_GRANT_ROLES, scope))
    return AssetGraph.build(resources, edges)


def targets(graph: AssetGraph) -> set[str]:
    return {path.target.provider_resource_id for path in graph.attack_paths()}


def test_reader_over_the_group_is_no_route_to_what_is_in_it() -> None:
    graph = estate([role("Reader", G_RG, READER)])
    assert targets(graph) == set()
    (end,) = [e for e in graph.dead_ends() if e.entry.provider_resource_id == G_WEB]
    assert end.reason is DeadEndReason.ROLES_WITHOUT_CONTROL


def test_a_role_that_was_not_read_reaches_nothing() -> None:
    graph = estate([role("Unknown role", G_RG, None)])
    assert targets(graph) == set()


def test_a_blob_reader_reaches_the_ledger_and_not_the_machine_beside_it() -> None:
    graph = estate(
        [role("Storage Blob Data Reader", G_RG, BLOB_READER)],
        [role("Owner", G_SUB, OWNER, grants_role_assignment=True)],
    )
    assert targets(graph) == {G_LEDGER}
    # The quiet machine runs as an Owner. Reaching it would have been a route
    # to everything; a blob reader cannot run anything on it.
    reached = graph.reachable_from(G_WEB)
    assert G_APP not in reached
    assert G_APP_ID not in reached


def test_running_code_on_a_machine_is_a_route_through_its_identity() -> None:
    graph = estate(
        [role("Virtual Machine Contributor", G_RG, VM_CONTRIBUTOR)],
        [role("Key Vault Secrets User", G_KV, SECRETS_USER)],
    )
    paths = [p for p in graph.attack_paths() if p.target.provider_resource_id == G_KV]
    assert paths
    assert [step.relationship for step in paths[0].steps] == [
        RelationshipType.HAS_IDENTITY,
        RelationshipType.GRANTS_ROLE,
        RelationshipType.CONTAINS,
        RelationshipType.HAS_IDENTITY,
        RelationshipType.GRANTS_ROLE,
    ]
    assert G_LEDGER not in targets(graph)


def test_a_vault_on_access_policies_is_held_by_whoever_edits_them() -> None:
    contributor = [role("Contributor", G_RG, CONTRIBUTOR)]
    assert G_KV not in targets(estate(contributor, vault={"governed_by_own_policy": False}))
    assert G_KV not in targets(estate(contributor))
    assert G_KV in targets(estate(contributor, vault={"governed_by_own_policy": True}))


def test_a_role_recorded_before_evaluation_walks_as_it_always_did() -> None:
    legacy = [{"role": "Reader", "scope": G_RG, "grants_role_assignment": False}]
    assert targets(estate(legacy)) == {G_LEDGER, G_KV}


def test_severance_agrees_with_the_walk() -> None:
    """A Reader edge beside a Contributor edge is no way round it."""
    graph = estate([role("Reader", G_SUB, READER), role("Contributor", G_RG, CONTRIBUTOR)])
    assert targets(graph) == {G_LEDGER}
    severance = graph.link_severance()
    closes = severance[(G_WEB_ID, RelationshipType.GRANTS_ROLE.value, G_RG)]
    assert {p.target.provider_resource_id for p in closes} == {G_LEDGER}
    assert not severance.get((G_WEB_ID, RelationshipType.GRANTS_ROLE.value, G_SUB))


def test_two_roles_that_each_reach_keep_each_other_alive() -> None:
    graph = estate(
        [
            role("Contributor", G_SUB, CONTRIBUTOR),
            role("Storage Blob Data Reader", G_RG, BLOB_READER),
        ]
    )
    assert G_LEDGER in targets(graph)
    severance = graph.link_severance()
    for scope in (G_SUB, G_RG):
        closed = severance.get((G_WEB_ID, RelationshipType.GRANTS_ROLE.value, scope), ())
        assert G_LEDGER not in {p.target.provider_resource_id for p in closed}


# ---------------------------------------------------------------- the views
def test_holders_of_an_asset_are_every_role_above_it_controllers_first() -> None:
    graph = estate(
        [role("Reader", G_SUB, READER)],
        [role("Storage Blob Data Reader", G_LEDGER, BLOB_READER)],
    )
    held = graph.access_to(G_LEDGER)
    assert [(h.principal.provider_resource_id, h.role, h.controls) for h in held] == [
        (G_APP_ID, "Storage Blob Data Reader", True),
        (G_WEB_ID, "Reader", False),
    ]
    assert held[0].at.provider_resource_id == G_LEDGER
    assert held[1].at.provider_resource_id == G_SUB
    assert [w.provider_resource_id for w in held[0].runs_on] == [G_APP]
    assert held[1].kinds == (AccessKind.READ,)


def test_an_escalating_holder_controls_whatever_it_can_grant_itself() -> None:
    graph = estate(
        [role("User Access Administrator", G_RG, READER, grants_role_assignment=True)]
    )
    (holder,) = graph.access_to(G_KV)
    assert holder.controls
    assert AccessKind.GRANT_ACCESS in holder.kinds


def test_an_unread_role_is_listed_and_claims_nothing() -> None:
    graph = estate([role("Unknown role", G_RG, None)])
    (holder,) = graph.access_to(G_LEDGER)
    assert not holder.resolved
    assert not holder.controls


def test_what_an_identity_holds_is_counted_per_role() -> None:
    graph = estate([role("Contributor", G_RG, CONTRIBUTOR), role("Reader", G_SUB, READER)])
    contributor, reader = graph.access_of(G_WEB_ID)
    assert contributor.role == "Contributor"
    assert {a.provider_resource_id for a in contributor.controlled} == {G_WEB, G_APP, G_LEDGER}
    assert reader.controlled == ()


def test_a_hop_names_the_role_that_gives_it_reach_first() -> None:
    graph = estate([role("Reader", G_RG, READER), role("Contributor", G_RG, CONTRIBUTOR)])
    facts = edge_facts(graph.nodes[G_WEB_ID], RelationshipType.GRANTS_ROLE, graph.nodes[G_RG])
    assert facts == ("Contributor", "Reader")


def test_an_inherited_role_says_where_it_came_from() -> None:
    graph = estate([role("Owner", G_SUB, OWNER, inherited_from=MG, scope=MG)])
    facts = edge_facts(graph.nodes[G_WEB_ID], RelationshipType.GRANTS_ROLE, graph.nodes[G_SUB])
    assert facts == ("Owner from management group contoso-root",)


def test_a_role_that_controls_nothing_is_not_drawn_as_reach() -> None:
    graph = estate([role("Reader", G_RG, READER)])
    around = graph.neighborhood(G_WEB_ID)
    assert around is not None
    assert not [edge for edge in around.edges if edge[1] is RelationshipType.GRANTS_ROLE]
    assert around.layers.get(G_RG, 0) <= 0  # upstream, as the machine's container
    assert not graph.conveys(G_WEB_ID, RelationshipType.GRANTS_ROLE, G_RG)
    # The access view still lists it: a fact about the identity, not reach.
    assert [grant.role for grant in graph.access_of(G_WEB_ID)] == ["Reader"]


def test_removing_an_owner_assignment_is_one_cut_that_closes_both_lines() -> None:
    """Owner is drawn twice -- what it does, and that it can grant the rest --
    and both lines are one assignment (DECISIONS.md section 127). Counted as two
    links each was the other's way round, and the fix a customer most often
    makes severed nothing."""
    graph = estate([role("Owner", G_RG, OWNER, grants_role_assignment=True)])
    assignment = (G_WEB_ID, RelationshipType.GRANTS_ROLE.value, G_RG)
    closes = {p.target.provider_resource_id for p in graph.link_severance()[assignment]}
    assert closes == targets(graph)

    escalation = graph.cut(G_WEB_ID, RelationshipType.CAN_GRANT_ROLES, G_RG)
    assert escalation is not None
    assert escalation.step.relationship is RelationshipType.GRANTS_ROLE
    assert escalation.after == 0

    owner_cut = [c for c in graph.choke_points() if c.step.key() == assignment]
    assert owner_cut and owner_cut[0].severs == len(targets(graph))
