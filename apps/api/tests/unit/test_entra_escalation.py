"""The directory's say over the estate, drawn as reach (DECISIONS.md §128).

Two Entra facts had no edge in the graph. A Global Administrator can elevate to
User Access Administrator at the root and so make themselves owner of every
subscription; the roles that can make themselves Global Administrator can do
the same a step later. And whoever owns an application registration, or holds
a directory role that manages every application, can add a credential to it
and sign in as its service principal -- holding every Azure role that principal
holds. A leaked secret on the registration does the same. These pin the
collection, the normalization, the edges derived from both, the severance that
keys a directory role apart from an Azure assignment, and the access view.
"""

from typing import Any

import httpx

from app.connectors.azure.access import access_profile
from app.connectors.azure.normalizer import AzureNormalizer
from app.connectors.azure.plan import AzurePlanBuilder
from app.connectors.base import NormalizedState, RawSnapshot
from app.core.enums import AccessKind, Level, Provider, RelationshipType, ResourceType
from app.domain.resource import CloudResource
from app.graph import AssetGraph
from app.graph.facts import edge_facts

BLOB_READER: dict[str, Any] = {
    "actions": [],
    "dataActions": ["Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"],
}
OWNER: dict[str, Any] = {"actions": ["*"]}

SUB = "/sub"
RG = "/sub/rg"
LEDGER = "/sub/rg/ledger"
ADMIN = "/users/admin"
DEV = "/users/dev"
APP = "/applications/pipeline"
SP = "/principals/sp-1"

UNSIGNED_APP: dict[str, Any] = {"acts_as": "sp-1", "controllers": [], "can_sign_in": False}


def definition(block: dict[str, Any]) -> dict[str, Any]:
    return {"id": "role", "properties": {"roleName": "Role", "permissions": [block]}}


def role(name: str, target: str, block: dict[str, Any], **extra: Any) -> dict[str, Any]:
    return {
        "role": name,
        "scope": target,
        "target": target,
        "grants_role_assignment": False,
        "conditional": False,
        "inherited_from": None,
        "access": access_profile(definition(block)),
        **extra,
    }


def node(
    rid: str,
    kind: ResourceType,
    *,
    exposure: Level = Level.UNKNOWN,
    sensitivity: Level = Level.UNKNOWN,
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


def user(rid: str, identity: str, *powers: tuple[str, str], **metadata: Any) -> CloudResource:
    return node(
        rid,
        ResourceType.USER,
        exposure=Level.HIGH,
        identity_id=identity,
        directory_powers=[{"power": power, "via": via} for power, via in powers],
        **metadata,
    )


BASE_EDGES = [
    (SUB, RelationshipType.CONTAINS, RG),
    (RG, RelationshipType.CONTAINS, LEDGER),
    (SP, RelationshipType.GRANTS_ROLE, RG),
]


def base(app: dict[str, Any] | None = None) -> list[CloudResource]:
    """A subscription with a ledger in it, a service principal that reads the
    ledger, and the application registration that principal belongs to."""
    return [
        node(SUB, ResourceType.SUBSCRIPTION),
        node(RG, ResourceType.RESOURCE_GROUP),
        node(LEDGER, ResourceType.STORAGE_ACCOUNT, sensitivity=Level.CRITICAL),
        node(
            SP,
            ResourceType.SERVICE_PRINCIPAL,
            identity_id="sp-1",
            stub=True,
            roles=[role("Storage Blob Data Reader", RG, BLOB_READER)],
        ),
        node(
            APP,
            ResourceType.APPLICATION,
            exposure=Level.HIGH,
            **(app if app is not None else UNSIGNED_APP),
        ),
    ]


def estate(*extra: CloudResource, app: dict[str, Any] | None = None) -> AssetGraph:
    return AssetGraph.build([*base(app), *extra], list(BASE_EDGES))


def entries(graph: AssetGraph) -> set[str]:
    return {path.entry.provider_resource_id for path in graph.attack_paths()}


def test_a_global_administrator_can_make_themselves_owner_of_every_subscription() -> None:
    graph = estate(user(ADMIN, "admin", ("control_all_scopes", "Global Administrator")))
    paths = [p for p in graph.attack_paths() if p.entry.provider_resource_id == ADMIN]
    assert [p.target.provider_resource_id for p in paths] == [LEDGER]
    assert paths[0].steps[0].relationship is RelationshipType.CAN_TAKE_OVER
    assert paths[0].steps[0].facts == ("Global Administrator",)


def test_removing_the_directory_role_is_not_removing_an_azure_assignment() -> None:
    """The take-over line is keyed apart from an Owner assignment on the same
    pair: removing one leaves the other, and severance must say so."""
    admin = user(
        ADMIN,
        "admin",
        ("control_all_scopes", "Global Administrator"),
        roles=[role("Owner", SUB, OWNER, grants_role_assignment=True)],
    )
    graph = AssetGraph.build(
        [*base(), admin],
        [
            *BASE_EDGES,
            (ADMIN, RelationshipType.GRANTS_ROLE, SUB),
            (ADMIN, RelationshipType.CAN_GRANT_ROLES, SUB),
        ],
    )
    take_over = graph.removal_key(ADMIN, RelationshipType.CAN_TAKE_OVER, SUB)
    assert take_over == (ADMIN, RelationshipType.CAN_TAKE_OVER.value, SUB)
    severance = graph.link_severance()
    # Each is a way round the other; neither closes the route alone.
    assert not severance.get(take_over)
    assert not severance.get((ADMIN, RelationshipType.GRANTS_ROLE.value, SUB))


def test_an_owner_of_the_registration_signs_in_as_its_principal() -> None:
    graph = estate(
        user(DEV, "dev"),
        app={"acts_as": "sp-1", "controllers": ["dev"], "can_sign_in": False},
    )
    (path,) = [p for p in graph.attack_paths() if p.entry.provider_resource_id == DEV]
    assert [s.relationship for s in path.steps][:2] == [
        RelationshipType.CAN_ACT_AS,
        RelationshipType.GRANTS_ROLE,
    ]
    assert path.steps[0].facts == ("owner of its application registration",)
    # Taking away the ownership closes it.
    closes = graph.link_severance()[(DEV, RelationshipType.CAN_ACT_AS.value, SP)]
    assert [p.target.provider_resource_id for p in closes] == [LEDGER]


def test_a_registration_with_a_credential_is_a_way_in_and_one_without_is_not() -> None:
    signed = estate(app={"acts_as": "sp-1", "controllers": [], "can_sign_in": True})
    assert APP in entries(signed)
    assert APP not in entries(estate())


def test_an_application_administrator_can_sign_in_as_every_application() -> None:
    graph = estate(
        user(ADMIN, "admin", ("act_as_any_application", "Application Administrator"))
    )
    (path,) = [p for p in graph.attack_paths() if p.entry.provider_resource_id == ADMIN]
    assert path.steps[0].relationship is RelationshipType.CAN_ACT_AS
    assert path.steps[0].facts == ("Application Administrator",)


def test_a_principal_the_graph_never_saw_is_reached_by_nobody() -> None:
    graph = estate(
        user(DEV, "dev"),
        app={"acts_as": "sp-unseen", "controllers": ["dev"], "can_sign_in": True},
    )
    assert entries(graph) == set()


# ---------------------------------------------------------------- the views
def test_the_ledger_lists_who_the_directory_lets_take_it() -> None:
    graph = estate(user(ADMIN, "admin", ("control_all_scopes", "Global Administrator")))
    held = {h.principal.provider_resource_id: h for h in graph.access_to(LEDGER)}
    admin = held[ADMIN]
    assert admin.through_directory
    assert admin.controls
    assert admin.role == "Global Administrator"
    assert admin.at.provider_resource_id == SUB


def test_a_principal_lists_who_can_sign_in_as_it() -> None:
    graph = estate(user(DEV, "dev"), app={"acts_as": "sp-1", "controllers": ["dev"]})
    (holder,) = [h for h in graph.access_to(SP) if h.through_directory]
    assert holder.principal.provider_resource_id == DEV
    assert holder.kinds == (AccessKind.ACT_AS,)


def test_what_a_person_holds_through_the_directory() -> None:
    graph = estate(
        user(DEV, "dev", ("control_all_scopes", "Global Administrator")),
        app={"acts_as": "sp-1", "controllers": ["dev"]},
    )
    grants = graph.access_of(DEV)
    take_over = [g for g in grants if g.through_directory]
    assert [(g.role, g.at.provider_resource_id if g.at else None) for g in take_over] == [
        ("Global Administrator", SUB)
    ]
    assert {a.provider_resource_id for a in take_over[0].controlled} == {LEDGER}
    (through_principal,) = [g for g in grants if g.via is not None]
    assert through_principal.via is not None
    assert through_principal.via.provider_resource_id == SP


def test_a_hop_names_the_directory_role() -> None:
    graph = estate(
        user(ADMIN, "admin", ("control_all_scopes", "Privileged Role Administrator"))
    )
    facts = edge_facts(graph.nodes[ADMIN], RelationshipType.CAN_TAKE_OVER, graph.nodes[SUB])
    assert facts == ("Privileged Role Administrator",)


# --------------------------------------------------------------- normalizer
def normalize(data: dict[str, Any]) -> NormalizedState:
    return AzureNormalizer().normalize(
        RawSnapshot(provider=Provider.AZURE, tenant_id="t", subscription_id=None, data=data)
    )


def test_directory_roles_become_neutral_powers() -> None:
    state = normalize(
        {
            "users": [{"id": "u-1", "displayName": "A"}, {"id": "u-2", "displayName": "B"}],
            "user_role_map": {
                "u-1": ["Global Administrator", "Security Reader"],
                "u-2": ["Cloud Application Administrator"],
            },
        }
    )
    powers = {r.name: r.metadata["directory_powers"] for r in state.resources}
    assert powers["A"] == [{"power": "control_all_scopes", "via": "Global Administrator"}]
    assert powers["B"] == [
        {"power": "act_as_any_application", "via": "Cloud Application Administrator"}
    ]


def test_a_registration_records_who_owns_it_and_what_it_signs_in_as() -> None:
    state = normalize(
        {
            "application_credentials": [
                {
                    "id": "obj-1",
                    "appId": "app-1",
                    "displayName": "pipeline",
                    "passwordCredentials": [{"endDateTime": "2099-01-01T00:00:00Z"}],
                    "keyCredentials": [],
                },
                {"id": "obj-2", "appId": "app-2", "displayName": "unread"},
            ],
            "application_owners": {"obj-1": ["u-1"]},
            "application_service_principals": {"app-1": "sp-1"},
        }
    )
    apps = {r.name: r.metadata for r in state.resources}
    assert apps["pipeline"]["acts_as"] == "sp-1"
    assert apps["pipeline"]["controllers"] == ["u-1"]
    assert apps["pipeline"]["can_sign_in"] is True
    # Owners not read: unknown, not "nobody".
    assert apps["unread"]["controllers"] is None
    assert apps["unread"]["acts_as"] is None


# --------------------------------------------------------------- collection
class FakeTokens:
    tenant_id = "t"

    def arm_token(self) -> str:
        return "arm"

    def graph_token(self) -> str:
        return "graph"


def graph_answering(fail: tuple[str, ...] = ()) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if any(fragment in path for fragment in fail):
            return httpx.Response(403, json={"error": {"message": "denied"}})
        if path.endswith("/owners"):
            return httpx.Response(200, json={"value": [{"id": "u-1"}]})
        if path.endswith("/servicePrincipals"):
            return httpx.Response(200, json={"value": [{"id": "sp-1", "appId": "app-1"}]})
        return httpx.Response(404, json={"error": {"message": "unexpected"}})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


COLLECTED = {"application_credentials": [{"id": "obj-1", "appId": "app-1"}]}


async def test_owners_and_principals_are_read_for_each_registration() -> None:
    builder = AzurePlanBuilder(FakeTokens(), None, graph_answering())  # type: ignore[arg-type]
    result = await builder._application_owners(COLLECTED)
    assert result.partial_reason is None
    assert result.data == {
        "application_owners": {"obj-1": ["u-1"]},
        "application_service_principals": {"app-1": "sp-1"},
    }


async def test_an_unreadable_owner_list_is_absent_and_said() -> None:
    builder = AzurePlanBuilder(
        FakeTokens(),  # type: ignore[arg-type]
        None,
        graph_answering(fail=("/owners",)),
    )
    result = await builder._application_owners(COLLECTED)
    assert result.data["application_owners"] == {}
    assert result.partial_reason is not None
    assert "could not be read" in result.partial_reason


# ------------------------------------------------------------ escalations
def test_owning_the_scope_already_is_no_escalation_over_it() -> None:
    """A Global Administrator takes the subscription, walks down to a machine
    whose identity can grant roles over that subscription -- and has gained
    nothing: the chain is a loop, and raised as a risk it doubled one."""
    vm, identity = "/sub/rg/vm", "/principals/vm-id"
    graph = AssetGraph.build(
        [
            *base(),
            user(ADMIN, "admin", ("control_all_scopes", "Global Administrator")),
            node(vm, ResourceType.VIRTUAL_MACHINE, exposure=Level.HIGH),
            node(
                identity,
                ResourceType.SERVICE_PRINCIPAL,
                identity_id="vm-id",
                roles=[role("Owner", SUB, OWNER, grants_role_assignment=True)],
            ),
        ],
        [
            *BASE_EDGES,
            (RG, RelationshipType.CONTAINS, vm),
            (vm, RelationshipType.HAS_IDENTITY, identity),
            (identity, RelationshipType.GRANTS_ROLE, SUB),
            (identity, RelationshipType.CAN_GRANT_ROLES, SUB),
        ],
    )
    entries = {chain.entry.provider_resource_id for chain in graph.escalation_chains()}
    # The exposed machine's chain is real; the administrator's is not.
    assert entries == {vm}


def test_a_narrower_role_over_the_scope_still_escalates() -> None:
    """Reaching the group as Virtual Machine Contributor is not holding it."""
    web, vm, identity = "/sub/rg/web", "/sub/rg/vm", "/principals/vm-id"
    vm_contributor = {"actions": ["Microsoft.Compute/virtualMachines/*"]}
    graph = AssetGraph.build(
        [
            *base(),
            node(web, ResourceType.VIRTUAL_MACHINE, exposure=Level.HIGH),
            node(
                "/principals/web-id",
                ResourceType.SERVICE_PRINCIPAL,
                identity_id="web-id",
                roles=[role("Virtual Machine Contributor", RG, vm_contributor)],
            ),
            node(vm, ResourceType.VIRTUAL_MACHINE),
            node(
                identity,
                ResourceType.SERVICE_PRINCIPAL,
                identity_id="vm-id",
                roles=[role("Owner", RG, OWNER, grants_role_assignment=True)],
            ),
        ],
        [
            *BASE_EDGES,
            (RG, RelationshipType.CONTAINS, web),
            (RG, RelationshipType.CONTAINS, vm),
            (web, RelationshipType.HAS_IDENTITY, "/principals/web-id"),
            ("/principals/web-id", RelationshipType.GRANTS_ROLE, RG),
            (vm, RelationshipType.HAS_IDENTITY, identity),
            (identity, RelationshipType.GRANTS_ROLE, RG),
            (identity, RelationshipType.CAN_GRANT_ROLES, RG),
        ],
    )
    chains = graph.escalation_chains()
    assert any(
        chain.entry.provider_resource_id == web and chain.target.provider_resource_id == RG
        for chain in chains
    )
