"""Graph permissions that are a directory role by another name (DECISIONS.md §129).

A managed identity granted ``RoleManagement.ReadWrite.Directory`` can make
itself Global Administrator, and from there owner of every subscription. One
granted ``AppRoleAssignment.ReadWrite.All`` can grant itself that permission
first. One granted ``Application.ReadWrite.All`` can add a credential to any
application and sign in as it. None of them holds an Azure role, and none of
them was drawn. These pin the collection, the directory's record of each such
principal, the merge that meets it with the subscription's, and the routes.
"""

from typing import Any

import httpx

from app.connectors.azure.normalizer import AzureNormalizer
from app.connectors.azure.plan import AzurePlanBuilder
from app.connectors.base import NormalizedState, RawSnapshot
from app.core.enums import Level, Provider, RelationshipType, ResourceType
from app.domain.resource import CloudResource
from app.graph import AssetGraph

CATALOGUE = {
    "role-rm": "RoleManagement.ReadWrite.Directory",
    "role-ara": "AppRoleAssignment.ReadWrite.All",
    "role-app": "Application.ReadWrite.All",
    "role-read": "User.Read.All",
}
TAKEOVER = "Graph permission RoleManagement.ReadWrite.Directory"


def grant(principal: str, role_id: str, name: str = "mi-web") -> dict[str, Any]:
    return {
        "principalId": principal,
        "principalType": "ServicePrincipal",
        "principalDisplayName": name,
        "appRoleId": role_id,
    }


def normalize(data: dict[str, Any]) -> NormalizedState:
    return AzureNormalizer().normalize(
        RawSnapshot(provider=Provider.AZURE, tenant_id="t", subscription_id=None, data=data)
    )


def principals(state: NormalizedState) -> dict[str, CloudResource]:
    return {
        r.provider_resource_id: r
        for r in state.resources
        if r.provider_resource_id.startswith("/principals/")
    }


def test_a_graph_permission_that_writes_directory_roles_is_a_takeover() -> None:
    state = normalize(
        {
            "graph_app_roles": CATALOGUE,
            "graph_permission_grants": [
                grant("mi-1", "role-rm"),
                grant("mi-2", "role-ara", "mi-sync"),
                grant("mi-3", "role-app", "mi-deploy"),
                grant("mi-4", "role-read", "mi-harmless"),
                grant("mi-5", "role-not-in-catalogue", "mi-unknown"),
            ],
        }
    )
    found = principals(state)
    assert set(found) == {"/principals/mi-1", "/principals/mi-2", "/principals/mi-3"}
    first = found["/principals/mi-1"]
    assert first.name == "mi-web"
    assert first.resource_type is ResourceType.SERVICE_PRINCIPAL
    assert first.metadata["identity_id"] == "mi-1"
    assert "stub" not in first.metadata
    assert first.metadata["directory_powers"] == [
        {"power": "control_all_scopes", "via": TAKEOVER}
    ]
    sync_powers = found["/principals/mi-2"].metadata["directory_powers"]
    assert sync_powers[0]["power"] == "control_all_scopes"
    assert found["/principals/mi-3"].metadata["directory_powers"] == [
        {"power": "act_as_any_application", "via": "Graph permission Application.ReadWrite.All"}
    ]


def test_a_non_user_holding_a_directory_role_gets_a_record_of_its_kind() -> None:
    state = normalize(
        {
            "users": [{"id": "u-1", "displayName": "A"}],
            "user_role_map": {
                "u-1": ["Global Administrator"],
                "sp-1": ["Global Administrator"],
                "g-1": ["Privileged Role Administrator"],
                "sp-2": ["Reports Reader"],
            },
            "directory_role_member_types": {
                "u-1": "#microsoft.graph.user",
                "sp-1": "#microsoft.graph.servicePrincipal",
                "g-1": "#microsoft.graph.group",
                "sp-2": "#microsoft.graph.servicePrincipal",
            },
        }
    )
    found = principals(state)
    # The user carries its own powers; a role with no power earns no record.
    assert set(found) == {"/principals/sp-1", "/principals/g-1"}
    assert found["/principals/sp-1"].resource_type is ResourceType.SERVICE_PRINCIPAL
    assert found["/principals/g-1"].resource_type is ResourceType.GROUP
    assert found["/principals/g-1"].name == "Group g-1"


# ------------------------------------------------------------------ merge
SUB = "/sub"
LEDGER = "/sub/ledger"
VM = "/sub/vm-web"
MI = "/principals/mi-1"


def stub() -> CloudResource:
    return CloudResource(
        provider_resource_id=MI,
        resource_type=ResourceType.SERVICE_PRINCIPAL,
        name="Managed identity",
        metadata={"identity_id": "mi-1", "stub": True, "principal_type": "ManagedIdentity"},
    )


def record() -> CloudResource:
    return CloudResource(
        provider_resource_id=MI,
        resource_type=ResourceType.SERVICE_PRINCIPAL,
        name="mi-web",
        metadata={
            "identity_id": "mi-1",
            "directory_powers": [{"power": "control_all_scopes", "via": TAKEOVER}],
        },
    )


def estate(order: list[CloudResource]) -> AssetGraph:
    return AssetGraph.build(
        [
            CloudResource(
                provider_resource_id=SUB, resource_type=ResourceType.SUBSCRIPTION, name="sub"
            ),
            CloudResource(
                provider_resource_id=LEDGER,
                resource_type=ResourceType.STORAGE_ACCOUNT,
                name="ledger",
                data_sensitivity=Level.CRITICAL,
            ),
            CloudResource(
                provider_resource_id=VM,
                resource_type=ResourceType.VIRTUAL_MACHINE,
                name="vm-web",
                public_exposure=Level.HIGH,
            ),
            *order,
        ],
        [
            (SUB, RelationshipType.CONTAINS, LEDGER),
            (VM, RelationshipType.HAS_IDENTITY, MI),
        ],
    )


def test_the_directory_record_wins_whichever_copy_arrives_first() -> None:
    for order in ([stub(), record()], [record(), stub()]):
        merged = estate(order).nodes[MI]
        assert merged.name == "mi-web"
        # A key only the stand-in had is kept.
        assert merged.metadata["principal_type"] == "ManagedIdentity"
        assert len(merged.metadata["directory_powers"]) == 1


def test_a_machine_running_as_a_graph_privileged_identity_reaches_everything() -> None:
    """No Azure role anywhere on the route: the permission is the whole of it."""
    (path,) = estate([stub(), record()]).attack_paths()
    assert [step.relationship for step in path.steps] == [
        RelationshipType.HAS_IDENTITY,
        RelationshipType.CAN_TAKE_OVER,
        RelationshipType.CONTAINS,
    ]
    assert path.steps[1].facts == (TAKEOVER,)


# ------------------------------------------------------------- collection
class FakeTokens:
    tenant_id = "t"

    def arm_token(self) -> str:
        return "arm"

    def graph_token(self) -> str:
        return "graph"


def graph_answering(*, catalogue: bool = True) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/appRoleAssignedTo"):
            return httpx.Response(200, json={"value": [grant("mi-1", "role-rm")]})
        if path.endswith("/servicePrincipals"):
            found = [
                {
                    "id": "graph-sp",
                    "appRoles": [{"id": "role-rm", "value": "RoleManagement.ReadWrite.Directory"}],
                }
            ]
            return httpx.Response(200, json={"value": found if catalogue else []})
        return httpx.Response(404, json={"error": {"message": "unexpected"}})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_grants_are_read_from_graphs_side_with_its_own_catalogue() -> None:
    builder = AzurePlanBuilder(FakeTokens(), None, graph_answering())  # type: ignore[arg-type]
    result = await builder._graph_permission_grants({})
    assert result.partial_reason is None
    assert result.data == {
        "graph_app_roles": {"role-rm": "RoleManagement.ReadWrite.Directory"},
        "graph_permission_grants": [grant("mi-1", "role-rm")],
    }


async def test_no_catalogue_is_a_gap_not_a_tenant_without_grants() -> None:
    builder = AzurePlanBuilder(
        FakeTokens(),  # type: ignore[arg-type]
        None,
        graph_answering(catalogue=False),
    )
    result = await builder._graph_permission_grants({})
    assert result.partial_reason is not None


def test_a_name_the_reading_gave_beats_one_made_up_from_an_id() -> None:
    unnamed = CloudResource(
        provider_resource_id=MI,
        resource_type=ResourceType.SERVICE_PRINCIPAL,
        name="Service principal mi-1",
        metadata={"identity_id": "mi-1", "unnamed": True, "directory_powers": []},
    )
    named = CloudResource(
        provider_resource_id=MI,
        resource_type=ResourceType.SERVICE_PRINCIPAL,
        name="vm-web (managed identity)",
        metadata={"identity_id": "mi-1", "stub": True},
    )
    for order in ([unnamed, named], [named, unnamed]):
        merged = estate(order).nodes[MI]
        assert merged.name == "vm-web (managed identity)"
        assert "unnamed" not in merged.metadata
