"""The six types role v9 reads, as assets and as graph nodes (DECISIONS.md section 169).

Managed Kubernetes clusters, container registries, Cosmos DB accounts, MySQL
flexible servers, Databricks workspaces and AI Search services used to reach the
inventory only as unchecked rows of type UNKNOWN. These pin what each listing
becomes: its neutral type, the exposure its own settings establish -- and UNKNOWN
where the setting that would decide it is not read -- the data floor for the
ones that hold data, the identity a cluster's nodes run as, and what a role
over each amounts to.

Payloads are shaped after the published REST reference for each api-version
the client asks for, and are fixtures: nothing here has been read from a live
tenant yet.
"""

from typing import Any

import pytest

from app.connectors.azure.access import access_profile
from app.connectors.azure.normalizer import AzureNormalizer
from app.connectors.base import NormalizedState, RawSnapshot
from app.core.enums import AccessKind, Level, Provider, RelationshipType, ResourceType
from app.domain.resource import CloudResource

SUB_ID = "00000000-0000-0000-0000-000000000001"
RG = f"/subscriptions/{SUB_ID}/resourceGroups/platform"

CLUSTER = f"{RG}/providers/Microsoft.ContainerService/managedClusters/aks-prod"
REGISTRY = f"{RG}/providers/Microsoft.ContainerRegistry/registries/acrprod"
COSMOS = f"{RG}/providers/Microsoft.DocumentDB/databaseAccounts/orders"
MYSQL = f"{RG}/providers/Microsoft.DBforMySQL/flexibleServers/shop"
DATABRICKS = f"{RG}/providers/Microsoft.Databricks/workspaces/analytics"
SEARCH = f"{RG}/providers/Microsoft.Search/searchServices/catalog"

KUBELET = "kubelet-object-id"
CONTROL_PLANE = "control-plane-principal"


def cluster(**props: Any) -> dict[str, Any]:
    return {
        "id": CLUSTER,
        "name": "aks-prod",
        "location": "westeurope",
        "identity": {"type": "SystemAssigned", "principalId": CONTROL_PLANE},
        "properties": {
            "kubernetesVersion": "1.29.2",
            "enableRBAC": True,
            "disableLocalAccounts": False,
            "agentPoolProfiles": [
                {"name": "system", "enableNodePublicIP": False},
                {"name": "edge", "enableNodePublicIP": True},
            ],
            "identityProfile": {
                "kubeletidentity": {"objectId": KUBELET, "clientId": "kubelet-client"}
            },
            **props,
        },
    }


def normalize(**data: Any) -> NormalizedState:
    return AzureNormalizer().normalize(
        RawSnapshot(
            provider=Provider.AZURE,
            tenant_id="tenant-1",
            subscription_id=SUB_ID,
            data=data,
        )
    )


def one(state: NormalizedState, resource_id: str) -> CloudResource:
    matches = [r for r in state.resources if r.provider_resource_id == resource_id]
    assert len(matches) == 1, f"{resource_id} appears {len(matches)} times"
    return matches[0]


# ---------------------------------------------------------------- clusters
def test_a_cluster_with_the_default_public_api_server_is_an_entry_point() -> None:
    """ARM leaves ``apiServerAccessProfile`` out for a cluster created with the
    defaults, and the default is a public API server."""
    node = one(normalize(kubernetes_clusters=[cluster()]), CLUSTER)
    assert node.resource_type is ResourceType.KUBERNETES_CLUSTER
    assert node.public_exposure is Level.HIGH
    assert node.get("node_public_ip_pools") == ["edge"]
    assert node.get("local_accounts_disabled") is False


@pytest.mark.parametrize(
    ("access", "expected"),
    [
        ({"enablePrivateCluster": True}, Level.LOW),
        ({"authorizedIPRanges": ["203.0.113.0/24"]}, Level.MEDIUM),
        ({"enablePrivateCluster": False, "authorizedIPRanges": []}, Level.HIGH),
    ],
)
def test_a_clusters_api_server_access_decides_its_exposure(
    access: dict[str, Any], expected: Level
) -> None:
    state = normalize(kubernetes_clusters=[cluster(apiServerAccessProfile=access)])
    assert one(state, CLUSTER).public_exposure is expected


def test_a_cluster_runs_as_its_control_plane_and_its_kubelet_identity() -> None:
    """The kubelet identity is the one a pod reaching the node acts as, so a
    route through a cluster runs through it -- stated as an object id under
    ``identityProfile``, not under ``identity``."""
    state = normalize(kubernetes_clusters=[cluster()])
    identities = {
        target
        for source, rel, target in state.relationships
        if source == CLUSTER and rel is RelationshipType.HAS_IDENTITY
    }
    assert identities == {f"/principals/{CONTROL_PLANE}", f"/principals/{KUBELET}"}
    names = {
        r.provider_resource_id: r.name
        for r in state.resources
        if r.provider_resource_id in identities
    }
    assert names[f"/principals/{KUBELET}"] == "aks-prod (kubelet identity)"


# --------------------------------------------------------------- the rest
CASES: list[tuple[str, str, ResourceType, dict[str, Any], Level]] = [
    (
        "container_registries",
        REGISTRY,
        ResourceType.CONTAINER_REGISTRY,
        {"publicNetworkAccess": "Enabled", "adminUserEnabled": True},
        Level.HIGH,
    ),
    (
        "container_registries",
        REGISTRY,
        ResourceType.CONTAINER_REGISTRY,
        {"publicNetworkAccess": "Enabled", "networkRuleSet": {"defaultAction": "Deny"}},
        Level.MEDIUM,
    ),
    (
        "container_registries",
        REGISTRY,
        ResourceType.CONTAINER_REGISTRY,
        {"publicNetworkAccess": "Disabled"},
        Level.LOW,
    ),
    (
        "cosmos_accounts",
        COSMOS,
        ResourceType.DOCUMENT_DATABASE,
        {"publicNetworkAccess": "Enabled", "ipRules": []},
        Level.HIGH,
    ),
    (
        "cosmos_accounts",
        COSMOS,
        ResourceType.DOCUMENT_DATABASE,
        {"publicNetworkAccess": "Enabled", "ipRules": [{"ipAddressOrRange": "203.0.113.4"}]},
        Level.MEDIUM,
    ),
    (
        "cosmos_accounts",
        COSMOS,
        ResourceType.DOCUMENT_DATABASE,
        {"publicNetworkAccess": "Disabled"},
        Level.LOW,
    ),
    # A public MySQL server admits whom its firewall rules name, and those are
    # not read: not established, rather than guessed either way.
    (
        "mysql_servers",
        MYSQL,
        ResourceType.MYSQL_SERVER,
        {"network": {"publicNetworkAccess": "Enabled"}},
        Level.UNKNOWN,
    ),
    (
        "mysql_servers",
        MYSQL,
        ResourceType.MYSQL_SERVER,
        {"network": {"publicNetworkAccess": "Disabled"}},
        Level.LOW,
    ),
    ("databricks_workspaces", DATABRICKS, ResourceType.ANALYTICS_WORKSPACE, {}, Level.HIGH),
    (
        "databricks_workspaces",
        DATABRICKS,
        ResourceType.ANALYTICS_WORKSPACE,
        {"publicNetworkAccess": "Disabled"},
        Level.LOW,
    ),
    (
        "search_services",
        SEARCH,
        ResourceType.SEARCH_SERVICE,
        {"publicNetworkAccess": "enabled", "networkRuleSet": {"ipRules": []}},
        Level.HIGH,
    ),
    (
        "search_services",
        SEARCH,
        ResourceType.SEARCH_SERVICE,
        {
            "publicNetworkAccess": "enabled",
            "networkRuleSet": {"ipRules": [{"value": "203.0.113.0/24"}]},
        },
        Level.MEDIUM,
    ),
    (
        "search_services",
        SEARCH,
        ResourceType.SEARCH_SERVICE,
        {"publicNetworkAccess": "disabled"},
        Level.LOW,
    ),
]


@pytest.mark.parametrize(("key", "resource_id", "resource_type", "props", "expected"), CASES)
def test_each_type_is_modelled_with_the_exposure_its_settings_establish(
    key: str,
    resource_id: str,
    resource_type: ResourceType,
    props: dict[str, Any],
    expected: Level,
) -> None:
    item = {"id": resource_id, "name": resource_id.rsplit("/", 1)[-1], "properties": props}
    node = one(normalize(**{key: [item]}), resource_id)
    assert node.resource_type is resource_type
    assert node.public_exposure is expected


def test_the_databases_and_the_index_hold_data_whatever_they_are_tagged() -> None:
    state = normalize(
        cosmos_accounts=[{"id": COSMOS, "name": "orders", "properties": {}}],
        mysql_servers=[{"id": MYSQL, "name": "shop", "properties": {}}],
        search_services=[{"id": SEARCH, "name": "catalog", "properties": {}}],
        container_registries=[{"id": REGISTRY, "name": "acrprod", "properties": {}}],
    )
    for resource_id in (COSMOS, MYSQL, SEARCH):
        assert one(state, resource_id).data_sensitivity is not Level.UNKNOWN
    # A registry holds code, not customer data: no floor, only what it is tagged.
    assert one(state, REGISTRY).data_sensitivity is Level.UNKNOWN


def test_a_modelled_type_is_not_listed_again_as_unchecked_inventory() -> None:
    """Resource Graph lists every resource, these included. A second row of
    type UNKNOWN would miscount the inventory and put the asset in the graph
    twice."""
    state = normalize(
        cosmos_accounts=[{"id": COSMOS, "name": "orders", "properties": {}}],
        resources=[
            {"id": COSMOS, "name": "orders", "type": "Microsoft.DocumentDB/databaseAccounts"}
        ],
    )
    assert one(state, COSMOS).resource_type is ResourceType.DOCUMENT_DATABASE


def test_a_missing_private_endpoint_field_is_not_zero() -> None:
    """A rule asking for private endpoints must tell "not stated" from "none"."""
    approved = {"properties": {"privateLinkServiceConnectionState": {"status": "Approved"}}}
    pending = {"properties": {"privateLinkServiceConnectionState": {"status": "Pending"}}}
    state = normalize(
        search_services=[
            {
                "id": SEARCH,
                "name": "catalog",
                "properties": {"privateEndpointConnections": [approved, pending]},
            }
        ],
        container_registries=[{"id": REGISTRY, "name": "acrprod", "properties": {}}],
    )
    assert one(state, SEARCH).get("private_endpoints") == 1
    assert one(state, REGISTRY).get("private_endpoints") is None


# ------------------------------------------------------------------ reach
READER: dict[str, Any] = {"actions": ["*/read"]}
CONTRIBUTOR: dict[str, Any] = {
    "actions": ["*"],
    "notActions": ["Microsoft.Authorization/*/Delete", "Microsoft.Authorization/*/Write"],
}
NEW_TYPES = (
    ResourceType.KUBERNETES_CLUSTER,
    ResourceType.CONTAINER_REGISTRY,
    ResourceType.DOCUMENT_DATABASE,
    ResourceType.MYSQL_SERVER,
    ResourceType.ANALYTICS_WORKSPACE,
    ResourceType.SEARCH_SERVICE,
)


def kinds(block: dict[str, Any], resource_type: ResourceType) -> set[str]:
    profile = access_profile({"properties": {"permissions": [block]}}) or {}
    return set(profile.get(resource_type.value, []))


@pytest.mark.parametrize("resource_type", NEW_TYPES)
def test_reader_still_reaches_nothing_in_the_new_types(resource_type: ResourceType) -> None:
    """Section 125 holds: Reader reads configuration and controls nothing --
    which is why a registry pull, inside ``*/read``, is not claimed."""
    assert kinds(READER, resource_type) == {AccessKind.READ.value}


def test_contributor_takes_what_each_type_hands_its_managers() -> None:
    assert AccessKind.EXECUTE.value in kinds(CONTRIBUTOR, ResourceType.KUBERNETES_CLUSTER)
    assert AccessKind.EXECUTE.value in kinds(CONTRIBUTOR, ResourceType.ANALYTICS_WORKSPACE)
    for data_type in (
        ResourceType.CONTAINER_REGISTRY,
        ResourceType.DOCUMENT_DATABASE,
        ResourceType.MYSQL_SERVER,
        ResourceType.SEARCH_SERVICE,
    ):
        assert AccessKind.READ_DATA.value in kinds(CONTRIBUTOR, data_type)
