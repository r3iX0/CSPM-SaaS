"""The rules over role v9's types, run on what the normalizer makes of a listing
(DECISIONS.md section 170).

``test_remediation_spec.py`` already holds every rule to its own declaration on
a hand-built asset. These go through the normalizer instead, so a field the
normalizer spells differently from the rule fails here rather than as a rule
that never fires -- and they pin the two cases a declaration cannot: what an
unreadable listing does, and what an absent setting means.
"""

from typing import Any

import pytest

from app.connectors.azure.evidence import AzureEvidence
from app.connectors.azure.normalizer import AzureNormalizer
from app.connectors.base import RawSnapshot
from app.core.enums import Provider, RuleState
from app.rules.base import RuleContext
from app.rules.registry import get_rule

SUB = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/rg/providers"


def verdict(
    rule_id: str, key: str, item: dict[str, Any], *, errors: dict[str, str] | None = None
) -> RuleState:
    state = AzureNormalizer().normalize(
        RawSnapshot(
            provider=Provider.AZURE,
            tenant_id="tenant-1",
            subscription_id="00000000-0000-0000-0000-000000000001",
            data={key: [item]},
        )
    )
    rule = get_rule(rule_id)
    assert rule is not None
    resource = next(r for r in state.resources if r.provider_resource_id == item["id"])
    assert rule.matches(resource)
    context = RuleContext(resources=state.resources, collection_errors=errors or {})
    result = rule.evaluate(resource, context)
    results = result if isinstance(result, list) else [result]
    return results[0].state


def item(kind: str, name: str, **props: Any) -> dict[str, Any]:
    return {"id": f"{SUB}/{kind}/{name}", "name": name, "properties": props}


AKS = "Microsoft.ContainerService/managedClusters"
ACR = "Microsoft.ContainerRegistry/registries"
COSMOS = "Microsoft.DocumentDB/databaseAccounts"
DATABRICKS = "Microsoft.Databricks/workspaces"
SEARCH = "Microsoft.Search/searchServices"

CASES: list[tuple[str, str, dict[str, Any], RuleState]] = [
    # A cluster created with the defaults: public API server, local accounts on.
    ("AZ-AKS-001", AKS, {}, RuleState.FAIL),
    ("AZ-AKS-001", AKS, {"apiServerAccessProfile": {"enablePrivateCluster": True}}, RuleState.PASS),
    (
        "AZ-AKS-001",
        AKS,
        {"apiServerAccessProfile": {"authorizedIPRanges": ["203.0.113.0/24"]}},
        RuleState.PASS,
    ),
    ("AZ-AKS-002", AKS, {}, RuleState.FAIL),
    ("AZ-AKS-002", AKS, {"disableLocalAccounts": True}, RuleState.PASS),
    ("AZ-AKS-003", AKS, {}, RuleState.UNKNOWN),
    ("AZ-AKS-003", AKS, {"enableRBAC": False}, RuleState.FAIL),
    ("AZ-AKS-003", AKS, {"enableRBAC": True}, RuleState.PASS),
    (
        "AZ-AKS-004",
        AKS,
        {"agentPoolProfiles": [{"name": "edge", "enableNodePublicIP": True}]},
        RuleState.FAIL,
    ),
    ("AZ-AKS-004", AKS, {"agentPoolProfiles": [{"name": "system"}]}, RuleState.PASS),
    ("AZ-AKS-005", AKS, {"networkProfile": {"networkPolicy": "none"}}, RuleState.FAIL),
    ("AZ-AKS-005", AKS, {"networkProfile": {"networkPolicy": "calico"}}, RuleState.PASS),
    ("AZ-ACR-001", ACR, {"adminUserEnabled": True}, RuleState.FAIL),
    ("AZ-ACR-001", ACR, {"adminUserEnabled": False}, RuleState.PASS),
    ("AZ-ACR-001", ACR, {}, RuleState.UNKNOWN),
    ("AZ-ACR-002", ACR, {"publicNetworkAccess": "Enabled"}, RuleState.FAIL),
    (
        "AZ-ACR-002",
        ACR,
        {"publicNetworkAccess": "Enabled", "networkRuleSet": {"defaultAction": "Deny"}},
        RuleState.PASS,
    ),
    ("AZ-ACR-002", ACR, {}, RuleState.UNKNOWN),
    ("AZ-COS-001", COSMOS, {"publicNetworkAccess": "Enabled", "ipRules": []}, RuleState.FAIL),
    (
        "AZ-COS-001",
        COSMOS,
        {"publicNetworkAccess": "Enabled", "isVirtualNetworkFilterEnabled": True},
        RuleState.PASS,
    ),
    ("AZ-COS-002", COSMOS, {}, RuleState.FAIL),
    ("AZ-COS-002", COSMOS, {"disableLocalAuth": True}, RuleState.PASS),
    ("AZ-COS-003", COSMOS, {"minimalTlsVersion": "Tls"}, RuleState.FAIL),
    ("AZ-COS-003", COSMOS, {"minimalTlsVersion": "Tls12"}, RuleState.PASS),
    ("AZ-COS-003", COSMOS, {}, RuleState.UNKNOWN),
    ("AZ-DBW-001", DATABRICKS, {}, RuleState.FAIL),
    ("AZ-DBW-001", DATABRICKS, {"publicNetworkAccess": "Disabled"}, RuleState.PASS),
    # The published sample lists a workspace with ``parameters: null``.
    ("AZ-DBW-002", DATABRICKS, {"parameters": None}, RuleState.UNKNOWN),
    (
        "AZ-DBW-002",
        DATABRICKS,
        {"parameters": {"enableNoPublicIp": {"value": False}}},
        RuleState.FAIL,
    ),
    (
        "AZ-DBW-002",
        DATABRICKS,
        {"parameters": {"enableNoPublicIp": {"value": True}}},
        RuleState.PASS,
    ),
    ("AZ-DBW-003", DATABRICKS, {"parameters": None}, RuleState.UNKNOWN),
    (
        "AZ-DBW-003",
        DATABRICKS,
        {"parameters": {"enableNoPublicIp": {"value": True}}},
        RuleState.FAIL,
    ),
    (
        "AZ-DBW-003",
        DATABRICKS,
        {"parameters": {"customVirtualNetworkId": {"value": "/subscriptions/x/vnet"}}},
        RuleState.PASS,
    ),
    ("AZ-SRCH-001", SEARCH, {"publicNetworkAccess": "enabled"}, RuleState.FAIL),
    (
        "AZ-SRCH-001",
        SEARCH,
        {"publicNetworkAccess": "enabled", "networkRuleSet": {"ipRules": [{"value": "1.2.3.4"}]}},
        RuleState.PASS,
    ),
    ("AZ-SRCH-001", SEARCH, {"publicNetworkAccess": "disabled"}, RuleState.PASS),
    # Section 171.
    ("AZ-ACR-003", ACR, {}, RuleState.UNKNOWN),
    ("AZ-ACR-003", ACR, {"privateEndpointConnections": []}, RuleState.FAIL),
    (
        "AZ-ACR-003",
        ACR,
        {
            "privateEndpointConnections": [
                {"properties": {"privateLinkServiceConnectionState": {"status": "Approved"}}}
            ]
        },
        RuleState.PASS,
    ),
    ("AZ-COS-004", COSMOS, {"privateEndpointConnections": []}, RuleState.FAIL),
    ("AZ-DBW-004", DATABRICKS, {}, RuleState.FAIL),
    (
        "AZ-DBW-004",
        DATABRICKS,
        {"encryption": {"entities": {"managedServices": {"keySource": "Microsoft.Keyvault"}}}},
        RuleState.PASS,
    ),
]

KEYS = {
    AKS: "kubernetes_clusters",
    ACR: "container_registries",
    COSMOS: "cosmos_accounts",
    DATABRICKS: "databricks_workspaces",
    SEARCH: "search_services",
}

RULE_IDS = sorted({case[0] for case in CASES})


@pytest.mark.parametrize(("rule_id", "kind", "props", "expected"), CASES)
def test_a_rule_reads_what_the_normalizer_made_of_the_listing(
    rule_id: str, kind: str, props: dict[str, Any], expected: RuleState
) -> None:
    assert verdict(rule_id, KEYS[kind], item(kind, "x", **props)) is expected


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_a_failed_listing_is_unknown_never_a_verdict(rule_id: str) -> None:
    """A refused listing on a v8 role is the common case until the redeploy."""
    rule = get_rule(rule_id)
    assert rule is not None
    (key,) = rule.requires_evidence
    assert isinstance(key, AzureEvidence)
    kind = next(k for k, v in KEYS.items() if v == key.value)
    state = verdict(rule_id, key.value, item(kind, "x"), errors={key.value: "Forbidden"})
    assert state is RuleState.UNKNOWN


def test_every_rule_over_these_types_is_exercised() -> None:
    assert len(RULE_IDS) == 17


# ------------------------------------------ function apps and Linux machines
SITE = f"{SUB}/Microsoft.Web/sites/fn-orders"
VM = f"{SUB}/Microsoft.Compute/virtualMachines/vm-linux"


def site_verdict(kind: str, config: dict[str, Any] | None, **props: Any) -> RuleState:
    data: dict[str, Any] = {
        "app_services": [{"id": SITE, "name": "fn-orders", "kind": kind, "properties": props}]
    }
    if config is not None:
        data["app_service_configs"] = {SITE: {"properties": config}}
    state = AzureNormalizer().normalize(
        RawSnapshot(provider=Provider.AZURE, tenant_id="t", subscription_id="s", data=data)
    )
    rule = get_rule("AZ-WEB-006")
    assert rule is not None
    resource = next(r for r in state.resources if r.provider_resource_id == SITE)
    result = rule.evaluate(resource, RuleContext(resources=state.resources))
    return (result if isinstance(result, list) else [result])[0].state


ALLOW_ALL = {"ipAddress": "Any", "action": "Allow", "priority": 2147483647, "name": "Allow all"}
ONE_RANGE = {"ipAddress": "203.0.113.0/24", "action": "Allow", "priority": 100, "name": "office"}


@pytest.mark.parametrize(
    ("kind", "config", "props", "expected"),
    [
        ("functionapp", {"ipSecurityRestrictions": [ALLOW_ALL]}, {}, RuleState.FAIL),
        ("functionapp", {"ipSecurityRestrictions": [ONE_RANGE]}, {}, RuleState.PASS),
        (
            "functionapp,linux",
            {"ipSecurityRestrictions": [ONE_RANGE], "ipSecurityRestrictionsDefaultAction": "Allow"},
            {},
            RuleState.FAIL,
        ),
        ("functionapp", None, {}, RuleState.UNKNOWN),
        ("functionapp", None, {"publicNetworkAccess": "Disabled"}, RuleState.PASS),
        # A web app is usually meant to be public; this rule is not about it.
        ("app", {"ipSecurityRestrictions": [ALLOW_ALL]}, {}, RuleState.NOT_APPLICABLE),
    ],
)
def test_a_function_app_is_judged_on_its_access_restrictions(
    kind: str, config: dict[str, Any] | None, props: dict[str, Any], expected: RuleState
) -> None:
    assert site_verdict(kind, config, **props) is expected


def vm_verdict(**os_profile: Any) -> RuleState:
    props: dict[str, Any] = {"storageProfile": {"osDisk": {"osType": "Linux"}}}
    if os_profile:
        props["osProfile"] = os_profile
    state = AzureNormalizer().normalize(
        RawSnapshot(
            provider=Provider.AZURE,
            tenant_id="t",
            subscription_id="s",
            data={"virtual_machines": [{"id": VM, "name": "vm-linux", "properties": props}]},
        )
    )
    rule = get_rule("AZ-CMP-004")
    assert rule is not None
    resource = next(r for r in state.resources if r.provider_resource_id == VM)
    result = rule.evaluate(resource, RuleContext(resources=state.resources))
    return (result if isinstance(result, list) else [result])[0].state


def test_a_linux_machine_is_judged_on_its_ssh_sign_in() -> None:
    assert vm_verdict(linuxConfiguration={"disablePasswordAuthentication": False}) is (
        RuleState.FAIL
    )
    assert vm_verdict(linuxConfiguration={"disablePasswordAuthentication": True}) is (
        RuleState.PASS
    )
    # A machine built from an attached disk has no osProfile at all.
    assert vm_verdict() is RuleState.UNKNOWN
