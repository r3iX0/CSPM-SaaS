"""The compliance controls a native rule could answer and none did
(DECISIONS.md section 204).

Three kinds of assertion. The readings: each small reduction in
``settings_v13`` keeps "not read" apart from "read and empty". The rules: each
passes, fails and declines to judge on what the normalizer makes of a payload.
And the invariant that is the point of the section: every control a scanner can
observe in the Azure and organization frameworks is mapped by some rule, and the
handful of CIS Azure 2.0 controls that are not are exactly the ones no API
exposes.

Payload shapes follow the published ARM and Graph references; nothing here has
been read from a live tenant.
"""

from collections import defaultdict
from datetime import UTC, datetime
from typing import Any

import pytest

from app.compliance.catalog import get_framework
from app.compliance.crosswalk import compliance_mappings_for, crosswalk
from app.connectors.azure import settings_v13 as v13
from app.connectors.azure.normalizer import AzureNormalizer
from app.connectors.azure.settings import subnets_without_nsg
from app.connectors.base import RawSnapshot
from app.core.enums import Level, Provider, ResourceType, RuleState
from app.domain.resource import CloudResource
from app.rules.base import RuleContext
from app.rules.registry import RULE_REGISTRY, get_rule

SUB = "00000000-0000-0000-0000-000000000001"
RG = f"/subscriptions/{SUB}/resourceGroups/rg"
COLLECTED = datetime(2026, 10, 1, tzinfo=UTC)


def normalize(**data: Any) -> list[CloudResource]:
    state = AzureNormalizer().normalize(
        RawSnapshot(
            provider=Provider.AZURE,
            tenant_id="t",
            subscription_id=SUB,
            data=data,
            collected_at=COLLECTED,
        )
    )
    return state.resources


def verdict(rule_id: str, resource: CloudResource) -> RuleState:
    rule = get_rule(rule_id)
    assert rule is not None
    result = rule.evaluate(resource, RuleContext(resources=[resource]))
    return (result if isinstance(result, list) else [result])[0].state


def tenant_verdict(rule_id: str, **data: Any) -> RuleState:
    state = AzureNormalizer().normalize(
        RawSnapshot(provider=Provider.AZURE, tenant_id="t", subscription_id=None, data=data)
    )
    rule = get_rule(rule_id)
    assert rule is not None
    result = rule.evaluate(None, RuleContext(resources=state.resources, controls=state.controls))
    return (result if isinstance(result, list) else [result])[0].state


def one(resources: list[CloudResource], resource_type: ResourceType) -> CloudResource:
    found = [r for r in resources if r.resource_type is resource_type]
    assert len(found) == 1, found
    return found[0]


# ---------------------------------------------------------------- the invariant
FULLY_COVERED = ("CIS_AZURE_6.0", "NIS2", "MITRE_ATTACK", "HIPAA", "GDPR", "NIST_CSF", "PCI_DSS_4")

# What no API exposes, or what Azure retired: SSPR's settings, the legacy
# "remember MFA" toggle and four portal-only Entra switches have no Graph or ARM
# read; the Log Analytics agent and PostgreSQL single server are retired; and
# 9.11 reads application settings behind ``config/list``, which also returns
# secrets (DECISIONS.md section 204, docs/NATIVE_COVERAGE_BACKLOG.md).
CIS_AZURE_2_UNREADABLE = {
    "1.1.4",
    "1.6",
    "1.8",
    "1.9",
    "1.10",
    "1.13",
    "1.17",
    "1.18",
    "1.20",
    "2.1.15",
    "4.3.8",
    "9.11",
}


def _covered() -> dict[str, set[str]]:
    covered: dict[str, set[str]] = defaultdict(set)
    for rule in RULE_REGISTRY:
        for framework, ids in compliance_mappings_for(
            rule.rule_id, rule.compliance_mappings
        ).items():
            covered[framework].update(ids)
    return covered


@pytest.mark.parametrize("framework_id", FULLY_COVERED)
def test_every_observable_control_is_answered_by_a_rule(framework_id: str) -> None:
    framework = get_framework(framework_id)
    assert framework is not None
    covered = _covered()[framework_id]
    gaps = [c.id for c in framework.controls if c.technically_assessable and c.id not in covered]
    assert gaps == [], f"{framework_id} has observable controls no rule answers: {gaps}"


def test_cis_azure_2_leaves_only_what_no_api_exposes() -> None:
    framework = get_framework("CIS_AZURE_2.0")
    assert framework is not None
    covered = _covered()["CIS_AZURE_2.0"]
    gaps = {c.id for c in framework.controls if c.technically_assessable and c.id not in covered}
    assert gaps == CIS_AZURE_2_UNREADABLE


def test_infrastructure_encryption_no_longer_claims_key_rotation_reminders() -> None:
    """CIS Azure 6.0 9.3.1.1 is key rotation reminders. The crosswalk had it on
    the infrastructure encryption rule; it belongs to the key expiry policy."""
    assert "CIS_AZURE_6.0" not in crosswalk().get("AZ-STO-007", {})
    assert crosswalk()["AZ-STO-015"]["CIS_AZURE_6.0"] == ["9.3.1.1"]
    assert crosswalk()["AZ-STO-015"]["CIS_AZURE_2.0"] == ["3.3"]


# ----------------------------------------------------------------- readings
def test_a_defender_extension_is_off_with_its_plan_and_unknown_when_unstated() -> None:
    def plans(tier: str, extensions: Any = None) -> list[dict[str, Any]]:
        props: dict[str, Any] = {"pricingTier": tier}
        if extensions is not None:
            props["extensions"] = extensions
        return [{"name": "VirtualMachines", "properties": props}]

    on = [{"name": "AgentlessVmScanning", "isEnabled": "True"}]
    assert v13.plan_extension(plans("Standard", on), "VirtualMachines", "AgentlessVmScanning")
    assert v13.plan_extension(plans("Free", on), "VirtualMachines", "AgentlessVmScanning") is False
    assert v13.plan_extension(plans("Standard"), "VirtualMachines", "AgentlessVmScanning") is None
    assert v13.plan_extension(None, "VirtualMachines", "AgentlessVmScanning") is None


def test_dns_protection_comes_from_servers_plan_two_since_the_dns_plan_retired() -> None:
    servers = {"name": "VirtualMachines", "properties": {"pricingTier": "Standard"}}
    p1 = {"name": "VirtualMachines", "properties": {"pricingTier": "Standard", "subPlan": "P1"}}
    retired = {"name": "Dns", "properties": {"pricingTier": "Standard", "deprecated": True}}
    assert v13.dns_threat_detection([servers]) is True
    assert v13.dns_threat_detection([p1, retired]) is False


def test_an_unenforced_allowed_locations_assignment_restricts_nothing() -> None:
    definition = (
        "/providers/Microsoft.Authorization/policyDefinitions/e56962a6-4747-49cd-b67b-bf8b01975c4c"
    )
    enforced = {"properties": {"policyDefinitionId": definition}}
    audit_only = {
        "properties": {"policyDefinitionId": definition, "enforcementMode": "DoNotEnforce"}
    }
    assert v13.locations_restricted([enforced]) is True
    assert v13.locations_restricted([audit_only]) is False
    assert v13.locations_restricted(None) is None


def test_key_age_is_judged_as_of_the_capture() -> None:
    props = {"keyCreationTime": {"key1": "2026-01-01T00:00:00Z", "key2": "2026-09-20T00:00:00Z"}}
    assert v13.key_age_days(props, COLLECTED) == 273
    assert v13.key_age_days({}, COLLECTED) is None


def test_a_storage_service_azure_says_does_not_exist_is_not_a_gap() -> None:
    account = {"id": f"{RG}/providers/Microsoft.Storage/storageAccounts/a", "kind": "StorageV2"}
    logged = [
        {
            "properties": {
                "workspaceId": "/w",
                "logs": [{"categoryGroup": "allLogs", "enabled": True}],
            }
        }
    ]
    readings = {
        account["id"]: {
            f"{account['id']}/blobServices/default": logged,
            f"{account['id']}/queueServices/default": [],
            f"{account['id']}/tableServices/default": None,
        }
    }
    assert v13.services_without_logging(account, readings) == ["queue"]
    assert v13.services_without_logging(account, None) is None
    blob_only = {**account, "kind": "BlobStorage"}
    assert v13.storage_services(blob_only) == ("blob",)


def test_a_certificate_lifetime_is_read_from_the_secret_holding_its_key() -> None:
    vault = "/v"
    year = 365 * 86400
    secrets = {
        vault: [
            {
                "name": "long",
                "properties": {
                    "contentType": "application/x-pkcs12",
                    "attributes": {"nbf": 0, "exp": 2 * year},
                },
            },
            {
                "name": "short",
                "properties": {
                    "contentType": "application/x-pkcs12",
                    "attributes": {"nbf": 0, "exp": year},
                },
            },
            {"name": "plain", "properties": {"attributes": {"exp": 9 * year}}},
        ]
    }
    found = v13.certificate_lifetimes(vault, secrets)
    assert found == {
        "certificate_count": 2,
        "holds_certificates": True,
        "long_lived_certificates": ["long"],
    }
    assert v13.certificate_lifetimes(vault, {vault: "error: 403"})["holds_certificates"] is None


def test_reserved_subnets_are_not_asked_for_a_network_security_group() -> None:
    subnets = [
        {"name": "GatewaySubnet", "properties": {}},
        {"name": "app", "properties": {}},
        {"name": "data", "properties": {"networkSecurityGroup": {"id": "/nsg"}}},
    ]
    assert subnets_without_nsg(subnets) == ["app"]


def test_a_lock_on_the_group_protects_what_is_in_it() -> None:
    locks = [
        {
            "id": f"{RG}/providers/Microsoft.Authorization/locks/keep",
            "properties": {"level": "CanNotDelete"},
        },
        {
            "id": f"/subscriptions/{SUB}/resourceGroups/other/providers"
            "/Microsoft.Authorization/locks/note",
            "properties": {"level": "NotSpecified"},
        },
    ]
    scopes = v13.lock_scopes(locks)
    assert v13.delete_locked(f"{RG}/providers/Microsoft.Storage/storageAccounts/a", scopes)
    assert not v13.delete_locked(
        f"/subscriptions/{SUB}/resourceGroups/other/providers/x/y/z", scopes
    )
    assert v13.delete_locked("/x", None) is None


def test_the_any_azure_service_rule_is_the_zero_address_pair() -> None:
    server = "/s"
    rules = {server: [{"properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "0.0.0.0"}}]}
    assert v13.admits_azure_services(server, rules) is True
    assert v13.admits_azure_services(server, {server: []}) is False
    assert v13.admits_azure_services(server, {server: "error: 403"}) is None


def test_a_gateway_tls_floor_is_read_from_its_policy_name() -> None:
    assert v13.gateway_min_tls({"sslPolicy": {"policyName": "AppGwSslPolicy20150501"}}) == "TLSv1_0"
    assert v13.gateway_min_tls({"sslPolicy": {"minProtocolVersion": "TLSv1_2"}}) == "TLSv1_2"
    assert v13.gateway_min_tls({}) is None


# -------------------------------------------------------------------- rules
def test_storage_account_rules_read_the_listing_the_scanner_already_takes() -> None:
    account = {
        "id": f"{RG}/providers/Microsoft.Storage/storageAccounts/a",
        "name": "a",
        "kind": "StorageV2",
        "properties": {
            "keyCreationTime": {"key1": "2025-01-01T00:00:00Z"},
            "networkAcls": {"defaultAction": "Deny"},
        },
    }
    resource = one(normalize(storage_accounts=[account]), ResourceType.STORAGE_ACCOUNT)
    # Shared key access left unset is allowed, as Azure documents.
    assert verdict("AZ-STO-017", resource) is RuleState.FAIL
    assert verdict("AZ-STO-018", resource) is RuleState.FAIL
    # Locks and service settings were never read: not judged.
    assert verdict("AZ-STO-019", resource) is RuleState.UNKNOWN
    assert verdict("AZ-STO-020", resource) is RuleState.UNKNOWN


def test_a_locked_group_passes_the_storage_lock_check() -> None:
    account = {"id": f"{RG}/providers/Microsoft.Storage/storageAccounts/a", "name": "a"}
    locks = [
        {
            "id": f"{RG}/providers/Microsoft.Authorization/locks/keep",
            "properties": {"level": "CanNotDelete"},
        }
    ]
    resource = one(
        normalize(storage_accounts=[account], resource_locks=locks), ResourceType.STORAGE_ACCOUNT
    )
    assert verdict("AZ-STO-019", resource) is RuleState.PASS


def test_application_gateway_rules() -> None:
    policy_id = (
        f"{RG}/providers/Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/p"
    )
    gateway = {
        "id": f"{RG}/providers/Microsoft.Network/applicationGateways/g",
        "name": "g",
        "properties": {
            "firewallPolicy": {"id": policy_id},
            "sslPolicy": {"policyName": "AppGwSslPolicy20170401"},
            "frontendIPConfigurations": [{"properties": {"publicIPAddress": {"id": "/pip"}}}],
        },
    }
    policy = {
        "id": policy_id,
        "properties": {
            "policySettings": {"state": "Enabled", "mode": "Prevention", "requestBodyCheck": False},
            "managedRules": {"managedRuleSets": [{"ruleSetType": "OWASP"}]},
        },
    }
    resource = one(
        normalize(application_gateways=[gateway], waf_policies=[policy]),
        ResourceType.APPLICATION_GATEWAY,
    )
    assert resource.public_exposure is Level.HIGH
    assert verdict("AZ-AGW-001", resource) is RuleState.PASS
    assert verdict("AZ-AGW-002", resource) is RuleState.FAIL
    assert verdict("AZ-AGW-003", resource) is RuleState.FAIL
    assert verdict("AZ-AGW-004", resource) is RuleState.FAIL
    assert verdict("AZ-AGW-005", resource) is RuleState.FAIL


def test_a_gateway_whose_policy_was_not_listed_is_not_judged() -> None:
    gateway = {
        "id": f"{RG}/providers/Microsoft.Network/applicationGateways/g",
        "name": "g",
        "properties": {"firewallPolicy": {"id": "/missing"}},
    }
    resource = one(
        normalize(application_gateways=[gateway], waf_policies=[]),
        ResourceType.APPLICATION_GATEWAY,
    )
    assert verdict("AZ-AGW-001", resource) is RuleState.UNKNOWN


def test_a_vpn_gateway_admits_only_entra_sign_ins() -> None:
    gateway_id = f"{RG}/providers/Microsoft.Network/virtualNetworkGateways/vpn"

    def gateway(*types: str) -> CloudResource:
        payload = {
            "id": gateway_id,
            "name": "vpn",
            "properties": {
                "gatewayType": "Vpn",
                "vpnClientConfiguration": {"vpnAuthenticationTypes": list(types)},
            },
        }
        return one(normalize(vpn_gateways={gateway_id: payload}), ResourceType.VPN_GATEWAY)

    assert verdict("AZ-VPN-001", gateway("AAD")) is RuleState.PASS
    assert verdict("AZ-VPN-001", gateway("AAD", "Certificate")) is RuleState.FAIL


def test_a_vault_open_to_every_network_is_left_to_az_kv_002() -> None:
    vault = {
        "id": f"{RG}/providers/Microsoft.KeyVault/vaults/v",
        "name": "v",
        "properties": {
            "publicNetworkAccess": "Enabled",
            "networkAcls": {"defaultAction": "Allow"},
            "privateEndpointConnections": [],
        },
    }
    resource = one(normalize(key_vaults=[vault]), ResourceType.KEY_VAULT)
    assert verdict("AZ-KV-007", resource) is RuleState.NOT_APPLICABLE
    assert verdict("AZ-KV-008", resource) is RuleState.FAIL


def test_a_postgresql_server_open_to_azure_fails() -> None:
    server_id = f"{RG}/providers/Microsoft.DBforPostgreSQL/flexibleServers/pg"
    rules = {server_id: [{"properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "0.0.0.0"}}]}
    resource = one(
        normalize(
            postgresql_servers=[{"id": server_id, "name": "pg", "properties": {}}],
            postgresql_firewall_rules=rules,
        ),
        ResourceType.POSTGRESQL_SERVER,
    )
    assert verdict("AZ-DB-025", resource) is RuleState.FAIL


def test_the_critical_asset_lock_check_asks_only_of_critical_assets() -> None:
    def asset(criticality: Level, locked: bool | None) -> CloudResource:
        return CloudResource(
            provider_resource_id="/a",
            resource_type=ResourceType.STORAGE_ACCOUNT,
            name="a",
            criticality=criticality,
            metadata={"delete_locked": locked},
        )

    assert verdict("AZ-LCK-001", asset(Level.LOW, False)) is RuleState.NOT_APPLICABLE
    assert verdict("AZ-LCK-001", asset(Level.CRITICAL, False)) is RuleState.FAIL
    assert verdict("AZ-LCK-001", asset(Level.HIGH, True)) is RuleState.PASS
    assert verdict("AZ-LCK-001", asset(Level.HIGH, None)) is RuleState.UNKNOWN


# ------------------------------------------------------------------ tenant
def _ca(**policy: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "state": "enabled",
        "conditions": {"users": {"includeUsers": ["All"]}, "applications": {}},
        "grantControls": {"builtInControls": ["mfa"]},
    }
    base.update(policy)
    return base


def test_risky_sign_ins_must_be_challenged_from_medium_up() -> None:
    medium = _ca(
        conditions={
            "users": {"includeUsers": ["All"]},
            "applications": {"includeApplications": ["All"]},
            "signInRiskLevels": ["high", "medium"],
        }
    )
    high_only = _ca(
        conditions={
            "users": {"includeUsers": ["All"]},
            "applications": {"includeApplications": ["All"]},
            "signInRiskLevels": ["high"],
        }
    )
    assert tenant_verdict("AZ-ID-024", conditional_access_policies=[medium]) is RuleState.PASS
    assert tenant_verdict("AZ-ID-024", conditional_access_policies=[high_only]) is RuleState.FAIL


def test_device_joining_passes_on_either_the_setting_or_a_policy() -> None:
    by_policy = _ca(
        conditions={
            "users": {"includeUsers": ["All"]},
            "applications": {"includeUserActions": ["urn:user:registerdevice"]},
        }
    )
    assert (
        tenant_verdict(
            "AZ-ID-029",
            conditional_access_policies=[by_policy],
            device_registration_policy={"multiFactorAuthConfiguration": "notRequired"},
        )
        is RuleState.PASS
    )
    assert (
        tenant_verdict(
            "AZ-ID-029",
            conditional_access_policies=[],
            device_registration_policy={"multiFactorAuthConfiguration": "required"},
        )
        is RuleState.PASS
    )
    assert (
        tenant_verdict(
            "AZ-ID-029",
            conditional_access_policies=[],
            device_registration_policy={"multiFactorAuthConfiguration": "notRequired"},
        )
        is RuleState.FAIL
    )


def test_an_unset_subscription_policy_blocks_moves_since_may_2026() -> None:
    assert tenant_verdict("AZ-ID-030", subscription_policy={"properties": {}}) is RuleState.PASS
    open_door = {"properties": {"blockSubscriptionsLeavingTenant": False}}
    assert tenant_verdict("AZ-ID-030", subscription_policy=open_door) is RuleState.FAIL


def test_a_banned_password_list_must_be_switched_on_and_non_empty() -> None:
    def settings(check: str, words: str) -> list[dict[str, Any]]:
        return [
            {
                "displayName": "Password Rule Settings",
                "values": [
                    {"name": "EnableBannedPasswordCheck", "value": check},
                    {"name": "BannedPasswordList", "value": words},
                ],
            }
        ]

    assert tenant_verdict("AZ-ID-026", group_settings=settings("True", "contoso")) is RuleState.PASS
    assert tenant_verdict("AZ-ID-026", group_settings=settings("True", "")) is RuleState.FAIL
    assert tenant_verdict("AZ-ID-026", group_settings=[]) is RuleState.FAIL


def test_guest_reviews_count_only_while_active() -> None:
    guests = {"status": "InProgress", "scope": {"query": "/users?$filter=(userType eq 'Guest')"}}
    done = {**guests, "status": "Completed"}
    assert tenant_verdict("AZ-ID-031", access_reviews=[guests]) is RuleState.PASS
    assert tenant_verdict("AZ-ID-031", access_reviews=[done]) is RuleState.FAIL


def test_authenticator_context_fails_only_when_explicitly_hidden() -> None:
    def methods(app: str, location: str) -> dict[str, Any]:
        return {
            "authenticationMethodConfigurations": [
                {
                    "id": "MicrosoftAuthenticator",
                    "state": "enabled",
                    "featureSettings": {
                        "displayAppInformationRequiredState": {"state": app},
                        "displayLocationInformationRequiredState": {"state": location},
                    },
                }
            ]
        }

    assert (
        tenant_verdict("AZ-ID-028", authentication_methods_policy=methods("default", "enabled"))
        is RuleState.PASS
    )
    assert (
        tenant_verdict("AZ-ID-028", authentication_methods_policy=methods("disabled", "default"))
        is RuleState.FAIL
    )
