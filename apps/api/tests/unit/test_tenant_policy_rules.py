"""Tenant policy and MySQL TLS rules, run on what the normalizer makes of a
reading (DECISIONS.md section 172).

Payload shapes follow the published Graph and ARM references; nothing here has
been read from a live tenant.
"""

from typing import Any

import pytest

from app.connectors.azure.normalizer import AzureNormalizer
from app.connectors.base import RawSnapshot
from app.core.enums import Provider, RuleState
from app.rules.azure.identity.tenant_policy import AZURE_MANAGEMENT_APP
from app.rules.base import RuleContext
from app.rules.registry import get_rule


def tenant_verdict(rule_id: str, **data: Any) -> RuleState:
    state = AzureNormalizer().normalize(
        RawSnapshot(provider=Provider.AZURE, tenant_id="t", subscription_id=None, data=data)
    )
    rule = get_rule(rule_id)
    assert rule is not None
    context = RuleContext(resources=state.resources, controls=state.controls)
    result = rule.evaluate(None, context)
    return (result if isinstance(result, list) else [result])[0].state


def policy(**overrides: Any) -> dict[str, Any]:
    """Graph's own sample response, which is the tenant default."""
    base: dict[str, Any] = {
        "id": "authorizationPolicy",
        "allowInvitesFrom": "everyone",
        "guestUserRoleId": "10dae51f-b6af-4016-8d66-8c2a99b929b3",
        "defaultUserRolePermissions": {
            "allowedToCreateApps": False,
            "allowedToCreateSecurityGroups": True,
            "allowedToCreateTenants": True,
            "permissionGrantPoliciesAssigned": [
                "ManagePermissionGrantsForSelf.microsoft-user-default-legacy"
            ],
        },
    }
    for key, value in overrides.items():
        if key in base["defaultUserRolePermissions"]:
            base["defaultUserRolePermissions"][key] = value
        else:
            base[key] = value
    return base


def test_the_graph_sample_tenant_fails_what_its_defaults_leave_open() -> None:
    sample = {"authorization_policy": policy()}
    assert tenant_verdict("AZ-ID-015", **sample) is RuleState.FAIL
    assert tenant_verdict("AZ-ID-016", **sample) is RuleState.PASS
    assert tenant_verdict("AZ-ID-017", **sample) is RuleState.FAIL
    assert tenant_verdict("AZ-ID-018", **sample) is RuleState.FAIL
    assert tenant_verdict("AZ-ID-019", **sample) is RuleState.FAIL


def test_a_hardened_tenant_passes_all_five() -> None:
    hardened = {
        "authorization_policy": policy(
            allowInvitesFrom="adminsAndGuestInviters",
            guestUserRoleId="2af84b1e-32c8-42b7-82bc-daa82404023b",
            allowedToCreateSecurityGroups=False,
            allowedToCreateTenants=False,
            permissionGrantPoliciesAssigned=[
                "ManagePermissionGrantsForSelf.microsoft-user-default-low"
            ],
        )
    }
    for rule_id in ("AZ-ID-015", "AZ-ID-016", "AZ-ID-017", "AZ-ID-018", "AZ-ID-019"):
        assert tenant_verdict(rule_id, **hardened) is RuleState.PASS, rule_id


@pytest.mark.parametrize(
    "rule_id", ["AZ-ID-015", "AZ-ID-016", "AZ-ID-017", "AZ-ID-018", "AZ-ID-019"]
)
def test_an_unread_policy_is_unknown(rule_id: str) -> None:
    assert tenant_verdict(rule_id) is RuleState.UNKNOWN


def ca_policy(apps: list[str], users: list[str] | None = None) -> dict[str, Any]:
    return {
        "id": "p1",
        "displayName": "MFA",
        "state": "enabled",
        "conditions": {
            "users": {"includeUsers": users or ["All"]},
            "applications": {"includeApplications": apps},
        },
        "grantControls": {"operator": "OR", "builtInControls": ["mfa"]},
    }


@pytest.mark.parametrize(
    ("rule_id", "apps", "expected"),
    [
        ("AZ-ID-013", [AZURE_MANAGEMENT_APP], RuleState.PASS),
        ("AZ-ID-013", ["All"], RuleState.PASS),
        ("AZ-ID-013", ["MicrosoftAdminPortals"], RuleState.FAIL),
        ("AZ-ID-014", ["MicrosoftAdminPortals"], RuleState.PASS),
        ("AZ-ID-014", [AZURE_MANAGEMENT_APP], RuleState.FAIL),
    ],
)
def test_a_policy_protects_the_doors_it_names(
    rule_id: str, apps: list[str], expected: RuleState
) -> None:
    data = {
        "security_defaults": {"isEnabled": False},
        "conditional_access_policies": [ca_policy(apps)],
    }
    assert tenant_verdict(rule_id, **data) is expected


def test_a_policy_for_some_users_protects_no_door() -> None:
    data = {
        "security_defaults": {"isEnabled": False},
        "conditional_access_policies": [ca_policy(["All"], users=["user-1"])],
    }
    assert tenant_verdict("AZ-ID-013", **data) is RuleState.FAIL


def test_security_defaults_protect_both_doors() -> None:
    data = {"security_defaults": {"isEnabled": True}, "conditional_access_policies": []}
    assert tenant_verdict("AZ-ID-013", **data) is RuleState.PASS
    assert tenant_verdict("AZ-ID-014", **data) is RuleState.PASS


# --------------------------------------------------------------------- MySQL
SERVER = (
    "/subscriptions/s/resourceGroups/rg/providers/Microsoft.DBforMySQL/flexibleServers/shop"
)


def mysql_verdict(rule_id: str, parameters: dict[str, Any] | str | None) -> RuleState:
    data: dict[str, Any] = {"mysql_servers": [{"id": SERVER, "name": "shop", "properties": {}}]}
    if parameters is not None:
        data["mysql_configurations"] = {SERVER: parameters}
    state = AzureNormalizer().normalize(
        RawSnapshot(provider=Provider.AZURE, tenant_id="t", subscription_id="s", data=data)
    )
    rule = get_rule(rule_id)
    assert rule is not None
    resource = next(r for r in state.resources if r.provider_resource_id == SERVER)
    result = rule.evaluate(resource, RuleContext(resources=state.resources))
    return (result if isinstance(result, list) else [result])[0].state


def parameters(secure: str, tls: str) -> dict[str, Any]:
    return {
        "require_secure_transport": {"properties": {"value": secure}},
        "tls_version": {"properties": {"value": tls}},
    }


@pytest.mark.parametrize(
    ("rule_id", "given", "expected"),
    [
        ("AZ-MYS-001", parameters("ON", "TLSv1.2"), RuleState.PASS),
        ("AZ-MYS-001", parameters("OFF", "TLSv1.2"), RuleState.FAIL),
        ("AZ-MYS-002", parameters("ON", "TLSv1.2,TLSv1.3"), RuleState.PASS),
        ("AZ-MYS-002", parameters("ON", "TLSv1,TLSv1.1,TLSv1.2"), RuleState.FAIL),
        # A role before v10, and a read that failed for this server.
        ("AZ-MYS-001", None, RuleState.UNKNOWN),
        ("AZ-MYS-002", "error: Forbidden", RuleState.UNKNOWN),
    ],
)
def test_a_mysql_server_is_judged_on_its_tls_parameters(
    rule_id: str, given: dict[str, Any] | str | None, expected: RuleState
) -> None:
    assert mysql_verdict(rule_id, given) is expected


# ------------------------------------------------------------ section 173
def methods(*enabled: str, campaign: str = "enabled") -> dict[str, Any]:
    ids = ["MicrosoftAuthenticator", "Fido2", "X509Certificate", "Sms"]
    return {
        "registrationEnforcement": {
            "authenticationMethodsRegistrationCampaign": {"state": campaign}
        },
        "authenticationMethodConfigurations": [
            {"id": i, "state": "enabled" if i in enabled else "disabled"} for i in ids
        ],
    }


@pytest.mark.parametrize(
    ("policy_", "expected"),
    [
        (methods("MicrosoftAuthenticator"), RuleState.PASS),
        (methods("Fido2", campaign="default"), RuleState.PASS),
        (methods("Sms"), RuleState.FAIL),
        (methods("MicrosoftAuthenticator", campaign="disabled"), RuleState.FAIL),
    ],
)
def test_strong_methods_and_the_campaign(policy_: dict[str, Any], expected: RuleState) -> None:
    assert tenant_verdict("AZ-ID-020", authentication_methods_policy=policy_) is expected
    assert tenant_verdict("AZ-ID-020") is RuleState.UNKNOWN


def unified(value: str) -> list[dict[str, Any]]:
    return [
        {
            "displayName": "Group.Unified",
            "values": [{"name": "EnableGroupCreation", "value": value}],
        }
    ]


def test_group_creation_is_open_until_the_setting_says_otherwise() -> None:
    # No Group.Unified setting is the tenant default, which lets everyone create.
    assert tenant_verdict("AZ-ID-021", group_settings=[]) is RuleState.FAIL
    assert tenant_verdict("AZ-ID-021", group_settings=unified("true")) is RuleState.FAIL
    assert tenant_verdict("AZ-ID-021", group_settings=unified("false")) is RuleState.PASS
    assert tenant_verdict("AZ-ID-021") is RuleState.UNKNOWN

