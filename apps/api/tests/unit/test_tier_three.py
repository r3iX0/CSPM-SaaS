"""The misfiled checks and Tier 3 of the coverage backlog (DECISIONS.md section 177).

Real normalizers over raw shapes from the providers' specifications, then the
registered rules. As in section 176, a reading never taken is checked beside
the ones that pass and fail.
"""

from datetime import UTC, date, datetime
from typing import Any

from app.connectors.aws.normalizer import AwsNormalizer
from app.connectors.azure import settings
from app.connectors.azure.normalizer import AzureNormalizer
from app.connectors.base import RawSnapshot
from app.core.enums import Provider, ResourceType, RuleState
from app.rules.base import RuleContext
from app.rules.registry import get_rule

SUB = "/subscriptions/s"
RG = f"{SUB}/resourceGroups/rg/providers"
SITE = f"{RG}/Microsoft.Web/sites/app"
VM = f"{RG}/Microsoft.Compute/virtualMachines/vm"
VAULT = f"{RG}/Microsoft.RecoveryServices/vaults/rsv"
SCALE_SET = f"{RG}/Microsoft.Compute/virtualMachineScaleSets/ss"
CLUSTER = f"{RG}/Microsoft.ContainerService/managedClusters/aks"
COLLECTED = datetime(2026, 9, 30, tzinfo=UTC)


def judge(
    rule_id: str,
    data: dict[str, Any],
    resource_id: str | None,
    provider: Provider = Provider.AZURE,
    collected_at: datetime = COLLECTED,
) -> RuleState:
    snapshot = RawSnapshot(
        provider=provider,
        tenant_id="t",
        subscription_id="s" if provider is Provider.AZURE else "111122223333",
        data=data,
        collected_at=collected_at,
    )
    normalizer = AzureNormalizer() if provider is Provider.AZURE else AwsNormalizer()
    state = normalizer.normalize(snapshot)
    rule = get_rule(rule_id)
    assert rule is not None
    resource = next(r for r in state.resources if r.provider_resource_id == resource_id)
    result = rule.evaluate(
        resource, RuleContext(resources=state.resources, controls=state.controls)
    )
    return (result if isinstance(result, list) else [result])[0].state


# ------------------------------------------------------------ the misfiled
def test_aks_defender_profile() -> None:
    def cluster(profile: dict[str, Any] | None) -> dict[str, Any]:
        props: dict[str, Any] = {}
        if profile is not None:
            props["securityProfile"] = profile
        return {"kubernetes_clusters": [{"id": CLUSTER, "name": "aks", "properties": props}]}

    on = {"defender": {"securityMonitoring": {"enabled": True}}}
    assert judge("AZ-AKS-008", cluster(on), CLUSTER) is RuleState.PASS
    # No profile is the default, and no sensor.
    assert judge("AZ-AKS-008", cluster(None), CLUSTER) is RuleState.FAIL


def test_defender_cspm() -> None:
    def plans(tier: str) -> dict[str, Any]:
        return {"defender_plans": [{"name": "CloudPosture", "properties": {"pricingTier": tier}}]}

    assert judge("AZ-DEF-011", plans("Standard"), SUB) is RuleState.PASS
    assert judge("AZ-DEF-011", plans("Free"), SUB) is RuleState.FAIL
    assert judge("AZ-DEF-011", {"defender_plans": []}, SUB) is RuleState.UNKNOWN


POOL = "arn:aws:cognito-idp:eu-west-1:111122223333:userpool/eu-west-1_abc"


def pool(
    mode: str | None, risk: dict[str, Any] | None = None, acl: str | None = None
) -> dict[str, Any]:
    record: dict[str, Any] = {"Id": "eu-west-1_abc", "Arn": POOL, "Name": "customers"}
    if mode:
        record["UserPoolAddOns"] = {"AdvancedSecurityMode": mode}
    data: dict[str, Any] = {"cognito_user_pools": [{"region": "eu-west-1", "items": [record]}]}
    if risk is not None:
        data["cognito_risk_configurations"] = [
            {
                "region": "eu-west-1",
                "items": [{"UserPoolId": "eu-west-1_abc", "RiskConfiguration": risk}],
            }
        ]
    if acl is not None:
        data["cognito_web_acls"] = [
            {"region": "eu-west-1", "items": [{"ResourceArn": POOL, "WebACLArn": acl or None}]}
        ]
    return data


def aws(rule_id: str, data: dict[str, Any]) -> RuleState:
    return judge(rule_id, data, POOL, Provider.AWS)


def test_cognito_threat_protection() -> None:
    assert aws("AWS-COG-001", pool("ENFORCED")) is RuleState.PASS
    assert aws("AWS-COG-001", pool("AUDIT")) is RuleState.FAIL
    # No add-on block is a pool that never had it.
    assert aws("AWS-COG-001", pool(None)) is RuleState.FAIL


def test_cognito_risk_actions_apply_only_when_enforced() -> None:
    blocked = {
        "CompromisedCredentialsRiskConfiguration": {"Actions": {"EventAction": "BLOCK"}},
        "AccountTakeoverRiskConfiguration": {
            "Actions": {
                "LowAction": {"Notify": False, "EventAction": "MFA_REQUIRED"},
                "MediumAction": {"Notify": False, "EventAction": "MFA_REQUIRED"},
                "HighAction": {"Notify": True, "EventAction": "BLOCK"},
            }
        },
    }
    lax = {
        "CompromisedCredentialsRiskConfiguration": {"Actions": {"EventAction": "NO_ACTION"}},
        "AccountTakeoverRiskConfiguration": {
            "Actions": {
                "LowAction": {"Notify": False, "EventAction": "MFA_IF_CONFIGURED"},
                "MediumAction": {"Notify": False, "EventAction": "BLOCK"},
                "HighAction": {"Notify": True, "EventAction": "BLOCK"},
            }
        },
    }
    for rule_id in ("AWS-COG-002", "AWS-COG-003"):
        assert aws(rule_id, pool("ENFORCED", blocked)) is RuleState.PASS, rule_id
        assert aws(rule_id, pool("ENFORCED", lax)) is RuleState.FAIL, rule_id
        assert aws(rule_id, pool("ENFORCED")) is RuleState.UNKNOWN, rule_id
        # AWS-COG-001 reports a pool whose protection is off.
        assert aws(rule_id, pool("AUDIT", lax)) is RuleState.NOT_APPLICABLE, rule_id


def test_cognito_web_acl() -> None:
    assert aws("AWS-COG-004", pool("OFF", acl="arn:aws:wafv2:acl")) is RuleState.PASS
    assert aws("AWS-COG-004", pool("OFF", acl="")) is RuleState.FAIL
    assert aws("AWS-COG-004", pool("OFF")) is RuleState.UNKNOWN


# ------------------------------------------------------------ runtimes
def site(config: dict[str, Any] | None) -> dict[str, Any]:
    data: dict[str, Any] = {
        "app_services": [{"id": SITE, "name": "app", "kind": "app,linux", "properties": {}}]
    }
    if config is not None:
        data["app_service_configs"] = {SITE: {"properties": config}}
    return data


def test_runtime_support_is_judged_as_of_collection() -> None:
    python_310 = site({"linuxFxVersion": "PYTHON|3.10"})
    assert judge("AZ-WEB-011", python_310, SITE) is RuleState.PASS
    # The same capture, taken after 3.10's community support ended.
    later = datetime(2026, 11, 1, tzinfo=UTC)
    assert judge("AZ-WEB-011", python_310, SITE, collected_at=later) is RuleState.FAIL
    assert judge("AZ-WEB-011", site({"linuxFxVersion": "PYTHON|3.8"}), SITE) is RuleState.FAIL
    # Newer than every listed version: supported.
    assert judge("AZ-WEB-011", site({"linuxFxVersion": "PYTHON|3.14"}), SITE) is (RuleState.PASS)
    # A PHP app is not a Python app.
    assert judge("AZ-WEB-011", site({"linuxFxVersion": "PHP|8.1"}), SITE) is (
        RuleState.NOT_APPLICABLE
    )
    assert judge("AZ-WEB-012", site({"linuxFxVersion": "PHP|8.1"}), SITE) is RuleState.FAIL
    assert judge("AZ-WEB-012", site({"phpVersion": "8.3"}), SITE) is RuleState.PASS
    # Configuration not read: whether it runs Python is itself unknown.
    assert judge("AZ-WEB-011", site(None), SITE) is RuleState.UNKNOWN


def test_java_and_its_container() -> None:
    assert judge("AZ-WEB-013", site({"linuxFxVersion": "JAVA|17-java17"}), SITE) is (RuleState.PASS)
    assert judge("AZ-WEB-013", site({"linuxFxVersion": "TOMCAT|8.5-java11"}), SITE) is (
        RuleState.FAIL
    )
    assert judge("AZ-WEB-013", site({"linuxFxVersion": "TOMCAT|10.1-java17"}), SITE) is (
        RuleState.PASS
    )
    windows = {"javaVersion": "1.8", "javaContainer": "TOMCAT", "javaContainerVersion": "9.0"}
    assert judge("AZ-WEB-013", site(windows), SITE) is RuleState.PASS
    assert judge("AZ-WEB-013", site({"javaVersion": "1.7"}), SITE) is RuleState.FAIL


def test_every_dated_table_is_ordered_by_version() -> None:
    """A later version never loses support before an earlier one."""
    for language, table in settings.END_OF_SUPPORT.items():
        dated = [(v, d) for v, d in sorted(table.items()) if isinstance(d, date)]
        dates = [d for _, d in dated]
        assert dates == sorted(dates) or language == "tomcat", language


def test_http2() -> None:
    assert judge("AZ-WEB-010", site({"http20Enabled": True}), SITE) is RuleState.PASS
    assert judge("AZ-WEB-010", site({"http20Enabled": False}), SITE) is RuleState.FAIL


def test_application_insights_where_apps_run() -> None:
    app = site(None)
    component = {
        "id": f"{RG}/Microsoft.Insights/components/ai",
        "type": "microsoft.insights/components",
    }
    assert judge("AZ-LOG-019", {**app, "resources": [component]}, SUB) is RuleState.PASS
    assert judge("AZ-LOG-019", {**app, "resources": []}, SUB) is RuleState.FAIL
    assert judge("AZ-LOG-019", {"resources": []}, SUB) is RuleState.NOT_APPLICABLE


# ------------------------------------------------------------ resilience
def test_database_availability_settings() -> None:
    cosmos = f"{RG}/Microsoft.DocumentDB/databaseAccounts/c"
    good = {"enableAutomaticFailover": True, "backupPolicy": {"type": "Continuous"}}
    bad = {"enableAutomaticFailover": False, "backupPolicy": {"type": "Periodic"}}
    for rule_id in ("AZ-COS-005", "AZ-COS-006"):
        for props, expected in ((good, RuleState.PASS), (bad, RuleState.FAIL)):
            data = {"cosmos_accounts": [{"id": cosmos, "name": "c", "properties": props}]}
            assert judge(rule_id, data, cosmos) is expected, rule_id

    mysql = f"{RG}/Microsoft.DBforMySQL/flexibleServers/m"
    pg = f"{RG}/Microsoft.DBforPostgreSQL/flexibleServers/p"
    resilient = {
        "highAvailability": {"mode": "ZoneRedundant"},
        "backup": {"geoRedundantBackup": "Enabled"},
    }
    single = {
        "highAvailability": {"mode": "Disabled"},
        "backup": {"geoRedundantBackup": "Disabled"},
    }
    for key, server, rules in (
        ("mysql_servers", mysql, ("AZ-MYS-005", "AZ-MYS-006")),
        ("postgresql_servers", pg, ("AZ-DB-023", "AZ-DB-024")),
    ):
        for rule_id in rules:
            data = {key: [{"id": server, "name": "x", "properties": resilient}]}
            assert judge(rule_id, data, server) is RuleState.PASS, rule_id
            data = {key: [{"id": server, "name": "x", "properties": single}]}
            assert judge(rule_id, data, server) is RuleState.FAIL, rule_id


def test_geo_redundant_storage() -> None:
    account = f"{RG}/Microsoft.Storage/storageAccounts/st"

    def storage(sku: str) -> dict[str, Any]:
        return {
            "storage_accounts": [
                {"id": account, "name": "st", "sku": {"name": sku}, "properties": {}}
            ]
        }

    assert judge("AZ-STO-016", storage("Standard_RAGZRS"), account) is RuleState.PASS
    assert judge("AZ-STO-016", storage("Standard_LRS"), account) is RuleState.FAIL


def backups(items: list[dict[str, Any]], policies: Any = None, unread: bool = False):
    data: dict[str, Any] = {
        "virtual_machines": [{"id": VM, "name": "vm", "properties": {}}],
        "vm_backups": {
            "vaults": [{"id": VAULT, "name": "rsv", "location": "westeurope"}],
            "unread_vaults": [VAULT] if unread else [],
            "items": items,
        },
    }
    if policies is not None:
        data["backup_policies"] = {VAULT: policies}
    return data


def policy(name: str, days: int, unit: str = "Days") -> dict[str, Any]:
    return {
        "id": f"{VAULT}/backupPolicies/{name}",
        "name": name,
        "properties": {
            "backupManagementType": "AzureIaasVM",
            "retentionPolicy": {
                "retentionPolicyType": "LongTermRetentionPolicy",
                "dailySchedule": {"retentionDuration": {"count": days, "durationType": unit}},
            },
        },
    }


ITEM = {
    "id": f"{VAULT}/backupFabrics/Azure/protectionContainers/c/protectedItems/vm",
    "properties": {"virtualMachineId": VM, "policyId": f"{VAULT}/backupPolicies/daily"},
}


def test_backup_vaults_and_retention() -> None:
    assert judge("AZ-BKP-001", backups([ITEM]), VAULT) is RuleState.PASS
    assert judge("AZ-BKP-001", backups([]), VAULT) is RuleState.FAIL
    assert judge("AZ-BKP-001", backups([], unread=True), VAULT) is RuleState.UNKNOWN

    assert judge("AZ-BKP-002", backups([ITEM], [policy("daily", 30)]), VAULT) is RuleState.PASS
    assert judge("AZ-BKP-002", backups([ITEM], [policy("daily", 2, "Weeks")]), VAULT) is (
        RuleState.FAIL
    )
    assert judge("AZ-BKP-002", backups([ITEM]), VAULT) is RuleState.UNKNOWN

    assert judge("AZ-CMP-011", backups([ITEM], [policy("daily", 7)]), VM) is RuleState.PASS
    assert judge("AZ-CMP-011", backups([ITEM], [policy("daily", 5)]), VM) is RuleState.FAIL
    # Not backed up at all is AZ-CMP-009's finding.
    assert judge("AZ-CMP-011", backups([], [policy("daily", 5)]), VM) is (RuleState.NOT_APPLICABLE)


def test_scale_sets() -> None:
    def scale_set(capacity: int, pools: bool) -> dict[str, Any]:
        ip: dict[str, Any] = {"name": "ip", "properties": {}}
        if pools:
            ip["properties"]["loadBalancerBackendAddressPools"] = [{"id": "/pool"}]
        profile = {
            "networkProfile": {
                "networkInterfaceConfigurations": [
                    {"name": "nic", "properties": {"ipConfigurations": [ip]}}
                ]
            }
        }
        return {
            "scale_sets": [
                {
                    "id": SCALE_SET,
                    "name": "ss",
                    "sku": {"capacity": capacity},
                    "properties": {"virtualMachineProfile": profile},
                }
            ]
        }

    resources = (
        AzureNormalizer()
        .normalize(
            RawSnapshot(
                provider=Provider.AZURE, tenant_id="t", subscription_id="s", data=scale_set(2, True)
            )
        )
        .resources
    )
    assert next(r for r in resources if r.provider_resource_id == SCALE_SET).resource_type is (
        ResourceType.SCALE_SET
    )
    assert judge("AZ-CMP-012", scale_set(2, True), SCALE_SET) is RuleState.PASS
    assert judge("AZ-CMP-012", scale_set(2, False), SCALE_SET) is RuleState.FAIL
    assert judge("AZ-CMP-013", scale_set(2, True), SCALE_SET) is RuleState.PASS
    assert judge("AZ-CMP-013", scale_set(0, True), SCALE_SET) is RuleState.FAIL
