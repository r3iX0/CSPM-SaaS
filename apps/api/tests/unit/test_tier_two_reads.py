"""The reads role v11 added, and the rules over them (DECISIONS.md section 176).

Each case runs the real normalizer over raw ARM and Graph shapes taken from the
providers' REST specifications, then the registered rule. A reading that was
never taken is always checked beside the ones that pass and fail: UNKNOWN is
the answer the whole engine is built to keep apart from PASS.
"""

from typing import Any

import pytest

from app.connectors.azure.normalizer import AzureNormalizer
from app.connectors.base import RawSnapshot
from app.core.enums import Provider, ResourceType, RuleState
from app.rules.base import RuleContext
from app.rules.registry import get_rule

SUB = "/subscriptions/s"
ACCOUNT = f"{SUB}/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st"
VAULT = f"{SUB}/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv"
SERVER = f"{SUB}/resourceGroups/rg/providers/Microsoft.Sql/servers/sql"
VM = f"{SUB}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
DISK = f"{SUB}/resourceGroups/rg/providers/Microsoft.Compute/disks/data-1"
VNET = f"{SUB}/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet"
NSG = f"{SUB}/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg"
WATCHER = f"{SUB}/resourceGroups/NetworkWatcherRG/providers/Microsoft.Network/networkWatchers/nw"
SITE = f"{SUB}/resourceGroups/rg/providers/Microsoft.Web/sites/app"


def verdicts(
    data: dict[str, Any], errors: dict[str, str] | None = None
) -> tuple[list[Any], RuleContext]:
    state = AzureNormalizer().normalize(
        RawSnapshot(provider=Provider.AZURE, tenant_id="t", subscription_id="s", data=data)
    )
    return state.resources, RuleContext(
        resources=state.resources,
        controls=state.controls,
        collection_errors=errors or {},
    )


def judge(
    rule_id: str,
    data: dict[str, Any],
    resource_id: str | None = SUB,
    errors: dict[str, str] | None = None,
) -> RuleState:
    resources, context = verdicts(data, errors)
    rule = get_rule(rule_id)
    assert rule is not None
    resource = (
        next(r for r in resources if r.provider_resource_id == resource_id) if resource_id else None
    )
    result = rule.evaluate(resource, context)
    return (result if isinstance(result, list) else [result])[0].state


# ------------------------------------------------------------ Defender
def contact(**props: Any) -> dict[str, Any]:
    return {"security_contacts": [{"name": "default", "properties": props}]}


def test_security_contact_rules() -> None:
    good = contact(
        emails="secops@contoso.com;soc@contoso.com",
        isEnabled=True,
        notificationsByRole={"state": "On", "roles": ["Owner", "Admin"]},
        notificationsSources=[
            {"sourceType": "Alert", "minimalSeverity": "High"},
            {"sourceType": "AttackPath", "minimalRiskLevel": "Medium"},
        ],
    )
    for rule_id in ("AZ-DEF-002", "AZ-DEF-003", "AZ-DEF-004", "AZ-DEF-005"):
        assert judge(rule_id, good) is RuleState.PASS, rule_id
        # Nothing read: not a subscription with no contact.
        assert judge(rule_id, {}) is RuleState.UNKNOWN, rule_id
        # A listing that arrived empty is one with no contact at all.
        assert judge(rule_id, {"security_contacts": []}) is RuleState.FAIL, rule_id

    critical_only = contact(
        emails="a@b.c",
        notificationsSources=[{"sourceType": "AttackPath", "minimalRiskLevel": "Critical"}],
    )
    assert judge("AZ-DEF-005", critical_only) is RuleState.FAIL
    disabled = contact(isEnabled=False, emails="a@b.c")
    assert judge("AZ-DEF-002", disabled) is RuleState.FAIL
    roles_off = contact(notificationsByRole={"state": "Off", "roles": ["Owner"]})
    assert judge("AZ-DEF-004", roles_off) is RuleState.FAIL


def test_defender_integrations() -> None:
    def settings(wdatp: bool, mcas: bool) -> dict[str, Any]:
        return {
            "security_settings": [
                {"name": "WDATP", "kind": "DataExportSettings", "properties": {"enabled": wdatp}},
                {"name": "MCAS", "kind": "DataExportSettings", "properties": {"enabled": mcas}},
            ]
        }

    assert judge("AZ-DEF-006", settings(True, False)) is RuleState.PASS
    assert judge("AZ-DEF-007", settings(True, False)) is RuleState.FAIL
    assert judge("AZ-DEF-006", {"security_settings": []}) is RuleState.UNKNOWN


def test_container_image_scanning_needs_the_plan_and_the_extension() -> None:
    def plans(tier: str, extensions: list[dict[str, Any]] | None) -> dict[str, Any]:
        props: dict[str, Any] = {"pricingTier": tier}
        if extensions is not None:
            props["extensions"] = extensions
        return {"defender_plans": [{"name": "Containers", "properties": props}]}

    scanning = [{"name": "ContainerRegistriesVulnerabilityAssessments", "isEnabled": "True"}]
    off = [{"name": "ContainerRegistriesVulnerabilityAssessments", "isEnabled": "False"}]
    assert judge("AZ-DEF-008", plans("Standard", scanning)) is RuleState.PASS
    assert judge("AZ-DEF-008", plans("Standard", off)) is RuleState.FAIL
    assert judge("AZ-DEF-008", plans("Free", scanning)) is RuleState.FAIL
    assert judge("AZ-DEF-008", plans("Standard", None)) is RuleState.UNKNOWN


def test_security_benchmark_enforcement() -> None:
    def assigned(mode: str | None) -> dict[str, Any]:
        props: dict[str, Any] = {
            "policyDefinitionId": "/providers/Microsoft.Authorization/policySetDefinitions/"
            "1f3afdf9-d0c9-4c3d-847f-89da613e70a8"
        }
        if mode:
            props["enforcementMode"] = mode
        return {"policy_assignments": [{"name": "SecurityCenterBuiltIn", "properties": props}]}

    assert judge("AZ-DEF-010", assigned("Default")) is RuleState.PASS
    # ARM's default when the field is left out.
    assert judge("AZ-DEF-010", assigned(None)) is RuleState.PASS
    assert judge("AZ-DEF-010", assigned("DoNotEnforce")) is RuleState.FAIL
    assert judge("AZ-DEF-010", {"policy_assignments": []}) is RuleState.FAIL


def test_iot_hubs_are_judged_only_where_there_are_hubs() -> None:
    hub = f"{SUB}/resourceGroups/rg/providers/Microsoft.Devices/IotHubs/hub"
    inventory = {"resources": [{"id": hub, "type": "Microsoft.Devices/IotHubs", "name": "hub"}]}
    watched = {
        "iot_security_solutions": [{"properties": {"status": "Enabled", "iotHubs": [hub.upper()]}}]
    }
    assert judge("AZ-DEF-009", {"resources": [], **watched}) is RuleState.NOT_APPLICABLE
    assert judge("AZ-DEF-009", {**inventory, **watched}) is RuleState.PASS
    assert judge("AZ-DEF-009", {**inventory, "iot_security_solutions": []}) is RuleState.FAIL
    assert judge("AZ-DEF-009", inventory) is RuleState.UNKNOWN


def test_a_machine_with_no_vulnerability_assessment() -> None:
    def assessed(*names: str) -> dict[str, Any]:
        return {
            "virtual_machines": [{"id": VM, "name": "vm", "properties": {}}],
            "security_assessments": [
                {
                    "name": name,
                    "properties": {
                        "status": {"code": "Unhealthy"},
                        "resourceDetails": {"Id": VM},
                        "displayName": "Machines should have a vulnerability assessment solution",
                        "metadata": {"severity": "High"},
                    },
                }
                for name in names
            ],
        }

    missing = "ffff0522-1e88-47fc-8382-2a80ba848f5d"
    assert judge("AZ-VULN-002", assessed(missing), VM) is RuleState.FAIL
    assert judge("AZ-VULN-002", assessed("other"), VM) is RuleState.PASS
    # Having no scanner is not a vulnerability found, so it no longer raises
    # AZ-VULN-001's finding on an internet-facing machine.
    resources, context = verdicts(assessed(missing))
    machine = next(r for r in resources if r.provider_resource_id == VM)
    machine.metadata["has_public_ip"] = True
    rule = get_rule("AZ-VULN-001")
    assert rule is not None
    result = rule.evaluate(machine, context)
    assert (result if isinstance(result, list) else [result])[0].state is not RuleState.FAIL


# ------------------------------------------------------------ alerts
def alert(*operations: str, scope: str = SUB, enabled: bool = True) -> dict[str, Any]:
    return {
        "name": "a",
        "properties": {
            "enabled": enabled,
            "scopes": [scope],
            "condition": {
                "allOf": [
                    {"field": "category", "equals": "Administrative"},
                    {"anyOf": [{"field": "operationName", "equals": op} for op in operations]},
                ]
            },
        },
    }


@pytest.mark.parametrize(
    ("rule_id", "operation"),
    [
        ("AZ-LOG-005", "Microsoft.Authorization/policyAssignments/write"),
        ("AZ-LOG-006", "Microsoft.Authorization/policyAssignments/delete"),
        ("AZ-LOG-007", "Microsoft.Network/networkSecurityGroups/write"),
        ("AZ-LOG-008", "Microsoft.Network/networkSecurityGroups/delete"),
        ("AZ-LOG-009", "Microsoft.Security/securitySolutions/write"),
        ("AZ-LOG-010", "Microsoft.Security/securitySolutions/delete"),
        ("AZ-LOG-011", "Microsoft.Sql/servers/firewallRules/write"),
        ("AZ-LOG-012", "Microsoft.Sql/servers/firewallRules/delete"),
        ("AZ-LOG-013", "Microsoft.Network/publicIPAddresses/write"),
        ("AZ-LOG-014", "Microsoft.Network/publicIPAddresses/delete"),
    ],
)
def test_each_operation_needs_its_own_subscription_wide_alert(rule_id: str, operation: str) -> None:
    assert judge(rule_id, {"activity_log_alerts": [alert(operation.upper())]}) is RuleState.PASS
    assert judge(rule_id, {"activity_log_alerts": [alert("x/y/write")]}) is RuleState.FAIL
    group = f"{SUB}/resourceGroups/rg"
    assert (
        judge(rule_id, {"activity_log_alerts": [alert(operation, scope=group)]}) is RuleState.FAIL
    )
    assert (
        judge(rule_id, {"activity_log_alerts": [alert(operation, enabled=False)]}) is RuleState.FAIL
    )
    assert judge(rule_id, {}) is RuleState.UNKNOWN


def test_service_health_alert() -> None:
    health = {
        "properties": {
            "scopes": [SUB],
            "condition": {"allOf": [{"field": "category", "equals": "ServiceHealth"}]},
        }
    }
    assert judge("AZ-LOG-015", {"activity_log_alerts": [health]}) is RuleState.PASS
    assert judge("AZ-LOG-015", {"activity_log_alerts": []}) is RuleState.FAIL


def export(*categories: str, account: str | None = None) -> dict[str, Any]:
    props: dict[str, Any] = {
        "logs": [{"category": c, "enabled": True} for c in categories],
    }
    props["storageAccountId" if account else "workspaceId"] = account or "/ws"
    return {"diagnostic_settings": {SUB: [{"name": "export", "properties": props}]}}


def test_activity_log_categories() -> None:
    four = ("Administrative", "Security", "Alert", "Policy")
    assert judge("AZ-LOG-016", export(*four)) is RuleState.PASS
    assert judge("AZ-LOG-016", export("Administrative", "Security")) is RuleState.FAIL
    assert judge("AZ-LOG-016", {}) is RuleState.UNKNOWN


def test_activity_log_storage_rules_apply_to_that_account_alone() -> None:
    def account(**props: Any) -> dict[str, Any]:
        return {"storage_accounts": [{"id": ACCOUNT, "name": "st", "properties": props}]}

    kept_here = export("Administrative", account=ACCOUNT)
    private_cmk = account(
        allowBlobPublicAccess=False, encryption={"keySource": "Microsoft.Keyvault"}
    )
    assert judge("AZ-LOG-017", {**private_cmk, **kept_here}, ACCOUNT) is RuleState.PASS
    assert judge("AZ-LOG-018", {**private_cmk, **kept_here}, ACCOUNT) is RuleState.PASS
    public = account(allowBlobPublicAccess=True, encryption={"keySource": "Microsoft.Storage"})
    assert judge("AZ-LOG-017", {**public, **kept_here}, ACCOUNT) is RuleState.FAIL
    assert judge("AZ-LOG-018", {**public, **kept_here}, ACCOUNT) is RuleState.FAIL
    elsewhere = export("Administrative")
    assert judge("AZ-LOG-018", {**public, **elsewhere}, ACCOUNT) is RuleState.NOT_APPLICABLE


# ------------------------------------------------------------ storage
def storage(kind: str = "StorageV2", files: dict[str, Any] | None = None, **props: Any):
    data: dict[str, Any] = {
        "storage_accounts": [{"id": ACCOUNT, "name": "st", "kind": kind, "properties": props}]
    }
    if files is not None:
        data["storage_file_services"] = {ACCOUNT: {"properties": files}}
    return data


def test_file_share_settings() -> None:
    hardened = {
        "shareDeleteRetentionPolicy": {"enabled": True, "days": 7},
        "protocolSettings": {"smb": {"versions": "SMB3.1.1", "channelEncryption": "AES-256-GCM"}},
    }
    for rule_id in ("AZ-STO-012", "AZ-STO-013", "AZ-STO-014"):
        assert judge(rule_id, storage(files=hardened), ACCOUNT) is RuleState.PASS, rule_id
        # Unset: soft delete off, and every SMB version and cipher allowed.
        assert judge(rule_id, storage(files={}), ACCOUNT) is RuleState.FAIL, rule_id
        assert judge(rule_id, storage(), ACCOUNT) is RuleState.UNKNOWN, rule_id
        assert judge(rule_id, storage("BlockBlobStorage"), ACCOUNT) is RuleState.NOT_APPLICABLE, (
            rule_id
        )


def test_access_key_expiry() -> None:
    assert (
        judge("AZ-STO-015", storage(keyPolicy={"keyExpirationPeriodInDays": 90}), ACCOUNT)
        is RuleState.PASS
    )
    assert (
        judge("AZ-STO-015", storage(keyPolicy={"keyExpirationPeriodInDays": 365}), ACCOUNT)
        is RuleState.FAIL
    )
    # No policy is the default, and the finding.
    assert judge("AZ-STO-015", storage(), ACCOUNT) is RuleState.FAIL


# ------------------------------------------------------------ vaults
def vault(keys: list[dict[str, Any]] | None, secrets: list[dict[str, Any]] | None):
    data: dict[str, Any] = {"key_vaults": [{"id": VAULT, "name": "kv", "properties": {}}]}
    if keys is not None:
        data["key_vault_keys"] = {VAULT: keys}
    if secrets is not None:
        data["key_vault_secrets"] = {VAULT: secrets}
    return data


def item(name: str, enabled: bool = True, exp: int | None = None, **props: Any):
    attributes: dict[str, Any] = {"enabled": enabled}
    if exp:
        attributes["exp"] = exp
    return {"name": name, "properties": {"attributes": attributes, **props}}


ROTATES = {"lifetimeActions": [{"action": {"type": "rotate"}}]}
NOTIFIES = {"lifetimeActions": [{"action": {"type": "notify"}}]}


def test_vault_contents() -> None:
    assert judge("AZ-KV-004", vault([item("k", exp=1)], None), VAULT) is RuleState.PASS
    assert judge("AZ-KV-004", vault([item("k")], None), VAULT) is RuleState.FAIL
    # A disabled key cannot be used, so its expiry does not matter.
    assert judge("AZ-KV-004", vault([item("k", enabled=False)], None), VAULT) is RuleState.PASS
    assert judge("AZ-KV-004", vault(None, None), VAULT) is RuleState.UNKNOWN

    assert judge("AZ-KV-005", vault(None, [item("s", exp=1)]), VAULT) is RuleState.PASS
    assert judge("AZ-KV-005", vault(None, [item("s")]), VAULT) is RuleState.FAIL

    rotating = item("k", rotationPolicy=ROTATES)
    assert judge("AZ-KV-006", vault([rotating], None), VAULT) is RuleState.PASS
    notifying = item("k", rotationPolicy=NOTIFIES)
    assert judge("AZ-KV-006", vault([notifying], None), VAULT) is RuleState.FAIL
    # A record stating no rotation policy is not read as a key that never
    # rotates, unless another key is known not to.
    assert judge("AZ-KV-006", vault([item("k")], None), VAULT) is RuleState.UNKNOWN
    assert judge("AZ-KV-006", vault([item("k"), notifying], None), VAULT) is RuleState.FAIL


# ------------------------------------------------------------ SQL
def sql(**readings: Any) -> dict[str, Any]:
    data: dict[str, Any] = {"sql_servers": [{"id": SERVER, "name": "sql", "properties": {}}]}
    data.update({key: {SERVER: value} for key, value in readings.items()})
    return data


def test_encryption_protector() -> None:
    cmk = {"properties": {"serverKeyType": "AzureKeyVault"}}
    service = {"properties": {"serverKeyType": "ServiceManaged"}}
    assert judge("AZ-DB-017", sql(sql_encryption_protector=cmk), SERVER) is RuleState.PASS
    assert judge("AZ-DB-017", sql(sql_encryption_protector=service), SERVER) is RuleState.FAIL
    assert judge("AZ-DB-017", sql(), SERVER) is RuleState.UNKNOWN


def test_defender_for_sql_from_the_server_or_the_plan() -> None:
    on = {"properties": {"state": "Enabled"}}
    off = {"properties": {"state": "Disabled"}}

    def plan(tier: str) -> dict[str, Any]:
        return {"defender_plans": [{"name": "SqlServers", "properties": {"pricingTier": tier}}]}

    assert judge("AZ-DB-018", sql(sql_threat_detection=on), SERVER) is RuleState.PASS
    assert (
        judge("AZ-DB-018", {**sql(sql_threat_detection=off), **plan("Standard")}, SERVER)
        is RuleState.PASS
    )
    assert (
        judge("AZ-DB-018", {**sql(sql_threat_detection=off), **plan("Free")}, SERVER)
        is RuleState.FAIL
    )
    # The server's own setting is off and the plan was not read.
    assert judge("AZ-DB-018", sql(sql_threat_detection=off), SERVER) is RuleState.UNKNOWN


def test_vulnerability_assessment_express_and_classic() -> None:
    express = {"express": {"properties": {"state": "Enabled"}}, "classic": {"properties": {}}}
    classic = {
        "express": {"properties": {"state": "Disabled"}},
        "classic": {
            "properties": {
                "storageContainerPath": "https://st.blob.core.windows.net/va/",
                "recurringScans": {
                    "isEnabled": True,
                    "emailSubscriptionAdmins": False,
                    "emails": ["dba@contoso.com"],
                },
            }
        },
    }
    neither = {"express": {"properties": {"state": "Disabled"}}, "classic": {"properties": {}}}
    reading = "sql_vulnerability_assessment"

    assert judge("AZ-DB-019", sql(**{reading: express}), SERVER) is RuleState.PASS
    assert judge("AZ-DB-019", sql(**{reading: classic}), SERVER) is RuleState.PASS
    assert judge("AZ-DB-019", sql(**{reading: neither}), SERVER) is RuleState.FAIL
    assert judge("AZ-DB-019", sql(), SERVER) is RuleState.UNKNOWN

    for rule_id in ("AZ-DB-020", "AZ-DB-021", "AZ-DB-022"):
        assert judge(rule_id, sql(**{reading: express}), SERVER) is RuleState.NOT_APPLICABLE, (
            rule_id
        )
        assert judge(rule_id, sql(), SERVER) is RuleState.UNKNOWN, rule_id
    assert judge("AZ-DB-020", sql(**{reading: classic}), SERVER) is RuleState.PASS
    assert judge("AZ-DB-021", sql(**{reading: classic}), SERVER) is RuleState.PASS
    assert judge("AZ-DB-022", sql(**{reading: classic}), SERVER) is RuleState.FAIL


# ------------------------------------------------------------ machines
def machine(**readings: Any) -> dict[str, Any]:
    return {"virtual_machines": [{"id": VM, "name": "vm", "properties": {}}], **readings}


def test_just_in_time_access() -> None:
    policy = {"properties": {"virtualMachines": [{"id": VM.upper(), "ports": []}]}}
    assert judge("AZ-CMP-008", machine(jit_policies=[policy]), VM) is RuleState.PASS
    assert judge("AZ-CMP-008", machine(jit_policies=[]), VM) is RuleState.FAIL
    assert judge("AZ-CMP-008", machine(), VM) is RuleState.UNKNOWN


def test_backup_is_unknown_while_a_vault_is_unread() -> None:
    item_ = {"properties": {"virtualMachineId": VM, "protectionState": "Protected"}}
    backed = {"vaults": ["/v"], "unread_vaults": [], "items": [item_]}
    assert judge("AZ-CMP-009", machine(vm_backups=backed), VM) is RuleState.PASS
    none = {"vaults": ["/v"], "unread_vaults": [], "items": []}
    assert judge("AZ-CMP-009", machine(vm_backups=none), VM) is RuleState.FAIL
    unread = {"vaults": ["/v"], "unread_vaults": ["/v"], "items": []}
    assert judge("AZ-CMP-009", machine(vm_backups=unread), VM) is RuleState.UNKNOWN


def test_disks_are_modelled_and_only_unattached_ones_judged() -> None:
    def disk(state: str, kind: str | None) -> dict[str, Any]:
        props: dict[str, Any] = {"diskState": state}
        if kind:
            props["encryption"] = {"type": kind}
        return {"disks": [{"id": DISK, "name": "data-1", "properties": props}]}

    resources, _ = verdicts(disk("Unattached", None))
    assert next(r for r in resources if r.provider_resource_id == DISK).resource_type is (
        ResourceType.DISK
    )
    assert judge("AZ-CMP-010", disk("Unattached", None), DISK) is RuleState.FAIL
    assert (
        judge("AZ-CMP-010", disk("Unattached", "EncryptionAtRestWithCustomerKey"), DISK)
        is RuleState.PASS
    )
    assert judge("AZ-CMP-010", disk("Attached", None), DISK) is RuleState.NOT_APPLICABLE


# ------------------------------------------------------------ networks
def network(
    *logs: dict[str, Any], watcher: bool = True, ddos: bool | None = None
) -> dict[str, Any]:
    props: dict[str, Any] = {
        "subnets": [
            {
                "id": f"{VNET}/subnets/app",
                "properties": {"networkSecurityGroup": {"id": NSG}},
            }
        ]
    }
    if ddos is not None:
        props["enableDdosProtection"] = ddos
    data: dict[str, Any] = {
        "virtual_networks": [
            {"id": VNET, "name": "vnet", "location": "westeurope", "properties": props}
        ],
        "network_watchers": ([{"id": WATCHER, "location": "westeurope"}] if watcher else []),
        "flow_logs": {WATCHER: list(logs)} if watcher else {},
    }
    return data


def flow_log(target: str, days: int = 90, analytics: bool = True) -> dict[str, Any]:
    return {
        "id": f"{WATCHER}/flowLogs/fl",
        "properties": {
            "targetResourceId": target,
            "enabled": True,
            "retentionPolicy": {"enabled": True, "days": days},
            "flowAnalyticsConfiguration": {
                "networkWatcherFlowAnalyticsConfiguration": {
                    "enabled": analytics,
                    "workspaceResourceId": "/ws",
                }
            },
        },
    }


def test_flow_logs_cover_a_network_through_it_or_its_subnets_groups() -> None:
    assert judge("AZ-NET-010", network(flow_log(VNET)), VNET) is RuleState.PASS
    assert judge("AZ-NET-010", network(flow_log(NSG)), VNET) is RuleState.PASS
    assert judge("AZ-NET-010", network(flow_log(VNET, analytics=False)), VNET) is (RuleState.FAIL)
    assert judge("AZ-NET-010", network(), VNET) is RuleState.FAIL
    assert judge("AZ-NET-010", network(watcher=False), VNET) is RuleState.FAIL

    assert judge("AZ-NET-011", network(flow_log(VNET, days=30)), VNET) is RuleState.FAIL
    # Zero keeps the records for ever.
    assert judge("AZ-NET-011", network(flow_log(VNET, days=0)), VNET) is RuleState.PASS
    assert judge("AZ-NET-011", network(), VNET) is RuleState.NOT_APPLICABLE

    unread = network()
    unread["flow_logs"] = {WATCHER: "error: Forbidden"}
    assert judge("AZ-NET-010", unread, VNET) is RuleState.UNKNOWN


def test_watcher_and_ddos() -> None:
    assert judge("AZ-NET-012", network(), VNET) is RuleState.PASS
    assert judge("AZ-NET-012", network(watcher=False), VNET) is RuleState.FAIL
    assert judge("AZ-NET-013", network(ddos=True), VNET) is RuleState.PASS
    # Absent is the documented default: off.
    assert judge("AZ-NET-013", network(), VNET) is RuleState.FAIL


def test_bastion_only_where_there_are_machines() -> None:
    assert judge("AZ-NET-014", machine(bastion_hosts=[{"id": "/b"}])) is RuleState.PASS
    assert judge("AZ-NET-014", machine(bastion_hosts=[])) is RuleState.FAIL
    assert judge("AZ-NET-014", {"bastion_hosts": []}) is RuleState.NOT_APPLICABLE


# ------------------------------------------------------------ web apps
def site(kind: str = "app", auth: dict[str, Any] | None = None, logs: list[str] | None = None):
    data: dict[str, Any] = {
        "app_services": [{"id": SITE, "name": "app", "kind": kind, "properties": {}}]
    }
    if auth is not None:
        data["app_service_auth"] = {SITE: {"properties": auth}}
    if logs is not None:
        data["diagnostic_settings"] = {
            SITE: [
                {
                    "name": "d",
                    "properties": {
                        "workspaceId": "/ws",
                        "logs": [{"category": c, "enabled": True} for c in logs],
                    },
                }
            ]
        }
    return data


def test_app_service_authentication() -> None:
    on = {"platform": {"enabled": True}}
    assert judge("AZ-WEB-008", site(auth=on), SITE) is RuleState.PASS
    assert judge("AZ-WEB-008", site(auth={}), SITE) is RuleState.FAIL
    assert judge("AZ-WEB-008", site(), SITE) is RuleState.UNKNOWN


def test_http_logs_for_web_apps_only() -> None:
    assert judge("AZ-WEB-009", site(logs=["AppServiceHTTPLogs"]), SITE) is RuleState.PASS
    assert judge("AZ-WEB-009", site(logs=["AppServiceConsoleLogs"]), SITE) is RuleState.FAIL
    assert judge("AZ-WEB-009", site(), SITE) is RuleState.UNKNOWN
    assert judge("AZ-WEB-009", site("functionapp", logs=[]), SITE) is RuleState.NOT_APPLICABLE


# ------------------------------------------------------------ directory
def test_trusted_named_location() -> None:
    trusted = {
        "@odata.type": "#microsoft.graph.ipNamedLocation",
        "displayName": "Head office",
        "isTrusted": True,
        "ipRanges": [{"cidrAddress": "203.0.113.0/24"}],
    }
    untrusted = {**trusted, "isTrusted": False}
    assert judge("AZ-ID-022", {"named_locations": [trusted]}, None) is RuleState.PASS
    assert judge("AZ-ID-022", {"named_locations": [untrusted]}, None) is RuleState.FAIL
    assert judge("AZ-ID-022", {}, None) is RuleState.UNKNOWN
