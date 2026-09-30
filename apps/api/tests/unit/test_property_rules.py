"""Rules declared as property specs, run on what the normalizer produced
(DECISIONS.md section 174)."""

from typing import Any

import pytest

from app.connectors.azure.normalizer import AzureNormalizer
from app.connectors.base import RawSnapshot
from app.core.enums import Provider, ResourceType, RuleState, Severity
from app.rules.base import RuleContext
from app.rules.property import PropertySpec
from app.rules.registry import get_rule

ACCOUNT = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/st"
APPROVED = {"properties": {"privateLinkServiceConnectionState": {"status": "Approved"}}}


def verdict(
    rule_id: str,
    props: dict[str, Any],
    blob_service: dict[str, Any] | None = None,
    errors: dict[str, str] | None = None,
) -> RuleState:
    data: dict[str, Any] = {
        "storage_accounts": [{"id": ACCOUNT, "name": "st", "properties": props}]
    }
    if blob_service is not None:
        data["storage_blob_services"] = {ACCOUNT: {"properties": blob_service}}
    state = AzureNormalizer().normalize(
        RawSnapshot(provider=Provider.AZURE, tenant_id="t", subscription_id="s", data=data)
    )
    rule = get_rule(rule_id)
    assert rule is not None
    resource = next(r for r in state.resources if r.provider_resource_id == ACCOUNT)
    context = RuleContext(resources=state.resources, collection_errors=errors or {})
    result = rule.evaluate(resource, context)
    return (result if isinstance(result, list) else [result])[0].state


CASES: list[tuple[str, dict[str, Any], dict[str, Any] | None, RuleState]] = [
    ("AZ-STO-006", {}, {"isVersioningEnabled": True}, RuleState.PASS),
    ("AZ-STO-006", {}, {}, RuleState.FAIL),
    # The blob service was not read: versioning is not known.
    ("AZ-STO-006", {}, None, RuleState.UNKNOWN),
    ("AZ-STO-007", {"encryption": {"requireInfrastructureEncryption": True}}, None, RuleState.PASS),
    # Absent unless requested at creation, which is the unsafe default.
    ("AZ-STO-007", {}, None, RuleState.FAIL),
    ("AZ-STO-008", {"encryption": {"keySource": "Microsoft.Keyvault"}}, None, RuleState.PASS),
    ("AZ-STO-008", {"encryption": {"keySource": "Microsoft.Storage"}}, None, RuleState.FAIL),
    ("AZ-STO-008", {}, None, RuleState.UNKNOWN),
    ("AZ-STO-009", {"defaultToOAuthAuthentication": True}, None, RuleState.PASS),
    ("AZ-STO-009", {}, None, RuleState.FAIL),
    ("AZ-STO-010", {"networkAcls": {"bypass": "Logging, AzureServices"}}, None, RuleState.PASS),
    ("AZ-STO-010", {"networkAcls": {"bypass": "None"}}, None, RuleState.FAIL),
    ("AZ-STO-011", {"privateEndpointConnections": [APPROVED]}, None, RuleState.PASS),
    ("AZ-STO-011", {"privateEndpointConnections": []}, None, RuleState.FAIL),
    ("AZ-STO-011", {}, None, RuleState.UNKNOWN),
]


@pytest.mark.parametrize(("rule_id", "props", "blobs", "expected"), CASES)
def test_each_storage_spec_judges_the_normalized_field(
    rule_id: str, props: dict[str, Any], blobs: dict[str, Any] | None, expected: RuleState
) -> None:
    assert verdict(rule_id, props, blobs) is expected


def test_a_failed_listing_is_unknown() -> None:
    state = verdict("AZ-STO-009", {}, errors={"storage_accounts": "Forbidden"})
    assert state is RuleState.UNKNOWN


def test_a_spec_must_say_what_passes_and_why_it_cannot_be_declared() -> None:
    common: dict[str, Any] = {
        "rule_id": "X",
        "name": "x",
        "description": "x",
        "rationale": "x",
        "remediation": "x",
        "cli": (),
        "severity": Severity.LOW,
        "exploitability": 0,
        "category": "storage",
        "resource_type": ResourceType.STORAGE_ACCOUNT,
        "evidence": (),
        "field": "f",
        "describes": "x",
        "mappings": {},
        "failure": "x",
    }
    with pytest.raises(ValueError, match="neither"):
        PropertySpec(**common)
    with pytest.raises(ValueError, match="no expected state"):
        PropertySpec(**common, passes=bool)


# ------------------------------------------------------------ section 175
def run(rule_id: str, data: dict[str, Any], resource_id: str) -> RuleState:
    state = AzureNormalizer().normalize(
        RawSnapshot(provider=Provider.AZURE, tenant_id="t", subscription_id="s", data=data)
    )
    rule = get_rule(rule_id)
    assert rule is not None
    resource = next(r for r in state.resources if r.provider_resource_id == resource_id)
    result = rule.evaluate(resource, RuleContext(resources=state.resources))
    return (result if isinstance(result, list) else [result])[0].state


PG = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.DBforPostgreSQL/flexibleServers/pg"
MYSQL = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.DBforMySQL/flexibleServers/my"
VM = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm"
SITE = "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Web/sites/fn"


def pg(parameters: dict[str, str] | None, **props: Any) -> dict[str, Any]:
    data: dict[str, Any] = {"postgresql_servers": [{"id": PG, "name": "pg", "properties": props}]}
    if parameters is not None:
        data["postgresql_logging"] = {
            PG: {name: {"properties": {"value": value}} for name, value in parameters.items()}
        }
    return data


def test_postgresql_parameters_are_judged_by_name() -> None:
    on = {
        "log_checkpoints": "on",
        "log_connections": "ON",
        "log_disconnections": "on",
        "connection_throttle.enable": "on",
        "logfiles.retention_days": "7",
    }
    for rule_id in ("AZ-DB-010", "AZ-DB-011", "AZ-DB-012", "AZ-DB-013", "AZ-DB-014"):
        assert run(rule_id, pg(on), PG) is RuleState.PASS, rule_id
        assert run(rule_id, pg(None), PG) is RuleState.UNKNOWN, rule_id
    off = {**on, "log_connections": "off", "logfiles.retention_days": "3"}
    assert run("AZ-DB-011", pg(off), PG) is RuleState.FAIL
    assert run("AZ-DB-014", pg(off), PG) is RuleState.FAIL
    assert (
        run("AZ-DB-015", pg(None, authConfig={"activeDirectoryAuth": "Enabled"}), PG)
        is RuleState.PASS
    )
    assert (
        run("AZ-DB-015", pg(None, authConfig={"activeDirectoryAuth": "Disabled"}), PG)
        is RuleState.FAIL
    )


def test_mysql_audit_parameters() -> None:
    def my(enabled: str, events: str) -> dict[str, Any]:
        return {
            "mysql_servers": [{"id": MYSQL, "name": "my", "properties": {}}],
            "mysql_configurations": {
                MYSQL: {
                    "audit_log_enabled": {"properties": {"value": enabled}},
                    "audit_log_events": {"properties": {"value": events}},
                }
            },
        }

    assert run("AZ-MYS-003", my("ON", "CONNECTION,DDL"), MYSQL) is RuleState.PASS
    assert run("AZ-MYS-003", my("OFF", "CONNECTION"), MYSQL) is RuleState.FAIL
    assert run("AZ-MYS-004", my("ON", "CONNECTION,DDL"), MYSQL) is RuleState.PASS
    assert run("AZ-MYS-004", my("ON", "DDL,DML"), MYSQL) is RuleState.FAIL


def test_virtual_machine_protection() -> None:
    def vm(**props: Any) -> dict[str, Any]:
        return {"virtual_machines": [{"id": VM, "name": "vm", "properties": props}]}

    trusted = {
        "securityType": "TrustedLaunch",
        "uefiSettings": {"secureBootEnabled": True, "vTpmEnabled": True},
    }
    assert run("AZ-CMP-005", vm(securityProfile=trusted), VM) is RuleState.PASS
    assert run("AZ-CMP-005", vm(), VM) is RuleState.FAIL
    des = {"diskEncryptionSet": {"id": "/des"}}
    cmk = {"osDisk": {"managedDisk": des}, "dataDisks": [{"managedDisk": des}]}
    mixed = {"osDisk": {"managedDisk": des}, "dataDisks": [{"managedDisk": {}}]}
    assert run("AZ-CMP-006", vm(storageProfile=cmk), VM) is RuleState.PASS
    assert run("AZ-CMP-006", vm(storageProfile=mixed), VM) is RuleState.FAIL
    assert run("AZ-CMP-006", vm(), VM) is RuleState.UNKNOWN


def test_function_app_integration_applies_to_function_apps_only() -> None:
    def site(kind: str, **props: Any) -> dict[str, Any]:
        return {"app_services": [{"id": SITE, "name": "fn", "kind": kind, "properties": props}]}

    assert (
        run("AZ-WEB-007", site("functionapp", virtualNetworkSubnetId="/subnet"), SITE)
        is RuleState.PASS
    )
    assert run("AZ-WEB-007", site("functionapp"), SITE) is RuleState.FAIL
    assert run("AZ-WEB-007", site("app"), SITE) is RuleState.NOT_APPLICABLE
