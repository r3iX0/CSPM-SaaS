"""The fourteen Azure checks added with role v7, from payload to verdict.

Five judge evidence the scanner already collected and need no new permission;
nine rest on the six reads v7 adds. The tests that matter most here are the
UNKNOWN ones. Every new reading is a fan-out beneath a listing, and a role that
predates it answers the listing perfectly well and refuses the fan-out -- so a
rule that read "never arrived" as "off" would tell every v6 customer that every
app, account and server they own was misconfigured.

The absent-versus-false readings are the other half. Two of these settings are
omitted by Azure when never set and documented as permissive in that state
(cross-tenant replication, a vault's permission model); the rest are not, and
the rules must not confuse the two.
"""

from typing import Any

import httpx
import pytest

from app.compliance.catalog import get_framework
from app.connectors.azure.collector import AzureCollector
from app.connectors.azure.evidence import AzureEvidence
from app.connectors.azure.normalizer import AzureNormalizer
from app.connectors.base import RawSnapshot
from app.core.enums import Provider, RelationshipType, ResourceType, RuleState
from app.domain.resource import CloudResource
from app.rules.azure.compute.disks import AzureUnmanagedDiskRule
from app.rules.azure.database.transport import (
    AzurePostgresTlsRule,
    AzureSqlEntraAdminRule,
    AzureSqlTlsRule,
)
from app.rules.azure.network.exposure import AzureOpenNsgRule, AzurePublicUdpRule
from app.rules.azure.posture.plans import AzureDefenderPlansRule
from app.rules.azure.secrets.key_vault import AzureKeyVaultAccessModelRule
from app.rules.azure.storage.data_protection import (
    AzureBlobSoftDeleteRule,
    AzureStorageCrossTenantReplicationRule,
)
from app.rules.azure.web.app_service import (
    AzureAppServiceFtpRule,
    AzureAppServiceHttpsRule,
    AzureAppServiceIdentityRule,
    AzureAppServiceRemoteDebuggingRule,
    AzureAppServiceTlsRule,
)
from app.rules.base import RuleContext
from app.rules.registry import RULE_REGISTRY

SUB = "00000000-0000-0000-0000-000000000001"
RG = f"/subscriptions/{SUB}/resourceGroups/rg"
SITE = f"{RG}/providers/Microsoft.Web/sites/shop"
ACCOUNT = f"{RG}/providers/Microsoft.Storage/storageAccounts/stg"
SQL = f"{RG}/providers/Microsoft.Sql/servers/sql"
PG = f"{RG}/providers/Microsoft.DBforPostgreSQL/flexibleServers/pg"
VM = f"{RG}/providers/Microsoft.Compute/virtualMachines/vm"


def asset(resource_type: ResourceType, **metadata: Any) -> CloudResource:
    return CloudResource(
        provider=Provider.AZURE,
        provider_resource_id="/x/asset",
        resource_type=resource_type,
        name="asset",
        metadata=metadata,
    )


def verdict(rule, resource: CloudResource, **context: Any) -> RuleState:
    result = rule.evaluate(resource, RuleContext(resources=[resource], **context))
    return result.state


def snapshot_of(**data: Any) -> RawSnapshot:
    return RawSnapshot(
        provider=Provider.AZURE,
        tenant_id="t",
        subscription_id=SUB,
        version="1",
        data=data,
        errors={},
    )


def normalize(**data: Any) -> list[CloudResource]:
    return AzureNormalizer().normalize(snapshot_of(**data)).resources


def one(resources: list[CloudResource], resource_type: ResourceType) -> CloudResource:
    (found,) = [r for r in resources if r.resource_type == resource_type]
    return found


# --------------------------------------------------------------- app service
class TestAppService:
    def site(self, **properties: Any) -> dict[str, Any]:
        return {"id": SITE, "name": "shop", "kind": "app", "properties": properties}

    def test_a_site_becomes_an_app_service_asset(self) -> None:
        app = one(normalize(app_services=[self.site(httpsOnly=True)]), ResourceType.APP_SERVICE)

        assert app.metadata["https_only"] is True
        assert app.metadata["kind"] == "app"

    def test_a_site_whose_configuration_was_never_read_carries_none(self) -> None:
        """The listing arrived and the configuration read did not -- which is
        exactly what a v6 role produces."""
        app = one(normalize(app_services=[self.site()]), ResourceType.APP_SERVICE)

        assert app.metadata["min_tls_version"] is None
        assert verdict(AzureAppServiceTlsRule(), app) is RuleState.UNKNOWN
        assert verdict(AzureAppServiceFtpRule(), app) is RuleState.UNKNOWN
        assert verdict(AzureAppServiceRemoteDebuggingRule(), app) is RuleState.UNKNOWN

    def test_a_refused_configuration_read_is_unknown_not_off(self) -> None:
        app = one(
            normalize(app_services=[self.site()], app_service_configs={SITE: "error: 403"}),
            ResourceType.APP_SERVICE,
        )

        assert verdict(AzureAppServiceFtpRule(), app) is RuleState.UNKNOWN

    def test_configuration_reaches_the_site_it_belongs_to(self) -> None:
        config = {
            "properties": {
                "minTlsVersion": "1.0",
                "ftpsState": "AllAllowed",
                "remoteDebuggingEnabled": True,
            }
        }
        app = one(
            normalize(app_services=[self.site()], app_service_configs={SITE: config}),
            ResourceType.APP_SERVICE,
        )

        assert verdict(AzureAppServiceTlsRule(), app) is RuleState.FAIL
        assert verdict(AzureAppServiceFtpRule(), app) is RuleState.FAIL
        assert verdict(AzureAppServiceRemoteDebuggingRule(), app) is RuleState.FAIL

    def test_ftps_only_is_not_plain_ftp(self) -> None:
        app = asset(ResourceType.APP_SERVICE, ftps_state="FtpsOnly")

        assert verdict(AzureAppServiceFtpRule(), app) is RuleState.PASS

    def test_a_site_with_no_identity_block_has_no_identity(self) -> None:
        """ARM omits ``identity`` on a site that never had one, and the listing
        that omitted it arrived -- so this is an answer, not a gap."""
        app = one(normalize(app_services=[self.site()]), ResourceType.APP_SERVICE)

        assert verdict(AzureAppServiceIdentityRule(), app) is RuleState.FAIL

    def test_https_only_absent_is_unknown(self) -> None:
        assert (
            verdict(AzureAppServiceHttpsRule(), asset(ResourceType.APP_SERVICE))
            is RuleState.UNKNOWN
        )

    def test_a_listing_failure_degrades_the_listing_rules(self) -> None:
        app = asset(ResourceType.APP_SERVICE, https_only=True)

        assert (
            verdict(
                AzureAppServiceHttpsRule(),
                app,
                collection_errors={AzureEvidence.APP_SERVICES.value: "denied"},
            )
            is RuleState.UNKNOWN
        )

    def test_a_site_s_identity_is_a_first_hop_in_the_graph(self) -> None:
        """A taken web app acts as its identity exactly as a taken machine does."""
        site = {**self.site(), "identity": {"type": "SystemAssigned", "principalId": "p-1"}}
        state = AzureNormalizer().normalize(snapshot_of(app_services=[site]))

        assert any(
            source == SITE and kind is RelationshipType.HAS_IDENTITY
            for source, kind, _target in state.relationships
        )


# ------------------------------------------------------------------- storage
class TestStorage:
    def account(self, **properties: Any) -> dict[str, Any]:
        return {"id": ACCOUNT, "name": "stg", "properties": properties}

    def test_absent_cross_tenant_replication_is_the_documented_default(self) -> None:
        stg = one(normalize(storage_accounts=[self.account()]), ResourceType.STORAGE_ACCOUNT)
        result = AzureStorageCrossTenantReplicationRule().evaluate(
            stg, RuleContext(resources=[stg])
        )

        assert result.state is RuleState.FAIL
        assert result.evidence["default_applied"] is True

    def test_explicitly_disallowed_replication_passes(self) -> None:
        stg = one(
            normalize(storage_accounts=[self.account(allowCrossTenantReplication=False)]),
            ResourceType.STORAGE_ACCOUNT,
        )

        assert verdict(AzureStorageCrossTenantReplicationRule(), stg) is RuleState.PASS

    def test_an_unread_blob_service_is_unknown(self) -> None:
        stg = one(normalize(storage_accounts=[self.account()]), ResourceType.STORAGE_ACCOUNT)

        assert stg.metadata["blob_soft_delete"] is None
        assert verdict(AzureBlobSoftDeleteRule(), stg) is RuleState.UNKNOWN

    def test_a_policy_nobody_configured_reads_as_off(self) -> None:
        """The service properties arrived and did not say soft delete was on."""
        stg = one(
            normalize(
                storage_accounts=[self.account()],
                storage_blob_services={ACCOUNT: {"properties": {}}},
            ),
            ResourceType.STORAGE_ACCOUNT,
        )

        assert stg.metadata["blob_soft_delete"] is False
        assert verdict(AzureBlobSoftDeleteRule(), stg) is RuleState.FAIL

    def test_both_retention_policies_on_passes(self) -> None:
        on = {"enabled": True, "days": 14}
        stg = one(
            normalize(
                storage_accounts=[self.account()],
                storage_blob_services={
                    ACCOUNT: {
                        "properties": {
                            "deleteRetentionPolicy": on,
                            "containerDeleteRetentionPolicy": on,
                        }
                    }
                },
            ),
            ResourceType.STORAGE_ACCOUNT,
        )

        assert verdict(AzureBlobSoftDeleteRule(), stg) is RuleState.PASS


# ----------------------------------------------------------------- databases
class TestDatabases:
    def server(self, **properties: Any) -> dict[str, Any]:
        return {"id": SQL, "name": "sql", "properties": properties}

    def test_no_minimum_tls_fails(self) -> None:
        sql = asset(ResourceType.SQL_SERVER, minimal_tls_version="None")

        assert verdict(AzureSqlTlsRule(), sql) is RuleState.FAIL

    def test_an_absent_minimum_is_unknown_not_none(self) -> None:
        assert verdict(AzureSqlTlsRule(), asset(ResourceType.SQL_SERVER)) is RuleState.UNKNOWN

    def test_an_empty_administrator_listing_is_the_finding(self) -> None:
        sql = one(
            normalize(sql_servers=[self.server()], sql_administrators={SQL: []}),
            ResourceType.SQL_SERVER,
        )

        assert sql.metadata["entra_administrators"] == []
        assert verdict(AzureSqlEntraAdminRule(), sql) is RuleState.FAIL

    def test_an_unread_administrator_listing_is_unknown(self) -> None:
        sql = one(
            normalize(sql_servers=[self.server()], sql_administrators={SQL: "error: 403"}),
            ResourceType.SQL_SERVER,
        )

        assert sql.metadata["entra_administrators"] is None
        assert verdict(AzureSqlEntraAdminRule(), sql) is RuleState.UNKNOWN

    def test_an_entra_administrator_passes(self) -> None:
        admin = {"properties": {"login": "dba", "administratorType": "ActiveDirectory"}}
        sql = one(
            normalize(sql_servers=[self.server()], sql_administrators={SQL: [admin]}),
            ResourceType.SQL_SERVER,
        )

        assert verdict(AzureSqlEntraAdminRule(), sql) is RuleState.PASS

    def test_postgres_parameter_is_read_case_insensitively(self) -> None:
        pg = one(
            normalize(
                postgresql_servers=[{"id": PG, "name": "pg", "properties": {}}],
                postgresql_configurations={PG: {"properties": {"value": "OFF"}}},
            ),
            ResourceType.POSTGRESQL_SERVER,
        )

        assert pg.metadata["require_secure_transport"] == "off"
        assert verdict(AzurePostgresTlsRule(), pg) is RuleState.FAIL

    def test_an_unread_postgres_parameter_is_unknown(self) -> None:
        pg = one(
            normalize(postgresql_servers=[{"id": PG, "name": "pg", "properties": {}}]),
            ResourceType.POSTGRESQL_SERVER,
        )

        assert verdict(AzurePostgresTlsRule(), pg) is RuleState.UNKNOWN


# --------------------------------------------------------------- key vaults
class TestKeyVaultAccessModel:
    def test_rbac_passes(self) -> None:
        kv = asset(ResourceType.KEY_VAULT, rbac_authorization=True)

        assert verdict(AzureKeyVaultAccessModelRule(), kv) is RuleState.PASS

    def test_absent_is_the_access_policy_default(self) -> None:
        kv = asset(ResourceType.KEY_VAULT, access_policy_count=3)

        assert verdict(AzureKeyVaultAccessModelRule(), kv) is RuleState.FAIL


# ------------------------------------------------------------------ compute
class TestDisks:
    def machine(self, storage_profile: dict[str, Any]) -> CloudResource:
        vm = {"id": VM, "name": "vm", "properties": {"storageProfile": storage_profile}}
        return one(normalize(virtual_machines=[vm]), ResourceType.VIRTUAL_MACHINE)

    def test_managed_disks_pass(self) -> None:
        vm = self.machine({"osDisk": {"managedDisk": {"id": "/disk"}}})

        assert vm.metadata["unmanaged_disks"] == []
        assert verdict(AzureUnmanagedDiskRule(), vm) is RuleState.PASS

    def test_a_vhd_data_disk_is_named(self) -> None:
        vm = self.machine(
            {
                "osDisk": {"managedDisk": {"id": "/disk"}},
                "dataDisks": [{"name": "logs", "vhd": {"uri": "https://stg/vhds/logs.vhd"}}],
            }
        )

        assert vm.metadata["unmanaged_disks"] == ["logs"]
        assert verdict(AzureUnmanagedDiskRule(), vm) is RuleState.FAIL

    def test_an_os_disk_that_is_neither_is_unknown(self) -> None:
        vm = self.machine({"osDisk": {"osType": "Linux"}})

        assert vm.metadata["unmanaged_disks"] is None
        assert verdict(AzureUnmanagedDiskRule(), vm) is RuleState.UNKNOWN


# ------------------------------------------------------------------ network
class TestUdp:
    def nsg(self, protocol: str, ports: list[str]) -> CloudResource:
        return asset(
            ResourceType.NETWORK_SECURITY_GROUP,
            security_rules=[
                {
                    "name": "open",
                    "direction": "Inbound",
                    "access": "Allow",
                    "protocol": protocol,
                    "source": "*",
                    "destination_ports": ports,
                }
            ],
        )

    def test_public_udp_fails(self) -> None:
        assert verdict(AzurePublicUdpRule(), self.nsg("Udp", ["123"])) is RuleState.FAIL

    def test_tcp_is_not_this_rule_s_finding(self) -> None:
        assert verdict(AzurePublicUdpRule(), self.nsg("Tcp", ["123"])) is RuleState.PASS

    def test_every_port_is_left_to_the_catch_all(self) -> None:
        """One NSG rule, one finding. AZ-NET-003 already reports every port
        open, whatever the protocol."""
        nsg = self.nsg("Udp", ["*"])

        assert verdict(AzurePublicUdpRule(), nsg) is RuleState.PASS
        assert verdict(AzureOpenNsgRule(), nsg) is RuleState.FAIL


# ------------------------------------------------------------------ defender
class TestDefenderPlans:
    def subscription(self, **data: Any) -> CloudResource:
        return one(normalize(**data), ResourceType.SUBSCRIPTION)

    def test_a_free_plan_fails_and_is_named(self) -> None:
        plans = [
            {"name": "VirtualMachines", "properties": {"pricingTier": "Free"}},
            {"name": "KeyVaults", "properties": {"pricingTier": "Standard"}},
        ]
        sub = self.subscription(defender_plans=plans)
        result = AzureDefenderPlansRule().evaluate(sub, RuleContext(resources=[sub]))

        assert result.state is RuleState.FAIL
        assert result.evidence["off"] == ["Servers"]

    def test_a_deprecated_plan_is_not_judged(self) -> None:
        plans = [
            {"name": "KeyVaults", "properties": {"pricingTier": "Standard"}},
            {"name": "Dns", "properties": {"pricingTier": "Free", "deprecated": True}},
        ]

        assert (
            verdict(AzureDefenderPlansRule(), self.subscription(defender_plans=plans))
            is RuleState.PASS
        )

    def test_an_unread_listing_is_unknown(self) -> None:
        assert verdict(AzureDefenderPlansRule(), self.subscription()) is RuleState.UNKNOWN

    def test_an_empty_listing_is_unknown_rather_than_everything_on(self) -> None:
        assert (
            verdict(AzureDefenderPlansRule(), self.subscription(defender_plans=[]))
            is RuleState.UNKNOWN
        )


# ------------------------------------------------------------- collection
def azure(fail: set[str] | None = None) -> httpx.AsyncClient:
    refused = fail or set()

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if any(fragment in path for fragment in refused):
            return httpx.Response(403, json={"error": {"message": "denied"}})
        if "Microsoft.ResourceGraph" in path:
            return httpx.Response(200, json={"data": [], "totalRecords": 0, "count": 0})
        return httpx.Response(
            200, json={"value": [{"id": f"/x/{path.rsplit('/', 1)[-1]}", "name": "a"}]}
        )

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class FakeTokens:
    def __init__(self, tenant_id: str = "t") -> None:
        self.tenant_id = tenant_id

    def arm_token(self) -> str:
        return "arm"

    def graph_token(self) -> str:
        return "graph"


async def collect(monkeypatch: pytest.MonkeyPatch, **kwargs: Any) -> RawSnapshot:
    monkeypatch.setattr("app.connectors.azure.collector.TokenProvider", FakeTokens)
    collector = AzureCollector(tenant_id="t", subscription_id="sub-1", http_client=azure(**kwargs))
    return await collector.collect()


FAN_OUTS = (
    ("sql_administrators", "Microsoft.Sql/servers", "sql_servers", "/administrators"),
    (
        "postgresql_configurations",
        "Microsoft.DBforPostgreSQL/flexibleServers",
        "postgresql_servers",
        "/configurations/",
    ),
    (
        "storage_blob_services",
        "Microsoft.Storage/storageAccounts",
        "storage_accounts",
        "/blobServices/",
    ),
    ("app_service_configs", "Microsoft.Web/sites", "app_services", "/config/web"),
)


class TestV7Readings:
    async def test_each_reading_is_collected_under_its_own_key(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        snapshot = await collect(monkeypatch)

        for key in ("defender_plans", "app_services", *(f[0] for f in FAN_OUTS)):
            assert snapshot.coverage[key]["outcome"] == "COMPLETE", key

    @pytest.mark.parametrize("key,_path,listing,fragment", FAN_OUTS)
    async def test_a_v6_role_loses_the_fan_out_and_keeps_the_listing(
        self, monkeypatch: pytest.MonkeyPatch, key: str, _path: str, listing: str, fragment: str
    ) -> None:
        """What a customer who has not redeployed sees: the listing complete,
        the new reading partial, and the role named as why."""
        snapshot = await collect(monkeypatch, fail={fragment})

        assert snapshot.coverage[listing]["outcome"] == "COMPLETE"
        assert snapshot.coverage[key]["outcome"] == "PARTIAL"
        assert "role deployed before" in snapshot.coverage[key]["detail"]

    @pytest.mark.parametrize("key,path,_listing,_fragment", FAN_OUTS)
    async def test_a_fan_out_waits_for_the_listing_it_reads(
        self, monkeypatch: pytest.MonkeyPatch, key: str, path: str, _listing: str, _fragment: str
    ) -> None:
        snapshot = await collect(monkeypatch, fail={path})

        assert snapshot.coverage[key]["outcome"] == "SKIPPED"


# --------------------------------------------------------------- catalogue
class TestCisAzureCatalogue:
    def test_every_control_is_a_leaf(self) -> None:
        """The old catalogue carried "8" and "9" as controls. A section is not a
        requirement anybody can be assessed against."""
        catalogue = get_framework("CIS_AZURE_2.0")
        assert catalogue is not None

        assert all("." in control.id for control in catalogue.controls)

    def test_the_numbers_that_used_to_mean_something_else_are_no_longer_cited(self) -> None:
        """1.21 is Microsoft 365 group creation and 6.5 is flow log retention in
        2.0. Neither is what any rule here checks."""
        cited = {
            control
            for rule in RULE_REGISTRY
            for control in rule.compliance_mappings.get("CIS_AZURE_2.0", [])
        }

        assert not cited & {"1.21", "6.5", "7.1", "5.3", "2", "8", "9"}

    def test_the_benchmark_is_listed_whole(self) -> None:
        catalogue = get_framework("CIS_AZURE_2.0")
        assert catalogue is not None

        assert len(catalogue.controls) == 151


# ----------------------------------------------------------- the recording
class TestTheRecordedEnvironment:
    """The fixture the demo and the integration suite replay.

    Recorded before v7, it gave every new rule UNKNOWN -- a demo of fourteen
    checks that could not see. It now carries the six readings, and the tests
    hold it to showing each new rule a verdict.
    """

    def report(self):
        import sys
        from pathlib import Path

        sys.path.insert(0, str(Path(__file__).parent))
        from test_normalizer import _edges, load_snapshot

        from app.rules.engine import RuleEngine

        state = AzureNormalizer().normalize(load_snapshot("snapshot_mixed"))
        return RuleEngine().evaluate(
            RuleContext(
                resources=state.resources,
                relationships=_edges(state),
                controls=state.controls,
                collection_errors=state.collection_errors,
            )
        )

    NEW = frozenset(
        {
            "AZ-NET-009", "AZ-STO-004", "AZ-STO-005", "AZ-DB-007", "AZ-DB-008",
            "AZ-KV-003", "AZ-CMP-003", "AZ-DEF-001", "AZ-WEB-001", "AZ-WEB-002",
            "AZ-WEB-003", "AZ-WEB-004", "AZ-WEB-005",
        }
    )

    def test_no_new_rule_is_blind_on_the_recording(self) -> None:
        report = self.report()

        assert not {e.rule.rule_id for e in report.gaps} & self.NEW

    def test_the_recording_shows_four_of_them_failing(self) -> None:
        """Enough to see the new checks work, not so many the demo reads as a
        catastrophe (DECISIONS.md section 79)."""
        failed = {e.rule.rule_id for e in self.report().failures} & self.NEW

        assert failed == {"AZ-DB-008", "AZ-DEF-001", "AZ-STO-004", "AZ-WEB-005"}
