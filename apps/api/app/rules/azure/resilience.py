"""Whether an estate survives losing something (DECISIONS.md section 177).

Tier 3 of the coverage backlog held these back as availability rather than
security. They are kept, at LOW severity and exploitability 0, because the
question they answer is the one ransomware and a bad deletion ask: when this is
gone, is there another copy, in another region, kept long enough to restore
from. None of them raises a finding's reachability; each is a setting on one
asset, read from a listing already collected or from role v12's backup policy
and scale set reads.
"""

from typing import Any

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, Severity
from app.rules.property import PropertySpec, property_rule

_RESILIENCE = {
    "ISO_27001": ["A.8.13"],
    "NIST_CSF": ["PR.IP-4", "RC.RP-1"],
    "GDPR": ["32(1)(c)"],
    "NIST_800_53": ["CP-9"],
    "SOC2": ["A1.2"],
    "PCI_DSS_4": ["12.10.1"],
}
_WHY_ONE_OF = "More than one value passes, so there is no one value to expect."


def _ha_on(mode: Any) -> bool:
    return bool(mode) and str(mode).lower() != "disabled"


def _geo_replicated(sku: Any) -> bool:
    return any(part in str(sku or "").upper() for part in ("GRS", "GZRS"))


def _none(names: Any) -> bool:
    return not names


def _at_least(days: int) -> Any:
    def test(value: Any) -> bool:
        return isinstance(value, int) and value >= days

    return test


def _spec(**kw: Any) -> PropertySpec:
    kw.setdefault("severity", Severity.LOW)
    kw.setdefault("exploitability", 0)
    kw.setdefault("mappings", _RESILIENCE)
    return PropertySpec(**kw)


SPECS = (
    _spec(
        rule_id="AZ-COS-005",
        name="Cosmos DB account does not fail over automatically",
        description=(
            "Automatic failover is off, so a regional outage leaves a multi-region "
            "account's writes down until someone fails it over by hand."
        ),
        rationale="Failover that needs a person happens at the speed of the pager.",
        remediation=(
            "Azure CLI:\n"
            "  az cosmosdb update --name <account> --resource-group <rg> \\\n"
            "    --enable-automatic-failover true"
        ),
        cli=(
            "az cosmosdb update --name <account> --resource-group <rg> "
            "--enable-automatic-failover true",
        ),
        category="database",
        resource_type=ResourceType.DOCUMENT_DATABASE,
        evidence=(AzureEvidence.COSMOS_ACCOUNTS,),
        field="automatic_failover",
        safe=True,
        describes="Automatic failover is enabled",
        failure="does not fail over automatically",
    ),
    _spec(
        rule_id="AZ-COS-006",
        name="Cosmos DB account has no continuous backup",
        description=(
            "The account takes periodic backups only, so data can be restored to a "
            "backup's moment rather than to any point before a bad write."
        ),
        rationale=(
            "Continuous backup restores to the second before the mistake, or before "
            "the ransomware; periodic backup loses everything since the last copy."
        ),
        remediation=(
            "Azure CLI:\n"
            "  az cosmosdb update --name <account> --resource-group <rg> \\\n"
            "    --backup-policy-type Continuous"
        ),
        cli=(
            "az cosmosdb update --name <account> --resource-group <rg> "
            "--backup-policy-type Continuous",
        ),
        category="database",
        resource_type=ResourceType.DOCUMENT_DATABASE,
        evidence=(AzureEvidence.COSMOS_ACCOUNTS,),
        field="backup_type",
        safe="Continuous",
        describes="The backup policy is continuous",
        failure="has no continuous backup",
    ),
    _spec(
        rule_id="AZ-MYS-005",
        name="MySQL server backups are not geo-redundant",
        description=(
            "The server's backups stay in its own region, so losing the region loses "
            "them with the server."
        ),
        rationale="A backup in the same region as the thing it backs up shares its fate.",
        remediation=(
            "Geo-redundant backup is chosen at creation: restore the server with "
            "geo-redundant backup enabled.\n\n"
            "Azure CLI:\n"
            "  az mysql flexible-server geo-restore --source-server <server> \\\n"
            "    --name <new-server> --resource-group <rg> --location <paired-region>"
        ),
        cli=(
            "az mysql flexible-server create --name <server> --resource-group <rg> "
            "--geo-redundant-backup Enabled",
        ),
        category="database",
        resource_type=ResourceType.MYSQL_SERVER,
        evidence=(AzureEvidence.MYSQL_SERVERS,),
        field="geo_redundant_backup",
        safe="Enabled",
        describes="Geo-redundant backup is enabled",
        failure="keeps its backups in one region",
    ),
    _spec(
        rule_id="AZ-MYS-006",
        name="MySQL server has no high availability",
        description=(
            "The server runs without a standby, so a zone or host failure takes it "
            "down until Azure restores it."
        ),
        rationale="A standby replica is what turns an outage into a failover.",
        remediation=(
            "Azure CLI:\n"
            "  az mysql flexible-server update --name <server> --resource-group <rg> \\\n"
            "    --high-availability ZoneRedundant"
        ),
        cli=(
            "az mysql flexible-server update --name <server> --resource-group <rg> "
            "--high-availability ZoneRedundant",
        ),
        category="database",
        resource_type=ResourceType.MYSQL_SERVER,
        evidence=(AzureEvidence.MYSQL_SERVERS,),
        field="high_availability",
        passes=_ha_on,
        why_no_expected_state=_WHY_ONE_OF,
        describes="High availability is same-zone or zone-redundant",
        failure="has no high availability",
    ),
    _spec(
        rule_id="AZ-DB-023",
        name="PostgreSQL server backups are not geo-redundant",
        description=(
            "The server's backups stay in its own region, so losing the region loses "
            "them with the server."
        ),
        rationale="A backup in the same region as the thing it backs up shares its fate.",
        remediation=(
            "Geo-redundant backup is chosen at creation: restore the server with "
            "geo-redundant backup enabled.\n\n"
            "Azure CLI:\n"
            "  az postgres flexible-server geo-restore --source-server <server> \\\n"
            "    --name <new-server> --resource-group <rg> --location <paired-region>"
        ),
        cli=(
            "az postgres flexible-server create --name <server> --resource-group <rg> "
            "--geo-redundant-backup Enabled",
        ),
        category="database",
        resource_type=ResourceType.POSTGRESQL_SERVER,
        evidence=(AzureEvidence.POSTGRESQL_SERVERS,),
        field="geo_redundant_backup",
        safe="Enabled",
        describes="Geo-redundant backup is enabled",
        failure="keeps its backups in one region",
    ),
    _spec(
        rule_id="AZ-DB-024",
        name="PostgreSQL server has no high availability",
        description=(
            "The server runs without a standby, so a zone or host failure takes it "
            "down until Azure restores it."
        ),
        rationale="A standby replica is what turns an outage into a failover.",
        remediation=(
            "Azure CLI:\n"
            "  az postgres flexible-server update --name <server> --resource-group <rg> \\\n"
            "    --high-availability ZoneRedundant"
        ),
        cli=(
            "az postgres flexible-server update --name <server> --resource-group <rg> "
            "--high-availability ZoneRedundant",
        ),
        category="database",
        resource_type=ResourceType.POSTGRESQL_SERVER,
        evidence=(AzureEvidence.POSTGRESQL_SERVERS,),
        field="high_availability",
        passes=_ha_on,
        why_no_expected_state=_WHY_ONE_OF,
        describes="High availability is same-zone or zone-redundant",
        failure="has no high availability",
    ),
    _spec(
        rule_id="AZ-STO-016",
        name="Storage account is not geo-redundant",
        description=(
            "The account keeps its data in one region (LRS or ZRS), so a regional "
            "disaster loses it."
        ),
        rationale=(
            "Geo-redundant replication keeps a copy in the paired region. It costs more, "
            "which is why this is a LOW finding a customer may reasonably dismiss for "
            "data that can be rebuilt."
        ),
        remediation=(
            "Azure CLI:\n"
            "  az storage account update --name <account> --resource-group <rg> \\\n"
            "    --sku Standard_GZRS"
        ),
        cli=(
            "az storage account update --name <account> --resource-group <rg> "
            "--sku Standard_GZRS",
        ),
        category="storage",
        resource_type=ResourceType.STORAGE_ACCOUNT,
        evidence=(AzureEvidence.STORAGE_ACCOUNTS,),
        field="sku",
        passes=_geo_replicated,
        why_no_expected_state="Four SKUs replicate across regions; none is the one answer.",
        describes="The account's SKU is GRS, RA-GRS, GZRS or RA-GZRS",
        failure="keeps its data in one region",
    ),
    _spec(
        rule_id="AZ-BKP-001",
        name="Recovery Services vault protects nothing",
        description=(
            "The vault holds no protected item, so whatever it was created to back up "
            "is not being backed up by it."
        ),
        rationale=(
            "An empty vault usually means protection was removed or never finished, "
            "and a machine somebody believes is backed up is not."
        ),
        remediation=(
            "Protect the workloads the vault was made for, or delete it.\n\n"
            "Azure CLI:\n"
            "  az backup protection enable-for-vm --resource-group <rg> \\\n"
            "    --vault-name <vault> --vm <vm> --policy-name DefaultPolicy"
        ),
        cli=(
            "az backup protection enable-for-vm --resource-group <rg> --vault-name <vault> "
            "--vm <vm> --policy-name DefaultPolicy",
        ),
        category="compute",
        resource_type=ResourceType.BACKUP_VAULT,
        evidence=(AzureEvidence.VM_BACKUPS,),
        field="protected_item_count",
        passes=_at_least(1),
        why_no_expected_state="Any number of items above none passes.",
        describes="The vault protects at least one item",
        failure="protects nothing",
    ),
    _spec(
        rule_id="AZ-BKP-002",
        name="Backup policy keeps recovery points under 30 days",
        description=(
            "A backup policy in the vault keeps daily recovery points for less than 30 "
            "days, shorter than intrusions and silent corruption usually go unnoticed."
        ),
        rationale=(
            "Restoring is only possible to a point still kept. Ransomware that sat "
            "quietly for five weeks has already aged out every clean copy of a "
            "four-week policy."
        ),
        remediation=(
            "Raise daily retention on the policies named in the finding to 30 days or "
            "more.\n\n"
            "Azure Portal: Recovery Services vault > Backup policies > select the "
            "policy > Modify > Retention of daily backup point > 30 days > Update."
        ),
        cli=(
            "az backup policy set --resource-group <rg> --vault-name <vault> "
            "--policy @policy.json",
        ),
        category="compute",
        resource_type=ResourceType.BACKUP_VAULT,
        evidence=(AzureEvidence.VM_BACKUPS, AzureEvidence.BACKUP_POLICIES),
        field="short_retention_policies",
        passes=_none,
        why_no_expected_state=(
            "The check passes when no policy is short, and the short ones are named in "
            "the finding."
        ),
        describes="Every backup policy keeps daily recovery points for 30 days or more",
        failure="has backup policies keeping recovery points under 30 days",
    ),
    _spec(
        rule_id="AZ-CMP-011",
        name="Virtual machine backups are kept under 7 days",
        description=(
            "The backup policy protecting this machine keeps daily recovery points for "
            "less than a week."
        ),
        rationale=(
            "A week is the least that covers noticing a problem over a weekend. Fewer "
            "days and the clean copy may be gone before anyone looks."
        ),
        remediation=(
            "Move the machine to a policy that keeps daily points for 7 days or more, "
            "or modify its policy.\n\n"
            "Azure CLI:\n"
            "  az backup item set-policy --resource-group <rg> --vault-name <vault> \\\n"
            "    --container-name <vm> --name <vm> --policy-name <policy>"
        ),
        cli=(
            "az backup item set-policy --resource-group <rg> --vault-name <vault> "
            "--container-name <vm> --name <vm> --policy-name <policy>",
        ),
        category="compute",
        resource_type=ResourceType.VIRTUAL_MACHINE,
        evidence=(
            AzureEvidence.VIRTUAL_MACHINES,
            AzureEvidence.VM_BACKUPS,
            AzureEvidence.BACKUP_POLICIES,
        ),
        field="backup_daily_retention_days",
        passes=_at_least(7),
        why_no_expected_state="Any retention of a week or more passes.",
        describes="Daily recovery points are kept for 7 days or more",
        failure="keeps its daily backups under 7 days",
        # AZ-CMP-009 reports a machine with no backup at all.
        applies_when=(("backed_up", "true"),),
    ),
    _spec(
        rule_id="AZ-CMP-012",
        name="Scale set is fronted by no load balancer",
        description=(
            "The scale set's instances are in no load balancer or application gateway "
            "backend pool, so nothing spreads traffic across them or stops sending it "
            "to one that failed."
        ),
        rationale=(
            "A scale set exists to run interchangeable instances. Without something in "
            "front of them, one unhealthy instance is an outage for its clients."
        ),
        remediation=(
            "Add the scale set's network configuration to a load balancer backend pool.\n\n"
            "Azure CLI:\n"
            "  az vmss update --name <scale-set> --resource-group <rg> --add \\\n"
            "    virtualMachineProfile.networkProfile.networkInterfaceConfigurations[0]"
            ".ipConfigurations[0].loadBalancerBackendAddressPools id=<pool-id>"
        ),
        cli=(
            "az vmss update --name <scale-set> --resource-group <rg> --add "
            "virtualMachineProfile.networkProfile.networkInterfaceConfigurations[0]"
            ".ipConfigurations[0].loadBalancerBackendAddressPools id=<pool-id>",
        ),
        category="compute",
        resource_type=ResourceType.SCALE_SET,
        evidence=(AzureEvidence.SCALE_SETS,),
        field="load_balanced",
        safe=True,
        describes="A load balancer or application gateway backend pool holds the instances",
        failure="is fronted by no load balancer",
    ),
    _spec(
        rule_id="AZ-CMP-013",
        name="Scale set runs no instances",
        description="The scale set's capacity is zero, so it serves nothing.",
        rationale=(
            "An empty scale set is either a service that is down or one nobody removed; "
            "either is worth a look."
        ),
        remediation=(
            "Scale it out, or delete it if nothing uses it.\n\n"
            "Azure CLI:\n"
            "  az vmss scale --name <scale-set> --resource-group <rg> --new-capacity 2"
        ),
        cli=("az vmss scale --name <scale-set> --resource-group <rg> --new-capacity 2",),
        category="compute",
        resource_type=ResourceType.SCALE_SET,
        evidence=(AzureEvidence.SCALE_SETS,),
        field="capacity",
        passes=_at_least(1),
        why_no_expected_state="Any capacity above zero passes.",
        describes="The scale set runs at least one instance",
        failure="runs no instances",
    ),
)

RULES = tuple(property_rule(spec) for spec in SPECS)
