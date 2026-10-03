"""Tier 2 configuration checks that need no new permission (DECISIONS.md section 175).

AKS, function apps, PostgreSQL and MySQL server parameters, SQL audit
retention and virtual machine protection, each one setting declared as a
:class:`~app.rules.property.PropertySpec`. The parameters are read by name under
configuration reads the scanner role already holds.

Section 176 adds machine protection -- just-in-time access and Azure Backup --
unattached disks, and two web app checks, under the reads role v11 added.
"""

from typing import Any

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, Severity
from app.rules.property import PropertySpec, property_rule

_LOGGING = {
    "ISO_27001": ["A.8.15", "A.8.16"],
    "NIST_CSF_2.0": ["PR.PS-04", "DE.AE-03"],
    "GDPR": ["32(1)(b)"],
    "NIST_800_53": ["AU-2", "SI-4"],
    "SOC2": ["CC7.2"],
    "PCI_DSS_4": ["10.2.1"],
}
_HARDENING = {
    "ISO_27001": ["A.8.8"],
    "NIST_CSF_2.0": ["ID.RA-01"],
    "GDPR": ["32(1)(b)"],
    "NIST_800_53": ["CM-6", "SI-2"],
    "SOC2": ["CC7.1"],
    "PCI_DSS_4": ["6.3.3"],
}
_ENCRYPTION = {
    "ISO_27001": ["A.8.24"],
    "NIST_CSF_2.0": ["PR.DS-01"],
    "GDPR": ["32(1)(a)"],
    "NIST_800_53": ["SC-12", "SC-28"],
    "SOC2": ["CC6.1"],
    "PCI_DSS_4": ["3.5.1"],
}
_IDENTITY = {
    "ISO_27001": ["A.5.16", "A.5.17"],
    "NIST_CSF_2.0": ["PR.AA-01"],
    "GDPR": ["32(1)(b)"],
    "NIST_800_53": ["IA-2", "AC-2"],
    "SOC2": ["CC6.1"],
    "PCI_DSS_4": ["8.2.1"],
}
_NETWORK = {
    "ISO_27001": ["A.8.20", "A.8.22"],
    "NIST_CSF_2.0": ["PR.IR-01"],
    "GDPR": ["32(1)(b)"],
    "NIST_800_53": ["SC-7"],
    "SOC2": ["CC6.6"],
    "PCI_DSS_4": ["1.3.1"],
}

_PG = (AzureEvidence.POSTGRESQL_SERVERS, AzureEvidence.POSTGRESQL_LOGGING)
_MYSQL = (AzureEvidence.MYSQL_SERVERS, AzureEvidence.MYSQL_CONFIGURATIONS)
_VMS = (AzureEvidence.VIRTUAL_MACHINES,)


def _upgrades_automatically(channel: Any) -> bool:
    return bool(channel) and str(channel).lower() != "none"


def _retains_logs_past_three_days(days: Any) -> bool:
    try:
        return int(str(days)) > 3
    except ValueError:
        return False


def _audits_connections(events: Any) -> bool:
    return "connection" in str(events or "").lower().replace(" ", "").split(",")


def _keeps_audit_ninety_days(days: Any) -> bool:
    # Zero is Azure SQL's spelling of "keep for ever".
    return isinstance(days, int) and (days == 0 or days >= 90)


def _pg_parameter(
    rule_id: str, name: str, field: str, what: str, why: str, severity: Severity
) -> PropertySpec:
    return PropertySpec(
        rule_id=rule_id,
        name=f"PostgreSQL server does not {what}",
        description=(
            f"The PostgreSQL flexible server's `{name}` parameter is off, so it does not {what}."
        ),
        rationale=why,
        remediation=(
            "Azure CLI:\n"
            "  az postgres flexible-server parameter set --resource-group <rg> \\\n"
            f"    --server-name <server> --name {name} --value on"
        ),
        cli=(
            "az postgres flexible-server parameter set --resource-group <rg> "
            f"--server-name <server> --name {name} --value on",
        ),
        severity=severity,
        exploitability=1,
        category="database",
        resource_type=ResourceType.POSTGRESQL_SERVER,
        evidence=_PG,
        field=field,
        safe="on",
        describes=f"`{name}` is on",
        failure=f"does not {what}",
        mappings=_LOGGING,
    )


SPECS = (
    PropertySpec(
        rule_id="AZ-AKS-006",
        name="Kubernetes cluster does not upgrade itself",
        description=(
            "The cluster has no automatic upgrade channel, so it stays on whatever "
            "Kubernetes version and node image it has until someone upgrades it by hand."
        ),
        rationale=(
            "Clusters left alone fall out of support and keep known vulnerabilities in "
            "the control plane and node images. A patch channel keeps both current."
        ),
        remediation=(
            "Azure CLI:\n"
            "  az aks update --name <cluster> --resource-group <rg> \\\n"
            "    --auto-upgrade-channel patch"
        ),
        cli=("az aks update --name <cluster> --resource-group <rg> --auto-upgrade-channel patch",),
        severity=Severity.MEDIUM,
        exploitability=1,
        category="compute",
        resource_type=ResourceType.KUBERNETES_CLUSTER,
        evidence=(AzureEvidence.KUBERNETES_CLUSTERS,),
        field="auto_upgrade_channel",
        passes=_upgrades_automatically,
        why_no_expected_state=(
            "Any channel but none upgrades the cluster, so there is no one value to expect."
        ),
        # Absent is the service default: no automatic upgrades.
        absent="fail",
        describes="An automatic upgrade channel is set",
        failure="has no automatic upgrade channel",
        mappings={**_HARDENING, "NIST_CSF_2.0": ["ID.RA-01", "PR.PS-02"]},
    ),
    PropertySpec(
        rule_id="AZ-AKS-007",
        name="Kubernetes cluster sends no monitoring data",
        description=(
            "Neither Container insights nor managed Prometheus collects the cluster's "
            "metrics and logs."
        ),
        rationale=(
            "Without them a compromised pod, a crash loop or a node under attack leaves "
            "nothing to investigate afterwards."
        ),
        remediation=(
            "Azure CLI:\n"
            "  az aks enable-addons --name <cluster> --resource-group <rg> --addons monitoring"
        ),
        cli=("az aks enable-addons --name <cluster> --resource-group <rg> --addons monitoring",),
        severity=Severity.LOW,
        exploitability=0,
        category="compute",
        resource_type=ResourceType.KUBERNETES_CLUSTER,
        evidence=(AzureEvidence.KUBERNETES_CLUSTERS,),
        field="monitoring_enabled",
        safe=True,
        describes="Container insights or managed Prometheus is on",
        failure="sends no monitoring data",
        mappings=_LOGGING,
    ),
    PropertySpec(
        rule_id="AZ-WEB-007",
        name="Function app has no virtual network integration",
        description=(
            "The function app's outbound traffic does not go through a virtual network, "
            "so the data stores it calls must accept connections from the public internet."
        ),
        rationale=(
            "VNet integration is what lets a function reach storage and databases over "
            "private endpoints, so those can switch public access off."
        ),
        remediation=(
            "Azure CLI:\n"
            "  az functionapp vnet-integration add --name <app> --resource-group <rg> \\\n"
            "    --vnet <vnet> --subnet <subnet>"
        ),
        cli=(
            "az functionapp vnet-integration add --name <app> --resource-group <rg> "
            "--vnet <vnet> --subnet <subnet>",
        ),
        severity=Severity.LOW,
        exploitability=1,
        category="web",
        resource_type=ResourceType.APP_SERVICE,
        evidence=(AzureEvidence.APP_SERVICES,),
        field="vnet_integrated",
        safe=True,
        applies_when=(("kind", "functionapp"),),
        describes="Outbound traffic goes through a virtual network",
        failure="has no virtual network integration",
        mappings=_NETWORK,
    ),
    _pg_parameter(
        "AZ-DB-010",
        "log_checkpoints",
        "log_checkpoints",
        "log checkpoints",
        "Checkpoint records are part of the timeline an investigation rebuilds, and "
        "cost almost nothing to keep.",
        Severity.LOW,
    ),
    _pg_parameter(
        "AZ-DB-011",
        "log_connections",
        "log_connections",
        "log connection attempts",
        "Connection attempts are how password spraying against a database shows up. "
        "Without them there is no record of who tried to sign in.",
        Severity.MEDIUM,
    ),
    _pg_parameter(
        "AZ-DB-012",
        "log_disconnections",
        "log_disconnections",
        "log session ends",
        "Session ends and their durations complete the connection record, and show "
        "an unusually long session that read more than it should.",
        Severity.LOW,
    ),
    _pg_parameter(
        "AZ-DB-013",
        "connection_throttle.enable",
        "connection_throttling",
        "throttle repeated failed sign-ins",
        "Throttling slows a password guessing attack against the server to the point "
        "it stops being worth running.",
        Severity.LOW,
    ),
    PropertySpec(
        rule_id="AZ-DB-014",
        name="PostgreSQL server keeps its logs for three days or less",
        description=(
            "The server's `logfiles.retention_days` is three days or less, so the logs "
            "an incident needs are gone before most incidents are noticed."
        ),
        rationale="Three days is shorter than the time most intrusions go unnoticed.",
        remediation=(
            "Azure CLI:\n"
            "  az postgres flexible-server parameter set --resource-group <rg> \\\n"
            "    --server-name <server> --name logfiles.retention_days --value 7"
        ),
        cli=(
            "az postgres flexible-server parameter set --resource-group <rg> "
            "--server-name <server> --name logfiles.retention_days --value 7",
        ),
        severity=Severity.LOW,
        exploitability=0,
        category="database",
        resource_type=ResourceType.POSTGRESQL_SERVER,
        evidence=_PG,
        field="log_retention_days",
        passes=_retains_logs_past_three_days,
        why_no_expected_state="What is expected is a range, more than three days.",
        describes="Logs are kept for more than three days",
        failure="keeps its logs for three days or less",
        mappings=_LOGGING,
    ),
    PropertySpec(
        rule_id="AZ-DB-015",
        name="PostgreSQL server does not accept Entra authentication",
        description=(
            "The server authenticates only its own PostgreSQL accounts, so database "
            "access is outside the directory's multi-factor, Conditional Access and "
            "offboarding."
        ),
        rationale=(
            "A local database password is not revoked when its owner leaves, and is "
            "never asked for a second factor."
        ),
        remediation=(
            "Azure CLI:\n"
            "  az postgres flexible-server update --name <server> --resource-group <rg> \\\n"
            "    --microsoft-entra-auth Enabled"
        ),
        cli=(
            "az postgres flexible-server update --name <server> --resource-group <rg> "
            "--microsoft-entra-auth Enabled",
        ),
        severity=Severity.MEDIUM,
        exploitability=2,
        category="database",
        resource_type=ResourceType.POSTGRESQL_SERVER,
        evidence=(AzureEvidence.POSTGRESQL_SERVERS,),
        field="entra_authentication",
        safe=True,
        describes="Microsoft Entra authentication is enabled",
        failure="accepts only local PostgreSQL accounts",
        mappings=_IDENTITY,
    ),
    PropertySpec(
        rule_id="AZ-MYS-003",
        name="MySQL server keeps no audit log",
        description="The server's `audit_log_enabled` parameter is off.",
        rationale="Without an audit log there is no record of who connected or what ran.",
        remediation=(
            "Azure CLI:\n"
            "  az mysql flexible-server parameter set --resource-group <rg> \\\n"
            "    --server-name <server> --name audit_log_enabled --value ON"
        ),
        cli=(
            "az mysql flexible-server parameter set --resource-group <rg> "
            "--server-name <server> --name audit_log_enabled --value ON",
        ),
        severity=Severity.MEDIUM,
        exploitability=1,
        category="database",
        resource_type=ResourceType.MYSQL_SERVER,
        evidence=_MYSQL,
        field="audit_log_enabled",
        safe="on",
        describes="`audit_log_enabled` is on",
        failure="keeps no audit log",
        mappings=_LOGGING,
    ),
    PropertySpec(
        rule_id="AZ-MYS-004",
        name="MySQL audit log does not record connections",
        description="The server's `audit_log_events` does not include CONNECTION.",
        rationale="Connection events are how a credential attack shows up in the audit log.",
        remediation=(
            "Azure CLI:\n"
            "  az mysql flexible-server parameter set --resource-group <rg> \\\n"
            "    --server-name <server> --name audit_log_events --value CONNECTION"
        ),
        cli=(
            "az mysql flexible-server parameter set --resource-group <rg> "
            "--server-name <server> --name audit_log_events --value CONNECTION",
        ),
        severity=Severity.LOW,
        exploitability=1,
        category="database",
        resource_type=ResourceType.MYSQL_SERVER,
        evidence=_MYSQL,
        field="audit_log_events",
        passes=_audits_connections,
        why_no_expected_state=(
            "The events are a list, and what is expected is that it includes CONNECTION."
        ),
        describes="The audit log records connections",
        failure="does not record connections in its audit log",
        mappings=_LOGGING,
    ),
    PropertySpec(
        rule_id="AZ-DB-016",
        name="SQL server keeps its audit records for under 90 days",
        description=(
            "The server's auditing keeps records for fewer than 90 days, shorter than "
            "most investigations need to look back."
        ),
        rationale=(
            "An intrusion found after a month needs the audit trail from before it "
            "started. Zero means kept indefinitely and passes."
        ),
        remediation=(
            "Azure CLI:\n"
            "  az sql server audit-policy update --name <server> --resource-group <rg> \\\n"
            "    --retention-days 90"
        ),
        cli=(
            "az sql server audit-policy update --name <server> --resource-group <rg> "
            "--retention-days 90",
        ),
        severity=Severity.LOW,
        exploitability=0,
        category="database",
        resource_type=ResourceType.SQL_SERVER,
        evidence=(AzureEvidence.SQL_SERVERS, AzureEvidence.SQL_AUDITING),
        field="auditing.retention_days",
        passes=_keeps_audit_ninety_days,
        why_no_expected_state="What is expected is a range: zero, or 90 days or more.",
        describes="Audit records are kept for 90 days or more",
        failure="keeps its audit records for under 90 days",
        mappings=_LOGGING,
    ),
    PropertySpec(
        rule_id="AZ-CMP-005",
        name="Virtual machine does not use Trusted Launch",
        description=(
            "The machine is not a Trusted Launch VM with secure boot and a virtual TPM, "
            "so a bootkit or rootkit can load before the operating system."
        ),
        rationale=(
            "Secure boot refuses unsigned boot components and the vTPM lets the boot be "
            "measured and attested."
        ),
        remediation=(
            "Recreate the machine as Trusted Launch, or upgrade a Gen2 machine in place.\n\n"
            "Azure CLI:\n"
            "  az vm update --name <vm> --resource-group <rg> \\\n"
            "    --security-type TrustedLaunch --enable-secure-boot true --enable-vtpm true"
        ),
        cli=(
            "az vm update --name <vm> --resource-group <rg> --security-type TrustedLaunch "
            "--enable-secure-boot true --enable-vtpm true",
        ),
        severity=Severity.LOW,
        exploitability=1,
        category="compute",
        resource_type=ResourceType.VIRTUAL_MACHINE,
        evidence=_VMS,
        field="trusted_launch",
        safe=True,
        describes="Trusted Launch with secure boot and vTPM",
        failure="does not use Trusted Launch with secure boot and a vTPM",
        mappings=_HARDENING,
    ),
    PropertySpec(
        rule_id="AZ-CMP-006",
        name="Virtual machine disks use Microsoft's keys",
        description=(
            "At least one managed disk attached to the machine is encrypted with a "
            "platform key rather than through a disk encryption set holding the "
            "customer's key."
        ),
        rationale=(
            "A customer-managed key lets the customer make the disks unreadable by "
            "revoking the key, and some regulated data requires it."
        ),
        remediation=(
            "Create a disk encryption set on a key in the customer's vault and assign it "
            "to each disk.\n\n"
            "Azure CLI:\n"
            "  az disk update --name <disk> --resource-group <rg> \\\n"
            "    --encryption-type EncryptionAtRestWithCustomerKey \\\n"
            "    --disk-encryption-set <disk-encryption-set-id>"
        ),
        cli=(
            "az disk update --name <disk> --resource-group <rg> --encryption-type "
            "EncryptionAtRestWithCustomerKey --disk-encryption-set <disk-encryption-set-id>",
        ),
        severity=Severity.LOW,
        exploitability=0,
        category="compute",
        resource_type=ResourceType.VIRTUAL_MACHINE,
        evidence=_VMS,
        field="disks_customer_managed_key",
        safe=True,
        describes="Every attached managed disk uses a customer-managed key",
        failure="has a disk encrypted with a platform key",
        mappings=_ENCRYPTION,
    ),
)

# Section 176: machine protection, unattached disks and web apps, under the
# reads role v11 added (and the site configuration read held since v7).
_BACKUP = {
    "ISO_27001": ["A.8.13"],
    "NIST_CSF_2.0": ["PR.DS-11", "RC.RP-01"],
    "GDPR": ["32(1)(c)"],
    "NIST_800_53": ["CP-9"],
    "SOC2": ["A1.2"],
    "PCI_DSS_4": ["12.10.1"],
}
_ADMIN_ACCESS = {
    "ISO_27001": ["A.8.20", "A.5.15"],
    "NIST_CSF_2.0": ["PR.IR-01"],
    "GDPR": ["32(1)(b)"],
    "NIST_800_53": ["AC-17", "SC-7"],
    "SOC2": ["CC6.6"],
    "PCI_DSS_4": ["1.3.1"],
}

PROTECTION_SPECS = (
    PropertySpec(
        rule_id="AZ-CMP-008",
        name="Virtual machine is not behind just-in-time access",
        description=(
            "No just-in-time access policy covers this machine, so its management ports "
            "are governed only by its network security groups, open or closed all the "
            "time."
        ),
        rationale=(
            "Just-in-time access keeps RDP and SSH closed until someone asks, for one "
            "address and a few hours. A port that is only open while it is used is a "
            "port nobody can spray passwords at the rest of the week."
        ),
        remediation=(
            "Enable just-in-time access for the machine (needs Defender for Servers "
            "Plan 2).\n\n"
            "Azure Portal: select the machine > Configuration > Just-in-time VM access "
            "> Enable just-in-time."
        ),
        cli=(
            "az rest --method PUT --url https://management.azure.com/subscriptions/"
            "<subscription-id>/resourceGroups/<rg>/providers/Microsoft.Security/locations/"
            "<region>/jitNetworkAccessPolicies/default?api-version=2020-01-01 "
            "--body @jit-policy.json",
        ),
        severity=Severity.LOW,
        exploitability=1,
        category="compute",
        resource_type=ResourceType.VIRTUAL_MACHINE,
        evidence=(AzureEvidence.VIRTUAL_MACHINES, AzureEvidence.JIT_POLICIES),
        field="jit_protected",
        safe=True,
        describes="A just-in-time access policy covers the machine",
        failure="is not behind just-in-time access",
        mappings=_ADMIN_ACCESS,
    ),
    PropertySpec(
        rule_id="AZ-CMP-009",
        name="Virtual machine is not backed up",
        description=(
            "No Recovery Services vault the scanner can read backs up this machine, so "
            "a deleted disk or an encrypted one is unrecoverable."
        ),
        rationale=(
            "Ransomware encrypts what it can reach and deletes what it can find. A "
            "backup in a vault with its own soft delete is the copy it cannot reach."
        ),
        remediation=(
            "Protect the machine with Azure Backup.\n\n"
            "Azure CLI:\n"
            "  az backup protection enable-for-vm --resource-group <rg> \\\n"
            "    --vault-name <vault> --vm <vm> --policy-name DefaultPolicy"
        ),
        cli=(
            "az backup protection enable-for-vm --resource-group <rg> --vault-name <vault> "
            "--vm <vm> --policy-name DefaultPolicy",
        ),
        severity=Severity.MEDIUM,
        exploitability=0,
        category="compute",
        resource_type=ResourceType.VIRTUAL_MACHINE,
        evidence=(AzureEvidence.VIRTUAL_MACHINES, AzureEvidence.VM_BACKUPS),
        field="backed_up",
        safe=True,
        describes="An Azure Backup vault protects the machine",
        failure="is not backed up by Azure Backup",
        mappings=_BACKUP,
        effort_minutes=45,
    ),
    PropertySpec(
        rule_id="AZ-CMP-010",
        name="Unattached disk is encrypted with Microsoft's keys",
        description=(
            "A managed disk attached to no machine is encrypted with a platform key. It "
            "still holds everything its machine wrote, and only a customer-managed key "
            "lets the customer make it unreadable."
        ),
        rationale=(
            "Unattached disks outlive the machines they were made for and are forgotten "
            "with them. Encrypting them with a key the customer controls means revoking "
            "one key retires them all."
        ),
        remediation=(
            "Delete the disk if nobody needs it; otherwise encrypt it through a disk "
            "encryption set.\n\n"
            "Azure CLI:\n"
            "  az disk update --name <disk> --resource-group <rg> \\\n"
            "    --encryption-type EncryptionAtRestWithCustomerKey \\\n"
            "    --disk-encryption-set <disk-encryption-set-id>"
        ),
        cli=(
            "az disk update --name <disk> --resource-group <rg> --encryption-type "
            "EncryptionAtRestWithCustomerKey --disk-encryption-set <disk-encryption-set-id>",
        ),
        severity=Severity.LOW,
        exploitability=0,
        category="compute",
        resource_type=ResourceType.DISK,
        evidence=(AzureEvidence.DISKS,),
        field="customer_managed_key",
        safe=True,
        describes="The disk is encrypted with a customer-managed key",
        failure="is unattached and encrypted with a platform key",
        mappings=_ENCRYPTION,
        applies_when=(("disk_state", "unattached"),),
    ),
    PropertySpec(
        rule_id="AZ-WEB-008",
        name="App Service Authentication is off",
        description=(
            "The app does not use App Service Authentication, so every request reaches "
            "the application code whether or not the caller signed in."
        ),
        rationale=(
            "Platform authentication turns away unauthenticated requests before the "
            "application runs. An app that authenticates in its own code is not wrong, "
            "and can dismiss this; one that relies on nobody finding its address is."
        ),
        remediation=(
            "Turn on App Service Authentication with an identity provider.\n\n"
            "Azure Portal: select the app > Authentication > Add identity provider > "
            "Microsoft > Require authentication > Add."
        ),
        cli=(
            "az webapp auth update --name <app> --resource-group <rg> --enabled true "
            "--action LoginWithAzureActiveDirectory",
        ),
        severity=Severity.LOW,
        exploitability=2,
        category="compute",
        resource_type=ResourceType.APP_SERVICE,
        evidence=(AzureEvidence.APP_SERVICES, AzureEvidence.APP_SERVICE_AUTH),
        field="authentication_enabled",
        safe=True,
        describes="App Service Authentication is on",
        failure="does not use App Service Authentication",
        mappings=_IDENTITY,
    ),
    PropertySpec(
        rule_id="AZ-WEB-009",
        name="Web app sends its HTTP logs nowhere",
        description=(
            "No diagnostic setting sends the web app's HTTP logs anywhere, so there is "
            "no record of which requests it served."
        ),
        rationale=(
            "HTTP logs are what show the probing before an exploit and the requests that "
            "carried it. Written nowhere, they cannot be searched afterwards."
        ),
        remediation=(
            "Send the AppServiceHTTPLogs category to a workspace.\n\n"
            "Azure CLI:\n"
            "  az monitor diagnostic-settings create --name http-logs \\\n"
            "    --resource <app-id> --workspace <workspace-id> \\\n"
            '    --logs \'[{"category":"AppServiceHTTPLogs","enabled":true}]\''
        ),
        cli=(
            "az monitor diagnostic-settings create --name http-logs --resource <app-id> "
            "--workspace <workspace-id> "
            '--logs \'[{"category":"AppServiceHTTPLogs","enabled":true}]\'',
        ),
        severity=Severity.LOW,
        exploitability=1,
        category="compute",
        resource_type=ResourceType.APP_SERVICE,
        evidence=(AzureEvidence.APP_SERVICES, AzureEvidence.DIAGNOSTIC_SETTINGS),
        field="http_logs_exported",
        safe=True,
        describes="A diagnostic setting sends the app's HTTP logs to a destination",
        failure="sends its HTTP logs nowhere",
        mappings=_LOGGING,
        # Function apps log through FunctionAppLogs, not HTTP logs.
        applies_when=(("is_function_app", "false"),),
    ),
)


# Section 177: a Defender profile on AKS, filed wrongly as reading activity and
# answerable from the cluster listing all along; and web apps' HTTP/2 and the
# language versions they run, from the configuration read held since v7.
def _no_runtime_past_support(*prefixes: str) -> Any:
    def test(unsupported: Any) -> bool:
        return not any(str(v).startswith(prefixes) for v in unsupported or [])

    return test


def _runtime(rule_id: str, language: str, label: str, *prefixes: str) -> PropertySpec:
    return PropertySpec(
        rule_id=rule_id,
        name=f"Web app runs a {label} version past end of support",
        description=(
            f"The app runs a {label} version whose community support has ended, so App "
            "Service no longer patches it."
        ),
        rationale=(
            "App Service follows each language's community timeline and stops patching "
            "a version when its community does. The app keeps running, and every "
            "vulnerability found in that runtime afterwards stays in it."
        ),
        remediation=(
            f"Move the app to a supported {label} version, and test it there first.\n\n"
            "Azure CLI:\n"
            "  az webapp config set --name <app> --resource-group <rg> \\\n"
            '    --linux-fx-version "<STACK>|<version>"'
        ),
        cli=(
            "az webapp config set --name <app> --resource-group <rg> "
            '--linux-fx-version "<STACK>|<version>"',
        ),
        severity=Severity.MEDIUM,
        exploitability=2,
        category="compute",
        resource_type=ResourceType.APP_SERVICE,
        evidence=(AzureEvidence.APP_SERVICES, AzureEvidence.APP_SERVICE_CONFIGS),
        field="unsupported_runtimes",
        passes=_no_runtime_past_support(*prefixes),
        why_no_expected_state=(
            "Every supported version passes, and which those are changes with the "
            "calendar, so there is no one value to expect."
        ),
        describes=f"The app runs a {label} version still in community support",
        failure=f"runs a {label} version past end of support",
        mappings={**_HARDENING, "NIST_CSF_2.0": ["ID.RA-01", "PR.PS-02"]},
        applies_when=(("runtime_languages", language),),
    )


LIFECYCLE_SPECS = (
    PropertySpec(
        rule_id="AZ-AKS-008",
        name="Kubernetes cluster has no Defender security profile",
        description=(
            "Defender for Containers' sensor is not enabled on the cluster, so its "
            "nodes and workloads get no runtime threat detection."
        ),
        rationale=(
            "The sensor is what sees a container spawning a shell, a miner started in "
            "a pod or a node reaching for the metadata service. The plan being on is "
            "not enough if the cluster never received it."
        ),
        remediation=(
            "Azure CLI:\n  az aks update --name <cluster> --resource-group <rg> --enable-defender"
        ),
        cli=("az aks update --name <cluster> --resource-group <rg> --enable-defender",),
        severity=Severity.MEDIUM,
        exploitability=1,
        category="compute",
        resource_type=ResourceType.KUBERNETES_CLUSTER,
        evidence=(AzureEvidence.KUBERNETES_CLUSTERS,),
        field="defender_enabled",
        safe=True,
        # Absent is the default: no security profile, no sensor.
        absent="fail",
        describes="The Defender security profile's monitoring is enabled",
        failure="has no Defender security profile",
        mappings=_LOGGING,
    ),
    PropertySpec(
        rule_id="AZ-WEB-010",
        name="Web app does not use HTTP/2",
        description="The app serves HTTP/1.1 only.",
        rationale=(
            "HTTP/2 is faster over TLS and every current browser speaks it. Listed for "
            "completeness at LOW: it is performance, not a door."
        ),
        remediation=(
            "Azure CLI:\n"
            "  az webapp config set --name <app> --resource-group <rg> --http20-enabled true"
        ),
        cli=("az webapp config set --name <app> --resource-group <rg> --http20-enabled true",),
        severity=Severity.LOW,
        exploitability=0,
        category="compute",
        resource_type=ResourceType.APP_SERVICE,
        evidence=(AzureEvidence.APP_SERVICES, AzureEvidence.APP_SERVICE_CONFIGS),
        field="http2_enabled",
        safe=True,
        terraform_attribute="site_config.http2_enabled",
        terraform_resource_types=("azurerm_linux_web_app", "azurerm_windows_web_app"),
        describes="HTTP/2 is enabled",
        failure="does not use HTTP/2",
        mappings=_HARDENING,
    ),
    _runtime("AZ-WEB-011", "python", "Python", "python "),
    _runtime("AZ-WEB-012", "php", "PHP", "php "),
    _runtime("AZ-WEB-013", "java", "Java", "java ", "tomcat "),
)

RULES = tuple(property_rule(spec) for spec in (*SPECS, *PROTECTION_SPECS, *LIFECYCLE_SPECS))
