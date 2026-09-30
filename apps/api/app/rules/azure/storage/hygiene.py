"""Storage account configuration hygiene (DECISIONS.md section 174).

Six Tier 2 checks, each one setting on the storage listing or the blob service
beneath it, declared as :class:`~app.rules.property.PropertySpec`. None needs a
permission the scanner does not already hold. Four more (section 176) read the
file service beneath the account, under role v11, and the access key expiry
policy the listing always carried.
"""

from typing import Any

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, Severity
from app.rules.property import PropertySpec, property_rule

_ACCOUNT = (AzureEvidence.STORAGE_ACCOUNTS,)
_BLOBS = (AzureEvidence.STORAGE_ACCOUNTS, AzureEvidence.STORAGE_BLOB_SERVICES)

_ENCRYPTION = {
    "ISO_27001": ["A.8.24"],
    "NIST_CSF": ["PR.DS-1"],
    "GDPR": ["32(1)(a)"],
    "NIST_800_53": ["SC-12", "SC-28"],
    "SOC2": ["CC6.1"],
    "PCI_DSS_4": ["3.5.1"],
}
_NETWORK = {
    "ISO_27001": ["A.8.20", "A.8.22"],
    "NIST_CSF": ["PR.AC-5"],
    "GDPR": ["32(1)(b)"],
    "NIST_800_53": ["SC-7"],
    "SOC2": ["CC6.6"],
    "PCI_DSS_4": ["1.3.1"],
}


def _bypasses_azure_services(value: Any) -> bool:
    return "azureservices" in str(value or "").replace(" ", "").lower().split(",")


def _has_private_endpoint(count: Any) -> bool:
    return isinstance(count, int) and count >= 1


SPECS = (
    PropertySpec(
        rule_id="AZ-STO-006",
        name="Blob versioning is off",
        description=(
            "The account keeps no earlier versions of a blob when it is overwritten, so "
            "a bad write or ransomware's encryption replaces the only copy."
        ),
        rationale=(
            "Soft delete recovers what was deleted; only versioning recovers what was "
            "overwritten -- which is what ransomware does to storage it can write to."
        ),
        remediation=(
            "Turn on blob versioning, with a lifecycle rule to expire old versions.\n\n"
            "Azure CLI:\n"
            "  az storage account blob-service-properties update \\\n"
            "    --account-name <account> --resource-group <rg> --enable-versioning true"
        ),
        cli=(
            "az storage account blob-service-properties update --account-name <account> "
            "--resource-group <rg> --enable-versioning true",
        ),
        severity=Severity.MEDIUM,
        exploitability=2,
        category="storage",
        resource_type=ResourceType.STORAGE_ACCOUNT,
        evidence=_BLOBS,
        field="blob_versioning",
        safe=True,
        describes="Blob versioning keeps earlier versions of overwritten blobs",
        terraform_attribute="blob_properties.versioning_enabled",
        failure="keeps no earlier versions of overwritten blobs",
        mappings={
            "ISO_27001": ["A.8.13"],
            "NIST_CSF": ["PR.IP-4"],
            "GDPR": ["32(1)(c)"],
            "NIST_800_53": ["CP-9"],
            "SOC2": ["A1.2"],
            "PCI_DSS_4": ["10.5.1"],
        },
    ),
    PropertySpec(
        rule_id="AZ-STO-007",
        name="Storage infrastructure encryption is off",
        description=(
            "Data is encrypted once at rest, not twice: the account was created without "
            "the second, infrastructure-level layer of encryption."
        ),
        rationale=(
            "The second layer uses a different algorithm and key, so a flaw in one does "
            "not expose the data. It can only be chosen when the account is created."
        ),
        remediation=(
            "Create a replacement account with infrastructure encryption and move the "
            "data; the setting cannot be changed on an existing account.\n\n"
            "Azure CLI:\n"
            "  az storage account create --name <account> --resource-group <rg> \\\n"
            "    --require-infrastructure-encryption"
        ),
        cli=(
            "az storage account create --name <account> --resource-group <rg> "
            "--require-infrastructure-encryption",
        ),
        severity=Severity.LOW,
        exploitability=0,
        category="storage",
        resource_type=ResourceType.STORAGE_ACCOUNT,
        evidence=_ACCOUNT,
        field="infrastructure_encryption",
        safe=True,
        # ARM leaves the field out unless it was requested at creation.
        absent="fail",
        describes="Data is encrypted twice at rest",
        terraform_attribute="infrastructure_encryption_enabled",
        failure="encrypts its data at rest once rather than twice",
        mappings=_ENCRYPTION,
    ),
    PropertySpec(
        rule_id="AZ-STO-008",
        name="Storage account is encrypted with Microsoft's keys",
        description=(
            "The account's data is encrypted with a key Microsoft manages rather than "
            "one in the customer's key vault."
        ),
        rationale=(
            "A customer-managed key is what lets the customer make the data unreadable "
            "by revoking a key, and what some regulated data requires."
        ),
        remediation=(
            "Grant the account's managed identity access to a key in a vault with purge "
            "protection, then point the account's encryption at it.\n\n"
            "Azure CLI:\n"
            "  az storage account update --name <account> --resource-group <rg> \\\n"
            "    --encryption-key-source Microsoft.Keyvault \\\n"
            "    --encryption-key-vault <vault-uri> --encryption-key-name <key>"
        ),
        cli=(
            "az storage account update --name <account> --resource-group <rg> "
            "--encryption-key-source Microsoft.Keyvault --encryption-key-vault <vault-uri> "
            "--encryption-key-name <key>",
        ),
        severity=Severity.LOW,
        exploitability=0,
        category="storage",
        resource_type=ResourceType.STORAGE_ACCOUNT,
        evidence=_ACCOUNT,
        field="customer_managed_key",
        safe=True,
        describes="Data at rest is encrypted with a customer-managed key",
        failure="encrypts its data with a key Microsoft manages",
        mappings=_ENCRYPTION,
    ),
    PropertySpec(
        rule_id="AZ-STO-009",
        name="Storage portal access does not default to Entra authorization",
        description=(
            "The Azure portal reaches this account's data with its access keys by "
            "default rather than with the signed-in user's own Entra permissions."
        ),
        rationale=(
            "With key-based access as the default, anyone who can list the keys sees all "
            "the data in the portal, whatever data roles they were given."
        ),
        remediation=(
            "Azure CLI:\n"
            "  az storage account update --name <account> --resource-group <rg> \\\n"
            "    --set defaultToOAuthAuthentication=true"
        ),
        cli=(
            "az storage account update --name <account> --resource-group <rg> "
            "--set defaultToOAuthAuthentication=true",
        ),
        severity=Severity.LOW,
        exploitability=1,
        category="storage",
        resource_type=ResourceType.STORAGE_ACCOUNT,
        evidence=_ACCOUNT,
        field="default_to_entra_auth",
        safe=True,
        # Absent is the documented default, false.
        absent="fail",
        describes="The portal uses the signed-in user's Entra permissions by default",
        terraform_attribute="default_to_oauth_authentication",
        failure="lets the portal read its data with its access keys by default",
        mappings={
            "ISO_27001": ["A.5.15"],
            "NIST_CSF": ["PR.AC-4"],
            "GDPR": ["32(1)(b)"],
            "NIST_800_53": ["AC-3", "AC-6"],
            "SOC2": ["CC6.1"],
            "PCI_DSS_4": ["7.2.1"],
        },
    ),
    PropertySpec(
        rule_id="AZ-STO-010",
        name="Trusted Azure services cannot reach a network-restricted account",
        description=(
            "The account's network rules do not let trusted Azure services through, so "
            "backup, logging and Defender cannot reach it once the rules deny by default."
        ),
        rationale=(
            "Without the bypass, tightening the network rules breaks the services that "
            "protect the account, and the usual response is to open the rules again."
        ),
        remediation=(
            "Azure CLI:\n"
            "  az storage account update --name <account> --resource-group <rg> \\\n"
            "    --bypass AzureServices"
        ),
        cli=(
            "az storage account update --name <account> --resource-group <rg> "
            "--bypass AzureServices",
        ),
        severity=Severity.LOW,
        exploitability=0,
        category="storage",
        resource_type=ResourceType.STORAGE_ACCOUNT,
        evidence=_ACCOUNT,
        field="network_bypass",
        passes=_bypasses_azure_services,
        why_no_expected_state=(
            "The bypass is a list of services, and what is expected is that it contains "
            "AzureServices -- which one equality cannot state."
        ),
        describes="Trusted Azure services may bypass the network rules",
        failure="does not let trusted Azure services through its network rules",
        mappings=_NETWORK,
    ),
    PropertySpec(
        rule_id="AZ-STO-011",
        name="Storage account has no private endpoint",
        description=(
            "No approved private endpoint serves the account, so every client reaches "
            "it over its public endpoint."
        ),
        rationale=(
            "A private endpoint is what lets public access be switched off without "
            "cutting off the workloads that use the account."
        ),
        remediation=(
            "Azure CLI:\n"
            "  az network private-endpoint create --name <endpoint> --resource-group <rg> \\\n"
            "    --vnet-name <vnet> --subnet <subnet> \\\n"
            "    --private-connection-resource-id <resource-id> --group-id blob \\\n"
            "    --connection-name <connection>"
        ),
        cli=(
            "az network private-endpoint create --name <endpoint> --resource-group <rg> "
            "--vnet-name <vnet> --subnet <subnet> --private-connection-resource-id "
            "<resource-id> --group-id blob --connection-name <connection>",
        ),
        severity=Severity.LOW,
        exploitability=1,
        category="storage",
        resource_type=ResourceType.STORAGE_ACCOUNT,
        evidence=_ACCOUNT,
        field="private_endpoints",
        passes=_has_private_endpoint,
        why_no_expected_state=(
            "What is expected is a count -- at least one approved private endpoint -- "
            "and the endpoint is a resource of its own."
        ),
        describes="At least one approved private endpoint serves the account",
        failure="has no approved private endpoint",
        mappings=_NETWORK,
    ),
)

# Section 176: the file service beneath the account, read under role v11, and
# the access key expiry policy the listing already carried.
_FILES = (AzureEvidence.STORAGE_ACCOUNTS, AzureEvidence.STORAGE_FILE_SERVICES)
_HAS_FILES = (("has_file_service", "true"),)
_RECOVERY = {
    "ISO_27001": ["A.8.13"],
    "NIST_CSF": ["PR.IP-4", "RC.RP-1"],
    "GDPR": ["32(1)(c)"],
    "NIST_800_53": ["CP-9"],
    "SOC2": ["A1.2"],
    "PCI_DSS_4": ["12.10.1"],
}
_TRANSPORT = {
    "ISO_27001": ["A.8.24"],
    "NIST_CSF": ["PR.DS-2"],
    "GDPR": ["32(1)(a)"],
    "NIST_800_53": ["SC-8"],
    "SOC2": ["CC6.7"],
    "PCI_DSS_4": ["4.2.1"],
}


def _only(allowed: str) -> Any:
    def test(value: Any) -> bool:
        offered = {v.strip().lower() for v in str(value or "").split(";") if v.strip()}
        return offered == {allowed}

    return test


def _keys_expire_within_ninety_days(days: Any) -> bool:
    return isinstance(days, int) and 0 < days <= 90


FILE_SPECS = (
    PropertySpec(
        rule_id="AZ-STO-012",
        name="File share soft delete is off",
        description=(
            "Deleted file shares in this account are gone at once: soft delete is off, "
            "so a share removed by mistake or by an intruder cannot be restored."
        ),
        rationale=(
            "Deleting a share is one call and removes every file in it. Soft delete keeps "
            "it recoverable for a retention period, which is the difference between an "
            "outage and a loss."
        ),
        remediation=(
            "Turn on soft delete for file shares.\n\n"
            "Azure CLI:\n"
            "  az storage account file-service-properties update \\\n"
            "    --account-name <account> --resource-group <rg> \\\n"
            "    --enable-delete-retention true --delete-retention-days 7"
        ),
        cli=(
            "az storage account file-service-properties update --account-name <account> "
            "--resource-group <rg> --enable-delete-retention true --delete-retention-days 7",
        ),
        severity=Severity.MEDIUM,
        exploitability=1,
        category="storage",
        resource_type=ResourceType.STORAGE_ACCOUNT,
        evidence=_FILES,
        field="file_share_soft_delete",
        safe=True,
        describes="Soft delete is on for file shares",
        failure="does not keep deleted file shares recoverable",
        mappings=_RECOVERY,
        applies_when=_HAS_FILES,
    ),
    PropertySpec(
        rule_id="AZ-STO-013",
        name="File shares accept SMB versions older than 3.1.1",
        description=(
            "The account's file shares accept SMB 2.1 or 3.0 as well as 3.1.1. An unset "
            "setting accepts all three."
        ),
        rationale=(
            "SMB 3.1.1 adds pre-authentication integrity, which stops a downgrade to a "
            "weaker dialect by someone on the path. Older clients are the only reason "
            "to keep the rest."
        ),
        remediation=(
            "Allow SMB 3.1.1 only.\n\n"
            "Azure CLI:\n"
            "  az storage account file-service-properties update \\\n"
            "    --account-name <account> --resource-group <rg> --versions SMB3.1.1"
        ),
        cli=(
            "az storage account file-service-properties update --account-name <account> "
            "--resource-group <rg> --versions SMB3.1.1",
        ),
        severity=Severity.LOW,
        exploitability=1,
        category="storage",
        resource_type=ResourceType.STORAGE_ACCOUNT,
        evidence=_FILES,
        field="smb_versions",
        passes=_only("smb3.1.1"),
        why_no_expected_state=(
            "The setting is a delimited list whose order is not fixed, so there is no one "
            "string to expect."
        ),
        describes="Only SMB 3.1.1 is allowed",
        failure="accepts SMB versions older than 3.1.1",
        mappings=_TRANSPORT,
        applies_when=_HAS_FILES,
    ),
    PropertySpec(
        rule_id="AZ-STO-014",
        name="File shares accept SMB channel ciphers weaker than AES-256-GCM",
        description=(
            "The account's file shares negotiate AES-128 channel encryption as well as "
            "AES-256-GCM. An unset setting accepts all three ciphers."
        ),
        rationale=(
            "AES-256-GCM is the strongest cipher SMB offers and every current client "
            "supports it; allowing the others only helps a downgrade."
        ),
        remediation=(
            "Allow AES-256-GCM only.\n\n"
            "Azure CLI:\n"
            "  az storage account file-service-properties update \\\n"
            "    --account-name <account> --resource-group <rg> \\\n"
            "    --channel-encryption AES-256-GCM"
        ),
        cli=(
            "az storage account file-service-properties update --account-name <account> "
            "--resource-group <rg> --channel-encryption AES-256-GCM",
        ),
        severity=Severity.LOW,
        exploitability=1,
        category="storage",
        resource_type=ResourceType.STORAGE_ACCOUNT,
        evidence=_FILES,
        field="smb_channel_encryption",
        passes=_only("aes-256-gcm"),
        why_no_expected_state=(
            "The setting is a delimited list whose order is not fixed, so there is no one "
            "string to expect."
        ),
        describes="Only AES-256-GCM is allowed for SMB channel encryption",
        failure="accepts SMB channel ciphers weaker than AES-256-GCM",
        mappings=_TRANSPORT,
        applies_when=_HAS_FILES,
    ),
    PropertySpec(
        rule_id="AZ-STO-015",
        name="Storage access keys are not set to expire within 90 days",
        description=(
            "The account has no key expiration policy, or one longer than 90 days, so "
            "nothing prompts its access keys to be rotated."
        ),
        rationale=(
            "An access key is full control of the account's data. A key expiration "
            "policy makes Azure flag a key overdue for rotation, which is how a key "
            "copied into a script three years ago gets noticed."
        ),
        remediation=(
            "Set a key expiration policy of 90 days or less.\n\n"
            "Azure CLI:\n"
            "  az storage account update --name <account> --resource-group <rg> \\\n"
            "    --key-exp-days 90"
        ),
        cli=(
            "az storage account update --name <account> --resource-group <rg> "
            "--key-exp-days 90",
        ),
        severity=Severity.MEDIUM,
        exploitability=1,
        category="storage",
        resource_type=ResourceType.STORAGE_ACCOUNT,
        evidence=_ACCOUNT,
        field="key_expiration_days",
        passes=_keys_expire_within_ninety_days,
        why_no_expected_state="Any period up to 90 days passes, so there is no one value.",
        # No policy is the default.
        absent="fail",
        describes="A key expiration policy of 90 days or less is set",
        failure="sets no access key expiry of 90 days or less",
        mappings={
            "ISO_27001": ["A.5.17"],
            "NIST_CSF": ["PR.AC-1"],
            "GDPR": ["32(1)(b)"],
            "NIST_800_53": ["IA-5"],
            "SOC2": ["CC6.1"],
            "PCI_DSS_4": ["8.3.1"],
        },
    ),
)

RULES = tuple(property_rule(spec) for spec in (*SPECS, *FILE_SPECS))
