"""Storage account keys, locks and logging (DECISIONS.md section 204).

Four checks CIS asks of a storage account that no rule answered. Two read the
listing the scanner has always taken -- whether shared keys are accepted at all,
and how long since one was regenerated -- one reads the locks role v13 lists,
and one the diagnostic settings beneath the account's services.
"""

from typing import Any

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, Severity
from app.rules.property import PropertySpec, property_rule

_ACCOUNT = (AzureEvidence.STORAGE_ACCOUNTS,)

_KEYS = {
    "ISO_27001": ["A.5.17"],
    "NIST_CSF_2.0": ["PR.AA-01"],
    "GDPR": ["32(1)(b)"],
    "NIST_800_53": ["IA-5"],
    "SOC2": ["CC6.1"],
    "PCI_DSS_4": ["8.3.1"],
}


def _regenerated_within_ninety_days(days: Any) -> bool:
    return isinstance(days, int) and days <= 90


def _every_service_logs(missing: Any) -> bool:
    return isinstance(missing, list) and not missing


SPECS = (
    PropertySpec(
        rule_id="AZ-STO-017",
        name="Storage account accepts shared key authorization",
        description=(
            "The account accepts requests signed with its access keys, and the shared "
            "access signatures made from them, as well as Entra ID. An unset setting "
            "accepts them."
        ),
        rationale=(
            "An access key is full control of every byte in the account, never expires on "
            "its own and names nobody when used. Accepting only Entra ID means every "
            "request is a person or workload with a role that can be revoked."
        ),
        remediation=(
            "Move every client to Entra ID authorization, then turn shared key access "
            "off.\n\n"
            "Azure CLI:\n"
            "  az storage account update --name <account> --resource-group <rg> \\\n"
            "    --allow-shared-key-access false\n\n"
            "Check the account's StorageRead and StorageWrite logs for requests "
            "authenticated with a key or SAS first: those clients stop working."
        ),
        cli=(
            "az storage account update --name <account> --resource-group <rg> "
            "--allow-shared-key-access false",
        ),
        severity=Severity.MEDIUM,
        exploitability=2,
        category="storage",
        resource_type=ResourceType.STORAGE_ACCOUNT,
        evidence=_ACCOUNT,
        field="allow_shared_key_access",
        safe=False,
        # Azure documents null as allowing shared key access.
        absent="fail",
        describes="Shared key authorization is disallowed",
        failure="accepts requests signed with its access keys",
        terraform_attribute="shared_access_key_enabled",
        terraform_value=False,
        terraform_resource_types=("azurerm_storage_account",),
        mappings={**_KEYS, "CIS_AZURE_6.0": ["9.3.1.3"]},
        effort_minutes=120,
    ),
    PropertySpec(
        rule_id="AZ-STO-018",
        name="Storage access key not regenerated in 90 days",
        description=(
            "One of the account's access keys was created or last regenerated more than "
            "90 days before this scan read the account."
        ),
        rationale=(
            "A key that has existed for a year has had a year to be copied into a script, "
            "a pipeline variable or a laptop. Regenerating it is the only way to know who "
            "still holds a working one."
        ),
        remediation=(
            "Regenerate the older key once the clients using it have moved to the other.\n\n"
            "Azure CLI:\n"
            "  az storage account keys renew --account-name <account> \\\n"
            "    --resource-group <rg> --key primary"
        ),
        cli=(
            "az storage account keys renew --account-name <account> --resource-group <rg> "
            "--key primary",
        ),
        severity=Severity.LOW,
        exploitability=1,
        category="storage",
        resource_type=ResourceType.STORAGE_ACCOUNT,
        evidence=_ACCOUNT,
        field="key_age_days",
        passes=_regenerated_within_ninety_days,
        why_no_expected_state=(
            "The age of a key is not a setting; it is reset by regenerating the key."
        ),
        describes="Both access keys were regenerated within 90 days",
        failure="has an access key not regenerated in over 90 days",
        mappings={
            **_KEYS,
            "PCI_DSS_4": ["8.3.1", "8.6"],
            "CIS_AZURE_2.0": ["3.4"],
            "CIS_AZURE_6.0": ["9.3.1.2"],
        },
        effort_minutes=30,
    ),
    PropertySpec(
        rule_id="AZ-STO-019",
        name="Storage account has no delete lock",
        description=(
            "No CanNotDelete or ReadOnly lock on the account, its resource group or its "
            "subscription stops it being deleted."
        ),
        rationale=(
            "Deleting a storage account deletes its data with it, and soft delete does not "
            "survive the account. A lock makes deletion a deliberate two-step act rather "
            "than one mistaken command or one compromised Contributor."
        ),
        remediation=(
            "Add a delete lock.\n\n"
            "Azure CLI:\n"
            "  az lock create --name keep-<account> --lock-type CanNotDelete \\\n"
            "    --resource-group <rg> --resource <account> \\\n"
            "    --resource-type Microsoft.Storage/storageAccounts"
        ),
        cli=(
            "az lock create --name keep-<account> --lock-type CanNotDelete --resource-group "
            "<rg> --resource <account> --resource-type Microsoft.Storage/storageAccounts",
        ),
        severity=Severity.LOW,
        exploitability=0,
        category="storage",
        resource_type=ResourceType.STORAGE_ACCOUNT,
        evidence=(AzureEvidence.STORAGE_ACCOUNTS, AzureEvidence.RESOURCE_LOCKS),
        field="delete_locked",
        safe=True,
        describes="A CanNotDelete or ReadOnly lock protects the account",
        failure="has no lock stopping its deletion",
        mappings={
            "ISO_27001": ["A.8.13"],
            "NIST_CSF_2.0": ["PR.DS-11"],
            "GDPR": ["32(1)(c)"],
            "NIST_800_53": ["CP-9", "CM-6"],
            "SOC2": ["A1.2"],
            "PCI_DSS_4": ["12.10.1"],
            "CIS_AZURE_6.0": ["9.3.9"],
            "MITRE_ATTACK": ["T1485"],
        },
        effort_minutes=10,
    ),
    PropertySpec(
        rule_id="AZ-STO-020",
        name="Storage services do not log reads, writes and deletes",
        description=(
            "The blob, queue or table service beneath the account has no diagnostic "
            "setting sending StorageRead, StorageWrite and StorageDelete logs anywhere."
        ),
        rationale=(
            "Without these logs there is no record of who read, changed or deleted data "
            "in the account -- the first question after a key leaks or a container is "
            "found public."
        ),
        remediation=(
            "Add a diagnostic setting to each service sending the three categories to a "
            "Log Analytics workspace.\n\n"
            "Azure CLI (repeat for queueServices and tableServices):\n"
            "  az monitor diagnostic-settings create --name storage-logs \\\n"
            "    --resource <account-id>/blobServices/default \\\n"
            "    --workspace <workspace-id> \\\n"
            '    --logs \'[{"categoryGroup":"allLogs","enabled":true}]\''
        ),
        cli=(
            "az monitor diagnostic-settings create --name storage-logs --resource "
            "<account-id>/blobServices/default --workspace <workspace-id> --logs "
            '\'[{"categoryGroup":"allLogs","enabled":true}]\'',
        ),
        severity=Severity.LOW,
        exploitability=0,
        category="logging",
        resource_type=ResourceType.STORAGE_ACCOUNT,
        evidence=(AzureEvidence.STORAGE_ACCOUNTS, AzureEvidence.STORAGE_SERVICE_DIAGNOSTICS),
        field="services_without_logging",
        passes=_every_service_logs,
        why_no_expected_state=(
            "The finding names services, each fixed by its own diagnostic setting."
        ),
        describes="Every service beneath the account logs reads, writes and deletes",
        failure="has services that log nothing of what is done to their data",
        mappings={
            "ISO_27001": ["A.8.15"],
            "NIST_CSF_2.0": ["PR.PS-04", "DE.AE-03"],
            "GDPR": ["30", "32(1)(d)"],
            "NIST_800_53": ["AU-2", "AU-6"],
            "SOC2": ["CC7.2"],
            "PCI_DSS_4": ["10.2.1"],
            "CIS_AZURE_2.0": ["3.5", "3.13", "3.14"],
        },
        effort_minutes=20,
    ),
)

RULES = tuple(property_rule(spec) for spec in SPECS)
