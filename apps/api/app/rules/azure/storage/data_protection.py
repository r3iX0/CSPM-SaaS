"""Storage rules about where data can go and whether it can come back.

``public_access.py`` asks who can read an account. These ask the two questions
after a breach or a mistake: whether its blobs can be copied into somebody
else's tenant, and whether a deleted blob is gone.
"""

from typing import ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import ExpectedState, RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule


class AzureStorageCrossTenantReplicationRule(SecurityRule):
    rule_id = "AZ-STO-004"
    name = "Storage account can replicate into another tenant"
    description = (
        "A storage account allows object replication policies whose destination is in "
        "a different Microsoft Entra tenant. Anyone who can write a replication policy "
        "on it can have every new blob copied continuously to an account they own."
    )
    category = "storage"
    severity = Severity.MEDIUM
    # Needs a foothold with rights to write a replication policy first. What it
    # then offers is exfiltration that looks like a feature and runs by itself.
    exploitability = 2
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.STORAGE_ACCOUNT]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.STORAGE_ACCOUNTS,
    )
    estimated_effort_minutes = 10
    rationale = (
        "Replication across tenants is almost never wanted and very hard to notice: "
        "the copying is done by Azure, not by a client, so there is no unusual download "
        "to alert on. Accounts created before 15 December 2023 permit it unless "
        "somebody turned it off, which most never did."
    )
    remediation = (
        "Disallow cross-tenant replication.\n\n"
        "Azure Portal: Storage account > Data management > Object replication > Advanced "
        "settings > untick 'Allow cross-tenant replication' > OK.\n\n"
        "Azure CLI:\n"
        "  az storage account update --name <account> --resource-group <rg> \\\n"
        "    --allow-cross-tenant-replication false\n\n"
        "Azure refuses the change while a cross-tenant policy exists; delete those "
        "first, and ask why they were there."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="allow_cross_tenant_replication",
                equals=False,
                describes="Object replication across Entra tenants is disallowed",
                # Verified against Microsoft's own audit and deny definitions in
                # "Prevent object replication across Microsoft Entra tenants".
                arm_alias="Microsoft.Storage/storageAccounts/allowCrossTenantReplication",
                terraform_attribute="cross_tenant_replication_enabled",
            ),
        ),
        cli=(
            "az storage account update --name <account> --resource-group <rg> "
            "--allow-cross-tenant-replication false",
        ),
        policy_resource_type="Microsoft.Storage/storageAccounts",
        policy_effect="Deny",
    )
    # No CIS mapping: CIS Azure 2.0 predates a control for this.
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.8.3", "A.5.10"],
        "NIST_CSF": ["PR.DS-5", "PR.AC-4"],
        "GDPR": ["5(1)(f)", "44"],
        "NIST_800_53": ["AC-3", "SC-7"],
        "SOC2": ["CC6.1", "CC6.7"],
        "PCI_DSS_4": ["7.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Storage configuration unavailable: {failure}")

        allowed = resource.get("allow_cross_tenant_replication")
        evidence = {"allow_cross_tenant_replication": allowed}
        if allowed is False:
            return RuleResult.passed(evidence)
        # Absent is read as allowed, and this is the documented default rather
        # than a guess: Azure does not return the property on an account created
        # before 15 December 2023 that never set it, and states that such an
        # account can take part in cross-tenant policies.
        return RuleResult.failed(
            evidence={**evidence, "default_applied": allowed is None},
            message=f"{resource.name} permits replication into another Entra tenant",
        )


class AzureBlobSoftDeleteRule(SecurityRule):
    rule_id = "AZ-STO-005"
    name = "Deleted blobs cannot be recovered"
    description = (
        "A storage account has soft delete off for blobs, for containers, or for both. "
        "A blob or container deleted by mistake, by a script, or by an attacker is gone "
        "at once."
    )
    category = "storage"
    severity = Severity.MEDIUM
    # A foothold with write access first. What it removes is the undo, the same
    # shape as a purgeable key vault one tier down.
    exploitability = 2
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.STORAGE_ACCOUNT]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.STORAGE_ACCOUNTS,
        AzureEvidence.STORAGE_BLOB_SERVICES,
    )
    estimated_effort_minutes = 10
    rationale = (
        "Ransomware against cloud storage does not encrypt blobs so much as delete "
        "them, and a deleted container takes every blob inside it. Soft delete turns "
        "that into a restore measured in minutes, for the price of keeping deleted data "
        "for the retention you choose."
    )
    remediation = (
        "Turn on soft delete for blobs and for containers.\n\n"
        "Azure Portal: Storage account > Data management > Data protection > tick "
        "'Enable soft delete for blobs' and 'Enable soft delete for containers', set a "
        "retention > Save.\n\n"
        "Azure CLI:\n"
        "  az storage account blob-service-properties update \\\n"
        "    --account-name <account> --resource-group <rg> \\\n"
        "    --enable-delete-retention true --delete-retention-days 14 \\\n"
        "    --enable-container-delete-retention true --container-delete-retention-days 14"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="blob_soft_delete",
                equals=True,
                describes="A deleted blob is kept for a retention period",
            ),
            ExpectedState(
                field="container_soft_delete",
                equals=True,
                describes="A deleted container is kept for a retention period",
            ),
        ),
        cli=(
            "az storage account blob-service-properties update --account-name <account> "
            "--resource-group <rg> --enable-delete-retention true "
            "--delete-retention-days 14 --enable-container-delete-retention true "
            "--container-delete-retention-days 14",
        ),
        notes=(
            "No policy is generated. Both settings live on the blob service child "
            "resource, and its aliases have not been verified against a real "
            "deployment from here."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["3.11"],
        "ISO_27001": ["A.8.13"],
        "NIST_CSF": ["PR.IP-4", "RC.RP-1"],
        "GDPR": ["32(1)(c)"],
        "NIST_800_53": ["CP-9"],
        "SOC2": ["A1.2"],
        "PCI_DSS_4": ["12.10.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Storage configuration unavailable: {failure}")

        blobs = resource.get("blob_soft_delete")
        containers = resource.get("container_soft_delete")
        if blobs is None or containers is None:
            return RuleResult.unknown(
                "The account's blob service could not be read. If this persists, the "
                "deployed scanner role may predate the permission that reads it."
            )

        evidence = {
            "blob_soft_delete": blobs,
            "blob_retention_days": resource.get("blob_retention_days"),
            "container_soft_delete": containers,
            "container_retention_days": resource.get("container_retention_days"),
            "blob_versioning": resource.get("blob_versioning"),
        }
        problems = []
        if blobs is not True:
            problems.append("Deleted blobs are not kept")
        if containers is not True:
            problems.append("Deleted containers are not kept")
        if not problems:
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence={**evidence, "problems": problems},
            message=f"{resource.name} cannot recover deleted data: " + "; ".join(problems),
        )
