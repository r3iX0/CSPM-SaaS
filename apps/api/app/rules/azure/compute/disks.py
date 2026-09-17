"""Virtual machine disks: where a machine's data actually lives."""

from typing import ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import Comparison, ExpectedState, RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule


class AzureUnmanagedDiskRule(SecurityRule):
    rule_id = "AZ-CMP-003"
    name = "Virtual machine runs on unmanaged disks"
    description = (
        "A virtual machine has disks stored as VHD blobs in a storage account rather "
        "than as managed disks. The machine's data is then as safe as that storage "
        "account -- its keys, its network rules and whoever can list its containers."
    )
    category = "compute"
    severity = Severity.MEDIUM
    # A storage account key or a role over the account is needed first. With
    # either, the disk is a blob to download, and nothing on the machine sees it.
    exploitability = 2
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.VIRTUAL_MACHINE]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (AzureEvidence.VIRTUAL_MACHINES,)
    estimated_effort_minutes = 120
    rationale = (
        "A managed disk is a resource with its own RBAC, its own encryption settings and "
        "no account key that unlocks it. An unmanaged disk is a file in a storage "
        "account, readable by anyone holding that account's key -- and Microsoft has "
        "retired unmanaged disks, so a machine still on them is also one living on "
        "borrowed time."
    )
    remediation = (
        "Convert the machine to managed disks. It needs a stop and a start.\n\n"
        "Azure CLI:\n"
        "  az vm deallocate --resource-group <rg> --name <vm>\n"
        "  az vm convert --resource-group <rg> --name <vm>\n"
        "  az vm start --resource-group <rg> --name <vm>\n\n"
        "Delete the original VHD blobs once the machine is confirmed working -- until "
        "then they are a full copy of its disks in a storage account."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="unmanaged_disks",
                comparison=Comparison.NONE_MATCHING,
                equals=None,
                describes="Every disk on the machine is a managed disk",
                example="OS disk",
            ),
        ),
        cli=(
            "az vm deallocate --resource-group <rg> --name <vm>",
            "az vm convert --resource-group <rg> --name <vm>",
            "az vm start --resource-group <rg> --name <vm>",
        ),
        notes=(
            "No policy is generated. Azure Policy can audit unmanaged disks through the "
            "virtual machine's storage profile, and that expression has not been "
            "verified against a real deployment from here."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["7.2"],
        "ISO_27001": ["A.8.24", "A.8.3"],
        "NIST_CSF": ["PR.DS-1"],
        "GDPR": ["32(1)(a)"],
        "NIST_800_53": ["SC-28", "AC-3"],
        "SOC2": ["CC6.1"],
        "PCI_DSS_4": ["3.5.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Virtual machine configuration unavailable: {failure}")

        unmanaged = resource.get("unmanaged_disks")
        if unmanaged is None:
            return RuleResult.unknown("The machine's disk configuration is missing from snapshot")

        evidence = {"unmanaged_disks": unmanaged, "os_type": resource.get("os_type")}
        if not unmanaged:
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=(
                f"{resource.name} stores {len(unmanaged)} disk(s) as VHD blobs in a "
                "storage account: " + ", ".join(unmanaged)
            ),
        )
