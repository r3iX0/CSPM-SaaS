"""Databricks workspace rules (DECISIONS.md section 170).

A workspace runs clusters on the customer's behalf, so the questions are
network ones: whether its front end answers the internet, whether its cluster
nodes get public addresses, and whether they live in a network the customer
controls. Judged on the workspace's ARM record only.

A workspace's custom ``parameters`` may be absent from the listing -- the
published sample shows ``"parameters": null`` -- and a setting read from them is
then UNKNOWN rather than assumed to be the service default.
"""

from typing import ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import ExpectedState, RemediationSpec
from app.rules.azure.containers.kubernetes import _NO_POLICY
from app.rules.base import RuleContext, RuleResult, SecurityRule

_NETWORK_MAPPINGS: dict[str, list[str]] = {
    "ISO_27001": ["A.8.20", "A.8.22"],
    "NIST_CSF": ["PR.AC-5"],
    "GDPR": ["32(1)(b)"],
    "NIST_800_53": ["SC-7"],
    "SOC2": ["CC6.6"],
    "PCI_DSS_4": ["1.3.1"],
}


class _WorkspaceRule(SecurityRule):
    category = "compute"
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.ANALYTICS_WORKSPACE]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (AzureEvidence.DATABRICKS_WORKSPACES,)
    compliance_mappings: ClassVar[dict[str, list[str]]] = _NETWORK_MAPPINGS

    def _unreadable(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | None:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Workspace configuration unavailable: {failure}")
        return None


class AzureDatabricksPublicNetworkRule(_WorkspaceRule):
    rule_id = "AZ-DBW-001"
    name = "Databricks workspace answers the whole internet"
    description = (
        "The workspace's web application and REST API accept connections from any "
        "network. Sign-in still goes through the directory, and a stolen session or "
        "personal access token works from anywhere."
    )
    severity = Severity.MEDIUM
    exploitability = 3
    estimated_effort_minutes = 180
    rationale = (
        "A Databricks personal access token runs code on the workspace's clusters "
        "and reads whatever those clusters can. Reachable only from the customer's "
        "networks, a leaked one is worth much less."
    )
    remediation = (
        "Put the workspace behind Private Link and disable public network access. "
        "The workspace must be deployed into a virtual network the customer manages "
        "first.\n\n"
        "Azure CLI:\n"
        "  az resource update --ids <resource-id> \\\n"
        "    --set properties.publicNetworkAccess=Disabled"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="public_network_access",
                equals="Disabled",
                describes="Public network access is disabled; the workspace is reached privately",
                terraform_attribute="public_network_access_enabled",
                terraform_value=False,
            ),
        ),
        cli=(
            "az resource update --ids <resource-id> --set properties.publicNetworkAccess=Disabled",
        ),
        notes=_NO_POLICY,
        terraform_resource_types=("azurerm_databricks_workspace",),
    )

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        blocked = self._unreadable(resource, context)
        if blocked or resource is None:
            return blocked or RuleResult.not_applicable("Rule is per-resource")

        public_access = resource.get("public_network_access")
        evidence = {
            "public_network_access": public_access,
            "private_endpoints": resource.get("private_endpoints"),
        }
        if str(public_access or "").lower() == "disabled":
            return RuleResult.passed(evidence)
        # Absent is the service default, which is enabled.
        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} accepts connections from any network",
        )


class AzureDatabricksNoPublicIpRule(_WorkspaceRule):
    rule_id = "AZ-DBW-002"
    name = "Databricks cluster nodes get public IP addresses"
    description = (
        "Secure cluster connectivity is off, so every cluster the workspace starts "
        "gives its nodes public IP addresses."
    )
    severity = Severity.HIGH
    exploitability = 3
    estimated_effort_minutes = 240
    rationale = (
        "Cluster nodes hold the credentials the workspace's jobs use to reach data. "
        "With public addresses they are reachable machines rather than private "
        "workers, and a network rule mistake exposes all of them at once."
    )
    remediation = (
        "Enable secure cluster connectivity (No Public IP). On an existing workspace "
        "this is an update of the workspace's custom parameters; on one deployed "
        "without VNet injection it may need a new workspace.\n\n"
        "Azure CLI:\n"
        "  az resource update --ids <resource-id> \\\n"
        "    --set properties.parameters.enableNoPublicIp.value=true"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="no_public_ip",
                equals=True,
                describes="Secure cluster connectivity is on; cluster nodes have no public IPs",
                terraform_attribute="custom_parameters.no_public_ip",
            ),
        ),
        cli=(
            "az resource update --ids <resource-id> "
            "--set properties.parameters.enableNoPublicIp.value=true",
        ),
        notes=_NO_POLICY,
        terraform_resource_types=("azurerm_databricks_workspace",),
    )

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        blocked = self._unreadable(resource, context)
        if blocked or resource is None:
            return blocked or RuleResult.not_applicable("Rule is per-resource")

        value = resource.get("no_public_ip")
        if value is None:
            return RuleResult.unknown(
                "The workspace's record does not state whether its nodes get public IPs"
            )
        evidence = {"no_public_ip": value}
        if value is True:
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} gives its cluster nodes public IP addresses",
        )


class AzureDatabricksVnetInjectionRule(_WorkspaceRule):
    rule_id = "AZ-DBW-003"
    name = "Databricks workspace is not in a customer-managed network"
    description = (
        "The workspace's clusters run in a virtual network Databricks manages, "
        "which the customer's own network security groups, firewalls and private "
        "endpoints cannot govern."
    )
    severity = Severity.MEDIUM
    exploitability = 2
    estimated_effort_minutes = 480
    rationale = (
        "Without VNet injection there is no customer-controlled boundary around the "
        "clusters: their egress cannot be filtered and the data stores they reach "
        "cannot be limited to private endpoints."
    )
    remediation = (
        "Deploy a replacement workspace into a virtual network you manage (VNet "
        "injection) and move notebooks and jobs to it; an existing workspace cannot "
        "be moved into one."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="custom_virtual_network",
                equals=True,
                describes="Clusters run in a virtual network the customer manages",
            ),
        ),
        cli=(
            "az databricks workspace create --name <workspace> --resource-group <rg> "
            "--vnet <vnet> --public-subnet <subnet> --private-subnet <subnet>",
        ),
        notes=_NO_POLICY,
    )

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        blocked = self._unreadable(resource, context)
        if blocked or resource is None:
            return blocked or RuleResult.not_applicable("Rule is per-resource")

        value = resource.get("custom_virtual_network")
        if value is None:
            return RuleResult.unknown(
                "The workspace's record does not state which network it runs in"
            )
        evidence = {"custom_virtual_network": value}
        if value is True:
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} runs its clusters in a network it does not control",
        )


class AzureDatabricksManagedServicesKeyRule(_WorkspaceRule):
    rule_id = "AZ-DBW-004"
    name = "Databricks workspace encrypts its notebooks with Microsoft's keys"
    description = (
        "The workspace's managed services -- notebooks, queries, secrets and job "
        "results in the control plane -- are encrypted with a key Microsoft holds "
        "rather than one in the customer's key vault."
    )
    severity = Severity.LOW
    exploitability = 1
    estimated_effort_minutes = 120
    rationale = (
        "A customer-managed key is what lets the customer revoke access to what the "
        "workspace stores by revoking a key, and what some regulated data requires."
    )
    remediation = (
        "Create a key in a key vault with purge protection, grant the Databricks "
        "service access to it, and set it as the workspace's managed-services key. "
        "Needs the Premium tier.\n\n"
        "Azure CLI:\n"
        "  az databricks workspace update --name <workspace> --resource-group <rg> \\\n"
        "    --key-source Microsoft.KeyVault --key-name <key> \\\n"
        "    --key-vault <vault-uri> --key-version <version>"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="managed_services_cmk",
                equals=True,
                describes="Managed services are encrypted with a customer-managed key",
            ),
        ),
        cli=(
            "az databricks workspace update --name <workspace> --resource-group <rg> "
            "--key-source Microsoft.KeyVault --key-name <key> --key-vault <vault-uri> "
            "--key-version <version>",
        ),
        notes=_NO_POLICY,
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.8.24"],
        "NIST_CSF": ["PR.DS-1"],
        "GDPR": ["32(1)(a)"],
        "NIST_800_53": ["SC-12", "SC-28"],
        "SOC2": ["CC6.1"],
        "PCI_DSS_4": ["3.5.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        blocked = self._unreadable(resource, context)
        if blocked or resource is None:
            return blocked or RuleResult.not_applicable("Rule is per-resource")

        value = resource.get("managed_services_cmk")
        evidence = {"managed_services_cmk": value}
        if value is True:
            return RuleResult.passed(evidence)
        # Absent is the service default: Microsoft-managed keys.
        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} encrypts its managed services with Microsoft's keys",
        )
