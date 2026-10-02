"""Container registry rules (DECISIONS.md section 170).

A registry holds the code that runs everywhere else, so what matters is who can
push to it and pull from it. Judged on its ARM record only; the scanner never
lists an image and holds no registry credential.
"""

from typing import ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import ExpectedState, RemediationSpec
from app.rules.azure.containers.kubernetes import _NO_POLICY
from app.rules.base import RuleContext, RuleResult, SecurityRule


class _RegistryRule(SecurityRule):
    category = "compute"
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.CONTAINER_REGISTRY]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (AzureEvidence.CONTAINER_REGISTRIES,)

    def _unreadable(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | None:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Registry configuration unavailable: {failure}")
        return None


class AzureRegistryAdminUserRule(_RegistryRule):
    rule_id = "AZ-ACR-001"
    name = "Container registry admin user is enabled"
    description = (
        "The registry's admin user is on: one shared username and password that can "
        "push and pull every image, outside the directory and without an owner."
    )
    severity = Severity.HIGH
    # The credential has to leak first, and it does: it is the one pasted into
    # CI variables and deployment scripts because it is the easy one.
    exploitability = 3
    estimated_effort_minutes = 60
    rationale = (
        "Whoever holds the admin password can replace an image that production "
        "pulls -- a supply-chain compromise with no sign-in to attribute it to."
    )
    remediation = (
        "Move the pipelines and clusters that use the admin login to an identity -- "
        "a managed identity or a service principal holding AcrPull or AcrPush -- then "
        "disable the admin user.\n\n"
        "Azure CLI:\n"
        "  az acr update --name <registry> --resource-group <rg> --admin-enabled false"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="admin_user_enabled",
                equals=False,
                describes="The shared admin login is disabled",
                terraform_attribute="admin_enabled",
            ),
        ),
        cli=("az acr update --name <registry> --resource-group <rg> --admin-enabled false",),
        notes=_NO_POLICY,
        terraform_resource_types=("azurerm_container_registry",),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.5.16", "A.5.17"],
        "NIST_CSF": ["PR.AC-1"],
        "GDPR": ["32(1)(b)"],
        "NIST_800_53": ["IA-2", "IA-5"],
        "SOC2": ["CC6.1"],
        "PCI_DSS_4": ["8.2.1", "8.3.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        blocked = self._unreadable(resource, context)
        if blocked or resource is None:
            return blocked or RuleResult.not_applicable("Rule is per-resource")

        enabled = resource.get("admin_user_enabled")
        if enabled is None:
            return RuleResult.unknown("The registry's record does not state its admin user")
        evidence = {"admin_user_enabled": enabled}
        if enabled is False:
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} has its shared admin login enabled",
        )


class AzureRegistryPublicNetworkRule(_RegistryRule):
    rule_id = "AZ-ACR-002"
    name = "Container registry answers the whole internet"
    description = (
        "The registry accepts connections from any network. Pushes and pulls still "
        "need a credential, and a leaked one works from anywhere."
    )
    severity = Severity.MEDIUM
    exploitability = 3
    estimated_effort_minutes = 90
    rationale = (
        "A registry that only the build agents and clusters can reach turns a leaked "
        "push credential into a credential nobody outside can use."
    )
    remediation = (
        "Deny by default and allow the networks your build agents and clusters use, "
        "or disable public access and reach the registry through a private endpoint. "
        "Both need the Premium tier.\n\n"
        "Azure CLI:\n"
        "  az acr network-rule add --name <registry> --ip-address <cidr>\n"
        "  az acr update --name <registry> --resource-group <rg> --default-action Deny"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="network_default_action",
                equals="Deny",
                describes="Network rules default to Deny, allowing only named networks",
                terraform_attribute="network_rule_set.default_action",
            ),
        ),
        cli=(
            "az acr network-rule add --name <registry> --ip-address <cidr>",
            "az acr update --name <registry> --resource-group <rg> --default-action Deny",
        ),
        notes=_NO_POLICY,
        terraform_resource_types=("azurerm_container_registry",),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.8.20", "A.8.22"],
        "NIST_CSF": ["PR.AC-5"],
        "GDPR": ["32(1)(b)"],
        "NIST_800_53": ["SC-7"],
        "SOC2": ["CC6.6"],
        "PCI_DSS_4": ["1.3.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        blocked = self._unreadable(resource, context)
        if blocked or resource is None:
            return blocked or RuleResult.not_applicable("Rule is per-resource")

        public_access = resource.get("public_network_access")
        default_action = resource.get("network_default_action")
        if public_access is None and default_action is None:
            return RuleResult.unknown("The registry's network settings are not in the snapshot")
        evidence = {
            "public_network_access": public_access,
            "network_default_action": default_action,
            "ip_rule_count": len(resource.get("ip_rules") or []),
            "private_endpoints": resource.get("private_endpoints"),
            "sku": resource.get("sku"),
        }
        if str(public_access or "").lower() == "disabled":
            return RuleResult.passed(evidence)
        if str(default_action or "").lower() == "deny":
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} accepts pushes and pulls from any network",
        )


class AzureRegistryPrivateEndpointRule(_RegistryRule):
    rule_id = "AZ-ACR-003"
    name = "Container registry has no private endpoint"
    description = (
        "No approved private endpoint serves the registry, so build agents and "
        "clusters can only reach it over its public endpoint."
    )
    severity = Severity.LOW
    # Hardening rather than an opening: whether the registry is reachable is the
    # public-network rule's question; this asks whether the private path exists.
    exploitability = 1
    estimated_effort_minutes = 120
    rationale = (
        "A private endpoint gives the registry an address inside the customer's own "
        "network, which is what lets public access be switched off without cutting "
        "off the workloads that use it."
    )
    remediation = (
        "Create a private endpoint for the registry in the virtual network its callers "
        "use, add the private DNS zone, and then switch public access off.\n\n"
        "Azure CLI:\n"
        "  az network private-endpoint create --name <endpoint> --resource-group <rg> \\\n"
        "    --vnet-name <vnet> --subnet <subnet> \\\n"
        "    --private-connection-resource-id <resource-id> --group-id registry \\\n"
        "    --connection-name <connection>"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(
            "az network private-endpoint create --name <endpoint> --resource-group <rg> "
            "--vnet-name <vnet> --subnet <subnet> --private-connection-resource-id "
            "<resource-id> --group-id registry --connection-name <connection>",
        ),
        notes=(
            "What is expected is a count -- at least one approved private endpoint -- "
            "which an equality over one setting cannot state, and the endpoint is a "
            "resource of its own rather than a setting on this one."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.8.20", "A.8.22"],
        "NIST_CSF": ["PR.AC-5"],
        "GDPR": ["32(1)(b)"],
        "NIST_800_53": ["SC-7"],
        "SOC2": ["CC6.6"],
        "PCI_DSS_4": ["1.3.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        blocked = self._unreadable(resource, context)
        if blocked or resource is None:
            return blocked or RuleResult.not_applicable("Rule is per-resource")

        count = resource.get("private_endpoints")
        if count is None:
            return RuleResult.unknown(
                "The listing did not state the registry's private endpoint connections"
            )
        evidence = {
            "private_endpoints": count,
            "public_network_access": resource.get("public_network_access"),
        }
        if count >= 1:
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} has no approved private endpoint",
        )
