"""AI Search service rules (DECISIONS.md section 170).

A search service holds copies of the documents it indexed, so it is judged as a
data store. Read from its ARM record; the scanner never holds its keys.
"""

from typing import ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import ExpectedState, RemediationSpec
from app.rules.azure.containers.kubernetes import _NO_POLICY
from app.rules.base import RuleContext, RuleResult, SecurityRule


class AzureSearchPublicNetworkRule(SecurityRule):
    rule_id = "AZ-SRCH-001"
    name = "AI Search service answers the whole internet"
    description = (
        "The search service accepts queries from any network: public access is on "
        "and no IP rule narrows it. Its admin and query keys are then the only thing "
        "between the internet and every document in its indexes."
    )
    category = "database"
    severity = Severity.HIGH
    exploitability = 3
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.SEARCH_SERVICE]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (AzureEvidence.SEARCH_SERVICES,)
    estimated_effort_minutes = 60
    rationale = (
        "Query keys are embedded in front-end code by design, and an index is often "
        "fed from sources nobody meant to publish. Open to every network, whatever "
        "the index holds is one key away from anyone."
    )
    remediation = (
        "Allow only the networks that query the service, or disable public access "
        "and reach it through a private endpoint.\n\n"
        "Azure CLI:\n"
        "  az search service update --name <service> --resource-group <rg> \\\n"
        "    --public-network-access disabled"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="public_network_access",
                equals="Disabled",
                describes="Public network access is disabled; the service is reached privately",
                terraform_attribute="public_network_access_enabled",
                terraform_value=False,
            ),
        ),
        cli=(
            "az search service update --name <service> --resource-group <rg> "
            "--public-network-access disabled",
        ),
        notes=_NO_POLICY,
        terraform_resource_types=("azurerm_search_service",),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.8.20", "A.8.22"],
        "NIST_CSF_2.0": ["PR.IR-01", "PR.DS-01"],
        "GDPR": ["5(1)(f)", "32(1)(b)"],
        "NIST_800_53": ["SC-7", "AC-3"],
        "SOC2": ["CC6.1", "CC6.6"],
        "PCI_DSS_4": ["1.3.1", "7.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Search service configuration unavailable: {failure}")

        public_access = resource.get("public_network_access")
        ip_rules = resource.get("ip_rules") or []
        evidence = {
            "public_network_access": public_access,
            "ip_rules": ip_rules,
            "private_endpoints": resource.get("private_endpoints"),
            "local_auth_disabled": resource.get("local_auth_disabled"),
        }
        if str(public_access or "").lower() == "disabled" or ip_rules:
            return RuleResult.passed(evidence)
        # Absent is the service default, which is enabled.
        return RuleResult.failed(
            evidence=evidence,
            # Keys still open it; a service that accepts only Entra tokens has
            # one fewer credential worth stealing.
            exploitability=2 if resource.get("local_auth_disabled") is True else None,
            message=f"{resource.name} accepts queries from any network",
        )
