"""Cosmos DB account rules (DECISIONS.md section 170).

Judged on the account's ARM record. The scanner never reads a key, a database
or a document: the listing carries when the keys were last generated and
nothing more.
"""

from typing import ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import ExpectedState, RemediationSpec
from app.rules.azure.containers.kubernetes import _NO_POLICY
from app.rules.base import RuleContext, RuleResult, SecurityRule


class _CosmosRule(SecurityRule):
    category = "database"
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.DOCUMENT_DATABASE]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (AzureEvidence.COSMOS_ACCOUNTS,)

    def _unreadable(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | None:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Cosmos DB configuration unavailable: {failure}")
        return None


class AzureCosmosPublicNetworkRule(_CosmosRule):
    rule_id = "AZ-COS-001"
    name = "Cosmos DB account answers the whole internet"
    description = (
        "The account accepts connections from any network: public access is on and "
        "no IP rule or virtual network filter narrows it. Its keys are then the only "
        "thing between the internet and every document it holds."
    )
    severity = Severity.HIGH
    exploitability = 4
    estimated_effort_minutes = 60
    rationale = (
        "Cosmos DB account keys are long-lived and routinely end up in configuration "
        "files. Reachable from anywhere, one leaked key reads the whole account from "
        "any network in the world."
    )
    remediation = (
        "Allow only the networks that need the account -- IP rules for fixed "
        "addresses, virtual network rules for workloads in Azure -- or disable public "
        "access and reach it through a private endpoint.\n\n"
        "Azure CLI:\n"
        "  az cosmosdb update --name <account> --resource-group <rg> \\\n"
        "    --public-network-access DISABLED"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="public_network_access",
                equals="Disabled",
                describes="Public network access is disabled; the account is reached privately",
                terraform_attribute="public_network_access_enabled",
                terraform_value=False,
            ),
        ),
        cli=(
            "az cosmosdb update --name <account> --resource-group <rg> "
            "--public-network-access DISABLED",
        ),
        notes=_NO_POLICY,
        terraform_resource_types=("azurerm_cosmosdb_account",),
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
        blocked = self._unreadable(resource, context)
        if blocked or resource is None:
            return blocked or RuleResult.not_applicable("Rule is per-resource")

        public_access = resource.get("public_network_access")
        if public_access is None:
            return RuleResult.unknown("The account's record does not state its public access")
        ip_rules = resource.get("ip_rules") or []
        vnet_filter = resource.get("virtual_network_filter")
        evidence = {
            "public_network_access": public_access,
            "ip_rules": ip_rules,
            "virtual_network_filter": vnet_filter,
            "private_endpoints": resource.get("private_endpoints"),
        }
        # Any one boundary is enough: public access off, or a firewall that names
        # who may connect.
        if str(public_access).lower() == "disabled" or ip_rules or vnet_filter is True:
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} accepts connections from any network",
        )


class AzureCosmosLocalAuthRule(_CosmosRule):
    rule_id = "AZ-COS-002"
    name = "Cosmos DB account accepts its account keys"
    description = (
        "The account still accepts its primary and secondary keys, which grant full "
        "access to every database in it and belong to nobody in the directory."
    )
    severity = Severity.MEDIUM
    exploitability = 3
    estimated_effort_minutes = 120
    rationale = (
        "Keys cannot be scoped, cannot require multi-factor authentication and do "
        "not say who used them. With key access off, every request is an Entra "
        "identity holding a Cosmos DB role."
    )
    remediation = (
        "Move applications to Microsoft Entra authentication with Cosmos DB's own "
        "data-plane roles, then disable key-based authentication on the account.\n\n"
        "Azure CLI:\n"
        "  az resource update --ids <resource-id> --set properties.disableLocalAuth=true"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="local_auth_disabled",
                equals=True,
                describes="Key-based authentication is disabled; only Entra identities connect",
                terraform_attribute="local_authentication_disabled",
            ),
        ),
        cli=("az resource update --ids <resource-id> --set properties.disableLocalAuth=true",),
        notes=_NO_POLICY,
        terraform_resource_types=("azurerm_cosmosdb_account",),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.5.16", "A.5.17"],
        "NIST_CSF_2.0": ["PR.AA-01", "PR.AA-03"],
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

        disabled = resource.get("local_auth_disabled")
        evidence = {"local_auth_disabled": disabled}
        if disabled is True:
            return RuleResult.passed(evidence)
        # Absent is the service default, which accepts the keys.
        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} accepts its account keys",
        )


class AzureCosmosTlsRule(_CosmosRule):
    rule_id = "AZ-COS-003"
    name = "Cosmos DB account accepts TLS below 1.2"
    description = (
        "The account's minimum TLS version is below 1.2, so clients may connect over "
        "protocol versions with known weaknesses."
    )
    severity = Severity.MEDIUM
    exploitability = 2
    estimated_effort_minutes = 30
    rationale = (
        "TLS 1.0 and 1.1 are deprecated. Accepting them lets a downgraded or "
        "outdated client move data over a channel that no longer protects it."
    )
    remediation = (
        "Set the minimum TLS version to 1.2 after confirming no client still "
        "connects with an older one.\n\n"
        "Azure CLI:\n"
        "  az resource update --ids <resource-id> --set properties.minimalTlsVersion=Tls12"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="minimal_tls_version",
                equals="Tls12",
                describes="The minimum TLS version is 1.2",
                terraform_attribute="minimal_tls_version",
            ),
        ),
        cli=("az resource update --ids <resource-id> --set properties.minimalTlsVersion=Tls12",),
        notes=_NO_POLICY,
        terraform_resource_types=("azurerm_cosmosdb_account",),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.8.24"],
        "NIST_CSF_2.0": ["PR.DS-02"],
        "GDPR": ["32(1)(a)"],
        "NIST_800_53": ["SC-8"],
        "SOC2": ["CC6.7"],
        "PCI_DSS_4": ["4.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        blocked = self._unreadable(resource, context)
        if blocked or resource is None:
            return blocked or RuleResult.not_applicable("Rule is per-resource")

        version = resource.get("minimal_tls_version")
        if version is None:
            return RuleResult.unknown("The account's record does not state its minimum TLS")
        evidence = {"minimal_tls_version": version}
        if str(version).lower() == "tls12":
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} accepts TLS below 1.2 ({version})",
        )


class AzureCosmosPrivateEndpointRule(_CosmosRule):
    rule_id = "AZ-COS-004"
    name = "Cosmos DB account has no private endpoint"
    description = (
        "No approved private endpoint serves the account, so every client reaches "
        "it over its public endpoint."
    )
    severity = Severity.LOW
    # Hardening rather than an opening: whether the account is reachable is the
    # public-network rule's question; this asks whether the private path exists.
    exploitability = 1
    estimated_effort_minutes = 120
    rationale = (
        "A private endpoint gives the account an address inside the customer's own "
        "network, which is what lets public access be switched off without cutting "
        "off the workloads that use it."
    )
    remediation = (
        "Create a private endpoint for the account in the virtual network its callers "
        "use, add the private DNS zone, and then switch public access off.\n\n"
        "Azure CLI:\n"
        "  az network private-endpoint create --name <endpoint> --resource-group <rg> \\\n"
        "    --vnet-name <vnet> --subnet <subnet> \\\n"
        "    --private-connection-resource-id <resource-id> --group-id Sql \\\n"
        "    --connection-name <connection>"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(
            "az network private-endpoint create --name <endpoint> --resource-group <rg> "
            "--vnet-name <vnet> --subnet <subnet> --private-connection-resource-id "
            "<resource-id> --group-id Sql --connection-name <connection>",
        ),
        notes=(
            "What is expected is a count -- at least one approved private endpoint -- "
            "which an equality over one setting cannot state, and the endpoint is a "
            "resource of its own rather than a setting on this one."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.8.20", "A.8.22"],
        "NIST_CSF_2.0": ["PR.IR-01"],
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
                "The listing did not state the account's private endpoint connections"
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
