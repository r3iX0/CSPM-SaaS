"""Single settings the compliance frameworks ask about (DECISIONS.md section 204).

The per-asset half of what section 204 closed: each is one setting on one kind
of asset, declared as a :class:`~app.rules.property.PropertySpec` the way
section 174 declares the rest. Grouped here by the section that added them
rather than spread across the type modules, because they share its reasoning:
every one answers a control in a catalogued framework that no rule reached.
Where a setting needs a reading role v13 added, the spec names that key, so a
v12 role costs exactly these verdicts.

One rule is not a spec: AZ-LCK-001 judges every type of asset the customer
marked critical, and a spec is about one type.
"""

from typing import Any, ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import Level, ResourceType, RuleScope, Severity
from app.domain.resource import CloudResource
from app.remediation import RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule
from app.rules.property import PropertySpec, property_rule

_NETWORK = {
    "ISO_27001": ["A.8.20", "A.8.22"],
    "NIST_CSF_2.0": ["PR.IR-01"],
    "GDPR": ["32(1)(b)"],
    "NIST_800_53": ["SC-7"],
    "SOC2": ["CC6.6"],
    "PCI_DSS_4": ["1.3.1"],
}
_TRANSPORT = {
    "ISO_27001": ["A.8.24"],
    "NIST_CSF_2.0": ["PR.DS-02"],
    "GDPR": ["32(1)(a)"],
    "NIST_800_53": ["SC-8"],
    "SOC2": ["CC6.7"],
    "PCI_DSS_4": ["4.2.1"],
}
_MONITORING = {
    "ISO_27001": ["A.8.16"],
    "NIST_CSF_2.0": ["DE.CM-01", "DE.AE-03"],
    "GDPR": ["32(1)(d)"],
    "NIST_800_53": ["SI-4"],
    "SOC2": ["CC7.2"],
    "PCI_DSS_4": ["11.5"],
}
_LOGGING = {
    "ISO_27001": ["A.8.15"],
    "NIST_CSF_2.0": ["PR.PS-04", "DE.AE-03"],
    "GDPR": ["30", "32(1)(d)"],
    "NIST_800_53": ["AU-2", "AU-6"],
    "SOC2": ["CC7.2"],
    "PCI_DSS_4": ["10.2.1"],
}
_VULNERABILITY = {
    "ISO_27001": ["A.8.8"],
    "NIST_CSF_2.0": ["ID.RA-01"],
    "GDPR": ["32(1)(d)"],
    "NIST_800_53": ["RA-5", "SI-2"],
    "SOC2": ["CC7.1"],
    "PCI_DSS_4": ["6.3.3", "11.3.1"],
}
_AUTHENTICATION = {
    "ISO_27001": ["A.5.17"],
    "NIST_CSF_2.0": ["PR.AA-03"],
    "GDPR": ["32(1)(b)"],
    "NIST_800_53": ["IA-2"],
    "SOC2": ["CC6.1"],
    "PCI_DSS_4": ["8.4.2"],
}
_RESILIENCE = {
    "ISO_27001": ["A.8.13"],
    "NIST_CSF_2.0": ["PR.DS-11"],
    "GDPR": ["32(1)(c)"],
    "NIST_800_53": ["CP-9", "CM-6"],
    "SOC2": ["A1.2"],
    "PCI_DSS_4": ["12.10.1"],
    "MITRE_ATTACK": ["T1485"],
}

_PREMIUM = (("sku", "premium"),)


def _at_least_one(count: Any) -> bool:
    return isinstance(count, int) and count >= 1


def _none_listed(entries: Any) -> bool:
    return isinstance(entries, list) and not entries


def _tls_1_2_or_later(version: Any) -> bool:
    return str(version or "").lower() in {"tlsv1_2", "tlsv1_3"}


def _entra_only(types: Any) -> bool:
    return isinstance(types, list) and bool(types) and all(str(t) == "AAD" for t in types)


# ------------------------------------------------------------ key vaults
VAULT_SPECS = (
    PropertySpec(
        rule_id="AZ-KV-007",
        name="Key vault public network access is not disabled",
        description=(
            "The vault's firewall denies by default, but its public endpoint is still "
            "on: named networks and addresses reach it over the internet rather than "
            "through a private endpoint only."
        ),
        rationale=(
            "A firewall rule is an address list somebody maintains; a disabled public "
            "endpoint is an absence nobody can widen by mistake. Not applicable where "
            "the vault answers every network, which AZ-KV-002 already reports."
        ),
        remediation=(
            "Put the vault behind a private endpoint, then disable public network "
            "access.\n\n"
            "Azure CLI:\n"
            "  az keyvault update --name <vault> --resource-group <rg> \\\n"
            "    --public-network-access Disabled"
        ),
        cli=(
            "az keyvault update --name <vault> --resource-group <rg> "
            "--public-network-access Disabled",
        ),
        severity=Severity.LOW,
        exploitability=1,
        category="secrets",
        resource_type=ResourceType.KEY_VAULT,
        evidence=(AzureEvidence.KEY_VAULTS,),
        field="public_network_access",
        safe="Disabled",
        describes="Public network access is disabled",
        failure="keeps its public endpoint on",
        terraform_attribute="public_network_access_enabled",
        terraform_value=False,
        terraform_resource_types=("azurerm_key_vault",),
        mappings={**_NETWORK, "CIS_AZURE_6.0": ["8.3.7"]},
        applies_when=(("network_default_action", "deny"),),
    ),
    PropertySpec(
        rule_id="AZ-KV-008",
        name="Key vault has no private endpoint",
        description=(
            "No approved private endpoint serves the vault, so every workload reaching "
            "it does so over its public endpoint."
        ),
        rationale=(
            "A private endpoint keeps secret reads on the virtual network and is what "
            "lets the public endpoint be switched off at all."
        ),
        remediation=(
            "Create a private endpoint for the vault in the network its workloads use.\n\n"
            "Azure CLI:\n"
            "  az network private-endpoint create --name <vault>-pe \\\n"
            "    --resource-group <rg> --vnet-name <vnet> --subnet <subnet> \\\n"
            "    --private-connection-resource-id <vault-id> --group-id vault \\\n"
            "    --connection-name <vault>-pe"
        ),
        cli=(
            "az network private-endpoint create --name <vault>-pe --resource-group <rg> "
            "--vnet-name <vnet> --subnet <subnet> --private-connection-resource-id "
            "<vault-id> --group-id vault --connection-name <vault>-pe",
        ),
        severity=Severity.LOW,
        exploitability=1,
        category="secrets",
        resource_type=ResourceType.KEY_VAULT,
        evidence=(AzureEvidence.KEY_VAULTS,),
        field="private_endpoints",
        passes=_at_least_one,
        why_no_expected_state="Any number of approved endpoints from one passes.",
        describes="At least one approved private endpoint serves the vault",
        failure="has no private endpoint",
        mappings={**_NETWORK, "CIS_AZURE_2.0": ["8.7"], "CIS_AZURE_6.0": ["8.3.8"]},
        effort_minutes=60,
    ),
    PropertySpec(
        rule_id="AZ-KV-009",
        name="Key vault holds certificates valid for more than a year",
        description=(
            "A certificate in the vault is valid for more than twelve months, read from "
            "the validity window on the secret that holds its key pair."
        ),
        rationale=(
            "A long-lived certificate is a long-lived key: if it leaks it is trusted "
            "until it expires. Browsers stopped trusting public certificates longer than "
            "about a year in 2020 for that reason."
        ),
        remediation=(
            "Set the certificate policy's validity to twelve months or less, with "
            "automatic renewal before expiry, and reissue the certificate.\n\n"
            "Azure CLI:\n"
            "  az keyvault certificate set-attributes --vault-name <vault> \\\n"
            "    --name <certificate> --policy @policy.json"
        ),
        cli=(
            "az keyvault certificate set-attributes --vault-name <vault> --name "
            "<certificate> --policy @policy.json",
        ),
        severity=Severity.LOW,
        exploitability=1,
        category="secrets",
        resource_type=ResourceType.KEY_VAULT,
        evidence=(AzureEvidence.KEY_VAULTS, AzureEvidence.KEY_VAULT_SECRETS),
        field="long_lived_certificates",
        passes=_none_listed,
        why_no_expected_state="The finding names certificates, each reissued on its own.",
        describes="No certificate in the vault is valid for more than twelve months",
        failure="holds certificates valid for more than twelve months",
        mappings={
            "ISO_27001": ["A.8.24"],
            "NIST_CSF_2.0": ["PR.DS-02"],
            "GDPR": ["32(1)(a)"],
            "NIST_800_53": ["SC-12"],
            "SOC2": ["CC6.1"],
            "PCI_DSS_4": ["3.6.1", "3.7"],
            "CIS_AZURE_6.0": ["8.3.11"],
        },
        applies_when=(("holds_certificates", "true"),),
    ),
)

# ------------------------------------------------------------- Databricks
WORKSPACE_SPECS = (
    PropertySpec(
        rule_id="AZ-DBW-005",
        name="Databricks workspace has no private endpoint",
        description=(
            "No approved private endpoint serves the workspace, so its users and "
            "clusters reach the control plane over the public internet."
        ),
        rationale=(
            "Private Link keeps both front-end access and the cluster's connection to "
            "the control plane off the internet, and is what lets public access be "
            "switched off."
        ),
        remediation=(
            "Create a private endpoint for the workspace (sub-resource "
            "databricks_ui_api). Private Link needs the Premium tier and a workspace "
            "in a customer-managed network."
        ),
        cli=(
            "az network private-endpoint create --name <workspace>-pe --resource-group "
            "<rg> --vnet-name <vnet> --subnet <subnet> --private-connection-resource-id "
            "<workspace-id> --group-id databricks_ui_api --connection-name <workspace>-pe",
        ),
        severity=Severity.LOW,
        exploitability=1,
        category="network",
        resource_type=ResourceType.ANALYTICS_WORKSPACE,
        evidence=(AzureEvidence.DATABRICKS_WORKSPACES,),
        field="private_endpoints",
        passes=_at_least_one,
        why_no_expected_state="Any number of approved endpoints from one passes.",
        describes="At least one approved private endpoint serves the workspace",
        failure="has no private endpoint",
        mappings={**_NETWORK, "CIS_AZURE_6.0": ["2.1.11"]},
        applies_when=_PREMIUM,
        effort_minutes=90,
    ),
    PropertySpec(
        rule_id="AZ-DBW-006",
        name="Databricks subnet has no network security group",
        description=(
            "One of the two subnets a workspace in a customer-managed network runs its "
            "clusters in has no network security group."
        ),
        rationale=(
            "Databricks writes the rules its clusters need into the group on each "
            "subnet; without one, nothing filters what reaches or leaves the cluster "
            "nodes."
        ),
        remediation=(
            "Attach a network security group to both workspace subnets. Databricks adds "
            "its required rules itself.\n\n"
            "Azure CLI:\n"
            "  az network vnet subnet update --resource-group <rg> --vnet-name <vnet> \\\n"
            "    --name <subnet> --network-security-group <nsg>"
        ),
        cli=(
            "az network vnet subnet update --resource-group <rg> --vnet-name <vnet> "
            "--name <subnet> --network-security-group <nsg>",
        ),
        severity=Severity.MEDIUM,
        exploitability=2,
        category="network",
        resource_type=ResourceType.ANALYTICS_WORKSPACE,
        evidence=(AzureEvidence.DATABRICKS_WORKSPACES, AzureEvidence.VIRTUAL_NETWORKS),
        field="subnets_without_nsg",
        passes=_none_listed,
        why_no_expected_state="The finding names subnets, each fixed on its own.",
        describes="Both workspace subnets carry a network security group",
        failure="runs clusters in a subnet no network security group guards",
        mappings={**_NETWORK, "CIS_AZURE_6.0": ["2.1.2"]},
        applies_when=(("custom_virtual_network", "true"),),
    ),
    PropertySpec(
        rule_id="AZ-DBW-007",
        name="Databricks workspace sends its logs nowhere",
        description=(
            "No diagnostic setting sends the workspace's audit and cluster logs to a "
            "workspace, storage account or event hub."
        ),
        rationale=(
            "Who ran which notebook against which data, and who changed a cluster's "
            "permissions, is recorded only if the workspace is told to send it "
            "somewhere."
        ),
        remediation=(
            "Add a diagnostic setting to the workspace sending all log categories to a "
            "Log Analytics workspace. Diagnostic logs need the Premium tier."
        ),
        cli=(
            "az monitor diagnostic-settings create --name databricks-logs --resource "
            "<workspace-id> --workspace <log-analytics-id> --logs "
            '\'[{"categoryGroup":"allLogs","enabled":true}]\'',
        ),
        severity=Severity.LOW,
        exploitability=0,
        category="logging",
        resource_type=ResourceType.ANALYTICS_WORKSPACE,
        evidence=(AzureEvidence.DATABRICKS_WORKSPACES, AzureEvidence.DATABRICKS_DIAGNOSTICS),
        field="sends_diagnostic_logs",
        safe=True,
        describes="A diagnostic setting sends the workspace's logs somewhere",
        failure="sends its audit and cluster logs nowhere",
        mappings={**_LOGGING, "CIS_AZURE_6.0": ["2.1.7"]},
        applies_when=_PREMIUM,
    ),
)

# ---------------------------------------------------------------- networks
NETWORK_SPECS = (
    PropertySpec(
        rule_id="AZ-NET-016",
        name="Subnet has no network security group",
        description=(
            "A subnet of the network has no network security group, so nothing filters "
            "traffic to the machines and services placed in it. Subnets Azure reserves "
            "for gateways, firewalls and route servers are left out."
        ),
        rationale=(
            "A group on the subnet is the boundary that holds for everything placed in "
            "it later, including resources whose own interface carries no group."
        ),
        remediation=(
            "Associate a network security group with the subnet.\n\n"
            "Azure CLI:\n"
            "  az network vnet subnet update --resource-group <rg> --vnet-name <vnet> \\\n"
            "    --name <subnet> --network-security-group <nsg>"
        ),
        cli=(
            "az network vnet subnet update --resource-group <rg> --vnet-name <vnet> "
            "--name <subnet> --network-security-group <nsg>",
        ),
        severity=Severity.MEDIUM,
        exploitability=2,
        category="network",
        resource_type=ResourceType.VIRTUAL_NETWORK,
        evidence=(AzureEvidence.VIRTUAL_NETWORKS,),
        field="subnets_without_nsg",
        passes=_none_listed,
        why_no_expected_state="The finding names subnets, each fixed on its own.",
        describes="Every subnet that can carry a network security group has one",
        failure="has subnets no network security group guards",
        mappings={**_NETWORK, "CIS_AZURE_6.0": ["7.11"]},
    ),
    PropertySpec(
        rule_id="AZ-NET-018",
        name="Public IP addresses on the retired Basic SKU",
        description=(
            "The subscription holds public IP addresses on the Basic SKU, which Azure "
            "retired on 30 September 2025: no SLA, no availability zones, and open to "
            "the internet unless a group says otherwise."
        ),
        rationale=(
            "A retired SKU is one Microsoft no longer supports. Standard addresses are "
            "closed by default and covered by the platform's SLA, which is what a "
            "workload that needs monitoring and an SLA assumes."
        ),
        remediation=(
            "Upgrade each Basic public IP address to Standard. Azure CLI:\n"
            "  az network public-ip update --name <address> --resource-group <rg> \\\n"
            "    --sku Standard"
        ),
        cli=("az network public-ip update --name <address> --resource-group <rg> --sku Standard",),
        severity=Severity.LOW,
        exploitability=1,
        category="network",
        resource_type=ResourceType.SUBSCRIPTION,
        evidence=(AzureEvidence.PUBLIC_IP_ADDRESSES,),
        field="basic_public_ips",
        passes=_none_listed,
        why_no_expected_state="The finding names addresses, each upgraded on its own.",
        describes="No public IP address is on the Basic SKU",
        failure="holds public IP addresses on the retired Basic SKU",
        mappings={
            **_RESILIENCE,
            "CIS_AZURE_2.0": ["5.5"],
            "CIS_AZURE_6.0": ["6.1.5"],
        },
    ),
)

# --------------------------------------------------- application gateways
_ON_WAF = (("waf_enabled", "true"),)

GATEWAY_SPECS = (
    PropertySpec(
        rule_id="AZ-AGW-001",
        name="Application gateway has no web application firewall",
        description=(
            "Neither a WAF policy nor the gateway's own firewall configuration inspects "
            "the traffic it forwards."
        ),
        rationale=(
            "The gateway is the front door to the web workloads behind it. A web "
            "application firewall there stops the injection and request-smuggling "
            "attacks every internet-facing application receives, before they reach "
            "code that may not."
        ),
        remediation=(
            "Move the gateway to the WAF_v2 tier and attach a WAF policy in Prevention "
            "mode with the default managed rule set.\n\n"
            "Azure CLI:\n"
            "  az network application-gateway waf-policy create --name <policy> \\\n"
            "    --resource-group <rg>\n"
            "  az network application-gateway update --name <gateway> \\\n"
            "    --resource-group <rg> --set firewallPolicy.id=<policy-id>"
        ),
        cli=(
            "az network application-gateway waf-policy create --name <policy> "
            "--resource-group <rg>",
            "az network application-gateway update --name <gateway> --resource-group <rg> "
            "--set firewallPolicy.id=<policy-id>",
        ),
        severity=Severity.MEDIUM,
        exploitability=3,
        category="network",
        resource_type=ResourceType.APPLICATION_GATEWAY,
        evidence=(AzureEvidence.APPLICATION_GATEWAYS, AzureEvidence.WAF_POLICIES),
        field="waf_enabled",
        safe=True,
        describes="A web application firewall inspects the gateway's traffic",
        failure="forwards traffic no web application firewall inspects",
        mappings={
            **_NETWORK,
            "PCI_DSS_4": ["1.3.1", "6.4"],
            "CIS_AZURE_6.0": ["7.10"],
            "MITRE_ATTACK": ["T1190"],
        },
        effort_minutes=120,
    ),
    PropertySpec(
        rule_id="AZ-AGW-002",
        name="Application gateway accepts TLS below 1.2",
        description=(
            "The gateway's TLS policy lets a client negotiate TLS 1.0 or 1.1. A gateway "
            "that states no policy is not judged: its default depends on when it was "
            "created."
        ),
        rationale=(
            "TLS 1.0 and 1.1 carry known weaknesses and every current client speaks "
            "1.2. Accepting the old versions helps only an attacker able to force a "
            "downgrade."
        ),
        remediation=(
            "Set a predefined policy with a TLS 1.2 floor.\n\n"
            "Azure CLI:\n"
            "  az network application-gateway ssl-policy set --gateway-name <gateway> \\\n"
            "    --resource-group <rg> --policy-type Predefined \\\n"
            "    --policy-name AppGwSslPolicy20220101"
        ),
        cli=(
            "az network application-gateway ssl-policy set --gateway-name <gateway> "
            "--resource-group <rg> --policy-type Predefined --policy-name "
            "AppGwSslPolicy20220101",
        ),
        severity=Severity.MEDIUM,
        exploitability=2,
        category="network",
        resource_type=ResourceType.APPLICATION_GATEWAY,
        evidence=(AzureEvidence.APPLICATION_GATEWAYS,),
        field="min_tls_version",
        passes=_tls_1_2_or_later,
        why_no_expected_state="TLS 1.2 and TLS 1.3 both pass, so there is no one value.",
        describes="The gateway's TLS policy accepts TLS 1.2 or later only",
        failure="accepts TLS versions below 1.2",
        mappings={**_TRANSPORT, "CIS_AZURE_6.0": ["7.12"]},
    ),
    PropertySpec(
        rule_id="AZ-AGW-003",
        name="Application gateway does not use HTTP/2",
        description="HTTP/2 is off on the gateway's listeners.",
        rationale=(
            "HTTP/2 multiplexes requests over one connection and carries current "
            "protocol fixes. A resilience setting rather than a door, so it is LOW."
        ),
        remediation=(
            "Turn HTTP/2 on.\n\n"
            "Azure CLI:\n"
            "  az network application-gateway update --name <gateway> \\\n"
            "    --resource-group <rg> --http2 Enabled"
        ),
        cli=(
            "az network application-gateway update --name <gateway> --resource-group <rg> "
            "--http2 Enabled",
        ),
        severity=Severity.LOW,
        exploitability=0,
        category="network",
        resource_type=ResourceType.APPLICATION_GATEWAY,
        evidence=(AzureEvidence.APPLICATION_GATEWAYS,),
        field="http2_enabled",
        safe=True,
        # ARM leaves the field out on a gateway where HTTP/2 was never enabled.
        absent="fail",
        describes="HTTP/2 is enabled",
        failure="does not use HTTP/2",
        mappings={**_TRANSPORT, "CIS_AZURE_6.0": ["7.13"]},
        effort_minutes=10,
    ),
    PropertySpec(
        rule_id="AZ-AGW-004",
        name="Web application firewall does not inspect request bodies",
        description=(
            "The gateway's web application firewall has request body inspection "
            "switched off, so it never sees what is posted to the application."
        ),
        rationale=(
            "Most injection arrives in a request body. A firewall that reads only the "
            "URL and headers misses it."
        ),
        remediation=(
            "Turn request body inspection on in the WAF policy.\n\n"
            "Azure CLI:\n"
            "  az network application-gateway waf-policy policy-setting update \\\n"
            "    --policy-name <policy> --resource-group <rg> \\\n"
            "    --request-body-check true"
        ),
        cli=(
            "az network application-gateway waf-policy policy-setting update --policy-name "
            "<policy> --resource-group <rg> --request-body-check true",
        ),
        severity=Severity.MEDIUM,
        exploitability=2,
        category="network",
        resource_type=ResourceType.APPLICATION_GATEWAY,
        evidence=(AzureEvidence.APPLICATION_GATEWAYS, AzureEvidence.WAF_POLICIES),
        field="waf_request_body_check",
        safe=True,
        describes="The web application firewall inspects request bodies",
        failure="has a firewall that does not inspect request bodies",
        mappings={**_NETWORK, "PCI_DSS_4": ["1.3.1", "6.4"], "CIS_AZURE_6.0": ["7.14"]},
        applies_when=_ON_WAF,
        effort_minutes=10,
    ),
    PropertySpec(
        rule_id="AZ-AGW-005",
        name="Web application firewall has no bot protection",
        description=(
            "The gateway's WAF policy does not include Microsoft's bot manager rule set, "
            "so known malicious bots are not blocked. A firewall configured on the "
            "gateway itself, rather than as a policy, cannot carry the rule set."
        ),
        rationale=(
            "Credential stuffing, scraping and vulnerability scanning come from bots "
            "Microsoft already tracks; the rule set blocks them before they count as "
            "traffic."
        ),
        remediation=(
            "Add the Microsoft_BotManagerRuleSet managed rule set to the WAF policy.\n\n"
            "Azure CLI:\n"
            "  az network application-gateway waf-policy managed-rule rule-set add \\\n"
            "    --policy-name <policy> --resource-group <rg> \\\n"
            "    --type Microsoft_BotManagerRuleSet --version 1.0"
        ),
        cli=(
            "az network application-gateway waf-policy managed-rule rule-set add "
            "--policy-name <policy> --resource-group <rg> --type "
            "Microsoft_BotManagerRuleSet --version 1.0",
        ),
        severity=Severity.LOW,
        exploitability=1,
        category="network",
        resource_type=ResourceType.APPLICATION_GATEWAY,
        evidence=(AzureEvidence.APPLICATION_GATEWAYS, AzureEvidence.WAF_POLICIES),
        field="waf_bot_protection",
        safe=True,
        describes="The WAF policy includes the bot manager rule set",
        failure="has a firewall with no bot protection",
        mappings={**_NETWORK, "PCI_DSS_4": ["1.3.1", "6.4"], "CIS_AZURE_6.0": ["7.15"]},
        applies_when=_ON_WAF,
        effort_minutes=15,
    ),
    PropertySpec(
        rule_id="AZ-VPN-001",
        name="VPN gateway accepts point-to-site clients without Entra ID",
        description=(
            "The gateway's point-to-site configuration accepts certificate or RADIUS "
            "authentication, so a VPN client can connect without signing in to Entra ID "
            "and meeting its Conditional Access policies."
        ),
        rationale=(
            "A client certificate copied from a laptop connects from anywhere, with no "
            "second factor and no record in the directory's sign-in log. Entra ID "
            "authentication makes every connection a sign-in the tenant's policies "
            "decide."
        ),
        remediation=(
            "Configure the point-to-site connection for Microsoft Entra ID "
            "authentication and remove the certificate and RADIUS types.\n\n"
            "Azure Portal: Virtual network gateway > Point-to-site configuration > "
            "Authentication type: Azure Active Directory only > Save."
        ),
        cli=(
            "az network vnet-gateway update --name <gateway> --resource-group <rg> "
            "--vpn-auth-type AAD",
        ),
        severity=Severity.MEDIUM,
        exploitability=2,
        category="network",
        resource_type=ResourceType.VPN_GATEWAY,
        evidence=(AzureEvidence.VPN_GATEWAYS,),
        field="point_to_site_auth_types",
        passes=_entra_only,
        why_no_expected_state="The setting is a list of types; only ['AAD'] passes.",
        describes="Point-to-site clients authenticate with Entra ID only",
        failure="admits point-to-site clients without an Entra ID sign-in",
        mappings={**_AUTHENTICATION, "CIS_AZURE_6.0": ["7.9"]},
        applies_when=(("point_to_site", "true"),),
        effort_minutes=120,
    ),
)

# --------------------------------------------------- machines, apps, data
WORKLOAD_SPECS = (
    PropertySpec(
        rule_id="AZ-CMP-014",
        name="Virtual machine is not assessed for missing updates",
        description=(
            "The machine's patch settings leave update assessment at ImageDefault, so "
            "Azure checks it for missing updates only when somebody asks rather than "
            "every 24 hours."
        ),
        rationale=(
            "A missing patch nobody looks for stays missing. Periodic assessment is what "
            "puts the machine into Azure Update Manager's and Defender's view of what "
            "needs patching."
        ),
        remediation=(
            "Set the machine's patch assessment mode to AutomaticByPlatform.\n\n"
            "Azure CLI:\n"
            "  az vm update --name <vm> --resource-group <rg> \\\n"
            "    --set osProfile.windowsConfiguration.patchSettings.assessmentMode=\\\n"
            "    AutomaticByPlatform\n\n"
            "Use linuxConfiguration on a Linux machine."
        ),
        cli=(
            "az vm update --name <vm> --resource-group <rg> --set "
            "osProfile.windowsConfiguration.patchSettings.assessmentMode=AutomaticByPlatform",
        ),
        severity=Severity.LOW,
        exploitability=1,
        category="compute",
        resource_type=ResourceType.VIRTUAL_MACHINE,
        evidence=(AzureEvidence.VIRTUAL_MACHINES,),
        field="patch_assessment_mode",
        safe="AutomaticByPlatform",
        describes="Azure assesses the machine for missing updates every 24 hours",
        failure="is not assessed for missing updates on a schedule",
        mappings={
            **_VULNERABILITY,
            "NIST_CSF_2.0": ["ID.RA-01", "PR.PS-02"],
            "CIS_AZURE_6.0": ["8.1.10"],
        },
        effort_minutes=10,
    ),
    PropertySpec(
        rule_id="AZ-WEB-014",
        name="Web app does not require client certificates",
        description=(
            "The web app does not ask callers for a client certificate, so any client "
            "that reaches it is served without proving which client it is."
        ),
        rationale=(
            "Mutual TLS is how an application that serves known clients rather than the "
            "public refuses everyone else before its own code runs. An app built for "
            "the public may dismiss this, which is why it is LOW (DECISIONS.md section "
            "204 reverses section 175's decision not to ask)."
        ),
        remediation=(
            "Require incoming client certificates.\n\n"
            "Azure CLI:\n"
            "  az webapp update --name <app> --resource-group <rg> \\\n"
            "    --set clientCertEnabled=true"
        ),
        cli=("az webapp update --name <app> --resource-group <rg> --set clientCertEnabled=true",),
        severity=Severity.LOW,
        exploitability=1,
        category="compute",
        resource_type=ResourceType.APP_SERVICE,
        evidence=(AzureEvidence.APP_SERVICES,),
        field="client_cert_enabled",
        safe=True,
        # App Service leaves client certificates off unless asked.
        absent="fail",
        describes="Incoming client certificates are required",
        failure="does not require client certificates",
        terraform_attribute="client_certificate_enabled",
        terraform_value=True,
        terraform_resource_types=("azurerm_linux_web_app", "azurerm_windows_web_app"),
        mappings={**_AUTHENTICATION, "CIS_AZURE_2.0": ["9.4"]},
        applies_when=(("is_function_app", "false"),),
    ),
    PropertySpec(
        rule_id="AZ-DB-025",
        name="PostgreSQL server admits every Azure service",
        description=(
            "The server's firewall holds the 0.0.0.0 rule the portal calls 'Allow public "
            "access from any Azure service', which admits any address inside Azure -- "
            "other customers' machines included."
        ),
        rationale=(
            "The rule reads as 'my Azure services' and means 'anyone's'. Anybody with "
            "an Azure subscription can reach the server's sign-in from inside the "
            "allowed range."
        ),
        remediation=(
            "Delete the AllowAllAzureServicesAndResourcesWithinAzureIps rule and admit "
            "the services that need the server by private endpoint or by their own "
            "addresses.\n\n"
            "Azure CLI:\n"
            "  az postgres flexible-server firewall-rule delete --name <server> \\\n"
            "    --resource-group <rg> --rule-name <rule>"
        ),
        cli=(
            "az postgres flexible-server firewall-rule delete --name <server> "
            "--resource-group <rg> --rule-name <rule>",
        ),
        severity=Severity.MEDIUM,
        exploitability=3,
        category="database",
        resource_type=ResourceType.POSTGRESQL_SERVER,
        evidence=(AzureEvidence.POSTGRESQL_SERVERS, AzureEvidence.POSTGRESQL_FIREWALL_RULES),
        field="admits_azure_services",
        safe=False,
        describes="No firewall rule admits every Azure service",
        failure="admits every address inside Azure",
        # A firewall rule applies only while public access is on. With it
        # Disabled the server answers its private endpoints alone, and a 0.0.0.0
        # rule left behind admits nobody.
        applies_when=(("public_network_access", "enabled"),),
        mappings={**_NETWORK, "CIS_AZURE_2.0": ["4.3.7"]},
        effort_minutes=30,
    ),
)

# ---------------------------------------------------------- subscription
_PLANS = (AzureEvidence.DEFENDER_PLANS,)

SUBSCRIPTION_SPECS = (
    PropertySpec(
        rule_id="AZ-DEF-012",
        name="Agentless scanning for machines is off",
        description=(
            "Defender for Servers is off, or on without agentless scanning, so machines "
            "are not scanned from disk snapshots for vulnerabilities, secrets and "
            "malware."
        ),
        rationale=(
            "Agentless scanning sees machines no agent was ever installed on, which are "
            "exactly the ones nobody is watching."
        ),
        remediation=(
            "Microsoft Defender for Cloud > Environment settings > the subscription > "
            "Defender plans > Servers: On > Settings > Agentless scanning for machines: "
            "On > Save."
        ),
        cli=(
            "az security pricing create --name VirtualMachines --tier Standard "
            "--extensions name=AgentlessVmScanning isEnabled=True",
        ),
        severity=Severity.LOW,
        exploitability=1,
        category="posture",
        resource_type=ResourceType.SUBSCRIPTION,
        evidence=_PLANS,
        field="agentless_vm_scanning",
        safe=True,
        describes="Defender for Servers scans machines agentlessly",
        failure="does not scan its machines agentlessly",
        mappings={**_VULNERABILITY, "CIS_AZURE_6.0": ["8.1.3.4"]},
        effort_minutes=10,
    ),
    PropertySpec(
        rule_id="AZ-DEF-013",
        name="File integrity monitoring is off",
        description=(
            "Defender for Servers Plan 2 is off, or on without file integrity "
            "monitoring, so changes to operating-system files and the registry go "
            "unrecorded."
        ),
        rationale=(
            "A modified system binary or a new autostart entry is how most persistence "
            "looks from the disk. Nothing notices it unless something is watching those "
            "files."
        ),
        remediation=(
            "Microsoft Defender for Cloud > Environment settings > the subscription > "
            "Defender plans > Servers Plan 2 > Settings > File Integrity Monitoring: On "
            "> Save."
        ),
        cli=(
            "az security pricing create --name VirtualMachines --tier Standard "
            "--subplan P2 --extensions name=FileIntegrityMonitoring isEnabled=True",
        ),
        severity=Severity.LOW,
        exploitability=1,
        category="posture",
        resource_type=ResourceType.SUBSCRIPTION,
        evidence=_PLANS,
        field="file_integrity_monitoring",
        safe=True,
        describes="Defender for Servers monitors file integrity",
        failure="does not monitor file integrity on its machines",
        mappings={**_MONITORING, "CIS_AZURE_6.0": ["8.1.3.5"]},
        effort_minutes=15,
    ),
    PropertySpec(
        rule_id="AZ-DEF-014",
        name="Defender sensor is not deployed to Kubernetes clusters",
        description=(
            "Defender for Containers is off, or on without its sensor, so clusters are "
            "not watched at runtime and their components are not provisioned "
            "automatically."
        ),
        rationale=(
            "The sensor is what sees a container start a shell or reach a metadata "
            "endpoint. Without it, Defender for Containers knows images, not what runs."
        ),
        remediation=(
            "Microsoft Defender for Cloud > Environment settings > the subscription > "
            "Defender plans > Containers: On > Settings > Defender sensor: On > Save."
        ),
        cli=(
            "az security pricing create --name Containers --tier Standard "
            "--extensions name=ContainerSensor isEnabled=True",
        ),
        severity=Severity.LOW,
        exploitability=1,
        category="posture",
        resource_type=ResourceType.SUBSCRIPTION,
        evidence=_PLANS,
        field="container_sensor",
        safe=True,
        describes="Defender for Containers deploys its sensor to clusters",
        failure="does not deploy the Defender sensor to its clusters",
        mappings={**_MONITORING, "CIS_AZURE_2.0": ["2.1.17"]},
        effort_minutes=10,
    ),
    PropertySpec(
        rule_id="AZ-DEF-015",
        name="DNS queries are not watched for threats",
        description=(
            "Neither the retired Defender for DNS plan nor Defender for Servers Plan 2, "
            "which absorbed it in 2023, is on, so queries to known malicious domains go "
            "unnoticed."
        ),
        rationale=(
            "Command and control and data exfiltration often travel over DNS, the one "
            "protocol every network lets out."
        ),
        remediation=(
            "Turn on Defender for Servers Plan 2.\n\n"
            "Azure CLI:\n"
            "  az security pricing create --name VirtualMachines --tier Standard \\\n"
            "    --subplan P2"
        ),
        cli=("az security pricing create --name VirtualMachines --tier Standard --subplan P2",),
        severity=Severity.LOW,
        exploitability=1,
        category="posture",
        resource_type=ResourceType.SUBSCRIPTION,
        evidence=_PLANS,
        field="dns_threat_detection",
        safe=True,
        describes="Defender watches DNS queries for threats",
        failure="does not watch DNS queries for threats",
        mappings={**_MONITORING, "CIS_AZURE_2.0": ["2.1.11"]},
        effort_minutes=10,
    ),
    PropertySpec(
        rule_id="AZ-POL-001",
        name="No policy limits the regions resources are created in",
        description=(
            "No enforced assignment of the built-in Allowed locations policy applies to "
            "the subscription, so resources can be created in any Azure region."
        ),
        rationale=(
            "An attacker with a stolen credential creates machines where nobody looks. "
            "Limiting the regions in use makes that a denied request rather than a bill."
        ),
        remediation=(
            "Assign the built-in 'Allowed locations' policy at the subscription or a "
            "management group above it, listing the regions in use.\n\n"
            "Azure CLI:\n"
            "  az policy assignment create --name allowed-locations \\\n"
            "    --policy e56962a6-4747-49cd-b67b-bf8b01975c4c \\\n"
            "    --scope /subscriptions/<id> \\\n"
            '    --params \'{"listOfAllowedLocations":{"value":["westeurope"]}}\''
        ),
        cli=(
            "az policy assignment create --name allowed-locations --policy "
            "e56962a6-4747-49cd-b67b-bf8b01975c4c --scope /subscriptions/<id> --params "
            '\'{"listOfAllowedLocations":{"value":["<region>"]}}\'',
        ),
        severity=Severity.LOW,
        exploitability=1,
        category="posture",
        resource_type=ResourceType.SUBSCRIPTION,
        evidence=(AzureEvidence.POLICY_ASSIGNMENTS,),
        field="locations_restricted",
        safe=True,
        describes="An enforced Allowed locations policy applies",
        failure="lets resources be created in any region",
        mappings={
            "NIST_CSF_2.0": ["GV.PO-01"],
            "GDPR": ["44"],
            "NIST_800_53": ["CM-7"],
            "SOC2": ["CC5.2"],
            "PCI_DSS_4": ["2.2.1"],
            "MITRE_ATTACK": ["T1535"],
        },
        effort_minutes=20,
    ),
)


class AzureCriticalAssetLockRule(SecurityRule):
    """An asset the customer marked critical that nothing stops being deleted."""

    rule_id = "AZ-LCK-001"
    name = "Critical asset has no delete lock"
    description = (
        "An asset tagged or inferred as high or critical has no CanNotDelete or ReadOnly "
        "lock on itself, its resource group or its subscription."
    )
    category = "posture"
    severity = Severity.LOW
    exploitability = 0
    scope = RuleScope.PER_RESOURCE
    applies_to: ClassVar[list[ResourceType]] = [
        ResourceType.VIRTUAL_MACHINE,
        ResourceType.STORAGE_ACCOUNT,
        ResourceType.SQL_SERVER,
        ResourceType.POSTGRESQL_SERVER,
        ResourceType.MYSQL_SERVER,
        ResourceType.DOCUMENT_DATABASE,
        ResourceType.KEY_VAULT,
        ResourceType.APP_SERVICE,
        ResourceType.KUBERNETES_CLUSTER,
        ResourceType.CONTAINER_REGISTRY,
        ResourceType.VIRTUAL_NETWORK,
        ResourceType.BACKUP_VAULT,
        ResourceType.APPLICATION_GATEWAY,
    ]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (AzureEvidence.RESOURCE_LOCKS,)
    estimated_effort_minutes = 10
    rationale = (
        "What a business cannot run without should take two deliberate steps to delete. "
        "A lock is that second step, and it stops a mistaken command or a compromised "
        "Contributor as surely as it stops a script."
    )
    remediation = (
        "Add a delete lock to the asset or its resource group.\n\n"
        "Azure CLI:\n"
        "  az lock create --name keep-<asset> --lock-type CanNotDelete \\\n"
        "    --resource <asset-id>"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=("az lock create --name keep-<asset> --lock-type CanNotDelete --resource <asset-id>",),
        notes=(
            "Judged only on assets marked high or critical, so no single expected state "
            "describes every asset it applies to. No policy is generated: a lock is not a "
            "property of the resource it protects."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        **_RESILIENCE,
        "CIS_AZURE_2.0": ["10.1"],
        "CIS_AZURE_6.0": ["6.2"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")
        if resource.criticality not in (Level.HIGH, Level.CRITICAL):
            return RuleResult.not_applicable("The asset is not marked high or critical")
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Locks unavailable: {failure}")
        locked = resource.get("delete_locked")
        if locked is None:
            return RuleResult.unknown("The locks were not read")
        evidence = {"delete_locked": locked, "criticality": resource.criticality.value}
        if locked:
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} is marked {resource.criticality.value} and has no lock",
        )


RULES = (
    *(
        property_rule(spec)
        for spec in (
            *VAULT_SPECS,
            *WORKSPACE_SPECS,
            *NETWORK_SPECS,
            *GATEWAY_SPECS,
            *WORKLOAD_SPECS,
            *SUBSCRIPTION_SPECS,
        )
    ),
    AzureCriticalAssetLockRule(),
)
