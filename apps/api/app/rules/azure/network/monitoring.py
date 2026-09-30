"""Whether the network is watched and defended (DECISIONS.md section 176).

Per virtual network: a Network Watcher in its region, a flow log recording its
traffic to a workspace and kept long enough, and DDoS Network Protection. Per
subscription: a Bastion host, so machines can be administered without a public
address. Virtual networks are modelled since role v11; before, they were
unchecked inventory rows.
"""

from typing import Any, ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule
from app.rules.property import PropertySpec, property_rule

_FLOW_LOGGING = {
    "ISO_27001": ["A.8.15", "A.8.16"],
    "NIST_CSF": ["DE.CM-1", "PR.PT-1"],
    "GDPR": ["32(1)(d)"],
    "NIST_800_53": ["AU-2", "SI-4"],
    "SOC2": ["CC7.2"],
    "PCI_DSS_4": ["10.2.1"],
}
_NETWORK = {
    "ISO_27001": ["A.8.20", "A.8.22"],
    "NIST_CSF": ["PR.AC-5", "PR.PT-4"],
    "GDPR": ["32(1)(b)"],
    "NIST_800_53": ["SC-7"],
    "SOC2": ["CC6.6"],
    "PCI_DSS_4": ["1.4.1"],
}
_WATCHED = (AzureEvidence.VIRTUAL_NETWORKS, AzureEvidence.NETWORK_WATCHERS)
_FLOW_LOGS = (*_WATCHED, AzureEvidence.FLOW_LOGS)
_NO_POLICY = (
    "No policy is generated: the policy aliases for this have not been verified yet "
    "(DECISIONS.md section 170)."
)


class _FlowLogRule(SecurityRule):
    category = "network"
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.VIRTUAL_NETWORK]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = _FLOW_LOGS
    compliance_mappings: ClassVar[dict[str, list[str]]] = _FLOW_LOGGING

    def _logs(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[dict[str, Any]]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Flow logs unavailable: {failure}")
        logs = resource.get("flow_logs")
        if logs is None:
            return RuleResult.unknown("The flow logs of this network's region were not read")
        return [log for log in logs if isinstance(log, dict) and log.get("enabled")]


class AzureFlowLogAnalyticsRule(_FlowLogRule):
    rule_id = "AZ-NET-010"
    name = "Virtual network traffic reaches no workspace"
    description = (
        "No enabled flow log sends this network's traffic to a Log Analytics workspace "
        "through traffic analytics, so who talked to what is either not recorded or "
        "recorded where nobody queries it."
    )
    severity = Severity.MEDIUM
    exploitability = 1
    estimated_effort_minutes = 45
    rationale = (
        "Flow records are how an investigation finds the machine that was talked to "
        "after the first one fell. Written only to a storage account they are there "
        "in principle; in a workspace they can be searched the day they are needed."
    )
    remediation = (
        "Create a virtual network flow log with traffic analytics on.\n\n"
        "Azure CLI:\n"
        "  az network watcher flow-log create --location <region> --name <name> \\\n"
        "    --resource-group <rg> --vnet <vnet> --storage-account <account-id> \\\n"
        "    --traffic-analytics true --workspace <workspace-id>"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(
            "az network watcher flow-log create --location <region> --name <name> "
            "--resource-group <rg> --vnet <vnet> --storage-account <account-id> "
            "--traffic-analytics true --workspace <workspace-id>",
        ),
        notes=(
            "No expected state: a flow log is a resource of its own under the region's "
            f"Network Watcher, not a setting on the network. {_NO_POLICY}"
        ),
    )

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        logs = self._logs(resource, context)
        if isinstance(logs, RuleResult):
            return logs
        assert resource is not None
        analysed = [log for log in logs if log.get("traffic_analytics")]
        evidence = {"enabled_flow_logs": len(logs), "with_traffic_analytics": len(analysed)}
        if analysed:
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=(
                f"{resource.name} has no flow log sending its traffic to a workspace"
                if logs
                else f"{resource.name} has no enabled flow log"
            ),
        )


class AzureFlowLogRetentionRule(_FlowLogRule):
    rule_id = "AZ-NET-011"
    name = "Flow logs are kept for under 90 days"
    description = (
        "A flow log recording this network deletes its records in under 90 days, "
        "shorter than most intrusions go unnoticed."
    )
    severity = Severity.LOW
    exploitability = 1
    estimated_effort_minutes = 15
    rationale = (
        "Breaches are found months late. Flow records that have rolled over cannot "
        "show where the intruder went, and 90 days is the least CIS asks for."
    )
    remediation = (
        "Keep flow logs for 90 days or more, or switch retention off to keep them.\n\n"
        "Azure CLI:\n"
        "  az network watcher flow-log update --location <region> --name <name> \\\n"
        "    --retention 90"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(
            "az network watcher flow-log update --location <region> --name <name> "
            "--retention 90",
        ),
        notes=(
            "No expected state: retention is set on each flow log, a resource of its "
            f"own, not on the network. {_NO_POLICY}"
        ),
    )

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        logs = self._logs(resource, context)
        if isinstance(logs, RuleResult):
            return logs
        assert resource is not None
        if not logs:
            # AZ-NET-010 reports a network with no flow log; there is no
            # retention to judge.
            return RuleResult.not_applicable("No enabled flow log records this network")
        short = [
            log
            for log in logs
            if log.get("retention_enabled")
            and isinstance(log.get("retention_days"), int)
            and 0 < log["retention_days"] < 90
        ]
        evidence = {
            "retention": [
                {"flow_log": log.get("id"), "days": log.get("retention_days")}
                for log in logs
            ]
        }
        if not short:
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=f"A flow log recording {resource.name} keeps its records under 90 days",
        )


class AzureBastionRule(SecurityRule):
    """A subscription with machines has a Bastion host to reach them through.

    Not applicable to one with no virtual machine: there is nothing to
    administer, and the catalogue's version failed every subscription regardless.
    """

    rule_id = "AZ-NET-014"
    name = "No Bastion host for administering machines"
    description = (
        "The subscription runs virtual machines and has no Azure Bastion host, so the "
        "way to administer them is a public address with RDP or SSH open, or a VPN "
        "somebody has to maintain."
    )
    category = "network"
    severity = Severity.LOW
    exploitability = 1
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.SUBSCRIPTION]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.BASTION_HOSTS,
        AzureEvidence.VIRTUAL_MACHINES,
    )
    estimated_effort_minutes = 60
    rationale = (
        "Bastion gives RDP and SSH through the portal over TLS, with no public address "
        "on the machine. Its absence is why machines end up with port 3389 open to the "
        "internet -- the finding AZ-CMP-001 raises."
    )
    remediation = (
        "Deploy Azure Bastion into the virtual network the machines use.\n\n"
        "Azure CLI:\n"
        "  az network bastion create --name <name> --resource-group <rg> \\\n"
        "    --vnet-name <vnet> --public-ip-address <public-ip> --location <region>"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(
            "az network bastion create --name <name> --resource-group <rg> "
            "--vnet-name <vnet> --public-ip-address <public-ip> --location <region>",
        ),
        notes=(
            "No expected state: a Bastion host is a resource to create, not a setting "
            f"on the subscription. {_NO_POLICY}"
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.8.20"],
        "NIST_CSF": ["PR.AC-3"],
        "GDPR": ["32(1)(b)"],
        "NIST_800_53": ["AC-17"],
        "SOC2": ["CC6.6"],
        "PCI_DSS_4": ["1.4.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Bastion hosts unavailable: {failure}")
        machines = context.get_resources_by_type(ResourceType.VIRTUAL_MACHINE)
        if not machines:
            return RuleResult.not_applicable("The subscription runs no virtual machine")
        count = resource.get("bastion_host_count")
        if count is None:
            return RuleResult.unknown("Bastion hosts were not read")
        evidence = {"bastion_hosts": count, "virtual_machines": len(machines)}
        if count:
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=f"{len(machines)} virtual machine(s) and no Bastion host to reach them",
        )


SPECS = (
    PropertySpec(
        rule_id="AZ-NET-012",
        name="No Network Watcher in the network's region",
        description=(
            "The virtual network's region has no Network Watcher, so no flow log, "
            "connection troubleshooting or packet capture is possible there."
        ),
        rationale=(
            "Network Watcher is what flow logs are created under. Without it in a region "
            "nothing about that region's traffic can be recorded."
        ),
        remediation=(
            "Enable Network Watcher for the region.\n\n"
            "Azure CLI:\n"
            "  az network watcher configure --locations <region> --enabled true \\\n"
            "    --resource-group NetworkWatcherRG"
        ),
        cli=(
            "az network watcher configure --locations <region> --enabled true "
            "--resource-group NetworkWatcherRG",
        ),
        severity=Severity.MEDIUM,
        exploitability=1,
        category="network",
        resource_type=ResourceType.VIRTUAL_NETWORK,
        evidence=_WATCHED,
        field="network_watcher_in_region",
        safe=True,
        describes="A Network Watcher exists in the network's region",
        failure="is in a region with no Network Watcher",
        mappings=_FLOW_LOGGING,
    ),
    PropertySpec(
        rule_id="AZ-NET-013",
        name="Virtual network has no DDoS Network Protection",
        description=(
            "The virtual network is not covered by an Azure DDoS Network Protection "
            "plan, so the public endpoints in it have only the platform's basic "
            "infrastructure protection."
        ),
        rationale=(
            "Network Protection tunes mitigation to the application's own traffic and "
            "comes with rapid response and cost protection. It is priced per plan, not "
            "per network, so one plan can cover every network that needs it."
        ),
        remediation=(
            "Associate the network with a DDoS protection plan.\n\n"
            "Azure CLI:\n"
            "  az network vnet update --name <vnet> --resource-group <rg> \\\n"
            "    --ddos-protection true --ddos-protection-plan <plan-id>"
        ),
        cli=(
            "az network vnet update --name <vnet> --resource-group <rg> "
            "--ddos-protection true --ddos-protection-plan <plan-id>",
        ),
        severity=Severity.LOW,
        exploitability=1,
        category="network",
        resource_type=ResourceType.VIRTUAL_NETWORK,
        evidence=(AzureEvidence.VIRTUAL_NETWORKS,),
        field="ddos_protection",
        safe=True,
        # Documented default: false.
        absent="fail",
        describes="DDoS Network Protection is enabled on the network",
        failure="has no DDoS Network Protection",
        mappings=_NETWORK,
        effort_minutes=60,
    ),
)

RULES = (
    AzureFlowLogAnalyticsRule(),
    AzureFlowLogRetentionRule(),
    *(property_rule(spec) for spec in SPECS),
    AzureBastionRule(),
)
