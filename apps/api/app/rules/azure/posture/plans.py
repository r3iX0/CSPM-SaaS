"""Defender for Cloud coverage: whether anything is watching.

The other posture rules read what Defender concluded. This one reads whether
Defender was asked to conclude anything, and the two cannot be folded together:
a plan that is off produces no assessments, so a subscription with no
vulnerability findings and a subscription nobody is scanning for vulnerabilities
look identical from the assessments alone.
"""

from typing import ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule

# The plans CIS Azure 2.0 section 2.1 asks for, by the name the pricing API
# gives them, with the control each answers. Named rather than "every plan the
# listing returns", because the listing also carries plans that are deprecated,
# folded into others, or priced per workload a subscription may not run.
PLANS: dict[str, tuple[str, str]] = {
    "VirtualMachines": ("Servers", "2.1.1"),
    "AppServices": ("App Service", "2.1.2"),
    "SqlServers": ("Azure SQL databases", "2.1.4"),
    "SqlServerVirtualMachines": ("SQL servers on machines", "2.1.5"),
    "OpenSourceRelationalDatabases": ("open-source relational databases", "2.1.6"),
    "StorageAccounts": ("Storage", "2.1.7"),
    "Containers": ("Containers", "2.1.8"),
    "CosmosDbs": ("Azure Cosmos DB", "2.1.9"),
    "KeyVaults": ("Key Vault", "2.1.10"),
    "Arm": ("Resource Manager", "2.1.12"),
}


class AzureDefenderPlansRule(SecurityRule):
    rule_id = "AZ-DEF-001"
    name = "Defender for Cloud plans are off"
    description = (
        "One or more Microsoft Defender for Cloud plans are on the free tier for this "
        "subscription. The workloads those plans cover get no threat detection, no "
        "vulnerability assessment and no alerts."
    )
    category = "posture"
    severity = Severity.MEDIUM
    # Exploitable by nobody. What it removes is the alarm, which is why it is
    # Medium rather than Low: every other finding here gets worse when nothing
    # would notice it being used.
    exploitability = 1
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.SUBSCRIPTION]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (AzureEvidence.DEFENDER_PLANS,)
    estimated_effort_minutes = 30
    rationale = (
        "Defender is where Azure's own detection lives: a sign-in to a storage account "
        "from a Tor exit node, a SQL injection attempt, a crypto-miner on a VM. With a "
        "plan off, those events still happen and nothing raises them.\n\n"
        "Plans are billed per protected resource, so a plan for a workload the "
        "subscription does not run costs nothing -- which is why this reports every "
        "plan that is off rather than guessing which ones matter."
    )
    remediation = (
        "Turn on the plans for the workloads you run, and preferably all of them.\n\n"
        "Azure Portal: Microsoft Defender for Cloud > Environment settings > select the "
        "subscription > Defender plans > set each plan to On > Save.\n\n"
        "Azure CLI:\n"
        "  az security pricing create --name <PlanName> --tier Standard\n\n"
        "Each plan is billed per protected resource. Check the pricing page before "
        "enabling Servers or Containers on a large estate."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(
            "az security pricing list -o table",
            "az security pricing create --name <PlanName> --tier Standard",
        ),
        notes=(
            "No expected state. The check is over the subscription's plan listing, "
            "and the one declaration that could express it -- no plan on the free "
            "tier -- is also satisfied by an empty listing, which this rule reports "
            "as UNKNOWN rather than as every plan on.\n\n"
            "No policy either. Microsoft ships a DeployIfNotExists built-in per plan, "
            "and choosing which to assign is a billing decision this rule should not "
            "make on the customer's behalf."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["2.1.3", *sorted({control for _, control in PLANS.values()})],
        "ISO_27001": ["A.8.16", "A.8.8"],
        "NIST_CSF": ["DE.CM-1", "DE.AE-3"],
        "GDPR": ["32(1)(b)", "32(1)(d)"],
        "NIST_800_53": ["SI-4", "RA-5"],
        "SOC2": ["CC7.2"],
        "PCI_DSS_4": ["11.4.1", "5.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Defender plans unavailable: {failure}")

        plans = resource.get("defender_plans")
        if plans is None:
            return RuleResult.unknown("Defender plan listing missing from snapshot")

        by_name = {
            str(plan.get("name")): plan for plan in plans if not plan.get("deprecated")
        }
        judged = {name: by_name[name] for name in PLANS if name in by_name}
        if not judged:
            # A listing that names none of the plans CIS asks about is not a
            # subscription with all of them on. Azure returns every plan for a
            # subscription it can price, so this is a reading to distrust.
            return RuleResult.unknown(
                "The plan listing named none of the Defender plans this check covers"
            )

        off = sorted(
            name for name, plan in judged.items() if str(plan.get("tier")).lower() != "standard"
        )
        evidence = {
            "plans": {name: plan.get("tier") for name, plan in sorted(judged.items())},
            "off": [PLANS[name][0] for name in off],
            "not_listed": sorted(set(PLANS) - set(judged)),
        }
        if not off:
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=(
                f"{len(off)} Defender for Cloud plan(s) are off for this subscription: "
                + ", ".join(PLANS[name][0] for name in off)
            ),
        )
