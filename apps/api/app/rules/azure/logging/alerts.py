"""Activity-log alerts, and where the activity log goes (DECISIONS.md section 176).

Eleven alerts CIS asks every subscription to have -- one per control-plane
change worth a person's attention the moment it happens, and one for Service
Health -- then what the activity log export carries, and the storage account
it is kept in. Each is a fact the normalizer already reduced to one field, so
each is a property spec.

An alert counts only when it is enabled and scoped to the whole subscription.
One scoped to a resource group watches that group and nothing created beside
it, which is where a change made to avoid notice would be made.
"""

from typing import Any, ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule
from app.rules.property import PropertySpec, property_rule

_ALERTING = {
    "ISO_27001": ["A.8.16"],
    "NIST_CSF": ["DE.CM-1", "DE.AE-3"],
    "GDPR": ["32(1)(d)"],
    "NIST_800_53": ["SI-4", "AU-6"],
    "SOC2": ["CC7.2"],
    "PCI_DSS_4": ["10.2.1"],
}
_LOG_PROTECTION = {
    "ISO_27001": ["A.8.15"],
    "NIST_CSF": ["PR.PT-1"],
    "GDPR": ["32(1)(b)"],
    "NIST_800_53": ["AU-9"],
    "SOC2": ["CC7.2"],
    "PCI_DSS_4": ["10.3.2"],
}
_ALERTS = (AzureEvidence.ACTIVITY_LOG_ALERTS,)


def _watches(operation: str) -> Any:
    def test(operations: Any) -> bool:
        return operation in [str(o).lower() for o in operations or []]

    return test


def _alert(
    rule_id: str, operation: str, event: str, why: str, severity: Severity
) -> PropertySpec:
    return PropertySpec(
        rule_id=rule_id,
        name=f"No alert fires when {event}",
        description=(
            f"No enabled activity-log alert across the subscription watches "
            f"`{operation}`, so nobody is told when {event}."
        ),
        rationale=why,
        remediation=(
            "Create an activity-log alert scoped to the subscription, with an action "
            "group that reaches a person.\n\n"
            "Azure CLI:\n"
            f"  az monitor activity-log alert create --name <name> --resource-group <rg> \\\n"
            "    --scope /subscriptions/<subscription-id> \\\n"
            f"    --condition category=Administrative and operationName={operation} \\\n"
            "    --action-group <action-group-id>"
        ),
        cli=(
            "az monitor activity-log alert create --name <name> --resource-group <rg> "
            "--scope /subscriptions/<subscription-id> --condition "
            f"category=Administrative and operationName={operation} "
            "--action-group <action-group-id>",
        ),
        severity=severity,
        exploitability=1,
        category="logging",
        resource_type=ResourceType.SUBSCRIPTION,
        evidence=_ALERTS,
        field="alerted_operations",
        passes=_watches(operation.lower()),
        why_no_expected_state=(
            "The subscription passes when some alert watches the operation among any "
            "others, so there is no one list to expect."
        ),
        describes=f"An enabled subscription-wide alert watches {operation}",
        failure=f"raises no alert when {event}",
        mappings=_ALERTING,
        effort_minutes=15,
    )


_REQUIRED_CATEGORIES = frozenset({"administrative", "security", "alert", "policy"})


def _exports_required_categories(categories: Any) -> bool:
    found = {str(c).lower() for c in categories or []}
    return "alllogs" in found or found >= _REQUIRED_CATEGORIES


SPECS = (
    _alert(
        "AZ-LOG-005",
        "Microsoft.Authorization/policyAssignments/write",
        "a policy is assigned",
        "A new policy assignment can change what is allowed or audited across a whole "
        "scope; one nobody expected is worth hearing about the day it lands.",
        Severity.LOW,
    ),
    _alert(
        "AZ-LOG-006",
        "Microsoft.Authorization/policyAssignments/delete",
        "a policy assignment is removed",
        "Removing an assignment switches off whatever it enforced or audited, in one "
        "call, and is how guardrails quietly disappear.",
        Severity.MEDIUM,
    ),
    _alert(
        "AZ-LOG-007",
        "Microsoft.Network/networkSecurityGroups/write",
        "a network security group is created or changed",
        "One added rule is the difference between a private machine and one answering "
        "the internet. AZ-NET-001 reports the open port at scan time; this is the "
        "moment it opened.",
        Severity.MEDIUM,
    ),
    _alert(
        "AZ-LOG-008",
        "Microsoft.Network/networkSecurityGroups/delete",
        "a network security group is deleted",
        "Deleting a group removes every rule it held, leaving whatever it guarded open "
        "to the network defaults.",
        Severity.MEDIUM,
    ),
    _alert(
        "AZ-LOG-009",
        "Microsoft.Security/securitySolutions/write",
        "a security solution is created or changed",
        "A security solution feeds Defender for Cloud; changing one changes what is "
        "watched.",
        Severity.LOW,
    ),
    _alert(
        "AZ-LOG-010",
        "Microsoft.Security/securitySolutions/delete",
        "a security solution is deleted",
        "Deleting a security solution stops whatever it was watching, which is the "
        "first thing an intruder who can would do.",
        Severity.LOW,
    ),
    _alert(
        "AZ-LOG-011",
        "Microsoft.Sql/servers/firewallRules/write",
        "a SQL server firewall rule is created or changed",
        "A firewall rule is what opens a database to an address range; a new one "
        "admitting 0.0.0.0 to 255.255.255.255 is a public database.",
        Severity.MEDIUM,
    ),
    _alert(
        "AZ-LOG-012",
        "Microsoft.Sql/servers/firewallRules/delete",
        "a SQL server firewall rule is deleted",
        "Deleting rules is how access is cut, and how evidence of who was admitted is "
        "removed; either is worth knowing about.",
        Severity.LOW,
    ),
    _alert(
        "AZ-LOG-013",
        "Microsoft.Network/publicIPAddresses/write",
        "a public IP address is created or changed",
        "A new public address is a new way in from the internet, created by whoever "
        "held the permission.",
        Severity.LOW,
    ),
    _alert(
        "AZ-LOG-014",
        "Microsoft.Network/publicIPAddresses/delete",
        "a public IP address is deleted",
        "Deleting an address can take a service offline, and a released address can be "
        "claimed by someone else while DNS still points at it.",
        Severity.LOW,
    ),
    PropertySpec(
        rule_id="AZ-LOG-015",
        name="No alert fires on a Service Health incident",
        description=(
            "No enabled activity-log alert across the subscription watches Service "
            "Health, so an Azure outage or planned maintenance affecting it reaches "
            "nobody until something breaks."
        ),
        rationale=(
            "Service Health is Azure telling you about its own incidents, including "
            "security advisories. Without an alert those notices sit in the portal."
        ),
        remediation=(
            "Create a Service Health alert for the subscription.\n\n"
            "Azure Portal: Service Health > Health alerts > Create service health alert > "
            "Subscription: this one > Event types: all > Action group > Create."
        ),
        cli=(
            "az monitor activity-log alert create --name service-health --resource-group "
            "<rg> --scope /subscriptions/<subscription-id> --condition "
            "category=ServiceHealth --action-group <action-group-id>",
        ),
        severity=Severity.LOW,
        exploitability=0,
        category="logging",
        resource_type=ResourceType.SUBSCRIPTION,
        evidence=_ALERTS,
        field="service_health_alert",
        safe=True,
        describes="An enabled subscription-wide alert watches Service Health",
        failure="raises no alert on a Service Health incident",
        mappings=_ALERTING,
        effort_minutes=15,
    ),
    PropertySpec(
        rule_id="AZ-LOG-016",
        name="The activity log export leaves out security categories",
        description=(
            "The subscription's activity log is exported, but not with all of the "
            "Administrative, Security, Alert and Policy categories, so part of the "
            "record is kept for 90 days and then lost."
        ),
        rationale=(
            "AZ-LOG-002 asks whether the log is exported at all. The categories decide "
            "what survives: Security holds Defender's alerts, Policy the deny and audit "
            "decisions, and an export without them keeps the changes and loses the "
            "context."
        ),
        remediation=(
            "Add the missing categories to the subscription's diagnostic setting.\n\n"
            "Azure Portal: Monitor > Activity log > Export Activity Logs > edit the "
            "setting > tick Administrative, Security, Alert and Policy > Save."
        ),
        cli=(
            "az monitor diagnostic-settings subscription create --name activity-log-export "
            "--location <region> --workspace <workspace-id> --logs "
            "'[{\"category\":\"Administrative\",\"enabled\":true},"
            "{\"category\":\"Security\",\"enabled\":true},"
            "{\"category\":\"Alert\",\"enabled\":true},"
            "{\"category\":\"Policy\",\"enabled\":true}]'",
        ),
        severity=Severity.MEDIUM,
        exploitability=1,
        category="logging",
        resource_type=ResourceType.SUBSCRIPTION,
        evidence=(AzureEvidence.DIAGNOSTIC_SETTINGS,),
        field="activity_log_categories",
        passes=_exports_required_categories,
        why_no_expected_state=(
            "The export passes with these four among any others, so there is no one list "
            "to expect."
        ),
        describes="The activity log export includes Administrative, Security, Alert and Policy",
        failure="does not export every security category of its activity log",
        mappings={
            "ISO_27001": ["A.8.15"],
            "NIST_CSF": ["PR.PT-1", "DE.AE-3"],
            "GDPR": ["5(2)"],
            "NIST_800_53": ["AU-2", "AU-11"],
            "SOC2": ["CC7.2"],
            "PCI_DSS_4": ["10.2.1"],
        },
    ),
    PropertySpec(
        rule_id="AZ-LOG-017",
        name="Activity log storage uses Microsoft's keys",
        description=(
            "The storage account the subscription's activity log is exported to "
            "encrypts it with Microsoft-managed keys rather than a key the customer "
            "controls."
        ),
        rationale=(
            "The activity log is evidence. A customer-managed key puts who can read it "
            "-- and the ability to revoke that -- in the customer's own vault."
        ),
        remediation=(
            "Encrypt the account with a key from your vault.\n\n"
            "Azure CLI:\n"
            "  az storage account update --name <account> --resource-group <rg> \\\n"
            "    --encryption-key-source Microsoft.Keyvault \\\n"
            "    --encryption-key-vault <vault-uri> --encryption-key-name <key>"
        ),
        cli=(
            "az storage account update --name <account> --resource-group <rg> "
            "--encryption-key-source Microsoft.Keyvault --encryption-key-vault <vault-uri> "
            "--encryption-key-name <key>",
        ),
        severity=Severity.LOW,
        exploitability=0,
        category="logging",
        resource_type=ResourceType.STORAGE_ACCOUNT,
        evidence=(AzureEvidence.STORAGE_ACCOUNTS, AzureEvidence.DIAGNOSTIC_SETTINGS),
        field="customer_managed_key",
        safe=True,
        describes="The account encrypts with a customer-managed key",
        failure="keeps the activity log under Microsoft-managed keys",
        mappings=_LOG_PROTECTION,
        applies_when=(("holds_activity_log", "true"),),
    ),
    PropertySpec(
        rule_id="AZ-LOG-018",
        name="Activity log storage allows public blob access",
        description=(
            "The storage account the subscription's activity log is exported to allows "
            "containers to be made public, so one setting away from anonymous readers."
        ),
        rationale=(
            "The activity log records every change and who made it -- the map an "
            "intruder would want first, and the record they would most like to read "
            "without leaving a sign-in."
        ),
        remediation=(
            "Disallow public blob access on the account.\n\n"
            "Azure CLI:\n"
            "  az storage account update --name <account> --resource-group <rg> \\\n"
            "    --allow-blob-public-access false"
        ),
        cli=(
            "az storage account update --name <account> --resource-group <rg> "
            "--allow-blob-public-access false",
        ),
        severity=Severity.HIGH,
        exploitability=2,
        category="logging",
        resource_type=ResourceType.STORAGE_ACCOUNT,
        evidence=(AzureEvidence.STORAGE_ACCOUNTS, AzureEvidence.DIAGNOSTIC_SETTINGS),
        field="allow_blob_public_access",
        safe=False,
        terraform_attribute="allow_nested_items_to_be_public",
        describes="Public blob access is disallowed on the account",
        failure="keeps the activity log in an account that allows public blob access",
        mappings=_LOG_PROTECTION,
        applies_when=(("holds_activity_log", "true"),),
    ),
)



class AzureApplicationInsightsRule(SecurityRule):
    """A subscription running apps has somewhere to send their telemetry
    (section 177). Not applicable where it runs no web or function app, where
    the catalogue failed every subscription alike.

    Which app sends to which component is written only in each app's settings,
    behind ``config/list``, which also returns its secrets and is never
    requested -- so this asks the one thing answerable without them: whether any
    Application Insights resource exists. Read from the inventory, like
    AZ-DEF-009."""

    rule_id = "AZ-LOG-019"
    name = "Apps run with no Application Insights resource"
    description = (
        "The subscription runs web or function apps and has no Application Insights "
        "resource, so no request, failure or dependency call from them is recorded."
    )
    category = "logging"
    severity = Severity.LOW
    exploitability = 0
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.SUBSCRIPTION]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.RESOURCES,
        AzureEvidence.APP_SERVICES,
    )
    estimated_effort_minutes = 30
    rationale = (
        "Application telemetry is where an injection attempt shows up as a burst of "
        "500s and an unfamiliar dependency call. Without it an app's behaviour is "
        "visible only as platform metrics."
    )
    remediation = (
        "Create an Application Insights resource and connect the apps to it.\n\n"
        "Azure CLI:\n"
        "  az monitor app-insights component create --app <name> --location <region> \\\n"
        "    --resource-group <rg> --workspace <workspace-id>"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(
            "az monitor app-insights component create --app <name> --location <region> "
            "--resource-group <rg> --workspace <workspace-id>",
        ),
        notes=(
            "No expected state: the check is whether a resource exists, not a setting "
            "on one. No policy is generated (DECISIONS.md section 170)."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.8.16"],
        "NIST_CSF": ["DE.CM-1"],
        "GDPR": ["32(1)(d)"],
        "NIST_800_53": ["SI-4"],
        "SOC2": ["CC7.2"],
        "PCI_DSS_4": ["10.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Inventory unavailable: {failure}")
        apps = context.get_resources_by_type(ResourceType.APP_SERVICE)
        if not apps:
            return RuleResult.not_applicable("The subscription runs no web or function app")
        count = resource.get("application_insights_count")
        if count is None:
            return RuleResult.unknown("The subscription's inventory was not read")
        evidence = {"application_insights": count, "apps": len(apps)}
        if count:
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=f"{len(apps)} app(s) run with no Application Insights resource",
        )


RULES = (*(property_rule(spec) for spec in SPECS), AzureApplicationInsightsRule())
