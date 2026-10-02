"""Defender for Cloud's own settings (DECISIONS.md section 176).

Who Defender emails, about what, and which integrations it runs; whether it
scans container images; whether the Microsoft cloud security benchmark is
enforced; and whether an IoT hub is watched. Each is a fact about the
subscription, so every rule here judges the subscription asset. None raises
exploitability above 1: what each removes is the alarm, not a door.
"""

from typing import Any, ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule
from app.rules.property import PropertySpec, property_rule

_MONITORING = {
    "ISO_27001": ["A.8.16"],
    "NIST_CSF": ["DE.CM-1", "DE.AE-3"],
    "GDPR": ["32(1)(d)", "33"],
    "NIST_800_53": ["SI-4", "IR-4"],
    "SOC2": ["CC7.2", "CC7.3"],
    "PCI_DSS_4": ["10.2.1"],
}
_VULNERABILITY = {
    "ISO_27001": ["A.8.8"],
    "NIST_CSF": ["ID.RA-1", "DE.CM-1"],
    "GDPR": ["32(1)(d)"],
    "NIST_800_53": ["RA-5", "SI-2"],
    "SOC2": ["CC7.1"],
    "PCI_DSS_4": ["11.3.1"],
}
_GOVERNANCE = {
    "ISO_27001": ["A.8.8"],
    "NIST_CSF": ["ID.GV-1"],
    "GDPR": ["25"],
    "NIST_800_53": ["CM-6"],
    "SOC2": ["CC5.2"],
    "PCI_DSS_4": ["12.1.1"],
}

_CONTACTS = (AzureEvidence.SECURITY_CONTACTS,)
_SETTINGS = (AzureEvidence.SECURITY_SETTINGS,)
_CONTACT_CLI = (
    "az rest --method PUT --url https://management.azure.com/subscriptions/"
    "<subscription-id>/providers/Microsoft.Security/securityContacts/default"
    "?api-version=2023-12-01-preview --body @security-contact.json"
)
_PORTAL_CONTACTS = (
    "Azure Portal: Microsoft Defender for Cloud > Environment settings > select the "
    "subscription > Email notifications."
)


def _any(value: Any) -> bool:
    return bool(value)


def _high_or_lower(level: Any) -> bool:
    # Any minimum at or below High sends everything at High. Critical alone, for
    # attack paths, leaves out the High ones CIS asks to be told about.
    return str(level or "").lower() in {"high", "medium", "low"}


def _owners_told(roles: Any) -> bool:
    return "owner" in [str(role).lower() for role in roles or []]


def _enforced(mode: Any) -> bool:
    return str(mode or "").lower() == "default"


SPECS = (
    PropertySpec(
        rule_id="AZ-DEF-002",
        name="Defender for Cloud emails no security contact",
        description=(
            "No email address is set on the subscription's security contact, so "
            "Defender for Cloud's alerts reach nobody named to act on them."
        ),
        rationale=(
            "An alert nobody receives is an alert nobody acts on. A named address -- a "
            "security team's shared mailbox -- is what turns detection into response."
        ),
        remediation=(
            "Add the security team's address to the subscription's security contact.\n\n"
            f"{_PORTAL_CONTACTS} Add email addresses > Save."
        ),
        cli=(_CONTACT_CLI,),
        severity=Severity.LOW,
        exploitability=1,
        category="posture",
        resource_type=ResourceType.SUBSCRIPTION,
        evidence=_CONTACTS,
        field="security_contact_emails",
        passes=_any,
        why_no_expected_state="Any address passes, so there is no one value to expect.",
        describes="The security contact names at least one email address",
        failure="has no security contact email address",
        mappings=_MONITORING,
    ),
    PropertySpec(
        rule_id="AZ-DEF-003",
        name="Defender for Cloud sends no email about high-severity alerts",
        description=(
            "Alert email notifications are off, so a high-severity Defender for Cloud "
            "alert is raised in the portal and nowhere else."
        ),
        rationale=(
            "High-severity alerts are the ones that mean an attack in progress -- a "
            "crypto-miner, a credential used from an attacker's infrastructure. They "
            "should reach a person the moment they are raised."
        ),
        remediation=(
            "Turn on alert notifications at High (or a lower minimum).\n\n"
            f"{_PORTAL_CONTACTS} Notify about alerts with the following severity (or "
            "higher): High > Save."
        ),
        cli=(_CONTACT_CLI,),
        severity=Severity.MEDIUM,
        exploitability=1,
        category="posture",
        resource_type=ResourceType.SUBSCRIPTION,
        evidence=_CONTACTS,
        field="alert_notification_severity",
        passes=_high_or_lower,
        why_no_expected_state=(
            "High, Medium and Low all send every high-severity alert, so there is no one "
            "value to expect."
        ),
        describes="Alert emails are sent at severity High or lower",
        failure="sends no email about high-severity alerts",
        mappings=_MONITORING,
    ),
    PropertySpec(
        rule_id="AZ-DEF-004",
        name="Defender for Cloud does not email subscription owners",
        description=(
            "Defender for Cloud's alert emails do not go to the subscription's Owners, "
            "the people who can change anything in it."
        ),
        rationale=(
            "Owners can act on an alert without asking anyone for access. Telling them is "
            "cheap, and it survives the day the named contact leaves."
        ),
        remediation=(
            "Send notifications to the Owner role.\n\n"
            f"{_PORTAL_CONTACTS} All users with the following roles: Owner > Save."
        ),
        cli=(_CONTACT_CLI,),
        severity=Severity.LOW,
        exploitability=1,
        category="posture",
        resource_type=ResourceType.SUBSCRIPTION,
        evidence=_CONTACTS,
        field="notify_roles",
        passes=_owners_told,
        why_no_expected_state=(
            "Owner may be one of several roles notified, so there is no one list to expect."
        ),
        describes="Alert emails go to users holding the Owner role",
        failure="does not email its Owners about alerts",
        mappings=_MONITORING,
    ),
    PropertySpec(
        rule_id="AZ-DEF-005",
        name="Defender for Cloud sends no email about attack paths",
        description=(
            "Attack path notifications are off, or limited to Critical, so Defender "
            "raises a new high-risk route to sensitive data and emails nobody."
        ),
        rationale=(
            "An attack path is a chain an attacker can walk today. A new one appearing is "
            "worth an email the day it appears, not the next time somebody opens the "
            "portal."
        ),
        remediation=(
            "Turn on attack path notifications at High risk or lower.\n\n"
            f"{_PORTAL_CONTACTS} Notify about attack paths with the following risk level "
            "(or higher): High > Save."
        ),
        cli=(_CONTACT_CLI,),
        severity=Severity.LOW,
        exploitability=1,
        category="posture",
        resource_type=ResourceType.SUBSCRIPTION,
        evidence=_CONTACTS,
        field="attack_path_notification_level",
        passes=_high_or_lower,
        why_no_expected_state=(
            "High, Medium and Low all send every high-risk path, so there is no one value "
            "to expect."
        ),
        describes="Attack path emails are sent at risk level High or lower",
        failure="sends no email about new high-risk attack paths",
        mappings=_MONITORING,
    ),
    PropertySpec(
        rule_id="AZ-DEF-006",
        name="Defender for Endpoint integration is off",
        description=(
            "Defender for Cloud does not hand this subscription's machines to Microsoft "
            "Defender for Endpoint, so they get no endpoint detection and response."
        ),
        rationale=(
            "Endpoint detection is what sees a process injecting into another or a "
            "credential dumped from memory -- the steps after a foothold that network "
            "and configuration checks never will."
        ),
        remediation=(
            "Turn on the integration.\n\n"
            "Azure Portal: Microsoft Defender for Cloud > Environment settings > select "
            "the subscription > Integrations > Allow Microsoft Defender for Endpoint to "
            "access my data > Save."
        ),
        cli=("az security setting update --name WDATP --enabled true",),
        severity=Severity.MEDIUM,
        exploitability=1,
        category="posture",
        resource_type=ResourceType.SUBSCRIPTION,
        evidence=_SETTINGS,
        field="defender_endpoint_integration",
        safe=True,
        describes="The WDATP setting is enabled",
        failure="does not hand its machines to Defender for Endpoint",
        mappings=_MONITORING,
    ),
    PropertySpec(
        rule_id="AZ-DEF-007",
        name="Defender for Cloud Apps integration is off",
        description=(
            "Defender for Cloud does not share this subscription's data with Microsoft "
            "Defender for Cloud Apps, so its activity analytics see none of it."
        ),
        rationale=(
            "Cloud Apps correlates what users do across services -- an impossible trip, "
            "a mass download. Without the integration, activity here is missing from "
            "that picture."
        ),
        remediation=(
            "Turn on the integration.\n\n"
            "Azure Portal: Microsoft Defender for Cloud > Environment settings > select "
            "the subscription > Integrations > Allow Microsoft Defender for Cloud Apps to "
            "access my data > Save."
        ),
        cli=("az security setting update --name MCAS --enabled true",),
        severity=Severity.LOW,
        exploitability=1,
        category="posture",
        resource_type=ResourceType.SUBSCRIPTION,
        evidence=_SETTINGS,
        field="cloud_apps_integration",
        safe=True,
        describes="The MCAS setting is enabled",
        failure="does not share its data with Defender for Cloud Apps",
        mappings=_MONITORING,
    ),
    PropertySpec(
        rule_id="AZ-DEF-008",
        name="Container images are not scanned for vulnerabilities",
        description=(
            "Defender for Containers is off, or on without registry image scanning, so "
            "images pushed to this subscription's registries are never checked for "
            "known vulnerabilities."
        ),
        rationale=(
            "An image is code that runs. A known-vulnerable base image pulled into every "
            "cluster is a vulnerability deployed everywhere at once, and the registry is "
            "where it is cheapest to catch."
        ),
        remediation=(
            "Turn on Defender for Containers with registry image scanning.\n\n"
            "Azure Portal: Microsoft Defender for Cloud > Environment settings > select "
            "the subscription > Defender plans > Containers: On > Settings > Agentless "
            "container vulnerability assessment: On > Save."
        ),
        cli=(
            "az security pricing create --name Containers --tier Standard "
            "--extensions name=ContainerRegistriesVulnerabilityAssessments isEnabled=True",
        ),
        severity=Severity.MEDIUM,
        exploitability=1,
        category="posture",
        resource_type=ResourceType.SUBSCRIPTION,
        evidence=(AzureEvidence.DEFENDER_PLANS,),
        field="container_image_scanning",
        safe=True,
        describes="Defender for Containers scans registry images",
        failure="does not scan its container images for vulnerabilities",
        mappings=_VULNERABILITY,
    ),
    PropertySpec(
        rule_id="AZ-DEF-010",
        name="The Microsoft cloud security benchmark is not enforced",
        description=(
            "The Microsoft cloud security benchmark -- the policy initiative Defender for "
            "Cloud's recommendations come from -- is unassigned here, or assigned with "
            "enforcement turned off."
        ),
        rationale=(
            "With the initiative unenforced its policies evaluate nothing, and the "
            "recommendations built on them go quiet: the posture view reads cleaner than "
            "the estate is."
        ),
        remediation=(
            "Assign the initiative, or set its enforcement mode back to Default.\n\n"
            "Azure Portal: Policy > Assignments > ASC Default (the Microsoft cloud "
            "security benchmark) > Edit assignment > Policy enforcement: Enabled > Save."
        ),
        cli=(
            "az policy assignment update --name SecurityCenterBuiltIn "
            "--scope /subscriptions/<subscription-id> --enforcement-mode Default",
        ),
        severity=Severity.MEDIUM,
        exploitability=1,
        category="posture",
        resource_type=ResourceType.SUBSCRIPTION,
        evidence=(AzureEvidence.POLICY_ASSIGNMENTS,),
        field="security_benchmark_enforcement",
        passes=_enforced,
        why_no_expected_state=(
            "One failing state is no assignment at all, which no setting on an "
            "assignment can express."
        ),
        describes="The Microsoft cloud security benchmark is assigned with enforcement on",
        failure="does not enforce the Microsoft cloud security benchmark",
        # An enforced benchmark is a hardened configuration standard in force
        # (PCI DSS 2.2.1; DECISIONS.md section 204).
        mappings={**_GOVERNANCE, "PCI_DSS_4": ["12.1.1", "2.2.1"]},
    ),
    # Section 177: filed as reading activity, and answerable from the plan
    # listing read since v7 all along.
    PropertySpec(
        rule_id="AZ-DEF-011",
        name="Defender CSPM is off",
        description=(
            "The subscription is on the free foundational posture tier. The paid "
            "Defender CSPM plan's attack path analysis, agentless scanning and data "
            "awareness are off."
        ),
        rationale=(
            "Foundational posture lists misconfigurations one by one; Defender CSPM is "
            "what Microsoft uses to join them into the routes an attacker would take."
        ),
        remediation=(
            "Turn on the Defender CSPM plan.\n\n"
            "Azure CLI:\n"
            "  az security pricing create --name CloudPosture --tier Standard"
        ),
        cli=("az security pricing create --name CloudPosture --tier Standard",),
        severity=Severity.LOW,
        exploitability=1,
        category="posture",
        resource_type=ResourceType.SUBSCRIPTION,
        evidence=(AzureEvidence.DEFENDER_PLANS,),
        field="defender_cspm",
        safe=True,
        describes="The Defender CSPM plan is on the Standard tier",
        failure="does not have Defender CSPM on",
        mappings=_MONITORING,
    ),
)


class AzureIotHubDefenderRule(SecurityRule):
    """Every IoT hub the inventory lists is watched by Defender for IoT.

    Not applicable to a subscription with no IoT hub, which is nearly every one:
    the catalogue's version failed any subscription without a solution, hub or
    no hub, and a check that fails everywhere is noise nobody reads.
    """

    rule_id = "AZ-DEF-009"
    name = "IoT hub is not watched by Defender for IoT"
    description = (
        "An IoT hub in this subscription is covered by no enabled Defender for IoT "
        "solution, so threats against it and its devices raise no alert."
    )
    category = "posture"
    severity = Severity.MEDIUM
    exploitability = 1
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.SUBSCRIPTION]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.RESOURCES,
        AzureEvidence.IOT_SECURITY_SOLUTIONS,
    )
    estimated_effort_minutes = 45
    rationale = (
        "IoT devices are rarely patched and often reachable. Defender for IoT is what "
        "notices a device behaving unlike its twin, or a hub being enumerated."
    )
    remediation = (
        "Turn on Defender for IoT for each hub.\n\n"
        "Azure Portal: select the IoT hub > Defender for IoT > Overview > Secure your IoT "
        "solution."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=(
            "az security iot-solution create --solution-name <name> --resource-group <rg> "
            "--iot-hubs <iot-hub-id> --display-name <name> --location <region>",
        ),
        notes=(
            "No expected state: the check is whether each hub appears in some enabled "
            "solution, which is a relationship between two resources rather than a "
            "setting on one. No policy is generated either (DECISIONS.md section 170)."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = _MONITORING

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"IoT coverage unavailable: {failure}")
        hubs = resource.get("iot_hubs")
        watched = resource.get("iot_hubs_watched")
        if hubs is None:
            return RuleResult.unknown("The subscription's inventory was not read")
        if not hubs:
            return RuleResult.not_applicable("The subscription has no IoT hub")
        if watched is None:
            return RuleResult.unknown("Defender for IoT solutions were not read")
        unwatched = [hub for hub in hubs if hub.lower() not in set(watched)]
        evidence = {"iot_hubs": hubs, "unwatched": unwatched}
        if not unwatched:
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=f"{len(unwatched)} IoT hub(s) are watched by no Defender for IoT solution",
        )


RULES = (*(property_rule(spec) for spec in SPECS), AzureIotHubDefenderRule())
