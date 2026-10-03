"""What stands behind a SQL server beyond its network (DECISIONS.md section 176).

Whether Defender for SQL watches it, whose key protects its encryption, and
whether anything assesses it for vulnerabilities -- and, for the classic
storage-backed assessment, whether it scans on a schedule and tells anyone.

The express configuration of vulnerability assessment, the default since 2022,
scans weekly and keeps its own results, with notifications through Defender
for Cloud's contacts rather than per server. The catalogue's checks read only
the classic configuration and failed every express server; here express
passes the first question and the three classic-only questions do not apply
to it.
"""

from typing import Any, ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule
from app.rules.property import PropertySpec, property_rule

_VULNERABILITY = {
    "ISO_27001": ["A.8.8"],
    "NIST_CSF_2.0": ["ID.RA-01", "DE.CM-01"],
    "GDPR": ["32(1)(d)"],
    "NIST_800_53": ["RA-5"],
    "SOC2": ["CC7.1"],
    "PCI_DSS_4": ["11.3.1"],
}
_NO_POLICY = (
    "No policy is generated: the policy aliases for this have not been verified yet "
    "(DECISIONS.md section 170)."
)
_ASSESSMENT = (AzureEvidence.SQL_SERVERS, AzureEvidence.SQL_VULNERABILITY_ASSESSMENT)


def _assessed(mode: Any) -> bool:
    return str(mode or "").lower() in {"express", "classic"}


SPECS = (
    PropertySpec(
        rule_id="AZ-DB-017",
        name="SQL server encrypts with a service-managed key",
        description=(
            "The server's transparent data encryption is protected by a key Azure "
            "manages rather than one in the customer's vault."
        ),
        rationale=(
            "A customer-managed protector lets the customer make every database on the "
            "server unreadable by revoking one key, and some regulated data requires "
            "it. AZ-DB-006 asks whether each database is encrypted at all."
        ),
        remediation=(
            "Set a key from your vault as the server's TDE protector.\n\n"
            "Azure CLI:\n"
            "  az sql server key create --server <server> --resource-group <rg> \\\n"
            "    --kid <key-identifier>\n"
            "  az sql server tde-key set --server <server> --resource-group <rg> \\\n"
            "    --server-key-type AzureKeyVault --kid <key-identifier>"
        ),
        cli=(
            "az sql server tde-key set --server <server> --resource-group <rg> "
            "--server-key-type AzureKeyVault --kid <key-identifier>",
        ),
        severity=Severity.LOW,
        exploitability=0,
        category="database",
        resource_type=ResourceType.SQL_SERVER,
        evidence=(AzureEvidence.SQL_SERVERS, AzureEvidence.SQL_ENCRYPTION_PROTECTOR),
        field="tde_customer_managed_key",
        safe=True,
        describes="The TDE protector is a key in the customer's vault",
        failure="protects its encryption with a service-managed key",
        mappings={
            "ISO_27001": ["A.8.24"],
            "NIST_CSF_2.0": ["PR.DS-01"],
            "GDPR": ["32(1)(a)"],
            "NIST_800_53": ["SC-12", "SC-28"],
            "SOC2": ["CC6.1"],
            "PCI_DSS_4": ["3.5.1"],
        },
    ),
    PropertySpec(
        rule_id="AZ-DB-019",
        name="SQL server is not assessed for vulnerabilities",
        description=(
            "Neither the express nor the classic vulnerability assessment is on for "
            "this server, so nothing reports its misconfigurations, excessive "
            "permissions or unprotected sensitive data."
        ),
        rationale=(
            "Vulnerability assessment is the database's own view of itself: logins with "
            "more than they need, features that should be off, columns holding data "
            "nobody classified. Nothing outside the database can see those."
        ),
        remediation=(
            "Turn on vulnerability assessment with the express configuration.\n\n"
            "Azure Portal: select the server > Microsoft Defender for Cloud > "
            "Vulnerability assessment settings > Express configuration > Enable."
        ),
        cli=(
            "az rest --method PUT --url https://management.azure.com/<server-id>"
            "/sqlVulnerabilityAssessments/default?api-version=2023-08-01 "
            '--body \'{"properties":{"state":"Enabled"}}\'',
        ),
        severity=Severity.MEDIUM,
        exploitability=1,
        category="database",
        resource_type=ResourceType.SQL_SERVER,
        evidence=_ASSESSMENT,
        field="vulnerability_assessment",
        passes=_assessed,
        why_no_expected_state=(
            "Either of two configurations passes, so there is no one value to expect."
        ),
        describes="Vulnerability assessment is on, in the express or classic configuration",
        failure="is not assessed for vulnerabilities",
        mappings=_VULNERABILITY,
    ),
)


class AzureSqlDefenderRule(SecurityRule):
    """Defender for SQL watches the server, set on the server or by the plan.

    Either is enough: the subscription plan covers every server, and a server
    can have it switched on alone. Reading only the server's own setting, as the
    catalogue did, would fail every server a subscription-wide plan protects.
    """

    rule_id = "AZ-DB-018"
    name = "SQL server is not watched by Defender for SQL"
    description = (
        "Neither the subscription's Defender for Azure SQL plan nor the server's own "
        "setting turns on Defender for SQL, so SQL injection, brute force and "
        "anomalous access raise no alert."
    )
    category = "database"
    severity = Severity.MEDIUM
    exploitability = 1
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.SQL_SERVER]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.SQL_SERVERS,
        AzureEvidence.SQL_THREAT_DETECTION,
    )
    estimated_effort_minutes = 20
    rationale = (
        "Defender for SQL is what notices a query shaped like an injection or a login "
        "from somewhere this server has never seen. Without it those events happen in "
        "a database nobody is watching."
    )
    remediation = (
        "Turn on the Defender for Azure SQL plan for the subscription, or Defender for "
        "SQL on this server.\n\n"
        "Azure CLI:\n"
        "  az security pricing create --name SqlServers --tier Standard"
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(),
        cli=("az security pricing create --name SqlServers --tier Standard",),
        notes=(
            "No expected state: either of two settings -- the subscription's plan or the "
            f"server's own -- satisfies the check. {_NO_POLICY}"
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.8.16"],
        "NIST_CSF_2.0": ["DE.CM-01"],
        "GDPR": ["32(1)(d)"],
        "NIST_800_53": ["SI-4"],
        "SOC2": ["CC7.2"],
        "PCI_DSS_4": ["11.4.1"],
    }

    @staticmethod
    def _plan_on(context: RuleContext) -> bool | None:
        for subscription in context.get_resources_by_type(ResourceType.SUBSCRIPTION):
            plans = subscription.get("defender_plans")
            if plans is None:
                continue
            for plan in plans:
                if plan.get("name") == "SqlServers":
                    return str(plan.get("tier") or "").lower() == "standard"
            return False
        return None

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Defender for SQL settings unavailable: {failure}")
        own = resource.get("threat_detection_enabled")
        plan = (
            None
            if context.has_collection_error(AzureEvidence.DEFENDER_PLANS)
            else self._plan_on(context)
        )
        evidence = {"server_setting": own, "subscription_plan": plan}
        if own is True or plan is True:
            return RuleResult.passed(evidence)
        if own is None or plan is None:
            return RuleResult.unknown(
                "Defender for SQL could not be established from both the server and the plan"
            )
        return RuleResult.failed(
            evidence=evidence, message=f"{resource.name} is not watched by Defender for SQL"
        )


class _ClassicAssessmentRule(SecurityRule):
    """A question only the classic, storage-backed assessment has."""

    category = "database"
    exploitability = 1
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.SQL_SERVER]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = _ASSESSMENT
    compliance_mappings: ClassVar[dict[str, list[str]]] = _VULNERABILITY
    estimated_effort_minutes = 15

    def _classic(self, resource: CloudResource | None, context: RuleContext) -> RuleResult | None:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Vulnerability assessment unavailable: {failure}")
        mode = resource.get("vulnerability_assessment")
        if mode is None:
            return RuleResult.unknown("Vulnerability assessment was not read")
        if mode != "classic":
            # Express scans weekly and notifies through Defender's contacts; a
            # server with neither is AZ-DB-019's finding.
            return RuleResult.not_applicable(
                "The server does not use the classic vulnerability assessment"
            )
        return None


_CLASSIC_NOTES = (
    "No expected state: the setting applies only to the classic configuration, "
    f"which the express configuration replaces. {_NO_POLICY}"
)
_SCANS_CLI = (
    "az rest --method PUT --url https://management.azure.com/<server-id>"
    "/vulnerabilityAssessments/default?api-version=2021-11-01 --body @va-settings.json"
)


class AzureSqlRecurringScanRule(_ClassicAssessmentRule):
    rule_id = "AZ-DB-020"
    name = "SQL vulnerability assessment does not scan on a schedule"
    description = (
        "The server's classic vulnerability assessment has recurring scans off, so it "
        "reports only when somebody remembers to run it."
    )
    severity = Severity.LOW
    rationale = (
        "A database drifts -- a login added, a permission widened. A weekly scan "
        "catches the drift; a manual one catches whatever was true the day it ran."
    )
    remediation = (
        "Turn on recurring scans, or move the server to the express configuration, "
        "which scans weekly by design.\n\n"
        "Azure Portal: select the server > Microsoft Defender for Cloud > "
        "Vulnerability assessment settings > Periodic recurring scans: On > Save."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(), cli=(_SCANS_CLI,), notes=_CLASSIC_NOTES
    )

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        guard = self._classic(resource, context)
        if guard is not None:
            return guard
        assert resource is not None
        scans = resource.get("va_recurring_scans")
        if scans is True:
            return RuleResult.passed({"recurring_scans": True})
        return RuleResult.failed(
            evidence={"recurring_scans": scans},
            message=f"{resource.name}'s vulnerability assessment does not scan on a schedule",
        )


class AzureSqlScanReportsRule(_ClassicAssessmentRule):
    rule_id = "AZ-DB-021"
    name = "SQL vulnerability scan results are sent to nobody"
    description = (
        "The server's classic vulnerability assessment names no email recipient and "
        "does not notify subscription administrators, so its results wait unread in a "
        "storage container."
    )
    severity = Severity.LOW
    rationale = (
        "A scan result nobody receives changes nothing. Sending the summary somewhere "
        "is what turns a finding into a ticket."
    )
    remediation = (
        "Name recipients for scan reports, or notify subscription administrators.\n\n"
        "Azure Portal: select the server > Microsoft Defender for Cloud > "
        "Vulnerability assessment settings > Send scan reports to > Save."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(), cli=(_SCANS_CLI,), notes=_CLASSIC_NOTES
    )

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        guard = self._classic(resource, context)
        if guard is not None:
            return guard
        assert resource is not None
        emails = resource.get("va_scan_emails") or []
        admins = resource.get("va_email_admins") is True
        evidence = {"recipients": emails, "subscription_admins": admins}
        if emails or admins:
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name}'s vulnerability scan results are sent to nobody",
        )


class AzureSqlScanAdminNoticeRule(_ClassicAssessmentRule):
    rule_id = "AZ-DB-022"
    name = "SQL vulnerability scans do not notify subscription administrators"
    description = (
        "The server's classic vulnerability assessment has notifications to "
        "subscription administrators switched off."
    )
    severity = Severity.LOW
    rationale = (
        "Administrators can act on a result without asking for access, and the setting "
        "keeps reports flowing after a named recipient leaves."
    )
    remediation = (
        "Turn on notifications to subscription administrators.\n\n"
        "Azure Portal: select the server > Microsoft Defender for Cloud > "
        "Vulnerability assessment settings > Also send email notification to admins "
        "and subscription owners > Save."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(), cli=(_SCANS_CLI,), notes=_CLASSIC_NOTES
    )

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        guard = self._classic(resource, context)
        if guard is not None:
            return guard
        assert resource is not None
        if resource.get("va_email_admins") is True:
            return RuleResult.passed({"subscription_admins": True})
        return RuleResult.failed(
            evidence={"subscription_admins": False},
            message=f"{resource.name}'s vulnerability scans do not notify administrators",
        )


RULES = (
    *(property_rule(spec) for spec in SPECS),
    AzureSqlDefenderRule(),
    AzureSqlRecurringScanRule(),
    AzureSqlScanReportsRule(),
    AzureSqlScanAdminNoticeRule(),
)
