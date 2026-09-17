"""How a client proves who it is to a database, and what protects it on the way.

Three rules about the connection rather than the data. Reachability is
``public_access.py``'s question and encryption at rest is ``encryption.py``'s;
these are about what a database accepts once somebody can reach it.
"""

from typing import ClassVar

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import Comparison, ExpectedState, RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule


class AzureSqlTlsRule(SecurityRule):
    rule_id = "AZ-DB-007"
    name = "SQL server accepts TLS below 1.2"
    description = (
        "An Azure SQL server accepts connections negotiated with TLS 1.0 or 1.1, or "
        "enforces no minimum at all. The credentials a client sends and the rows it "
        "reads cross the network under a protocol with known downgrade attacks."
    )
    category = "database"
    severity = Severity.MEDIUM
    exploitability = 2
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.SQL_SERVER]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (AzureEvidence.SQL_SERVERS,)
    estimated_effort_minutes = 15
    rationale = (
        "Every supported SQL driver speaks TLS 1.2, so the floor exists only for clients "
        "nobody should still be running -- and for an attacker on the path who would "
        "rather they were. The login a SQL client sends is frequently an application "
        "credential that is never rotated."
    )
    remediation = (
        "Set the minimum TLS version to 1.2.\n\n"
        "Azure Portal: SQL server > Security > Networking > Connectivity > Minimum TLS "
        "version: 1.2 > Save.\n\n"
        "Azure CLI:\n"
        "  az sql server update --name <server> --resource-group <rg> "
        "--minimal-tls-version 1.2\n\n"
        "Clients still negotiating 1.0 or 1.1 are refused once this is set; the server's "
        "connection logs show whether any exist."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="minimal_tls_version",
                equals="1.2",
                also_accepts=("1.3",),
                describes="The server refuses TLS below 1.2",
                # Verified against the built-in definition "Azure SQL Database
                # should be running TLS version 1.2 or newer", which matches on it.
                arm_alias="Microsoft.Sql/servers/minimalTlsVersion",
                terraform_attribute="minimum_tls_version",
            ),
        ),
        cli=(
            "az sql server update --name <server> --resource-group <rg> "
            "--minimal-tls-version 1.2",
        ),
        policy_resource_type="Microsoft.Sql/servers",
        policy_effect="Audit",
    )
    # No CIS mapping: CIS Azure 2.0 has no control for SQL's minimum TLS version.
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "ISO_27001": ["A.8.24"],
        "NIST_CSF": ["PR.DS-2"],
        "GDPR": ["32(1)(a)"],
        "NIST_800_53": ["SC-8"],
        "SOC2": ["CC6.7"],
        "PCI_DSS_4": ["4.2.1"],
    }

    ACCEPTABLE: ClassVar[frozenset[str]] = frozenset({"1.2", "1.3"})

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Database configuration unavailable: {failure}")

        version = resource.get("minimal_tls_version")
        if version is None:
            # Absent from the listing, not "None". A server that enforces no
            # minimum says so with the string; one that says nothing has not
            # told this reading anything to judge.
            return RuleResult.unknown("Minimum TLS version missing from snapshot")

        evidence = {
            "minimal_tls_version": version,
            "public_network_access": resource.get("public_network_access"),
        }
        if str(version).strip() in self.ACCEPTABLE:
            return RuleResult.passed(evidence)
        shown = "no minimum" if str(version).strip().lower() == "none" else f"TLS {version}"
        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} accepts connections under {shown}",
        )


class AzureSqlEntraAdminRule(SecurityRule):
    rule_id = "AZ-DB-008"
    name = "SQL server has no Entra administrator"
    description = (
        "An Azure SQL server has no Microsoft Entra administrator, so the only way to "
        "administer it is the SQL login it was created with -- a password with no "
        "second factor, no Conditional Access and no central way to revoke it."
    )
    category = "database"
    severity = Severity.MEDIUM
    # A credential still has to be obtained, and it is the kind that gets
    # sprayed: a SQL login is a name and a password on a public endpoint.
    exploitability = 3
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.SQL_SERVER]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.SQL_SERVERS,
        AzureEvidence.SQL_ADMINISTRATORS,
    )
    estimated_effort_minutes = 30
    rationale = (
        "Entra authentication is what lets a database inherit the identity controls "
        "the rest of the tenant already has: MFA, Conditional Access, and an account "
        "that is disabled when the person leaves. A server with no Entra administrator "
        "has none of them, and its server admin login outlives every person who has "
        "ever known the password."
    )
    remediation = (
        "Set an Entra group as the server's administrator, move people to Entra logins, "
        "then consider Microsoft Entra-only authentication.\n\n"
        "Azure Portal: SQL server > Settings > Microsoft Entra ID > Set admin > choose a "
        "group > Save.\n\n"
        "Azure CLI:\n"
        "  az sql server ad-admin create --server-name <server> --resource-group <rg> \\\n"
        "    --display-name <group-name> --object-id <group-object-id>\n\n"
        "A group rather than a person, so the administrator survives a leaver."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="entra_administrators",
                comparison=Comparison.NOT_EMPTY,
                equals=None,
                describes="The server has a Microsoft Entra administrator",
                example={
                    "login": "sql-administrators",
                    "administrator_type": "ActiveDirectory",
                    "entra_only": False,
                },
            ),
        ),
        cli=(
            "az sql server ad-admin create --server-name <server> --resource-group <rg> "
            "--display-name <group-name> --object-id <group-object-id>",
        ),
        notes=(
            "No policy is generated. The administrator is a child resource of the "
            "server rather than a property on it, so the only policy that could "
            "express this is an existence condition whose form has not been verified "
            "against a real deployment from here."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["4.1.4"],
        "ISO_27001": ["A.5.16", "A.5.17", "A.8.2"],
        "NIST_CSF": ["PR.AC-1", "PR.AC-7"],
        "GDPR": ["32(1)(b)"],
        "NIST_800_53": ["IA-2", "AC-2"],
        "SOC2": ["CC6.1", "CC6.2"],
        "PCI_DSS_4": ["8.4.2", "8.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Database configuration unavailable: {failure}")

        administrators = resource.get("entra_administrators")
        if administrators is None:
            return RuleResult.unknown(
                "The server's Entra administrator could not be read. If this persists, "
                "the deployed scanner role may predate the permission that reads it."
            )

        evidence = {
            "entra_administrators": administrators,
            "server_admin_login": resource.get("administrator_login"),
            "entra_only": any(a.get("entra_only") is True for a in administrators),
        }
        if administrators:
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=(
                f"{resource.name} has no Entra administrator and is administered only "
                "through its SQL login"
            ),
        )


class AzurePostgresTlsRule(SecurityRule):
    rule_id = "AZ-DB-009"
    name = "PostgreSQL server accepts connections without TLS"
    description = (
        "An Azure Database for PostgreSQL flexible server has require_secure_transport "
        "turned off, so a client may connect in plain text and send its password and "
        "every query unencrypted."
    )
    category = "database"
    severity = Severity.HIGH
    # Plain text on the wire, with the credential in it. A position on the path
    # is still needed, which is what keeps this from being higher.
    exploitability = 3
    applies_to: ClassVar[list[ResourceType]] = [ResourceType.POSTGRESQL_SERVER]
    requires_evidence: ClassVar[tuple[AzureEvidence, ...]] = (
        AzureEvidence.POSTGRESQL_SERVERS,
        AzureEvidence.POSTGRESQL_CONFIGURATIONS,
    )
    estimated_effort_minutes = 15
    rationale = (
        "The parameter is on by default, so a server with it off is one somebody "
        "turned off -- usually to get an old client connecting -- and the password that "
        "client sends is now readable by anything on the path."
    )
    remediation = (
        "Turn require_secure_transport back on.\n\n"
        "Azure Portal: PostgreSQL flexible server > Settings > Server parameters > "
        "require_secure_transport: ON > Save.\n\n"
        "Azure CLI:\n"
        "  az postgres flexible-server parameter set --resource-group <rg> \\\n"
        "    --server-name <server> --name require_secure_transport --value on\n\n"
        "Clients connecting without TLS are refused afterwards; set sslmode=require "
        "(or verify-full) in their connection strings first."
    )
    remediation_spec: ClassVar[RemediationSpec | None] = RemediationSpec(
        expected=(
            ExpectedState(
                field="require_secure_transport",
                equals="on",
                describes="The server refuses connections that do not use TLS",
            ),
        ),
        cli=(
            "az postgres flexible-server parameter set --resource-group <rg> "
            "--server-name <server> --name require_secure_transport --value on",
        ),
        notes=(
            "No policy is generated. A server parameter is a child resource with its "
            "own value, not a property Azure Policy reads from the server."
        ),
    )
    compliance_mappings: ClassVar[dict[str, list[str]]] = {
        "CIS_AZURE_2.0": ["4.3.1"],
        "ISO_27001": ["A.8.24"],
        "NIST_CSF": ["PR.DS-2"],
        "GDPR": ["32(1)(a)"],
        "NIST_800_53": ["SC-8"],
        "SOC2": ["CC6.7"],
        "PCI_DSS_4": ["4.2.1"],
    }

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")

        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Database configuration unavailable: {failure}")

        value = resource.get("require_secure_transport")
        if value is None:
            return RuleResult.unknown(
                "The server's require_secure_transport parameter could not be read. If "
                "this persists, the deployed scanner role may predate the permission "
                "that reads it."
            )

        evidence = {
            "require_secure_transport": value,
            "public_network_access": resource.get("public_network_access"),
        }
        if str(value).lower() == "on":
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} accepts PostgreSQL connections without TLS",
        )
