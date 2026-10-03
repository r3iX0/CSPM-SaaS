"""The framework catalogue -- what the control identifiers on rules mean.

Rules already carry framework references (``rules.compliance_mappings``), but a
reference is only half of a mapping: ``A.8.20`` tells a user nothing on its own.
This module is the other half, and it is **data, not logic**. Nothing here
branches on a framework, and no rule ever imports it -- which is what keeps
PRODUCT_SPEC.md requirement 15 true while still being able to render a coverage
page.

Three deliberate choices, each of which changes what the coverage number means:

**Control titles are CloudGuard's own words.** CIS Benchmarks and ISO/IEC 27001
are copyrighted works under licences that restrict redistribution of their text;
GDPR is public law but is quoted in summary here for consistency. So every title
below is a short descriptor written for this product, not the official wording.
The identifiers are the durable part -- follow ``url`` for authoritative text.

**Uncovered areas are in the catalogue on purpose.** A catalogue containing only
the controls CloudGuard happens to check would report 100% coverage forever,
which is worse than reporting nothing. Entries a rule cannot reach are listed
too, and resolve to NOT_COVERED.

**Gaps are listed at whatever resolution is honest.** Where a benchmark's own
index is to hand, every leaf is listed; where it is not, a whole unchecked area is
listed by its section number rather than by leaf numbers invented to mark it
absent. A wrong control number in a compliance view is worse than a coarse one --
which is what the CIS Azure catalogue turned out to be holding, and why it was
rebuilt from the published index (DECISIONS.md section 89).

None of this produces a compliance claim. It produces evidence, mapped to a
requirement, attributed to a framework -- the chain in ROADMAP.md, no further.
"""

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.core.enums import Provider

# Frameworks kept as data rather than written out below: the current CIS
# benchmarks, AWS FSBP, NIS2, HIPAA and ATT&CK (DECISIONS.md section 168).
FRAMEWORKS_PATH = Path(__file__).resolve().parent / "data" / "frameworks.json"

# The standards a customer is audited against by name -- ISO 27001, SOC 2, PCI DSS,
# NIST CSF 2.0, CIS Controls v8.1, CSA CCM v4.1, NIST 800-171 and DORA -- kept as data
# because each is listed in full (DECISIONS.md sections 209 and 210). Each entry carries
# its own summary and scope note, which the six above do not.
STANDARDS_PATH = Path(__file__).resolve().parent / "data" / "standards.json"


@dataclass(frozen=True)
class Control:
    """One requirement a rule can produce evidence toward."""

    id: str
    title: str
    group: str
    # False where the requirement is organizational, procedural or physical --
    # something no scanner can observe. Kept distinct from "not covered yet":
    # one is a backlog item, the other never will be, and a user deciding where
    # to spend effort needs to know which is which.
    technically_assessable: bool = True


@dataclass(frozen=True)
class Framework:
    id: str
    name: str
    short_name: str
    version: str
    authority: str
    url: str
    summary: str
    # What subset of the published framework this catalogue represents. Shown
    # in the UI verbatim, because a coverage percentage against an unstated
    # denominator is a number that misleads.
    scope_note: str
    controls: tuple[Control, ...]
    # Which cloud this framework is about, where it is about one. ``None`` for
    # ISO, GDPR, NIST, SOC 2 and PCI, which are written about organizations
    # rather than about providers and apply whatever a customer runs.
    #
    # It exists to stop a misleading number. An AWS-only tenant measured against
    # CIS Azure would report near-zero coverage for reasons that have nothing to
    # do with its security posture, which is the same class of overclaim the
    # coverage ledger was built to prevent -- pointed the other way
    # (MULTI_CLOUD.md section 7).
    provider: Provider | None = None

    def control(self, control_id: str) -> Control | None:
        return next((c for c in self.controls if c.id == control_id), None)


CIS_AZURE = Framework(
    provider=Provider.AZURE,
    id="CIS_AZURE_2.0",
    name="CIS Microsoft Azure Foundations Benchmark",
    short_name="CIS Azure",
    version="2.0.0",
    authority="Center for Internet Security",
    url="https://www.cisecurity.org/benchmark/azure",
    summary=(
        "Consensus-built configuration baseline for Azure subscriptions. The "
        "closest thing this product has to a peer: prescriptive, technical, and "
        "checkable without interviewing anybody."
    ),
    scope_note=(
        "Every recommendation in the published benchmark, leaf by leaf. Controls "
        "without a Cleave check behind them are listed so the gap is visible "
        "rather than absent, and the few that describe a review process rather "
        "than a setting are marked as beyond what a scanner can observe."
    ),
    # Rebuilt from the benchmark's own index in DECISIONS.md section 89. The
    # earlier catalogue listed nineteen entries, several of them whole sections
    # ("8", "9"), and cited leaf numbers that name different controls in 2.0 --
    # 1.21 is Microsoft 365 group creation, not subscription administrators, and
    # 6.5 is flow log retention, not unrestricted inbound rules. Titles remain
    # CloudGuard's own wording; the identifiers are the benchmark's.
    controls=(
        # 1 -- Identity and Access Management
        Control(
            "1.1.1",
            "Security defaults enabled on the directory",
            "Identity and Access Management",
        ),
        Control(
            "1.1.2",
            "Multi-factor authentication required for privileged users",
            "Identity and Access Management",
        ),
        Control(
            "1.1.3",
            "Multi-factor authentication required for non-privileged users",
            "Identity and Access Management",
        ),
        Control(
            "1.1.4",
            "Users cannot skip MFA by remembering a trusted device",
            "Identity and Access Management",
        ),
        Control(
            "1.2.1",
            "Trusted locations defined for Conditional Access",
            "Identity and Access Management",
        ),
        Control("1.2.2", "Geographic access policy considered", "Identity and Access Management"),
        Control(
            "1.2.3",
            "Conditional Access requires MFA for administrative groups",
            "Identity and Access Management",
        ),
        Control(
            "1.2.4",
            "Conditional Access requires MFA for all users",
            "Identity and Access Management",
        ),
        Control("1.2.5", "MFA required for risky sign-ins", "Identity and Access Management"),
        Control("1.2.6", "MFA required for Azure management", "Identity and Access Management"),
        Control("1.3", "Users cannot create new tenants", "Identity and Access Management"),
        Control(
            "1.4",
            "Access reviews set up for external users with privileged roles",
            "Identity and Access Management",
        ),
        Control(
            "1.5",
            "Guest users reviewed on a regular basis",
            "Identity and Access Management",
            technically_assessable=False,
        ),
        Control("1.6", "Password reset requires two methods", "Identity and Access Management"),
        Control("1.7", "Custom banned-password list enforced", "Identity and Access Management"),
        Control(
            "1.8",
            "Users re-confirm authentication information periodically",
            "Identity and Access Management",
        ),
        Control("1.9", "Users notified of password resets", "Identity and Access Management"),
        Control(
            "1.10",
            "Administrators notified when another administrator resets a password",
            "Identity and Access Management",
        ),
        Control("1.11", "Users cannot consent to applications", "Identity and Access Management"),
        Control(
            "1.12",
            "User consent limited to verified publishers",
            "Identity and Access Management",
        ),
        Control(
            "1.13",
            "Users cannot add gallery apps to My Apps",
            "Identity and Access Management",
        ),
        Control("1.14", "Users cannot register applications", "Identity and Access Management"),
        Control(
            "1.15",
            "Guest access restricted to their own directory objects",
            "Identity and Access Management",
        ),
        Control(
            "1.16",
            "Guest invitations limited to specific administrator roles",
            "Identity and Access Management",
        ),
        Control(
            "1.17",
            "Entra administration portal restricted to administrators",
            "Identity and Access Management",
        ),
        Control(
            "1.18",
            "Group features in the access pane restricted",
            "Identity and Access Management",
        ),
        Control("1.19", "Users cannot create security groups", "Identity and Access Management"),
        Control(
            "1.20",
            "Group owners cannot manage membership requests in the access pane",
            "Identity and Access Management",
        ),
        Control(
            "1.21",
            "Users cannot create Microsoft 365 groups",
            "Identity and Access Management",
        ),
        Control(
            "1.22",
            "MFA required to register or join devices",
            "Identity and Access Management",
        ),
        Control(
            "1.23",
            "No custom subscription administrator roles",
            "Identity and Access Management",
        ),
        Control(
            "1.24",
            "A custom role administers resource locks",
            "Identity and Access Management",
        ),
        Control(
            "1.25",
            "Subscriptions cannot enter or leave the directory freely",
            "Identity and Access Management",
        ),
        # 2 -- Microsoft Defender for Cloud
        Control("2.1.1", "Defender for Servers on", "Microsoft Defender for Cloud"),
        Control("2.1.2", "Defender for App Service on", "Microsoft Defender for Cloud"),
        Control("2.1.3", "Defender for Databases on", "Microsoft Defender for Cloud"),
        Control("2.1.4", "Defender for Azure SQL databases on", "Microsoft Defender for Cloud"),
        Control("2.1.5", "Defender for SQL servers on machines on", "Microsoft Defender for Cloud"),
        Control(
            "2.1.6",
            "Defender for open-source relational databases on",
            "Microsoft Defender for Cloud",
        ),
        Control("2.1.7", "Defender for Storage on", "Microsoft Defender for Cloud"),
        Control("2.1.8", "Defender for Containers on", "Microsoft Defender for Cloud"),
        Control("2.1.9", "Defender for Azure Cosmos DB on", "Microsoft Defender for Cloud"),
        Control("2.1.10", "Defender for Key Vault on", "Microsoft Defender for Cloud"),
        Control("2.1.11", "Defender for DNS on", "Microsoft Defender for Cloud"),
        Control("2.1.12", "Defender for Resource Manager on", "Microsoft Defender for Cloud"),
        Control(
            "2.1.13",
            "System updates applied where Defender recommends them",
            "Microsoft Defender for Cloud",
        ),
        Control(
            "2.1.14",
            "Default Defender policy settings not disabled",
            "Microsoft Defender for Cloud",
        ),
        Control(
            "2.1.15",
            "Log Analytics agent auto-provisioned to virtual machines",
            "Microsoft Defender for Cloud",
        ),
        Control(
            "2.1.16",
            "Vulnerability assessment auto-provisioned to machines",
            "Microsoft Defender for Cloud",
        ),
        Control(
            "2.1.17",
            "Defender for Containers components auto-provisioned",
            "Microsoft Defender for Cloud",
        ),
        Control(
            "2.1.18",
            "Subscription owners receive security alert email",
            "Microsoft Defender for Cloud",
        ),
        Control(
            "2.1.19",
            "A security contact email address is configured",
            "Microsoft Defender for Cloud",
        ),
        Control(
            "2.1.20",
            "Notifications sent for high-severity alerts",
            "Microsoft Defender for Cloud",
        ),
        Control(
            "2.1.21",
            "Defender for Cloud Apps integration enabled",
            "Microsoft Defender for Cloud",
        ),
        Control(
            "2.1.22",
            "Defender for Endpoint integration enabled",
            "Microsoft Defender for Cloud",
        ),
        Control("2.2.1", "Defender for IoT Hub on", "Microsoft Defender for Cloud"),
        # 3 -- Storage Accounts
        Control("3.1", "Secure transfer required on storage accounts", "Storage Accounts"),
        Control("3.2", "Infrastructure encryption enabled on storage accounts", "Storage Accounts"),
        Control("3.3", "Key rotation reminders enabled on storage accounts", "Storage Accounts"),
        Control("3.4", "Storage account access keys regenerated periodically", "Storage Accounts"),
        Control("3.5", "Queue service logs reads, writes and deletes", "Storage Accounts"),
        Control(
            "3.6",
            "Shared access signatures expire within an hour",
            "Storage Accounts",
            technically_assessable=False,
        ),
        Control("3.7", "Public blob access disabled", "Storage Accounts"),
        Control("3.8", "Storage account network access denied by default", "Storage Accounts"),
        Control(
            "3.9",
            "Trusted Azure services allowed through the storage firewall",
            "Storage Accounts",
        ),
        Control("3.10", "Private endpoints used to reach storage accounts", "Storage Accounts"),
        Control("3.11", "Soft delete enabled for blobs and containers", "Storage Accounts"),
        Control(
            "3.12",
            "Storage for critical data encrypted with customer-managed keys",
            "Storage Accounts",
        ),
        Control("3.13", "Blob service logs reads, writes and deletes", "Storage Accounts"),
        Control("3.14", "Table service logs reads, writes and deletes", "Storage Accounts"),
        Control("3.15", "Minimum TLS version 1.2 on storage accounts", "Storage Accounts"),
        # 4 -- Database Services
        Control("4.1.1", "Auditing on for SQL servers", "Database Services"),
        Control("4.1.2", "No SQL firewall rule admits every address", "Database Services"),
        Control("4.1.3", "SQL TDE protector is a customer-managed key", "Database Services"),
        Control("4.1.4", "SQL servers have an Entra administrator", "Database Services"),
        Control("4.1.5", "Data encryption on for SQL databases", "Database Services"),
        Control("4.1.6", "SQL auditing retained for more than 90 days", "Database Services"),
        Control("4.2.1", "Defender for SQL on for critical SQL servers", "Database Services"),
        Control("4.2.2", "SQL vulnerability assessment stores its results", "Database Services"),
        Control("4.2.3", "SQL vulnerability assessment runs recurring scans", "Database Services"),
        Control("4.2.4", "SQL vulnerability assessment sends its reports", "Database Services"),
        Control(
            "4.2.5",
            "SQL vulnerability assessment notifies administrators",
            "Database Services",
        ),
        Control("4.3.1", "PostgreSQL requires TLS connections", "Database Services"),
        Control("4.3.2", "PostgreSQL logs checkpoints", "Database Services"),
        Control("4.3.3", "PostgreSQL logs connections", "Database Services"),
        Control("4.3.4", "PostgreSQL logs disconnections", "Database Services"),
        Control("4.3.5", "PostgreSQL connection throttling on", "Database Services"),
        Control("4.3.6", "PostgreSQL logs retained for more than three days", "Database Services"),
        Control("4.3.7", "PostgreSQL does not admit all Azure services", "Database Services"),
        Control("4.3.8", "PostgreSQL infrastructure double encryption on", "Database Services"),
        Control("4.4.1", "MySQL requires TLS connections", "Database Services"),
        Control("4.4.2", "MySQL flexible server requires TLS 1.2", "Database Services"),
        Control("4.4.3", "MySQL audit logging on", "Database Services"),
        Control("4.4.4", "MySQL audit log records connections", "Database Services"),
        Control("4.5.1", "Cosmos DB reachable only from selected networks", "Database Services"),
        Control("4.5.2", "Cosmos DB reached through private endpoints", "Database Services"),
        Control("4.5.3", "Cosmos DB uses Entra authentication and RBAC", "Database Services"),
        # 5 -- Logging and Monitoring
        Control("5.1.1", "A subscription diagnostic setting exists", "Logging and Monitoring"),
        Control(
            "5.1.2",
            "Subscription diagnostic setting captures the right categories",
            "Logging and Monitoring",
        ),
        Control("5.1.3", "Activity log storage container is not public", "Logging and Monitoring"),
        Control(
            "5.1.4",
            "Activity log storage account encrypted with a customer-managed key",
            "Logging and Monitoring",
        ),
        Control("5.1.5", "Key vault logging enabled", "Logging and Monitoring"),
        Control(
            "5.1.6",
            "Network security group flow logs sent to Log Analytics",
            "Logging and Monitoring",
        ),
        Control("5.1.7", "App Service HTTP logs enabled", "Logging and Monitoring"),
        Control("5.2.1", "Alert on policy assignment creation", "Logging and Monitoring"),
        Control("5.2.2", "Alert on policy assignment deletion", "Logging and Monitoring"),
        Control("5.2.3", "Alert on network security group changes", "Logging and Monitoring"),
        Control("5.2.4", "Alert on network security group deletion", "Logging and Monitoring"),
        Control("5.2.5", "Alert on security solution changes", "Logging and Monitoring"),
        Control("5.2.6", "Alert on security solution deletion", "Logging and Monitoring"),
        Control("5.2.7", "Alert on SQL firewall rule changes", "Logging and Monitoring"),
        Control("5.2.8", "Alert on SQL firewall rule deletion", "Logging and Monitoring"),
        Control("5.2.9", "Alert on public IP address changes", "Logging and Monitoring"),
        Control("5.2.10", "Alert on public IP address deletion", "Logging and Monitoring"),
        Control("5.3.1", "Application Insights configured", "Logging and Monitoring"),
        Control(
            "5.4",
            "Resource logs enabled for every service that supports them",
            "Logging and Monitoring",
        ),
        Control(
            "5.5",
            "Monitored workloads not on Basic or Consumption SKUs",
            "Logging and Monitoring",
        ),
        # 6 -- Networking
        Control("6.1", "RDP not reachable from the internet", "Networking"),
        Control("6.2", "SSH not reachable from the internet", "Networking"),
        Control("6.3", "UDP not reachable from the internet", "Networking"),
        Control("6.4", "HTTP and HTTPS exposure to the internet reviewed", "Networking"),
        Control("6.5", "Flow logs retained for more than 90 days", "Networking"),
        Control("6.6", "Network Watcher enabled", "Networking"),
        Control(
            "6.7",
            "Public IP addresses reviewed periodically",
            "Networking",
            technically_assessable=False,
        ),
        # 7 -- Virtual Machines
        Control("7.1", "An Azure Bastion host exists", "Virtual Machines"),
        Control("7.2", "Virtual machines use managed disks", "Virtual Machines"),
        Control(
            "7.3",
            "OS and data disks encrypted with customer-managed keys",
            "Virtual Machines",
        ),
        Control("7.4", "Unattached disks encrypted with customer-managed keys", "Virtual Machines"),
        Control(
            "7.5",
            "Only approved extensions installed",
            "Virtual Machines",
            technically_assessable=False,
        ),
        Control("7.6", "Endpoint protection installed on virtual machines", "Virtual Machines"),
        Control("7.7", "Legacy VHDs encrypted", "Virtual Machines"),
        # 8 -- Key Vault
        Control("8.1", "Keys in RBAC vaults have an expiry date", "Key Vault"),
        Control("8.2", "Keys in access-policy vaults have an expiry date", "Key Vault"),
        Control("8.3", "Secrets in RBAC vaults have an expiry date", "Key Vault"),
        Control("8.4", "Secrets in access-policy vaults have an expiry date", "Key Vault"),
        Control("8.5", "Key vaults are recoverable", "Key Vault"),
        Control("8.6", "Key vaults use Azure RBAC", "Key Vault"),
        Control("8.7", "Key vaults reached through private endpoints", "Key Vault"),
        Control("8.8", "Automatic key rotation enabled", "Key Vault"),
        # 9 -- AppService
        Control("9.1", "App Service authentication set up", "AppService"),
        Control("9.2", "Web apps redirect HTTP to HTTPS", "AppService"),
        Control("9.3", "Web apps use a current TLS version", "AppService"),
        Control("9.4", "Web apps require client certificates", "AppService"),
        Control("9.5", "Web apps run as a managed identity", "AppService"),
        Control("9.6", "PHP version current where used", "AppService"),
        Control("9.7", "Python version current where used", "AppService"),
        Control("9.8", "Java version current where used", "AppService"),
        Control("9.9", "HTTP version current", "AppService"),
        Control("9.10", "FTP deployments disabled", "AppService"),
        Control("9.11", "Key vaults hold application secrets", "AppService"),
        # 10 -- Miscellaneous
        Control("10.1", "Resource locks on mission-critical resources", "Miscellaneous"),
    ),
)


GDPR = Framework(
    id="GDPR",
    name="General Data Protection Regulation",
    short_name="GDPR",
    version="Regulation (EU) 2016/679",
    authority="European Union",
    url="https://eur-lex.europa.eu/eli/reg/2016/679/oj",
    summary=(
        "A law, not a control framework. Article 32 requires security measures "
        "appropriate to the risk, and that is the only place a scanner can "
        "contribute — as evidence a controller cites, never as a verdict."
    ),
    scope_note=(
        "Only the articles with a technical-measures component. A green result "
        "here means specific misconfigurations were absent at the last scan. It "
        "is not, and cannot be, a statement about lawful processing."
    ),
    controls=(
        Control("5(1)(f)", "Integrity and confidentiality of personal data", "Principles"),
        Control("5(2)", "Accountability — demonstrating compliance", "Principles"),
        Control(
            "17",
            "Right to erasure",
            "Data subject rights",
            technically_assessable=False,
        ),
        Control("25", "Data protection by design and by default", "Controller obligations"),
        Control(
            "30",
            "Records of processing activities",
            "Controller obligations",
            technically_assessable=False,
        ),
        Control(
            "32(1)(a)", "Pseudonymisation and encryption of personal data", "Security of processing"
        ),
        Control(
            "32(1)(b)",
            "Ongoing confidentiality, integrity and availability",
            "Security of processing",
        ),
        Control("32(1)(c)", "Restoring availability after an incident", "Security of processing"),
        Control("32(1)(d)", "Regular testing and evaluation of measures", "Security of processing"),
        Control("33", "Notifying a personal data breach", "Breach obligations"),
        Control(
            "44",
            "General principle for international transfers",
            "Transfers",
            technically_assessable=False,
        ),
    ),
)


NIST_800_53 = Framework(
    id="NIST_800_53",
    name="NIST SP 800-53 Rev. 5",
    short_name="NIST 800-53",
    version="Rev. 5",
    authority="National Institute of Standards and Technology",
    url="https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final",
    summary=(
        "The control catalogue US federal systems are assessed against, and the "
        "one FedRAMP and CMMC are built on. Prescriptive where CSF is "
        "outcome-based, which is why an organization reporting against both "
        "needs them listed separately."
    ),
    scope_note=(
        "The technical controls in the AC, AU, CM, IA, SC and SI families that "
        "an Azure configuration reading can speak to. The publication holds "
        "over a thousand controls across twenty families; the personnel, "
        "training, incident response and physical families are absent because "
        "no scanner can observe them, and the families below are represented by "
        "their base controls rather than their enhancements."
    ),
    controls=(
        # --- Access Control -------------------------------------------------
        Control("AC-2", "Accounts are managed through their lifecycle", "Access Control"),
        Control("AC-3", "Access is enforced against an approved authorization", "Access Control"),
        Control("AC-6", "Privilege is held only where the work requires it", "Access Control"),
        Control("AC-17", "Remote access is authorized and controlled", "Access Control"),
        # --- Audit and Accountability ---------------------------------------
        Control("AU-2", "The events worth recording are decided and recorded", "Audit"),
        Control(
            "AU-6",
            "Audit records are reviewed for indications of harm",
            "Audit",
            technically_assessable=False,
        ),
        Control("AU-9", "Audit records are protected from alteration and loss", "Audit"),
        Control("AU-11", "Audit records are retained long enough to investigate", "Audit"),
        # --- Configuration Management ---------------------------------------
        Control("CM-6", "Systems run the configuration settings that were agreed", "Configuration"),
        Control(
            "CM-7",
            "Only the functions and ports the system needs are enabled",
            "Configuration",
        ),
        # --- Contingency Planning -------------------------------------------
        Control("CP-9", "System state is backed up and recoverable", "Contingency"),
        # --- Identification and Authentication ------------------------------
        Control("IA-2", "Users are uniquely identified and authenticated", "Identification"),
        Control("IA-5", "Authenticators are issued, protected and rotated", "Identification"),
        # --- Risk Assessment ------------------------------------------------
        Control("RA-5", "Systems are monitored for known vulnerabilities", "Risk Assessment"),
        # --- System and Communications Protection ---------------------------
        Control("SC-7", "Traffic at the system boundary is controlled", "System Protection"),
        Control("SC-8", "Information in transit is protected", "System Protection"),
        Control("SC-12", "Cryptographic keys are established and managed", "System Protection"),
        Control("SC-28", "Information at rest is protected", "System Protection"),
        # --- System and Information Integrity -------------------------------
        Control("SI-2", "Flaws are identified, reported and corrected", "System Integrity"),
        Control("SI-4", "The system is monitored for attacks and indicators", "System Integrity"),
        # --- Families no configuration reading can reach --------------------
        # Listed rather than omitted, for the reason at the top of this file: a
        # catalogue of only what CloudGuard checks would report full coverage
        # for ever. These are the families an assessor will ask about and this
        # product will never answer.
        Control(
            "AT-2",
            "People are trained on the risks their work carries",
            "Awareness",
            technically_assessable=False,
        ),
        Control(
            "IR-4",
            "Incidents are handled from detection to recovery",
            "Incident Response",
            technically_assessable=False,
        ),
        Control(
            "PS-4",
            "Access is removed when someone leaves",
            "Personnel",
            technically_assessable=False,
        ),
        Control(
            "PE-3",
            "Physical access to the facility is controlled",
            "Physical",
            technically_assessable=False,
        ),
    ),
)


CIS_AWS = Framework(
    provider=Provider.AWS,
    id="CIS_AWS_3.0",
    name="CIS Amazon Web Services Foundations Benchmark",
    short_name="CIS AWS",
    version="3.0.0",
    authority="Center for Internet Security",
    url="https://www.cisecurity.org/benchmark/amazon_web_services",
    summary=(
        "The AWS sibling of the Azure benchmark, and the same kind of document: "
        "prescriptive, technical, and checkable without interviewing anybody."
    ),
    scope_note=(
        "A subset of the published benchmark: the controls a read-only posture "
        "scanner could reach, plus the account-level ones it cannot. Controls "
        "listed without a Cleave check behind them are shown so the gap is "
        "visible rather than absent -- a catalogue of only what this product "
        "checks would report full coverage for ever, which is the same class of "
        "misleading number the coverage ledger exists to prevent."
    ),
    controls=(
        # 1 -- Identity and Access Management
        Control(
            "1.1",
            "Current contact details are maintained",
            "Identity and Access Management",
            technically_assessable=False,
        ),
        Control(
            "1.2",
            "Security contact information is registered",
            "Identity and Access Management",
            technically_assessable=False,
        ),
        Control(
            "1.3",
            "Security questions are registered in the account",
            "Identity and Access Management",
            technically_assessable=False,
        ),
        Control("1.4", "No root user access key exists", "Identity and Access Management"),
        Control(
            "1.5",
            "MFA is enabled for the root user",
            "Identity and Access Management",
        ),
        Control(
            "1.6",
            "Hardware MFA is enabled for the root user",
            "Identity and Access Management",
        ),
        Control(
            "1.7",
            "The root user is not used for day-to-day tasks",
            "Identity and Access Management",
        ),
        Control(
            "1.8",
            "IAM password policy requires a minimum length of 14",
            "Identity and Access Management",
        ),
        Control(
            "1.9",
            "IAM password policy prevents password reuse",
            "Identity and Access Management",
        ),
        Control(
            "1.10",
            "MFA is enabled for all IAM users with a console password",
            "Identity and Access Management",
        ),
        Control(
            "1.12",
            "Credentials unused for 45 days or more are disabled",
            "Identity and Access Management",
        ),
        Control(
            "1.14",
            "Access keys are rotated every 90 days or less",
            "Identity and Access Management",
        ),
        Control(
            "1.13",
            "Only one active access key exists per IAM user",
            "Identity and Access Management",
        ),
        Control(
            "1.15",
            "IAM users receive permissions only through groups",
            "Identity and Access Management",
        ),
        Control(
            "1.16",
            "IAM policies that allow full administrative privileges are not attached",
            "Identity and Access Management",
        ),
        Control(
            "1.17",
            "A support role exists to manage incidents with AWS Support",
            "Identity and Access Management",
        ),
        Control(
            "1.18",
            "EC2 instances use IAM roles rather than stored credentials",
            "Identity and Access Management",
        ),
        Control(
            "1.19",
            "Expired TLS certificates are removed from IAM",
            "Identity and Access Management",
        ),
        Control(
            "1.20",
            "IAM Access Analyzer is enabled in every region",
            "Identity and Access Management",
        ),
        # 2 -- Storage
        # Numbered as 3.0 numbers them. These three were listed under 1.x's
        # numbering -- encryption at 2.1.1, HTTPS at 2.1.2 -- until the
        # crosswalk against Prowler's CIS 3.0 index put the two engines' answers
        # side by side (DECISIONS.md section 150). 3.0 dropped the encryption
        # control: S3 has encrypted every new object by default since 2023.
        Control(
            "2.1.1",
            "S3 bucket policies deny requests that are not over HTTPS",
            "Storage",
        ),
        Control("2.1.2", "S3 buckets require MFA to delete object versions", "Storage"),
        Control(
            "2.1.3",
            "Data held in S3 is discovered and classified",
            "Storage",
        ),
        Control("2.1.4", "S3 buckets block public access", "Storage"),
        Control("2.2.1", "EBS volumes are encrypted by default", "Storage"),
        Control("2.3.1", "RDS instances encrypt their storage at rest", "Storage"),
        Control("2.3.2", "RDS instances have auto minor version upgrade on", "Storage"),
        Control("2.3.3", "RDS instances are not publicly accessible", "Storage"),
        Control(
            "2.4.1",
            "EFS file systems encrypt data at rest",
            "Storage",
        ),
        # 3 -- Logging
        Control("3.1", "CloudTrail is enabled in all regions", "Logging"),
        Control("3.2", "CloudTrail log file validation is enabled", "Logging"),
        Control("3.3", "AWS Config is enabled in all regions", "Logging"),
        Control("3.4", "S3 bucket access logging is enabled on the CloudTrail bucket", "Logging"),
        Control("3.5", "CloudTrail logs are encrypted at rest with a KMS key", "Logging"),
        Control("3.6", "KMS key rotation is enabled", "Logging"),
        Control("3.7", "VPC flow logging is enabled in all VPCs", "Logging"),
        # 4 -- Monitoring. Every control here is the same shape: a metric filter
        # over the CloudTrail log group, a metric, and an alarm that notifies
        # somebody. CloudGuard walks that chain for all sixteen (DECISIONS.md
        # §82) -- the two of §80 and the thirteen that followed them, plus 4.16,
        # which asks about Security Hub rather than a filter. The gaps in this
        # framework are now in sections 1, 2 and 5, and they are still listed,
        # because a catalogue of only what this product checks would report full
        # coverage for ever.
        Control(
            "4.1",
            "A log metric filter and alarm exist for unauthorized API calls",
            "Monitoring",
        ),
        Control(
            "4.2",
            "A log metric filter and alarm exist for console sign-in without MFA",
            "Monitoring",
        ),
        Control(
            "4.3",
            "A log metric filter and alarm exist for root account usage",
            "Monitoring",
        ),
        Control(
            "4.4",
            "A log metric filter and alarm exist for IAM policy changes",
            "Monitoring",
        ),
        Control(
            "4.5",
            "A log metric filter and alarm exist for CloudTrail configuration changes",
            "Monitoring",
        ),
        Control(
            "4.6",
            "A log metric filter and alarm exist for console authentication failures",
            "Monitoring",
        ),
        Control(
            "4.7",
            "A log metric filter and alarm exist for disabling or deleting customer keys",
            "Monitoring",
        ),
        Control(
            "4.8",
            "A log metric filter and alarm exist for S3 bucket policy changes",
            "Monitoring",
        ),
        Control(
            "4.9",
            "A log metric filter and alarm exist for AWS Config configuration changes",
            "Monitoring",
        ),
        Control(
            "4.10",
            "A log metric filter and alarm exist for security group changes",
            "Monitoring",
        ),
        Control(
            "4.11",
            "A log metric filter and alarm exist for network ACL changes",
            "Monitoring",
        ),
        Control(
            "4.12",
            "A log metric filter and alarm exist for network gateway changes",
            "Monitoring",
        ),
        Control(
            "4.13",
            "A log metric filter and alarm exist for route table changes",
            "Monitoring",
        ),
        Control(
            "4.14",
            "A log metric filter and alarm exist for VPC changes",
            "Monitoring",
        ),
        Control(
            "4.15",
            "A log metric filter and alarm exist for AWS Organizations changes",
            "Monitoring",
        ),
        Control(
            "4.16",
            "AWS Security Hub is enabled",
            "Monitoring",
        ),
        # 5 -- Networking
        Control(
            "5.1",
            "Network ACLs do not allow ingress from 0.0.0.0/0 to admin ports",
            "Networking",
        ),
        Control(
            "5.2",
            "Security groups do not allow ingress from 0.0.0.0/0 to admin ports",
            "Networking",
        ),
        Control(
            "5.4",
            "The default security group of every VPC restricts all traffic",
            "Networking",
        ),
        Control(
            "5.3",
            "VPC default security groups are not used by any resource",
            "Networking",
        ),
        Control(
            "5.5",
            "Routing tables for VPC peering are least access",
            "Networking",
        ),
        Control(
            "5.6",
            "EC2 instances require IMDSv2",
            "Networking",
        ),
    ),
)


def _from_data(raw: dict[str, Any]) -> Framework:
    """A framework read from ``data/frameworks.json``.

    Kept as data because six frameworks and 683 requirements written out as
    ``Control(...)`` calls would bury the ones above. The titles are the
    requirement names as the frameworks' own indexes give them -- the one place
    this catalogue does not use CloudGuard's own words, which needs a licensing
    decision for the CIS benchmarks before they are offered commercially
    (DECISIONS.md sections 150 and 168).

    Everything the frameworks written by hand promise still holds: controls no
    rule reaches are listed and resolve to NOT_COVERED, and a requirement the
    framework itself marks manual is not technically assessable.
    """
    controls = tuple(
        Control(
            str(control["id"]),
            str(control["title"]),
            str(control["group"]),
            technically_assessable=bool(control["technically_assessable"]),
        )
        for control in raw["controls"]
    )
    assessable = sum(1 for control in controls if control.technically_assessable)
    return Framework(
        id=str(raw["id"]),
        name=str(raw["name"]),
        short_name=str(raw["short_name"]),
        version=str(raw["version"]),
        authority=str(raw["authority"]),
        url=str(raw["url"]),
        summary=raw.get("summary")
        or (
            f"{raw['name']}. {len(controls)} requirements, {assessable} of them "
            "technically assessable."
        ),
        scope_note=raw.get("scope_note")
        or (
            "Every requirement in the published framework is listed. A requirement "
            "no rule reaches is shown as not covered rather than left out."
        ),
        controls=controls,
        provider=Provider(raw["provider"]) if raw.get("provider") else None,
    )


def _data_frameworks() -> tuple[Framework, ...]:
    raw = json.loads(FRAMEWORKS_PATH.read_text())
    return tuple(_from_data(entry) for entry in raw["frameworks"])


def _standards() -> dict[str, Framework]:
    raw = json.loads(STANDARDS_PATH.read_text())
    return {entry["id"]: _from_data(entry) for entry in raw["frameworks"]}


_STANDARDS = _standards()

FRAMEWORKS: tuple[Framework, ...] = (
    CIS_AZURE,
    CIS_AWS,
    _STANDARDS["ISO_27001"],
    GDPR,
    _STANDARDS["NIST_CSF_2.0"],
    NIST_800_53,
    _STANDARDS["SOC2"],
    _STANDARDS["PCI_DSS_4"],
    _STANDARDS["CIS_CONTROLS_8.1"],
    _STANDARDS["CSA_CCM_4.1"],
    _STANDARDS["NIST_800_171_R2"],
    _STANDARDS["DORA"],
    *_data_frameworks(),
)


def get_framework(framework_id: str) -> Framework | None:
    return next((f for f in FRAMEWORKS if f.id == framework_id), None)


def _assert_unique() -> None:
    """A duplicate framework or control id would make coverage double-count."""
    framework_ids: set[str] = set()
    for framework in FRAMEWORKS:
        if framework.id in framework_ids:
            raise RuntimeError(f"Duplicate framework id in catalogue: {framework.id}")
        framework_ids.add(framework.id)

        control_ids: set[str] = set()
        for control in framework.controls:
            if control.id in control_ids:
                raise RuntimeError(f"Duplicate control id in {framework.id}: {control.id}")
            control_ids.add(control.id)


_assert_unique()
