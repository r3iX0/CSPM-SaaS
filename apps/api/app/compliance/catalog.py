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

from dataclasses import dataclass

from app.core.enums import Provider


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
        "without a CloudGuard check behind them are listed so the gap is visible "
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

ISO_27001 = Framework(
    id="ISO_27001",
    name="ISO/IEC 27001:2022 Annex A",
    short_name="ISO 27001",
    version="2022",
    authority="ISO/IEC",
    url="https://www.iso.org/standard/27001",
    summary=(
        "The control set an ISMS certification audits against. Most of it is "
        "about people and process; the technological controls in A.8 are where "
        "a cloud scanner has anything to say."
    ),
    scope_note=(
        "A subset of Annex A: the controls a cloud posture scan can produce "
        "evidence toward, plus nearby controls it cannot, marked as such. The "
        "other Annex A controls are outside anything this product observes."
    ),
    controls=(
        Control("A.5.10", "Acceptable use of information and associated assets", "Organizational"),
        Control("A.5.15", "Access control", "Organizational"),
        Control("A.5.16", "Identity management", "Organizational"),
        Control("A.5.17", "Authentication information", "Organizational"),
        Control("A.5.18", "Access rights", "Organizational"),
        Control(
            "A.5.30",
            "ICT readiness for business continuity",
            "Organizational",
            technically_assessable=False,
        ),
        Control(
            "A.6.3",
            "Information security awareness and training",
            "People",
            technically_assessable=False,
        ),
        Control("A.8.2", "Privileged access rights", "Technological"),
        Control("A.8.3", "Information access restriction", "Technological"),
        Control("A.8.8", "Management of technical vulnerabilities", "Technological"),
        Control("A.8.13", "Information backup", "Technological"),
        Control("A.8.15", "Logging", "Technological"),
        Control("A.8.16", "Monitoring activities", "Technological"),
        Control("A.8.20", "Networks security", "Technological"),
        Control("A.8.22", "Segregation of networks", "Technological"),
        Control("A.8.23", "Web filtering", "Technological"),
        Control("A.8.24", "Use of cryptography", "Technological"),
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

NIST_CSF = Framework(
    id="NIST_CSF",
    name="NIST Cybersecurity Framework",
    short_name="NIST CSF",
    version="1.1",
    authority="National Institute of Standards and Technology",
    url="https://www.nist.gov/cyberframework",
    summary=(
        "Outcome-based subcategories rather than prescriptive settings. Useful "
        "as a common vocabulary when an organization already reports against it."
    ),
    scope_note=(
        "The Protect and Detect subcategories CloudGuard's rules speak to. The "
        "Identify, Respond and Recover functions are largely organizational."
    ),
    controls=(
        Control("PR.AC-1", "Identities and credentials are managed", "Protect"),
        Control("PR.AC-3", "Remote access is managed", "Protect"),
        Control("PR.AC-4", "Access permissions follow least privilege", "Protect"),
        Control("PR.AC-5", "Network integrity is protected and segregated", "Protect"),
        Control("PR.AC-7", "Authentication is proportionate to risk", "Protect"),
        Control("PR.DS-1", "Data at rest is protected", "Protect"),
        Control("PR.DS-2", "Data in transit is protected", "Protect"),
        Control("PR.DS-5", "Protections against data leaks are implemented", "Protect"),
        Control(
            "PR.IP-4",
            "Backups of information are conducted, maintained and tested",
            "Protect",
        ),
        Control("PR.PT-1", "Audit records are determined, documented and reviewed", "Protect"),
        Control("PR.PT-4", "Communications and control networks are protected", "Protect"),
        Control("DE.AE-3", "Event data are collected and correlated", "Detect"),
        Control("DE.CM-1", "The network is monitored to detect events", "Detect"),
        # The functions the scope note above admits are out of reach, named
        # rather than merely mentioned. Listing only Protect and Detect made
        # this the one framework here that could report full coverage, which
        # ``test_catalogue_lists_controls_no_rule_covers`` correctly refused --
        # and the fault was the catalogue understating CSF rather than a
        # mapping being wrong. CSF holds over a hundred subcategories; these are
        # representative of the four functions a configuration reading cannot
        # speak to.
        Control(
            "ID.AM-1",
            "Physical devices and systems are inventoried",
            "Identify",
        ),
        Control(
            "ID.RA-1",
            "Asset vulnerabilities are identified and documented",
            "Identify",
        ),
        Control(
            "ID.GV-1",
            "An organizational security policy is established",
            "Identify",
            technically_assessable=False,
        ),
        Control(
            "RS.RP-1",
            "A response plan is executed during or after an incident",
            "Respond",
            technically_assessable=False,
        ),
        Control(
            "RC.RP-1",
            "A recovery plan is executed during or after an incident",
            "Recover",
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

SOC2 = Framework(
    id="SOC2",
    name="SOC 2 Trust Services Criteria",
    short_name="SOC 2",
    version="2017 (rev. 2022)",
    authority="American Institute of Certified Public Accountants",
    url="https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services",
    summary=(
        "What an auditor tests during a SOC 2 examination. Not a configuration "
        "standard: most criteria are about whether an organization has a "
        "control and operates it, and a scanner can only ever be evidence "
        "toward the subset that lands in a cloud configuration."
    ),
    scope_note=(
        "The Common Criteria concerning logical access and monitoring, plus the "
        "availability criterion covering recovery. CC1 to CC5 -- control "
        "environment, communication, risk assessment, monitoring and control "
        "activities -- are about how an organization is run and are listed here "
        "unassessable rather than omitted. Nothing on this page is an opinion "
        "about a SOC 2 examination, which only a licensed firm can issue."
    ),
    controls=(
        # --- Common Criteria: logical and physical access -------------------
        Control(
            "CC6.1",
            "Access to systems and data is restricted to those authorized",
            "Logical Access",
        ),
        Control(
            "CC6.2",
            "Access is granted on authorization and removed when it ends",
            "Logical Access",
        ),
        Control("CC6.3", "Access rights follow least privilege and are reviewed", "Logical Access"),
        Control(
            "CC6.6",
            "The system is protected against access from outside its boundary",
            "Logical Access",
        ),
        Control(
            "CC6.7",
            "Information is protected as it moves and as it is stored",
            "Logical Access",
        ),
        Control(
            "CC6.8",
            "Unauthorized or malicious software is prevented and detected",
            "Logical Access",
        ),
        # --- Common Criteria: system operations -----------------------------
        Control(
            "CC7.1",
            "Configuration is monitored for change and for vulnerability",
            "Operations",
        ),
        Control(
            "CC7.2",
            "The system is monitored for anomalies that indicate an incident",
            "Operations",
        ),
        Control(
            "CC7.3",
            "Detected events are evaluated to decide whether they are incidents",
            "Operations",
            technically_assessable=False,
        ),
        Control(
            "CC7.4",
            "Incidents are responded to and recovered from",
            "Operations",
            technically_assessable=False,
        ),
        # --- Common Criteria: change and risk -------------------------------
        Control(
            "CC8.1",
            "Changes are authorized, designed, tested and approved",
            "Change Management",
            technically_assessable=False,
        ),
        Control(
            "CC9.1",
            "Risks from business disruption are identified and mitigated",
            "Risk Mitigation",
            technically_assessable=False,
        ),
        # --- Availability ---------------------------------------------------
        Control("A1.2", "Recovery of the environment is provided for and tested", "Availability"),
        # --- The criteria a scanner has nothing to say about ----------------
        # An organization is judged on all of these and CloudGuard reads none of
        # them. Listing them is the difference between a page that reports
        # honest partial coverage and one that implies a SOC 2 report is a
        # configuration problem.
        Control(
            "CC1.1",
            "The organization demonstrates a commitment to integrity",
            "Control Environment",
            technically_assessable=False,
        ),
        Control(
            "CC1.4",
            "The organization attracts and retains competent people",
            "Control Environment",
            technically_assessable=False,
        ),
        Control(
            "CC2.1",
            "Quality information is used to support the controls",
            "Communication",
            technically_assessable=False,
        ),
        Control(
            "CC2.2",
            "Responsibilities for security are communicated internally",
            "Communication",
            technically_assessable=False,
        ),
        Control(
            "CC3.1",
            "Objectives are set clearly enough for risks to be judged against",
            "Risk Assessment",
            technically_assessable=False,
        ),
        Control(
            "CC3.2",
            "Risks to the objectives are identified and analysed",
            "Risk Assessment",
            technically_assessable=False,
        ),
        Control(
            "CC3.3",
            "The potential for fraud is considered when assessing risk",
            "Risk Assessment",
            technically_assessable=False,
        ),
        Control(
            "CC4.1",
            "The controls are evaluated for whether they are working",
            "Monitoring",
            technically_assessable=False,
        ),
        Control(
            "CC4.2",
            "Control deficiencies are communicated to those who can act",
            "Monitoring",
            technically_assessable=False,
        ),
        Control(
            "CC5.1",
            "Control activities are selected to bring risks to an acceptable level",
            "Control Activities",
            technically_assessable=False,
        ),
        Control(
            "CC5.2",
            "Controls over technology are selected and developed",
            "Control Activities",
            technically_assessable=False,
        ),
        Control(
            "CC5.3",
            "Control activities are deployed through policies people follow",
            "Control Activities",
            technically_assessable=False,
        ),
        Control(
            "CC7.5",
            "The organization recovers from identified incidents",
            "Operations",
            technically_assessable=False,
        ),
        Control(
            "CC9.2",
            "Risks carried by vendors and business partners are managed",
            "Risk Mitigation",
            technically_assessable=False,
        ),
    ),
)

PCI_DSS = Framework(
    id="PCI_DSS_4",
    name="PCI DSS v4.0.1",
    short_name="PCI DSS",
    version="4.0.1",
    authority="PCI Security Standards Council",
    url="https://www.pcisecuritystandards.org/document_library/",
    summary=(
        "The card brands' requirements for anyone who stores, processes or "
        "transmits cardholder data. Unlike the frameworks above it is "
        "contractual rather than advisory: a merchant is assessed against it "
        "and can lose the ability to take payments."
    ),
    scope_note=(
        "PCI applies to the cardholder data environment, and CloudGuard does "
        "not know which of your resources are in it. That is the caveat that "
        "matters most on this page. Scope is a decision a QSA makes with you "
        "about network segmentation, data flows and where card data actually "
        "goes -- and every number here is computed over the whole subscription "
        "instead. A resource group holding no card data is counted the same as "
        "the one that does. Read these as configuration evidence you can hand "
        "to an assessor for the systems they have already scoped in, never as "
        "a position on requirements 3 or 4 for the environment as a whole. The "
        "requirements below are the technical ones a configuration reading "
        "reaches; the standard holds several hundred."
    ),
    controls=(
        # --- 1. Network security controls -----------------------------------
        Control(
            "1.2.1",
            "Network security controls are configured and enforced",
            "Network Security",
        ),
        Control(
            "1.3.1",
            "Inbound traffic to the cardholder data environment is restricted",
            "Network Security",
        ),
        Control(
            "1.4.1",
            "Connections between trusted and untrusted networks are controlled",
            "Network Security",
        ),
        # --- 2. Secure configuration ----------------------------------------
        Control(
            "2.2.1",
            "System components are configured to a hardened standard",
            "Secure Configuration",
        ),
        # --- 3. Protect stored account data ---------------------------------
        Control(
            "3.5.1",
            "Stored account data is rendered unreadable",
            "Stored Data",
        ),
        Control(
            "3.6.1",
            "Cryptographic keys are protected against disclosure and misuse",
            "Stored Data",
        ),
        # --- 4. Protect data in transit -------------------------------------
        Control(
            "4.2.1",
            "Strong cryptography protects account data in transit",
            "Data In Transit",
        ),
        # --- 5. Malicious software ------------------------------------------
        Control(
            "5.2.1",
            "Systems are protected against malicious software",
            "Malware",
        ),
        # --- 6. Secure systems and software ---------------------------------
        Control(
            "6.3.3",
            "Known vulnerabilities are corrected by applying security patches",
            "Secure Software",
        ),
        Control(
            "6.5.1",
            "Changes to system components follow a change control process",
            "Secure Software",
            technically_assessable=False,
        ),
        # --- 7. Access by business need to know -----------------------------
        Control(
            "7.2.1",
            "Access is granted on business need and least privilege",
            "Access Control",
        ),
        Control(
            "7.2.2",
            "Privileges assigned are the least the role requires",
            "Access Control",
        ),
        # --- 8. Identify and authenticate -----------------------------------
        Control(
            "8.2.1",
            "Every user is identified by a unique account",
            "Authentication",
        ),
        Control(
            "8.3.1",
            "Access is authenticated by a strong factor",
            "Authentication",
        ),
        Control(
            "8.4.2",
            "Multi-factor authentication is required for administrative access",
            "Authentication",
        ),
        # --- 9. Physical access ---------------------------------------------
        Control(
            "9.1.1",
            "Physical access to cardholder data is restricted",
            "Physical Access",
            technically_assessable=False,
        ),
        # --- 10. Log and monitor --------------------------------------------
        Control(
            "10.2.1",
            "Audit logs record access to system components and card data",
            "Logging",
        ),
        Control(
            "10.3.2",
            "Audit logs are protected from alteration and destruction",
            "Logging",
        ),
        Control(
            "10.5.1",
            "Audit history is retained long enough to investigate",
            "Logging",
        ),
        # --- 11. Test security ----------------------------------------------
        Control(
            "11.3.1",
            "Internal vulnerability scans are run and findings resolved",
            "Security Testing",
        ),
        Control(
            "11.4.1",
            "Penetration testing is performed and findings addressed",
            "Security Testing",
            technically_assessable=False,
        ),
        # --- 12. Organizational policy --------------------------------------
        Control(
            "12.1.1",
            "An information security policy is established and maintained",
            "Policy",
            technically_assessable=False,
        ),
        Control(
            "12.10.1",
            "An incident response plan exists and is exercised",
            "Policy",
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
        "listed without a CloudGuard check behind them are shown so the gap is "
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
        Control("2.1.1", "S3 buckets apply encryption by default", "Storage"),
        Control(
            "2.1.2",
            "S3 bucket policies deny requests that are not over HTTPS",
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


FRAMEWORKS: tuple[Framework, ...] = (
    CIS_AZURE,
    CIS_AWS,
    ISO_27001,
    GDPR,
    NIST_CSF,
    NIST_800_53,
    SOC2,
    PCI_DSS,
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
