"""Every unit of evidence CloudGuard collects from Azure.

One member per collection task. The task declares which it produces, the rule
declares which it needs, and the executor's coverage report is keyed by the same
values -- so "this rule lost its verdict because that listing failed" is one
lookup rather than three strings agreeing by hand.

Each key knows its own category. Tasks therefore do not declare one, which
removes the way the two used to drift: a task whose key said storage and whose
category said network was a perfectly valid thing to write, and the only symptom
was a rule that quietly never degraded.
"""

from datetime import timedelta

from app.connectors.evidence import EvidenceCategory, EvidenceKey


class AzureEvidence(EvidenceKey):
    """The keys. Values match the snapshot's own payload keys, deliberately.

    A snapshot holds ``{"storage_accounts": [...]}``, so keeping the key equal
    to the payload name means the evidence a rule asks for and the data it then
    reads are named the same thing in both places.
    """

    # Resource Graph inventory: everything in the subscription, unjudged.
    RESOURCES = "resources"
    # The subscription's own record: its display name. Unjudged too; it names
    # the node every subscription-wide role assignment points at.
    SUBSCRIPTION = "subscription"

    NETWORK_SECURITY_GROUPS = "network_security_groups"
    NETWORK_INTERFACES = "network_interfaces"
    PUBLIC_IP_ADDRESSES = "public_ip_addresses"

    VIRTUAL_MACHINES = "virtual_machines"

    # Web apps and function apps -- both are ``Microsoft.Web/sites``. The
    # listing carries what the site is and whether it insists on HTTPS; the
    # configuration beneath each one carries TLS, FTP and remote debugging,
    # and ARM leaves ``siteConfig`` empty in the listing, so the two are two
    # reads and two keys.
    APP_SERVICES = "app_services"
    APP_SERVICE_CONFIGS = "app_service_configs"

    STORAGE_ACCOUNTS = "storage_accounts"
    # The blob service beneath each account: whether a deleted blob or
    # container can be recovered. A separate resource with its own read, so a
    # role predating v7 loses this and keeps every account-level verdict.
    STORAGE_BLOB_SERVICES = "storage_blob_services"

    SQL_SERVERS = "sql_servers"
    # Whether each server records who queried it. Its own key rather than part
    # of the listing above, because a key is the unit a rule depends on and
    # these two are separately deniable: the auditing read arrived in role v4,
    # so a customer who has not redeployed reads their servers and firewall
    # rules perfectly well and gets a 403 here. Folded together, that 403 cost
    # the public-access rule its verdict as well -- a gap CloudGuard invented,
    # which is the same mistake ``requires_evidence`` was introduced to stop
    # one layer up.
    SQL_AUDITING = "sql_auditing"
    # Whether the data each database holds is encrypted where it sits. Its own
    # key for the same reason auditing is: it arrives in role v6, it is a
    # per-database fan-out beneath the server listing, and a customer who has
    # not redeployed reads their servers perfectly well and is refused exactly
    # this. Folded into the server listing, that refusal would cost the
    # reachability rule its verdict over a call it never reads.
    SQL_TDE = "sql_tde"
    POSTGRESQL_SERVERS = "postgresql_servers"
    # Who the SQL server accepts as its Entra administrator, if anybody. Its own
    # key for the reason auditing is: it is a per-server call beneath the
    # listing, it arrives in role v7, and a role that predates it must cost
    # exactly this verdict rather than the reachability rule's as well.
    #
    # Not ``$expand=administrators`` on the server listing, which would have
    # been one call fewer. Whether the expansion is authorized by the server
    # read alone is not documented, and guessing wrong would turn a missing
    # permission into a failed listing of every SQL server a customer owns.
    SQL_ADMINISTRATORS = "sql_administrators"
    # One server parameter per PostgreSQL server: whether it refuses clients
    # that do not negotiate TLS. Read by name rather than by listing all of
    # them, because a listing is a few hundred parameters nothing reads.
    POSTGRESQL_CONFIGURATIONS = "postgresql_configurations"

    # The vault's configuration. Never its contents -- reading a secret is a
    # data-plane permission this connector does not hold.
    KEY_VAULTS = "key_vaults"
    # v9. Six listings, each one type the connector did not model before and
    # listed only in the inventory as unchecked: managed Kubernetes clusters,
    # container registries, Cosmos DB accounts, MySQL flexible servers,
    # Databricks workspaces and AI Search services. One key each, so a
    # refused listing costs only its own type's verdicts (DECISIONS.md
    # section 169).
    KUBERNETES_CLUSTERS = "kubernetes_clusters"
    CONTAINER_REGISTRIES = "container_registries"
    COSMOS_ACCOUNTS = "cosmos_accounts"
    MYSQL_SERVERS = "mysql_servers"
    DATABRICKS_WORKSPACES = "databricks_workspaces"
    SEARCH_SERVICES = "search_services"
    # v10. Two MySQL server parameters, read by name per server beneath the
    # listing -- whether it requires TLS and which TLS versions it accepts --
    # the way PostgreSQL's one parameter is (DECISIONS.md section 172).
    MYSQL_CONFIGURATIONS = "mysql_configurations"
    # Five PostgreSQL server parameters about what the server logs and how it
    # meets a connection flood, read by name under the configurations read the
    # role has held since v7 (DECISIONS.md section 175).
    POSTGRESQL_LOGGING = "postgresql_logging"

    # v11 (DECISIONS.md section 176). The reads the rest of Tier 2 needed, one
    # key each so a refusal costs only the checks resting on it.
    #
    # Beneath a SQL server: whether Defender for SQL watches it, which key
    # protects its encryption, and how it is assessed for vulnerabilities.
    SQL_THREAT_DETECTION = "sql_threat_detection"
    SQL_ENCRYPTION_PROTECTOR = "sql_encryption_protector"
    SQL_VULNERABILITY_ASSESSMENT = "sql_vulnerability_assessment"
    # The file service beneath a storage account: share soft delete and SMB.
    STORAGE_FILE_SERVICES = "storage_file_services"
    # The attributes of the keys and secrets in each vault -- when each stops
    # working, and whether a key rotates. The management-plane reads, which
    # never return a secret's value or a key's private material.
    KEY_VAULT_KEYS = "key_vault_keys"
    KEY_VAULT_SECRETS = "key_vault_secrets"
    # Whether App Service Authentication stands in front of each site. Read
    # under the site configuration read held since v7.
    APP_SERVICE_AUTH = "app_service_auth"
    # Defender for Cloud's subscription settings: who is emailed about what,
    # which integrations are on, and the IoT hubs it watches.
    SECURITY_CONTACTS = "security_contacts"
    SECURITY_SETTINGS = "security_settings"
    IOT_SECURITY_SOLUTIONS = "iot_security_solutions"
    # Which machines are behind just-in-time access, and which are backed up.
    JIT_POLICIES = "jit_policies"
    VM_BACKUPS = "vm_backups"
    DISKS = "disks"
    # Which activity-log alerts exist, and which policy assignments apply here.
    ACTIVITY_LOG_ALERTS = "activity_log_alerts"
    POLICY_ASSIGNMENTS = "policy_assignments"
    # Networks, the watchers that observe them, their flow logs, and Bastion.
    VIRTUAL_NETWORKS = "virtual_networks"
    NETWORK_WATCHERS = "network_watchers"
    FLOW_LOGS = "flow_logs"
    BASTION_HOSTS = "bastion_hosts"
    # v12 (section 177): each Recovery Services vault's backup policies -- how
    # long it keeps what it holds -- and virtual machine scale sets.
    BACKUP_POLICIES = "backup_policies"
    SCALE_SETS = "scale_sets"
    # v13 (section 204): application gateways and the WAF policies attached to
    # them, virtual network gateways read one by one from the inventory's ids,
    # the subscription's resource locks, and each PostgreSQL server's firewall
    # rules. One key each, so a refusal costs only the checks resting on it.
    APPLICATION_GATEWAYS = "application_gateways"
    WAF_POLICIES = "waf_policies"
    VPN_GATEWAYS = "vpn_gateways"
    RESOURCE_LOCKS = "resource_locks"
    POSTGRESQL_FIREWALL_RULES = "postgresql_firewall_rules"
    # Diagnostic settings beneath each storage account's blob, queue and table
    # services, and on each Databricks workspace. Their own keys rather than
    # targets of DIAGNOSTIC_SETTINGS: that task depends on every listing it
    # draws ids from, so a refused Databricks listing would have skipped it and
    # cost every logging rule its verdict.
    STORAGE_SERVICE_DIAGNOSTICS = "storage_service_diagnostics"
    DATABRICKS_DIAGNOSTICS = "databricks_diagnostics"

    # Microsoft Defender for Cloud's own assessments of this subscription.
    #
    # The one reading that is somebody else's conclusion rather than a
    # configuration. CloudGuard does not re-report them: it reads them as
    # evidence and reaches its own verdict, which is what lets a vulnerability
    # finding become "on an internet-facing machine" -- a sentence Defender has
    # the finding for and CloudGuard has the exposure for, and neither says
    # alone.
    SECURITY_ASSESSMENTS = "security_assessments"
    # Which Defender for Cloud plans this subscription pays for. A statement
    # about coverage rather than a finding Defender reached, and the reason it
    # is not folded into the assessments above: a plan that is off produces no
    # assessments at all, so the silence of the key above cannot say whether
    # anything was looking.
    DEFENDER_PLANS = "defender_plans"

    DIAGNOSTIC_SETTINGS = "diagnostic_settings"

    # Who may act on what, within this subscription. Read from ARM under the
    # scanner role, unlike the directory keys below, which come from Graph
    # under admin consent -- two grants that fail independently.
    ROLE_ASSIGNMENTS = "role_assignments"
    ROLE_DEFINITIONS = "role_definitions"
    # Who is in each group that holds a role here, nested groups flattened.
    # From Graph rather than ARM, and per subscription rather than with the
    # directory, because only this subscription's assignments say which groups
    # matter: reading every group's members once per tenant would be a
    # directory dump to answer a question about a handful (section 126).
    ROLE_GROUP_MEMBERS = "role_group_members"
    # Roles a principal is eligible to activate under Privileged Identity
    # Management, as opposed to ones it holds. Needs the v8 role (section 130).
    ROLE_ELIGIBILITIES = "role_eligibilities"

    # Directory. Read once per scan against the tenant, never per subscription.
    USERS = "users"
    DIRECTORY_ROLES = "directory_roles"
    USER_ROLE_MAP = "user_role_map"

    # Defences rather than faults. Neither produces a finding of its own; both
    # are read so a rule can tell whether something already stands between an
    # attacker and the misconfiguration it found (``rules/controls.py``).
    #
    # Both come from Graph under ``Policy.Read.All``, which is already in
    # ``REQUIRED_GRAPH_PERMISSIONS`` and already consented by every connected
    # tenant -- so this costs no customer a second trip to a Global
    # Administrator.
    SECURITY_DEFAULTS = "security_defaults"
    # The tenant's authorization policy: who may invite guests, what guests can
    # see, whether users can register applications, create tenants and groups,
    # and consent to applications themselves. Graph, under ``Policy.Read.All``,
    # which every connected tenant already consented (section 172).
    AUTHORIZATION_POLICY = "authorization_policy"
    # Which sign-in methods the tenant allows and whether it campaigns for
    # registration (``Policy.Read.All``), and the tenant's directory settings,
    # read for who may create Microsoft 365 groups (``Directory.Read.All``).
    # Both already consented (DECISIONS.md section 173).
    AUTHENTICATION_METHODS_POLICY = "authentication_methods_policy"
    GROUP_SETTINGS = "group_settings"
    CONDITIONAL_ACCESS_POLICIES = "conditional_access_policies"
    # The tenant's named locations, for whether any network is marked trusted
    # (``Policy.Read.All``, already consented; section 176).
    NAMED_LOCATIONS = "named_locations"
    # Section 204. Whether joining a device asks for a second factor
    # (``Policy.Read.DeviceConfiguration``) and which access reviews exist
    # (``AccessReview.Read.All``) -- the two permissions that section added to
    # consent -- and the tenant's subscription policy, read from ARM at the
    # tenant scope, which every user may read and no role action governs.
    DEVICE_REGISTRATION_POLICY = "device_registration_policy"
    ACCESS_REVIEWS = "access_reviews"
    SUBSCRIPTION_POLICY = "subscription_policy"

    # The credentials on this tenant's own application registrations: client
    # secrets and certificates, with the dates they stop working.
    #
    # Read under ``Application.Read.All``, which admin consent has requested
    # since onboarding existed and no collector has ever used -- so this costs
    # no customer a second trip to a Global Administrator
    # (``DECISIONS.md`` section 63).
    APPLICATION_CREDENTIALS = "application_credentials"

    # Who owns each application registration, and which service principal each
    # registration signs in as. No rule reads it; the graph does, because an
    # owner can add a credential and act as the principal (section 128).
    # ``Application.Read.All`` again, so no customer grants anything new.
    APPLICATION_OWNERS = "application_owners"

    # Which principals hold which Microsoft Graph application permissions. A
    # few of them are a directory role by another name -- a principal that may
    # write role assignments in the directory can make itself Global
    # Administrator -- so the graph reads them as powers (section 129).
    GRAPH_PERMISSION_GRANTS = "graph_permission_grants"

    # Directory roles a principal is eligible to activate (section 130). Its
    # own key because it is separately deniable: it needs Entra ID P2, and a
    # tenant without it must not lose the active roles to that.
    DIRECTORY_ROLE_ELIGIBILITIES = "directory_role_eligibilities"

    # When each account last signed in. Its own key rather than a wider
    # ``users`` listing, because it is separately deniable in a way none of the
    # other directory reads are: ``signInActivity`` needs an Entra ID P1 or P2
    # licence, so a fully consented tenant on the free tier reads its users,
    # roles and policies perfectly well and is refused exactly this. Folded
    # into ``USERS``, that refusal would cost the MFA rule its verdict over a
    # licence that has nothing to do with it.
    USER_SIGN_IN_ACTIVITY = "user_sign_in_activity"

    @property
    def category(self) -> EvidenceCategory:
        return _CATEGORIES[self]

    @property
    def reuse_window(self) -> timedelta | None:
        return _REUSE_WINDOWS.get(self)


_CATEGORIES: dict[AzureEvidence, EvidenceCategory] = {
    AzureEvidence.RESOURCES: EvidenceCategory.RESOURCES,
    AzureEvidence.SUBSCRIPTION: EvidenceCategory.RESOURCES,
    AzureEvidence.NETWORK_SECURITY_GROUPS: EvidenceCategory.NETWORK,
    AzureEvidence.NETWORK_INTERFACES: EvidenceCategory.NETWORK,
    AzureEvidence.PUBLIC_IP_ADDRESSES: EvidenceCategory.NETWORK,
    AzureEvidence.VIRTUAL_MACHINES: EvidenceCategory.COMPUTE,
    AzureEvidence.APP_SERVICES: EvidenceCategory.COMPUTE,
    AzureEvidence.APP_SERVICE_CONFIGS: EvidenceCategory.COMPUTE,
    AzureEvidence.STORAGE_ACCOUNTS: EvidenceCategory.STORAGE,
    AzureEvidence.STORAGE_BLOB_SERVICES: EvidenceCategory.STORAGE,
    AzureEvidence.SQL_SERVERS: EvidenceCategory.DATABASE,
    AzureEvidence.SQL_AUDITING: EvidenceCategory.DATABASE,
    AzureEvidence.SQL_TDE: EvidenceCategory.DATABASE,
    AzureEvidence.SQL_ADMINISTRATORS: EvidenceCategory.DATABASE,
    AzureEvidence.POSTGRESQL_CONFIGURATIONS: EvidenceCategory.DATABASE,
    AzureEvidence.KEY_VAULTS: EvidenceCategory.SECRETS,
    AzureEvidence.KUBERNETES_CLUSTERS: EvidenceCategory.COMPUTE,
    AzureEvidence.CONTAINER_REGISTRIES: EvidenceCategory.COMPUTE,
    AzureEvidence.DATABRICKS_WORKSPACES: EvidenceCategory.COMPUTE,
    AzureEvidence.COSMOS_ACCOUNTS: EvidenceCategory.DATABASE,
    AzureEvidence.MYSQL_SERVERS: EvidenceCategory.DATABASE,
    AzureEvidence.SEARCH_SERVICES: EvidenceCategory.DATABASE,
    AzureEvidence.MYSQL_CONFIGURATIONS: EvidenceCategory.DATABASE,
    AzureEvidence.POSTGRESQL_LOGGING: EvidenceCategory.DATABASE,
    AzureEvidence.SQL_THREAT_DETECTION: EvidenceCategory.DATABASE,
    AzureEvidence.SQL_ENCRYPTION_PROTECTOR: EvidenceCategory.DATABASE,
    AzureEvidence.SQL_VULNERABILITY_ASSESSMENT: EvidenceCategory.DATABASE,
    AzureEvidence.STORAGE_FILE_SERVICES: EvidenceCategory.STORAGE,
    AzureEvidence.KEY_VAULT_KEYS: EvidenceCategory.SECRETS,
    AzureEvidence.KEY_VAULT_SECRETS: EvidenceCategory.SECRETS,
    AzureEvidence.APP_SERVICE_AUTH: EvidenceCategory.COMPUTE,
    AzureEvidence.SECURITY_CONTACTS: EvidenceCategory.POSTURE,
    AzureEvidence.SECURITY_SETTINGS: EvidenceCategory.POSTURE,
    AzureEvidence.IOT_SECURITY_SOLUTIONS: EvidenceCategory.POSTURE,
    AzureEvidence.JIT_POLICIES: EvidenceCategory.POSTURE,
    AzureEvidence.POLICY_ASSIGNMENTS: EvidenceCategory.POSTURE,
    AzureEvidence.VM_BACKUPS: EvidenceCategory.COMPUTE,
    AzureEvidence.DISKS: EvidenceCategory.COMPUTE,
    AzureEvidence.ACTIVITY_LOG_ALERTS: EvidenceCategory.LOGGING,
    AzureEvidence.VIRTUAL_NETWORKS: EvidenceCategory.NETWORK,
    AzureEvidence.NETWORK_WATCHERS: EvidenceCategory.NETWORK,
    AzureEvidence.FLOW_LOGS: EvidenceCategory.NETWORK,
    AzureEvidence.BASTION_HOSTS: EvidenceCategory.NETWORK,
    AzureEvidence.NAMED_LOCATIONS: EvidenceCategory.IDENTITY,
    AzureEvidence.BACKUP_POLICIES: EvidenceCategory.COMPUTE,
    AzureEvidence.SCALE_SETS: EvidenceCategory.COMPUTE,
    AzureEvidence.APPLICATION_GATEWAYS: EvidenceCategory.NETWORK,
    AzureEvidence.WAF_POLICIES: EvidenceCategory.NETWORK,
    AzureEvidence.VPN_GATEWAYS: EvidenceCategory.NETWORK,
    AzureEvidence.RESOURCE_LOCKS: EvidenceCategory.POSTURE,
    AzureEvidence.POSTGRESQL_FIREWALL_RULES: EvidenceCategory.DATABASE,
    AzureEvidence.STORAGE_SERVICE_DIAGNOSTICS: EvidenceCategory.LOGGING,
    AzureEvidence.DATABRICKS_DIAGNOSTICS: EvidenceCategory.LOGGING,
    AzureEvidence.DEVICE_REGISTRATION_POLICY: EvidenceCategory.IDENTITY,
    AzureEvidence.ACCESS_REVIEWS: EvidenceCategory.IDENTITY,
    AzureEvidence.SUBSCRIPTION_POLICY: EvidenceCategory.IDENTITY,
    AzureEvidence.SECURITY_ASSESSMENTS: EvidenceCategory.POSTURE,
    AzureEvidence.DEFENDER_PLANS: EvidenceCategory.POSTURE,
    AzureEvidence.POSTGRESQL_SERVERS: EvidenceCategory.DATABASE,
    AzureEvidence.DIAGNOSTIC_SETTINGS: EvidenceCategory.LOGGING,
    AzureEvidence.ROLE_ASSIGNMENTS: EvidenceCategory.AUTHORIZATION,
    AzureEvidence.ROLE_DEFINITIONS: EvidenceCategory.AUTHORIZATION,
    AzureEvidence.ROLE_GROUP_MEMBERS: EvidenceCategory.AUTHORIZATION,
    AzureEvidence.ROLE_ELIGIBILITIES: EvidenceCategory.AUTHORIZATION,
    AzureEvidence.USERS: EvidenceCategory.IDENTITY,
    AzureEvidence.DIRECTORY_ROLES: EvidenceCategory.IDENTITY,
    AzureEvidence.USER_ROLE_MAP: EvidenceCategory.IDENTITY,
    AzureEvidence.SECURITY_DEFAULTS: EvidenceCategory.IDENTITY,
    AzureEvidence.AUTHORIZATION_POLICY: EvidenceCategory.IDENTITY,
    AzureEvidence.AUTHENTICATION_METHODS_POLICY: EvidenceCategory.IDENTITY,
    AzureEvidence.GROUP_SETTINGS: EvidenceCategory.IDENTITY,
    AzureEvidence.CONDITIONAL_ACCESS_POLICIES: EvidenceCategory.IDENTITY,
    AzureEvidence.APPLICATION_CREDENTIALS: EvidenceCategory.IDENTITY,
    AzureEvidence.APPLICATION_OWNERS: EvidenceCategory.IDENTITY,
    AzureEvidence.GRAPH_PERMISSION_GRANTS: EvidenceCategory.IDENTITY,
    AzureEvidence.DIRECTORY_ROLE_ELIGIBILITIES: EvidenceCategory.IDENTITY,
    AzureEvidence.USER_SIGN_IN_ACTIVITY: EvidenceCategory.IDENTITY,
}

# Enumerated rather than compared at call time: a key added without a category
# would otherwise fail as a KeyError inside a running scan, on the one path
# whose job is to be reliable when everything else is not.
_missing = set(AzureEvidence) - set(_CATEGORIES)
if _missing:  # pragma: no cover - import-time guard
    raise RuntimeError("AzureEvidence members with no category: " + ", ".join(sorted(_missing)))


# Evidence CloudGuard collects because the product needs it, not because a rule
# judges it. Every other key in the plans above is named by some rule's
# ``requires_evidence``; these are named by none, and would therefore be dropped
# the moment a plan is derived from the rule set rather than written out by
# hand.
#
# The authorization listings earn their place plainly: they are what the asset
# graph's identity edges are built from -- who holds which role, and what that
# role permits -- so dropping them costs every privilege path at once. The two
# control readings earn theirs the same way, as the defences that lower a
# finding's score rather than raise one.
#
# ``RESOURCES`` is the one to be honest about. This comment used to claim the
# customer's asset list was made of it. It is not: every asset CloudGuard shows
# comes from the per-service listings -- the storage listing, the SQL listing,
# the virtual machine listing -- normalized into ``cloud_resources``. The
# Resource Graph payload is stored verbatim in the snapshot and read by nothing,
# today, anywhere.
#
# It is kept because of what it is rather than what it does: the only reading
# that covers the resource types no rule has been written for, which is the
# evidence behind the sentence the product cannot yet say -- "you have forty
# resources CloudGuard does not check". Until something says that, this is a
# query per subscription per scan and a stored blob for a capability that does
# not exist, and the honest options are to build it or to stop asking.
#
# Since section 176 one rule does name it: AZ-DEF-009 learns from the inventory
# which IoT hubs exist, a type the connector does not model. It stays baseline
# evidence all the same, because the unchecked-inventory view needs it whether
# or not a subscription has a hub.
#
# Declared here rather than inferred, because "no rule needs it" and "nothing
# needs it" are different statements and only the second is a reason to stop
# collecting.
BASELINE_EVIDENCE: frozenset[AzureEvidence] = frozenset(
    {
        AzureEvidence.RESOURCES,
        # The subscription's display name. No verdict rests on what a
        # subscription is called, and a failed read costs only the name: the
        # node falls back to its id. It is collected because a graph whose most
        # connected node is a GUID is a graph nobody can read.
        AzureEvidence.SUBSCRIPTION,
        AzureEvidence.ROLE_ASSIGNMENTS,
        AzureEvidence.ROLE_DEFINITIONS,
        # Who a group's role reaches. No rule reads it; without it every role
        # held by a group is a role held by nobody the graph can name.
        AzureEvidence.ROLE_GROUP_MEMBERS,
        # Who can sign in as an application, and which principal that is.
        AzureEvidence.APPLICATION_OWNERS,
        AzureEvidence.GRAPH_PERMISSION_GRANTS,
        # Who could activate a role, for the access view (section 130).
        AzureEvidence.ROLE_ELIGIBILITIES,
        AzureEvidence.DIRECTORY_ROLE_ELIGIBILITIES,
        # The two control readings. No rule *requires* them -- a rule that did
        # would report UNKNOWN when a defence could not be read, which is
        # backwards: an unreadable control is an absent one, and the finding
        # keeps its full score. They are collected because the score is worse
        # without them, not because a verdict depends on them.
        AzureEvidence.SECURITY_DEFAULTS,
        AzureEvidence.CONDITIONAL_ACCESS_POLICIES,
    }
)

# How old a complete reading may be and still be carried into a later scan
# instead of re-read. Absent means never, which is now the answer for every key.
#
# Role definitions used to carry a week, on the stated grounds that no rule read
# them -- they only labelled the graph's identity edges, so a stale catalogue
# could not turn a FAIL into a PASS. AZ-IAM-003 made that false. It asks whether
# a role permits writing role assignments, which is a fact about the definition's
# permissions, so a customer who edits a custom role to remove that action and
# rescans to check would be answered from the catalogue as it stood a week
# before the edit. That is the exact shape of "verified fixed" being untrue, and
# the window is worth less than the guarantee.
#
# ``test_no_rule_reads_evidence_that_may_be_carried_forward`` is what caught it,
# and is why this dict is empty rather than merely smaller.
_REUSE_WINDOWS: dict[AzureEvidence, timedelta] = {}


def keys_in(category: EvidenceCategory) -> frozenset[AzureEvidence]:
    """Every key that belongs to one category.

    Used where a category-level fact has to be applied to the keys underneath
    it -- a stale role grants no permission for a whole category, and the rules
    that lost their verdict did so one key at a time.
    """
    return frozenset(key for key, value in _CATEGORIES.items() if value is category)
