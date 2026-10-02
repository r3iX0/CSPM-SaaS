"""Azure's collection plans: what to gather, and what each piece needs.

Two plans, not one, because a scan reads two different things. ARM answers
questions about a *subscription* and is asked once per subscription;
Graph answers questions about the *tenant* and must be asked once for the whole
scan. Collecting both under one plan meant the directory was re-read for every
subscription -- and, worse than the cost, normalized into a separate set of user
resources each time, so one administrator without MFA produced one finding per
subscription.

One entry per listing, rather than one per category. That granularity is the
whole reason the plan exists -- ``_collect_network`` used to gather NSGs, NICs
and public IPs under a single ``try``, so a failure reading public IPs took the
NSG data with it and every network rule reported UNKNOWN over data that had
arrived intact.

Each task also carries the ARM actions it needs. ``rbac.py`` derives the
permission set from this, so a listing and the permission that grants it can no
longer disagree: adding a task without its action fails a test rather than
reaching a customer as a 403 inside one collection category.

Every task gets its own client over a shared connection pool. Truncation is
recorded per client, and tasks in a wave run concurrently -- a single shared
client would record a truncated listing without saying which task it belonged
to, and the resulting PARTIAL would be attributed to whichever task happened to
be awaiting at the time.
"""

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from app.connectors.azure.auth import GRAPH_RESOURCE_APP_ID, TokenProvider
from app.connectors.azure.client import (
    EDGE_BLOCK_MESSAGE,
    ArmClient,
    AzureApiError,
    GraphClient,
    RequestLimiter,
    ResourceGraphClient,
)
from app.connectors.azure.evidence import AzureEvidence
from app.connectors.azure.rbac import first_version_granting
from app.connectors.azure.settings_v13 import STORAGE_SERVICES, VPN_GATEWAY_TYPE
from app.connectors.collection import CollectionTask, ReadingUnavailable, TaskData
from app.connectors.evidence import ProviderEndpoint
from app.core.logging import get_logger

log = get_logger(__name__)


async def _mysql_parameters(arm: ArmClient, server_id: str) -> dict[str, Any]:
    """Both TLS parameters of one MySQL server, read by name.

    Together rather than as two tasks: one rule reads each, both are the same
    permission, and a role that refuses one refuses the other.
    """
    return {
        "require_secure_transport": await arm.get_mysql_secure_transport(server_id),
        "tls_version": await arm.get_mysql_tls_version(server_id),
        # Section 175: whether the server keeps an audit log, and of what.
        "audit_log_enabled": await arm.get_mysql_parameter(server_id, "audit_log_enabled"),
        "audit_log_events": await arm.get_mysql_parameter(server_id, "audit_log_events"),
    }


POSTGRES_LOGGING_PARAMETERS = (
    "log_checkpoints",
    "log_connections",
    "log_disconnections",
    "connection_throttle.enable",
    "logfiles.retention_days",
)


async def _postgres_logging(arm: ArmClient, server_id: str) -> dict[str, Any]:
    """Five PostgreSQL parameters by name (DECISIONS.md section 175). A name the
    server does not have fails that server's read, which is UNKNOWN downstream."""
    return {
        name: await arm.get_postgresql_parameter(server_id, name)
        for name in POSTGRES_LOGGING_PARAMETERS
    }


async def _sql_assessments(arm: ArmClient, server_id: str) -> dict[str, Any]:
    """Both forms of a SQL server's vulnerability assessment (section 176).

    Read together because either one answers "is this server assessed": the
    express configuration keeps its own results and needs no storage account,
    and the classic one needs a container to write to. A server may carry
    both, and a rule that read only one would fail servers the other covers.
    """
    return {
        "classic": await arm.get_sql_vulnerability_assessment(server_id),
        "express": await arm.get_sql_express_assessment(server_id),
    }


# Storage account kinds with no file service. Asking one for its file service
# is an error rather than an answer, and the checks on shares do not apply to
# it, so it is not asked (section 176).
_NO_FILE_SERVICE = frozenset({"blobstorage", "blockblobstorage"})


def _has_file_service(account: dict[str, Any]) -> bool:
    return str(account.get("kind") or "").lower() not in _NO_FILE_SERVICE


def _is_vpn_gateway(resource: dict[str, Any]) -> bool:
    return str(resource.get("type") or "").lower() == VPN_GATEWAY_TYPE


async def _storage_service_diagnostics(arm: ArmClient, account_id: str) -> dict[str, Any]:
    """The diagnostic settings of each service beneath one storage account,
    keyed by the service's own scope (section 204). Every service is asked,
    because the listing's kind is not passed here; a kind without the service
    answers with an error that stays on that service alone."""
    found: dict[str, Any] = {}
    for service in STORAGE_SERVICES:
        scope = f"{account_id}/{service}Services/default"
        try:
            found[scope] = await arm.list_diagnostic_settings(scope)
        except AzureApiError as exc:
            if exc.azure_status_code not in (400, 404):
                raise
            found[scope] = None
    return found


# How many per-resource detail calls one task runs at once. Enough to keep a
# scan brisk, low enough not to trip Azure's throttling on its own -- and now
# per task rather than global, since the executor already limits how many tasks
# are in flight.
DETAIL_CONCURRENCY = 8


# What each ARM listing calls, and the contract it calls under.
#
# Declared here beside the tasks rather than parsed out of ``client.py``: a
# parser would make the record a function of how the URL happens to be spelled,
# and the point is a statement that can be checked against the client rather
# than derived from it. ``tests/unit/test_provider_endpoints.py`` asserts every
# api-version below appears in the client, and that every ARM listing the client
# offers is declared by some task -- the same discipline ``rbac.py`` applies to
# actions, for the same reason: a declaration nothing verifies is a
# plausible-looking string.
ARM = "https://management.azure.com"

NSG_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Network/networkSecurityGroups",
    "2023-09-01",
)
NIC_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Network/networkInterfaces",
    "2023-09-01",
)
PUBLIC_IP_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Network/publicIPAddresses",
    "2023-09-01",
)
VM_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Compute/virtualMachines",
    "2023-09-01",
)
STORAGE_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Storage/storageAccounts",
    "2023-01-01",
)
SQL_SERVERS_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Sql/servers",
    "2021-11-01",
)
# The second call the SQL task makes, per server. Declared rather than folded
# into the one above, because a reading of servers whose firewall rules failed
# is a different reading from one where both succeeded.
SQL_FIREWALL_ENDPOINT = ProviderEndpoint(f"{ARM}/{{serverId}}/firewallRules", "2021-11-01")
# The third call the SQL task makes, per server, and declared for the same
# reason: a reading of servers whose auditing settings failed is a different
# reading from one where all three succeeded.
SQL_AUDITING_ENDPOINT = ProviderEndpoint(
    f"{ARM}/{{serverId}}/auditingSettings/default", "2021-11-01"
)
# The two calls behind encryption at rest, and the reason it is a task of its
# own: encryption is a per-database setting, so answering it means listing what
# a server holds and then asking each one -- a fan-out beneath a listing rather
# than another field on it.
SQL_DATABASES_ENDPOINT = ProviderEndpoint(f"{ARM}/{{serverId}}/databases", "2021-11-01")
SQL_TDE_ENDPOINT = ProviderEndpoint(f"{ARM}/{{databaseId}}/transparentDataEncryption", "2021-11-01")
SECURITY_ASSESSMENTS_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Security/assessments",
    "2020-01-01",
)
KEY_VAULT_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.KeyVault/vaults",
    "2023-07-01",
)
POSTGRES_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.DBforPostgreSQL/flexibleServers",
    "2023-03-01-preview",
)
# v9. Six listings of types the connector models from here on, each under the
# provider's generally available api-version as the published REST reference
# gave it on 2026-09-29 (DECISIONS.md section 169).
AKS_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.ContainerService/managedClusters",
    "2024-02-01",
)
ACR_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.ContainerRegistry/registries",
    "2023-07-01",
)
COSMOS_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.DocumentDB/databaseAccounts",
    "2024-11-15",
)
MYSQL_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.DBforMySQL/flexibleServers",
    "2023-12-30",
)
DATABRICKS_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Databricks/workspaces",
    "2024-05-01",
)
SEARCH_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Search/searchServices",
    "2023-11-01",
)
# v10. Two MySQL server parameters, each read by name beneath the listing
# (DECISIONS.md section 172).
MYSQL_SECURE_TRANSPORT_ENDPOINT = ProviderEndpoint(
    f"{ARM}/{{serverId}}/configurations/require_secure_transport", "2023-12-30"
)
MYSQL_TLS_VERSION_ENDPOINT = ProviderEndpoint(
    f"{ARM}/{{serverId}}/configurations/tls_version", "2023-12-30"
)
# Section 175. Further parameters by name under reads the role already holds.
MYSQL_PARAMETER_ENDPOINT = ProviderEndpoint(
    f"{ARM}/{{serverId}}/configurations/{{name}}", "2023-12-30"
)
POSTGRES_PARAMETER_ENDPOINT = ProviderEndpoint(
    f"{ARM}/{{serverId}}/configurations/{{name}}", "2023-03-01-preview"
)
# v7. Four fan-outs beneath listings the plan already takes, and two new
# listings.
SQL_ADMINISTRATORS_ENDPOINT = ProviderEndpoint(f"{ARM}/{{serverId}}/administrators", "2021-11-01")
POSTGRES_SECURE_TRANSPORT_ENDPOINT = ProviderEndpoint(
    f"{ARM}/{{serverId}}/configurations/require_secure_transport",
    "2023-03-01-preview",
)
BLOB_SERVICE_ENDPOINT = ProviderEndpoint(f"{ARM}/{{accountId}}/blobServices/default", "2023-01-01")
APP_SERVICES_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Web/sites",
    "2022-09-01",
)
APP_SERVICE_CONFIG_ENDPOINT = ProviderEndpoint(f"{ARM}/{{siteId}}/config/web", "2022-09-01")
SUBSCRIPTION_ENDPOINT = ProviderEndpoint(f"{ARM}/subscriptions/{{subscriptionId}}", "2022-12-01")
DEFENDER_PLANS_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Security/pricings",
    "2024-01-01",
)
ROLE_ASSIGNMENTS_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Authorization/roleAssignments",
    "2022-04-01",
)
ROLE_DEFINITIONS_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Authorization/roleDefinitions",
    "2022-04-01",
)
ROLE_ELIGIBILITIES_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Authorization"
    "/roleEligibilityScheduleInstances",
    "2020-10-01",
)
DIAGNOSTICS_ENDPOINT = ProviderEndpoint(
    f"{ARM}/{{resourceId}}/providers/Microsoft.Insights/diagnosticSettings",
    "2021-05-01-preview",
)
# v11 (DECISIONS.md section 176). Each api-version is the one whose contract
# the fields read were checked against, in the provider's REST specification,
# on 2026-09-30.
SQL_THREAT_DETECTION_ENDPOINT = ProviderEndpoint(
    f"{ARM}/{{serverId}}/securityAlertPolicies/Default", "2021-11-01"
)
SQL_ENCRYPTION_PROTECTOR_ENDPOINT = ProviderEndpoint(
    f"{ARM}/{{serverId}}/encryptionProtector/current", "2021-11-01"
)
SQL_VULNERABILITY_ASSESSMENT_ENDPOINT = ProviderEndpoint(
    f"{ARM}/{{serverId}}/vulnerabilityAssessments/default", "2021-11-01"
)
SQL_EXPRESS_ASSESSMENT_ENDPOINT = ProviderEndpoint(
    f"{ARM}/{{serverId}}/sqlVulnerabilityAssessments/default", "2023-08-01"
)
FILE_SERVICE_ENDPOINT = ProviderEndpoint(f"{ARM}/{{accountId}}/fileServices/default", "2023-01-01")
VAULT_KEYS_ENDPOINT = ProviderEndpoint(f"{ARM}/{{vaultId}}/keys", "2023-07-01")
VAULT_SECRETS_ENDPOINT = ProviderEndpoint(f"{ARM}/{{vaultId}}/secrets", "2023-07-01")
APP_SERVICE_AUTH_ENDPOINT = ProviderEndpoint(
    f"{ARM}/{{siteId}}/config/authsettingsV2", "2022-09-01"
)
SECURITY_CONTACTS_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Security/securityContacts",
    "2023-12-01-preview",
)
SECURITY_SETTINGS_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Security/settings",
    "2022-05-01",
)
IOT_SECURITY_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Security/iotSecuritySolutions",
    "2019-08-01",
)
JIT_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Security/jitNetworkAccessPolicies",
    "2020-01-01",
)
RECOVERY_VAULTS_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.RecoveryServices/vaults",
    "2023-04-01",
)
BACKUP_ITEMS_ENDPOINT = ProviderEndpoint(f"{ARM}/{{vaultId}}/backupProtectedItems", "2023-04-01")
# v12 (DECISIONS.md section 177).
BACKUP_POLICIES_ENDPOINT = ProviderEndpoint(f"{ARM}/{{vaultId}}/backupPolicies", "2023-04-01")
SCALE_SETS_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Compute/virtualMachineScaleSets",
    "2023-09-01",
)
DISKS_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Compute/disks",
    "2023-04-02",
)
ACTIVITY_LOG_ALERTS_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Insights/activityLogAlerts",
    "2020-10-01",
)
POLICY_ASSIGNMENTS_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Authorization/policyAssignments",
    "2022-06-01",
)
VIRTUAL_NETWORKS_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Network/virtualNetworks",
    "2023-09-01",
)
NETWORK_WATCHERS_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Network/networkWatchers",
    "2023-09-01",
)
FLOW_LOGS_ENDPOINT = ProviderEndpoint(f"{ARM}/{{watcherId}}/flowLogs", "2023-09-01")
BASTION_HOSTS_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Network/bastionHosts",
    "2023-09-01",
)
# v13 (DECISIONS.md section 204), each api-version the one whose contract the
# fields read were checked against on 2026-10-02.
APPLICATION_GATEWAYS_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Network/applicationGateways",
    "2023-09-01",
)
WAF_POLICIES_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Network"
    "/ApplicationGatewayWebApplicationFirewallPolicies",
    "2023-09-01",
)
VPN_GATEWAY_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/resourceGroups/{{resourceGroupName}}"
    "/providers/Microsoft.Network/virtualNetworkGateways/{gatewayName}",
    "2023-09-01",
)
LOCKS_ENDPOINT = ProviderEndpoint(
    f"{ARM}/subscriptions/{{subscriptionId}}/providers/Microsoft.Authorization/locks",
    "2020-05-01",
)
POSTGRES_FIREWALL_ENDPOINT = ProviderEndpoint(
    f"{ARM}/{{serverId}}/firewallRules", "2023-03-01-preview"
)
SUBSCRIPTION_POLICY_ENDPOINT = ProviderEndpoint(
    f"{ARM}/providers/Microsoft.Subscription/policies/default", "2021-10-01"
)
RESOURCE_GRAPH_ENDPOINT = ProviderEndpoint(
    f"{ARM}/providers/Microsoft.ResourceGraph/resources", "2022-10-01"
)

# Microsoft Graph versions itself in the path rather than in a query parameter,
# so "v1.0" is the api-version here in every sense that matters: it is the
# contract the response shape is a function of, which is the whole reason this
# is recorded. Writing it as a version rather than leaving it blank keeps the
# question answerable in the same terms for both providers.
GRAPH = "https://graph.microsoft.com/v1.0"
GRAPH_VERSION = "v1.0"

USERS_ENDPOINT = ProviderEndpoint(f"{GRAPH}/users", GRAPH_VERSION)
DIRECTORY_ROLES_ENDPOINT = ProviderEndpoint(f"{GRAPH}/directoryRoles", GRAPH_VERSION)
ROLE_MEMBERS_ENDPOINT = ProviderEndpoint(
    f"{GRAPH}/directoryRoles/{{roleId}}/members", GRAPH_VERSION
)
AUTH_METHODS_ENDPOINT = ProviderEndpoint(
    f"{GRAPH}/users/{{userId}}/authentication/methods", GRAPH_VERSION
)
AUTHORIZATION_POLICY_ENDPOINT = ProviderEndpoint(
    f"{GRAPH}/policies/authorizationPolicy", GRAPH_VERSION
)
AUTH_METHODS_POLICY_ENDPOINT = ProviderEndpoint(
    f"{GRAPH}/policies/authenticationMethodsPolicy", GRAPH_VERSION
)
GROUP_SETTINGS_ENDPOINT = ProviderEndpoint(f"{GRAPH}/groupSettings", GRAPH_VERSION)
NAMED_LOCATIONS_ENDPOINT = ProviderEndpoint(
    f"{GRAPH}/identity/conditionalAccess/namedLocations", GRAPH_VERSION
)
SECURITY_DEFAULTS_ENDPOINT = ProviderEndpoint(
    f"{GRAPH}/policies/identitySecurityDefaultsEnforcementPolicy", GRAPH_VERSION
)
CONDITIONAL_ACCESS_ENDPOINT = ProviderEndpoint(
    f"{GRAPH}/identity/conditionalAccess/policies", GRAPH_VERSION
)
GROUP_MEMBERS_ENDPOINT = ProviderEndpoint(f"{GRAPH}/groups/{{groupId}}/members", GRAPH_VERSION)
GROUPS_ENDPOINT = ProviderEndpoint(f"{GRAPH}/groups", GRAPH_VERSION)
DIRECTORY_ROLE_ELIGIBILITIES_ENDPOINT = ProviderEndpoint(
    f"{GRAPH}/roleManagement/directory/roleEligibilityScheduleInstances", GRAPH_VERSION
)
GROUP_TRANSITIVE_MEMBERS_ENDPOINT = ProviderEndpoint(
    f"{GRAPH}/groups/{{groupId}}/transitiveMembers", GRAPH_VERSION
)
APPLICATIONS_ENDPOINT = ProviderEndpoint(f"{GRAPH}/applications", GRAPH_VERSION)
APPLICATION_OWNERS_ENDPOINT = ProviderEndpoint(
    f"{GRAPH}/applications/{{applicationId}}/owners", GRAPH_VERSION
)
DEVICE_REGISTRATION_POLICY_ENDPOINT = ProviderEndpoint(
    f"{GRAPH}/policies/deviceRegistrationPolicy", GRAPH_VERSION
)
ACCESS_REVIEWS_ENDPOINT = ProviderEndpoint(
    f"{GRAPH}/identityGovernance/accessReviews/definitions", GRAPH_VERSION
)
SERVICE_PRINCIPALS_ENDPOINT = ProviderEndpoint(f"{GRAPH}/servicePrincipals", GRAPH_VERSION)
APP_ROLE_ASSIGNED_TO_ENDPOINT = ProviderEndpoint(
    f"{GRAPH}/servicePrincipals/{{servicePrincipalId}}/appRoleAssignedTo", GRAPH_VERSION
)

# Groups whose members one subscription's reading resolves. A subscription
# with more role-holding groups than this is read partially and says so; the
# bound is on calls, two per group, not on how many people a group holds.
ROLE_GROUP_LIMIT = 100
# Application registrations whose owners one scan reads, one call each. A
# tenant with more is read partially and says so.
APPLICATION_OWNER_LIMIT = 300
# Values Graph's ``in`` filter accepts in one call.
GRAPH_IN_FILTER_LIMIT = 15
# The ``$select`` is part of the path here and nowhere else, because it is part
# of the contract: ``/users`` alone returns no sign-in activity at all, and this
# is not the same read as USERS_ENDPOINT above however similar the URL looks.
SIGN_IN_ACTIVITY_ENDPOINT = ProviderEndpoint(
    f"{GRAPH}/users?$select=id,signInActivity", GRAPH_VERSION
)

# The reads behind the two SQL tasks, named once so a refused read's hint
# and the task's declared actions cannot drift apart.
SQL_AUDITING_ACTION = "Microsoft.Sql/servers/auditingSettings/read"
SQL_TDE_ACTIONS = (
    "Microsoft.Sql/servers/databases/read",
    "Microsoft.Sql/servers/databases/transparentDataEncryption/read",
)

# What Azure says when the tenant is consented correctly and simply not
# licensed for a reading. Graph refuses sign-in activity with a 403, "Neither
# tenant is B2C or tenant doesn't have premium license"; ARM and Graph both
# refuse Privileged Identity Management with a 400, "AadPremiumLicenseRequired:
# The tenant needs to have Microsoft Entra ID P2 or Microsoft Entra ID
# Governance license". Matched on the durable parts of those -- a refusal whose
# remedy is a licence has to be told apart from one whose remedy is a Global
# Administrator or a role redeploy, or the customer is sent to fix a connection
# that is already correct (section 196).
_UNLICENSED_MARKERS = (
    "premium license",
    "premium licence",
    "aadpremiumlicenserequired",
    "governance license",
)
_LICENCE_STATUSES = (400, 403)

SIGN_IN_LICENCE = (
    "Sign-in activity requires a Microsoft Entra ID P1 or P2 licence, which this "
    "tenant does not have. Admin consent cannot grant it, so dormant accounts "
    "cannot be assessed until the tenant is licensed."
)
PIM_LICENCE = (
    "Roles that could be activated under Privileged Identity Management are "
    "listed only for a tenant with a Microsoft Entra ID P2 or Governance licence, "
    "which this one does not have. No role or consent can grant it, so eligible "
    "roles stay unlisted until the tenant is licensed."
)


ACCESS_REVIEW_LICENCE = (
    "Access reviews are available only to a tenant with a Microsoft Entra ID P2 or "
    "Governance licence, which this one does not have, so whether guests are "
    "reviewed cannot be assessed until the tenant is licensed."
)


def _refused_for_licence(exc: AzureApiError) -> bool:
    """Whether Azure attributed this refusal to the tenant's licence."""
    return exc.azure_status_code in _LICENCE_STATUSES and any(
        marker in str(exc).lower() for marker in _UNLICENSED_MARKERS
    )


def _encryption_state(payload: dict[str, Any]) -> str | None:
    """The state ARM reports for one database's encryption.

    The provider models this as a collection holding a single member named
    ``current``, so the answer arrives wrapped in a listing. ``None`` where the
    response holds no state at all, which is not the same as "Disabled" and must
    not be read as one.
    """
    values = payload.get("value")
    entry = values[0] if isinstance(values, list) and values else payload
    if not isinstance(entry, dict):
        return None
    state = (entry.get("properties") or {}).get("state")
    return str(state) if state is not None else None


def _per_resource_reason(
    noun: str, of: str, failures: list[Exception], total: int, actions: tuple[str, ...]
) -> str:
    """Why a per-resource reading came back short, blaming the role only when the role refused.

    Every failure used to be reported as an out-of-date role, so a 404, a 400 from an API
    version, a timeout or a block at Microsoft's edge sent the customer to redeploy a role that
    was already current. Only ARM's own 403 across every failure names the role; anything else
    quotes the first error, which is what the worker's ``azure.request_failed`` line explains.
    """
    head = f"{noun} could not be read for {len(failures)} of {total} {of}."
    refused_by_role = all(
        isinstance(exc, AzureApiError)
        and exc.azure_status_code == 403
        and EDGE_BLOCK_MESSAGE not in str(exc)
        for exc in failures
    )
    if refused_by_role:
        return (
            f"{head} A scanner role deployed before {first_version_granting(*actions)} "
            "does not grant the permission this needs."
        )
    if all(_is_disabled_account(exc) for exc in failures):
        # A state of the resource, not a failed read: nobody can read these settings while
        # the account is off, and they stay unknown rather than passing (section 200).
        return (
            f"{head} Azure has disabled these {of}, which it does when their subscription is "
            "disabled or past due; their settings cannot be read by anyone until the "
            "subscription is active again."
        )
    return f"{head} The first failure: {failures[0]}"


def _is_disabled_account(exc: Exception) -> bool:
    """Azure's refusal for a storage account it has switched off.

    Two spellings, one per service: the file service answers ``AccountIsDisabled`` and the
    blob service ``ContainerOperationFailure: The specified account is disabled``.
    """
    text = str(exc)
    return isinstance(exc, AzureApiError) and (
        "AccountIsDisabled" in text or "account is disabled" in text.lower()
    )


class AzurePlanBuilder:
    """Builds the task lists a scan runs.

    ``subscription_id`` is optional because the directory plan does not need
    one: it reads the tenant, and the tenant is whichever one the token
    provider authenticates against. Building an account plan without a
    subscription is refused rather than allowed to produce URLs with ``None``
    in them.
    """

    def __init__(
        self,
        tokens: TokenProvider,
        subscription_id: str | None,
        http_client: httpx.AsyncClient,
        limiter: RequestLimiter | None = None,
    ) -> None:
        self.tokens = tokens
        self.subscription_id = subscription_id
        self._http = http_client
        # Handed to every client the plan builds, so the ceiling covers the
        # whole run rather than each task separately. DETAIL_CONCURRENCY below
        # still bounds one task's fan-out; that is fairness inside a wave, and
        # this is what keeps the product of the two off the subscription.
        self._limiter = limiter

    # ------------------------------------------------------------- plumbing
    def _arm_task(
        self,
        key: AzureEvidence,
        actions: tuple[str, ...],
        call: Callable[[ArmClient], Awaitable[dict[str, Any] | TaskData]],
        depends_on: tuple[AzureEvidence, ...] = (),
        endpoints: tuple[ProviderEndpoint, ...] = (),
    ) -> CollectionTask:
        """Wrap one ARM listing, turning truncation into a PARTIAL result.

        The client is created inside the task so its ``truncated`` set belongs
        to this task alone. Without that, a truncated listing during a
        concurrent wave could be attributed to the wrong task, and a PARTIAL
        pointing at the wrong data is worse than no PARTIAL at all.

        A call may return ``TaskData`` rather than a plain dict when it knows
        something about its own completeness that the wrapper cannot see. The
        SQL task does: it makes two further calls per server, and a role that
        cannot read one of them produces a full listing of servers whose
        settings are missing. Both reasons are reported when both apply, since
        a truncated listing of partially-read servers is two problems.
        """

        async def run(collected: dict[str, Any]) -> TaskData:
            arm = ArmClient(self.tokens, self._http, limiter=self._limiter)
            result = await call(arm)
            outcome = result if isinstance(result, TaskData) else TaskData(result)
            if not arm.truncated:
                return outcome

            truncation = (
                "the listing was longer than Cleave reads in one scan, "
                "so these results are incomplete and cannot support a pass"
            )
            return TaskData(
                outcome.data,
                partial_reason=(
                    f"{truncation}; and {outcome.partial_reason}"
                    if outcome.partial_reason
                    else truncation
                ),
            )

        return CollectionTask(
            key=key,
            run=run,
            depends_on=depends_on,
            actions=actions,
            endpoints=endpoints,
        )

    async def _gather_limited(self, coros: list[Awaitable[Any]]) -> list[Any]:
        semaphore = asyncio.Semaphore(DETAIL_CONCURRENCY)

        async def bounded(coro: Awaitable[Any]) -> Any:
            async with semaphore:
                return await coro

        return list(await asyncio.gather(*(bounded(c) for c in coros)))

    # ----------------------------------------------------------------- plans
    def build_account_plan(self) -> list[CollectionTask]:
        """Everything that is a reading of one subscription.

        No Graph task belongs here. A directory read placed in this plan runs
        once per subscription and is the same answer every time, which is both
        the cost and the correctness problem this split exists to fix.
        """
        if not self.subscription_id:
            raise ValueError("An account plan reads one subscription and needs its id")
        sub = self.subscription_id

        async def nsgs(arm: ArmClient) -> dict[str, Any]:
            return {"network_security_groups": await arm.list_network_security_groups(sub)}

        async def nics(arm: ArmClient) -> dict[str, Any]:
            return {"network_interfaces": await arm.list_network_interfaces(sub)}

        async def public_ips(arm: ArmClient) -> dict[str, Any]:
            return {"public_ip_addresses": await arm.list_public_ips(sub)}

        async def vms(arm: ArmClient) -> dict[str, Any]:
            return {"virtual_machines": await arm.list_virtual_machines(sub)}

        async def storage(arm: ArmClient) -> dict[str, Any]:
            return {"storage_accounts": await arm.list_storage_accounts(sub)}

        async def security_assessments(arm: ArmClient) -> dict[str, Any]:
            return {"security_assessments": await arm.list_security_assessments(sub)}

        async def key_vaults(arm: ArmClient) -> dict[str, Any]:
            return {"key_vaults": await arm.list_key_vaults(sub)}

        async def postgres(arm: ArmClient) -> dict[str, Any]:
            return {"postgresql_servers": await arm.list_postgresql_servers(sub)}

        async def kubernetes_clusters(arm: ArmClient) -> dict[str, Any]:
            return {"kubernetes_clusters": await arm.list_kubernetes_clusters(sub)}

        async def container_registries(arm: ArmClient) -> dict[str, Any]:
            return {"container_registries": await arm.list_container_registries(sub)}

        async def cosmos_accounts(arm: ArmClient) -> dict[str, Any]:
            return {"cosmos_accounts": await arm.list_cosmos_accounts(sub)}

        async def mysql_servers(arm: ArmClient) -> dict[str, Any]:
            return {"mysql_servers": await arm.list_mysql_servers(sub)}

        async def databricks_workspaces(arm: ArmClient) -> dict[str, Any]:
            return {"databricks_workspaces": await arm.list_databricks_workspaces(sub)}

        async def search_services(arm: ArmClient) -> dict[str, Any]:
            return {"search_services": await arm.list_search_services(sub)}

        async def app_services(arm: ArmClient) -> dict[str, Any]:
            return {"app_services": await arm.list_app_services(sub)}

        # v11 (section 176). Subscription-wide listings, one key each.
        async def security_contacts(arm: ArmClient) -> dict[str, Any]:
            return {"security_contacts": await arm.list_security_contacts(sub)}

        async def security_settings(arm: ArmClient) -> dict[str, Any]:
            return {"security_settings": await arm.list_security_settings(sub)}

        async def iot_security(arm: ArmClient) -> dict[str, Any]:
            return {"iot_security_solutions": await arm.list_iot_security_solutions(sub)}

        async def jit_policies(arm: ArmClient) -> dict[str, Any]:
            return {"jit_policies": await arm.list_jit_policies(sub)}

        async def disks(arm: ArmClient) -> dict[str, Any]:
            return {"disks": await arm.list_disks(sub)}

        async def activity_log_alerts(arm: ArmClient) -> dict[str, Any]:
            return {"activity_log_alerts": await arm.list_activity_log_alerts(sub)}

        async def policy_assignments(arm: ArmClient) -> dict[str, Any]:
            return {"policy_assignments": await arm.list_policy_assignments(sub)}

        async def virtual_networks(arm: ArmClient) -> dict[str, Any]:
            return {"virtual_networks": await arm.list_virtual_networks(sub)}

        async def network_watchers(arm: ArmClient) -> dict[str, Any]:
            return {"network_watchers": await arm.list_network_watchers(sub)}

        async def bastion_hosts(arm: ArmClient) -> dict[str, Any]:
            return {"bastion_hosts": await arm.list_bastion_hosts(sub)}

        async def scale_sets(arm: ArmClient) -> dict[str, Any]:
            return {"scale_sets": await arm.list_scale_sets(sub)}

        # v13 (section 204).
        async def application_gateways(arm: ArmClient) -> dict[str, Any]:
            return {"application_gateways": await arm.list_application_gateways(sub)}

        async def waf_policies(arm: ArmClient) -> dict[str, Any]:
            return {"waf_policies": await arm.list_waf_policies(sub)}

        async def locks(arm: ArmClient) -> dict[str, Any]:
            return {"resource_locks": await arm.list_locks(sub)}

        async def subscription(arm: ArmClient) -> dict[str, Any]:
            return {"subscription": await arm.get_subscription(sub)}

        async def defender_plans(arm: ArmClient) -> dict[str, Any]:
            return {"defender_plans": await arm.list_defender_plans(sub)}

        async def role_assignments(arm: ArmClient) -> dict[str, Any]:
            """Who holds which role over what, inside this subscription.

            The half of "who can do what" that ARM answers. The directory says
            which principals exist; this says what they are allowed to do, and
            a tenant can have a perfectly readable directory alongside no
            visibility into this at all -- the two are different grants.
            """
            return {"role_assignments": await arm.list_role_assignments(sub)}

        async def role_eligibilities(arm: ArmClient) -> dict[str, Any]:
            """Roles a principal could activate rather than holds (section 130).

            ARM refuses this with a 400 in a tenant without the licence PIM
            needs, which is a fact about the tenant rather than a failure
            (section 196).
            """
            try:
                found = await arm.list_role_eligibilities(sub)
            except AzureApiError as exc:
                if _refused_for_licence(exc):
                    raise ReadingUnavailable(PIM_LICENCE) from exc
                raise
            return {"role_eligibilities": found}

        async def role_definitions(arm: ArmClient) -> dict[str, Any]:
            """What each role actually permits.

            Collected beside the assignments because an assignment on its own
            names a GUID. "Contributor over this subscription" and "Reader over
            one storage account" are the same shape of row, and only the
            definition tells them apart.
            """
            return {"role_definitions": await arm.list_role_definitions(sub)}

        async def sql(arm: ArmClient) -> TaskData:
            servers = await arm.list_sql_servers(sub)

            # Firewall rules are a per-server call; without them AZ-DB-001
            # cannot tell "locked down" from "open to the world". A server
            # whose rules failed carries the reason, so the rule degrades for
            # that server rather than for the whole subscription.
            async def with_rules(server: dict[str, Any]) -> dict[str, Any]:
                try:
                    server["_firewall_rules"] = await arm.list_sql_firewall_rules(server["id"])
                except Exception as exc:
                    server["_firewall_rules_error"] = str(exc)
                return server

            read = await self._gather_limited([with_rules(s) for s in servers])

            # A server whose firewall rules or auditing settings could not be
            # read is a server CloudGuard listed and did not finish reading, and
            # the reading has to say so. It used to come back COMPLETE: the
            # per-server failure was recorded on the server for the rules to
            # degrade on, and the collection panel -- the one screen whose job
            # is saying what was and was not read -- reported the whole task as
            # read in full.
            #
            # That gap is exactly what a role upgrade produces. A customer on a
            # role predating v4 gets a 403 on every auditing call while the
            # server listing and firewall rules succeed, so every SQL server
            # they own reports UNKNOWN against a task claiming it read
            # everything.
            data = {"sql_servers": read}
            unread = sum(1 for s in read if "_firewall_rules_error" in s)
            if not unread:
                return TaskData(data)
            return TaskData(
                data,
                partial_reason=(
                    f"firewall rules could not be read for {unread} of {len(read)} servers"
                ),
            )

        tasks = [
            self._arm_task(
                AzureEvidence.NETWORK_SECURITY_GROUPS,
                ("Microsoft.Network/networkSecurityGroups/read",),
                nsgs,
                endpoints=(NSG_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.NETWORK_INTERFACES,
                ("Microsoft.Network/networkInterfaces/read",),
                nics,
                endpoints=(NIC_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.PUBLIC_IP_ADDRESSES,
                ("Microsoft.Network/publicIPAddresses/read",),
                public_ips,
                endpoints=(PUBLIC_IP_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.VIRTUAL_MACHINES,
                ("Microsoft.Compute/virtualMachines/read",),
                vms,
                endpoints=(VM_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.STORAGE_ACCOUNTS,
                ("Microsoft.Storage/storageAccounts/read",),
                storage,
                endpoints=(STORAGE_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.SQL_SERVERS,
                (
                    "Microsoft.Sql/servers/read",
                    "Microsoft.Sql/servers/firewallRules/read",
                ),
                sql,
                endpoints=(SQL_SERVERS_ENDPOINT, SQL_FIREWALL_ENDPOINT),
            ),
            self._arm_task(
                AzureEvidence.SECURITY_ASSESSMENTS,
                ("Microsoft.Security/assessments/read",),
                security_assessments,
                endpoints=(SECURITY_ASSESSMENTS_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.KEY_VAULTS,
                ("Microsoft.KeyVault/vaults/read",),
                key_vaults,
                endpoints=(KEY_VAULT_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.POSTGRESQL_SERVERS,
                ("Microsoft.DBforPostgreSQL/flexibleServers/read",),
                postgres,
                endpoints=(POSTGRES_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.APP_SERVICES,
                ("Microsoft.Web/sites/read",),
                app_services,
                endpoints=(APP_SERVICES_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.KUBERNETES_CLUSTERS,
                ("Microsoft.ContainerService/managedClusters/read",),
                kubernetes_clusters,
                endpoints=(AKS_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.CONTAINER_REGISTRIES,
                ("Microsoft.ContainerRegistry/registries/read",),
                container_registries,
                endpoints=(ACR_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.COSMOS_ACCOUNTS,
                ("Microsoft.DocumentDB/databaseAccounts/read",),
                cosmos_accounts,
                endpoints=(COSMOS_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.MYSQL_SERVERS,
                ("Microsoft.DBforMySQL/flexibleServers/read",),
                mysql_servers,
                endpoints=(MYSQL_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.DATABRICKS_WORKSPACES,
                ("Microsoft.Databricks/workspaces/read",),
                databricks_workspaces,
                endpoints=(DATABRICKS_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.SEARCH_SERVICES,
                ("Microsoft.Search/searchServices/read",),
                search_services,
                endpoints=(SEARCH_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.SUBSCRIPTION,
                ("Microsoft.Resources/subscriptions/read",),
                subscription,
                endpoints=(SUBSCRIPTION_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.DEFENDER_PLANS,
                ("Microsoft.Security/pricings/read",),
                defender_plans,
                endpoints=(DEFENDER_PLANS_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.ROLE_ASSIGNMENTS,
                ("Microsoft.Authorization/roleAssignments/read",),
                role_assignments,
                endpoints=(ROLE_ASSIGNMENTS_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.ROLE_DEFINITIONS,
                ("Microsoft.Authorization/roleDefinitions/read",),
                role_definitions,
                endpoints=(ROLE_DEFINITIONS_ENDPOINT,),
            ),
            self._role_group_members_task(),
            self._arm_task(
                AzureEvidence.ROLE_ELIGIBILITIES,
                ("Microsoft.Authorization/roleEligibilityScheduleInstances/read",),
                role_eligibilities,
                endpoints=(ROLE_ELIGIBILITIES_ENDPOINT,),
            ),
            self._inventory_task(),
            self._sql_auditing_task(),
            self._sql_tde_task(),
            self._per_resource_task(
                AzureEvidence.SQL_ADMINISTRATORS,
                source=AzureEvidence.SQL_SERVERS,
                action="Microsoft.Sql/servers/administrators/read",
                endpoint=SQL_ADMINISTRATORS_ENDPOINT,
                read=lambda arm, server_id: arm.list_sql_administrators(server_id),
                noun="Entra administrators",
                of="servers",
            ),
            self._per_resource_task(
                AzureEvidence.POSTGRESQL_CONFIGURATIONS,
                source=AzureEvidence.POSTGRESQL_SERVERS,
                action="Microsoft.DBforPostgreSQL/flexibleServers/configurations/read",
                endpoint=POSTGRES_SECURE_TRANSPORT_ENDPOINT,
                read=lambda arm, server_id: arm.get_postgresql_secure_transport(server_id),
                noun="the TLS requirement",
                of="PostgreSQL servers",
            ),
            self._per_resource_task(
                AzureEvidence.MYSQL_CONFIGURATIONS,
                source=AzureEvidence.MYSQL_SERVERS,
                action="Microsoft.DBforMySQL/flexibleServers/configurations/read",
                endpoint=MYSQL_SECURE_TRANSPORT_ENDPOINT,
                also=(MYSQL_TLS_VERSION_ENDPOINT, MYSQL_PARAMETER_ENDPOINT),
                read=_mysql_parameters,
                noun="the TLS parameters",
                of="MySQL servers",
            ),
            self._per_resource_task(
                AzureEvidence.POSTGRESQL_LOGGING,
                source=AzureEvidence.POSTGRESQL_SERVERS,
                action="Microsoft.DBforPostgreSQL/flexibleServers/configurations/read",
                endpoint=POSTGRES_PARAMETER_ENDPOINT,
                read=_postgres_logging,
                noun="the logging parameters",
                of="PostgreSQL servers",
            ),
            self._per_resource_task(
                AzureEvidence.STORAGE_BLOB_SERVICES,
                source=AzureEvidence.STORAGE_ACCOUNTS,
                action="Microsoft.Storage/storageAccounts/blobServices/read",
                endpoint=BLOB_SERVICE_ENDPOINT,
                read=lambda arm, account_id: arm.get_blob_service(account_id),
                noun="blob recovery settings",
                of="storage accounts",
            ),
            self._per_resource_task(
                AzureEvidence.APP_SERVICE_CONFIGS,
                source=AzureEvidence.APP_SERVICES,
                action="Microsoft.Web/sites/config/read",
                endpoint=APP_SERVICE_CONFIG_ENDPOINT,
                read=lambda arm, site_id: arm.get_app_service_config(site_id),
                noun="configuration",
                of="apps",
            ),
            # v11 (section 176).
            self._arm_task(
                AzureEvidence.SECURITY_CONTACTS,
                ("Microsoft.Security/securityContacts/read",),
                security_contacts,
                endpoints=(SECURITY_CONTACTS_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.SECURITY_SETTINGS,
                ("Microsoft.Security/settings/read",),
                security_settings,
                endpoints=(SECURITY_SETTINGS_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.IOT_SECURITY_SOLUTIONS,
                ("Microsoft.Security/iotSecuritySolutions/read",),
                iot_security,
                endpoints=(IOT_SECURITY_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.JIT_POLICIES,
                (
                    "Microsoft.Security/jitNetworkAccessPolicies/read",
                    "Microsoft.Security/locations/jitNetworkAccessPolicies/read",
                ),
                jit_policies,
                endpoints=(JIT_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.DISKS,
                ("Microsoft.Compute/disks/read",),
                disks,
                endpoints=(DISKS_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.ACTIVITY_LOG_ALERTS,
                ("Microsoft.Insights/activityLogAlerts/read",),
                activity_log_alerts,
                endpoints=(ACTIVITY_LOG_ALERTS_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.POLICY_ASSIGNMENTS,
                ("Microsoft.Authorization/policyAssignments/read",),
                policy_assignments,
                endpoints=(POLICY_ASSIGNMENTS_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.VIRTUAL_NETWORKS,
                ("Microsoft.Network/virtualNetworks/read",),
                virtual_networks,
                endpoints=(VIRTUAL_NETWORKS_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.NETWORK_WATCHERS,
                ("Microsoft.Network/networkWatchers/read",),
                network_watchers,
                endpoints=(NETWORK_WATCHERS_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.BASTION_HOSTS,
                ("Microsoft.Network/bastionHosts/read",),
                bastion_hosts,
                endpoints=(BASTION_HOSTS_ENDPOINT,),
            ),
            self._per_resource_task(
                AzureEvidence.FLOW_LOGS,
                source=AzureEvidence.NETWORK_WATCHERS,
                action="Microsoft.Network/networkWatchers/flowLogs/read",
                endpoint=FLOW_LOGS_ENDPOINT,
                read=lambda arm, watcher_id: arm.list_flow_logs(watcher_id),
                noun="flow logs",
                of="network watchers",
            ),
            self._per_resource_task(
                AzureEvidence.SQL_THREAT_DETECTION,
                source=AzureEvidence.SQL_SERVERS,
                action="Microsoft.Sql/servers/securityAlertPolicies/read",
                endpoint=SQL_THREAT_DETECTION_ENDPOINT,
                read=lambda arm, server_id: arm.get_sql_threat_detection(server_id),
                noun="Defender for SQL settings",
                of="servers",
            ),
            self._per_resource_task(
                AzureEvidence.SQL_ENCRYPTION_PROTECTOR,
                source=AzureEvidence.SQL_SERVERS,
                action="Microsoft.Sql/servers/encryptionProtector/read",
                endpoint=SQL_ENCRYPTION_PROTECTOR_ENDPOINT,
                read=lambda arm, server_id: arm.get_sql_encryption_protector(server_id),
                noun="the encryption protector",
                of="servers",
            ),
            self._per_resource_task(
                AzureEvidence.SQL_VULNERABILITY_ASSESSMENT,
                source=AzureEvidence.SQL_SERVERS,
                action="Microsoft.Sql/servers/vulnerabilityAssessments/read",
                also_actions=("Microsoft.Sql/servers/sqlVulnerabilityAssessments/read",),
                endpoint=SQL_VULNERABILITY_ASSESSMENT_ENDPOINT,
                also=(SQL_EXPRESS_ASSESSMENT_ENDPOINT,),
                read=_sql_assessments,
                noun="vulnerability assessment settings",
                of="servers",
            ),
            self._per_resource_task(
                AzureEvidence.STORAGE_FILE_SERVICES,
                source=AzureEvidence.STORAGE_ACCOUNTS,
                action="Microsoft.Storage/storageAccounts/fileServices/read",
                endpoint=FILE_SERVICE_ENDPOINT,
                read=lambda arm, account_id: arm.get_file_service(account_id),
                noun="file share settings",
                of="storage accounts",
                where=_has_file_service,
            ),
            self._per_resource_task(
                AzureEvidence.KEY_VAULT_KEYS,
                source=AzureEvidence.KEY_VAULTS,
                action="Microsoft.KeyVault/vaults/keys/read",
                endpoint=VAULT_KEYS_ENDPOINT,
                read=lambda arm, vault_id: arm.list_vault_keys(vault_id),
                noun="key attributes",
                of="vaults",
            ),
            self._per_resource_task(
                AzureEvidence.KEY_VAULT_SECRETS,
                source=AzureEvidence.KEY_VAULTS,
                action="Microsoft.KeyVault/vaults/secrets/read",
                endpoint=VAULT_SECRETS_ENDPOINT,
                read=lambda arm, vault_id: arm.list_vault_secrets(vault_id),
                noun="secret attributes",
                of="vaults",
            ),
            self._per_resource_task(
                AzureEvidence.APP_SERVICE_AUTH,
                source=AzureEvidence.APP_SERVICES,
                action="Microsoft.Web/sites/config/read",
                endpoint=APP_SERVICE_AUTH_ENDPOINT,
                read=lambda arm, site_id: arm.get_app_service_auth(site_id),
                noun="authentication settings",
                of="apps",
            ),
            self._vm_backups_task(),
            self._backup_policies_task(),
            self._arm_task(
                AzureEvidence.SCALE_SETS,
                ("Microsoft.Compute/virtualMachineScaleSets/read",),
                scale_sets,
                endpoints=(SCALE_SETS_ENDPOINT,),
            ),
            self._diagnostics_task(),
            # v13 (section 204).
            self._arm_task(
                AzureEvidence.APPLICATION_GATEWAYS,
                ("Microsoft.Network/applicationGateways/read",),
                application_gateways,
                endpoints=(APPLICATION_GATEWAYS_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.WAF_POLICIES,
                ("Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies/read",),
                waf_policies,
                endpoints=(WAF_POLICIES_ENDPOINT,),
            ),
            self._arm_task(
                AzureEvidence.RESOURCE_LOCKS,
                ("Microsoft.Authorization/locks/read",),
                locks,
                endpoints=(LOCKS_ENDPOINT,),
            ),
            self._per_resource_task(
                AzureEvidence.VPN_GATEWAYS,
                source=AzureEvidence.RESOURCES,
                action="Microsoft.Network/virtualNetworkGateways/read",
                endpoint=VPN_GATEWAY_ENDPOINT,
                read=lambda arm, gateway_id: arm.get_virtual_network_gateway(gateway_id),
                noun="gateway configuration",
                of="virtual network gateways",
                where=_is_vpn_gateway,
            ),
            self._per_resource_task(
                AzureEvidence.POSTGRESQL_FIREWALL_RULES,
                source=AzureEvidence.POSTGRESQL_SERVERS,
                action="Microsoft.DBforPostgreSQL/flexibleServers/firewallRules/read",
                endpoint=POSTGRES_FIREWALL_ENDPOINT,
                read=lambda arm, server_id: arm.list_postgresql_firewall_rules(server_id),
                noun="firewall rules",
                of="PostgreSQL servers",
            ),
            self._per_resource_task(
                AzureEvidence.STORAGE_SERVICE_DIAGNOSTICS,
                source=AzureEvidence.STORAGE_ACCOUNTS,
                action="Microsoft.Insights/diagnosticSettings/read",
                endpoint=DIAGNOSTICS_ENDPOINT,
                read=_storage_service_diagnostics,
                noun="service diagnostic settings",
                of="storage accounts",
            ),
            self._per_resource_task(
                AzureEvidence.DATABRICKS_DIAGNOSTICS,
                source=AzureEvidence.DATABRICKS_WORKSPACES,
                action="Microsoft.Insights/diagnosticSettings/read",
                endpoint=DIAGNOSTICS_ENDPOINT,
                read=lambda arm, workspace_id: arm.list_diagnostic_settings(workspace_id),
                noun="diagnostic settings",
                of="Databricks workspaces",
            ),
        ]
        return tasks

    def _per_resource_task(
        self,
        key: AzureEvidence,
        *,
        source: AzureEvidence,
        action: str,
        endpoint: ProviderEndpoint,
        read: Callable[[ArmClient, str], Awaitable[Any]],
        noun: str,
        of: str,
        also: tuple[ProviderEndpoint, ...] = (),
        also_actions: tuple[str, ...] = (),
        where: Callable[[dict[str, Any]], bool] | None = None,
    ) -> CollectionTask:
        """One read per resource another listing produced, keyed by its id.

        The shape the auditing task has, written once for the four v7 readings
        that share it rather than four more times. Each is a dependent task
        rather than a further call inside its listing, for the reason auditing
        is: the rule that reads it and the rules that read the listing rest on
        different evidence, and a role predating v7 must cost exactly the
        first.

        A resource whose read failed is recorded as ``"error: ..."`` against its
        own id, so one refusal costs one resource its verdict and the task says
        how many -- naming the role only when every failure was ARM's 403,
        which is what a v6 role produces (``_per_resource_reason``).
        """

        async def run(collected: dict[str, Any]) -> TaskData:
            arm = ArmClient(self.tokens, self._http, limiter=self._limiter)
            ids = [
                item["id"]
                for item in collected.get(source, [])
                if item.get("id") and (where is None or where(item))
            ]

            failures: list[Exception] = []

            async def for_resource(resource_id: str) -> tuple[str, Any]:
                try:
                    return resource_id, await read(arm, resource_id)
                except Exception as exc:
                    failures.append(exc)
                    return resource_id, f"error: {exc}"

            pairs = await self._gather_limited([for_resource(i) for i in ids])
            data = {key.value: dict(pairs)}

            # A per-resource listing -- a vault's keys, a watcher's flow logs --
            # can be longer than one scan reads, and a short list is not a
            # clean one (section 176).
            if arm.truncated:
                return TaskData(
                    data,
                    partial_reason=f"the {noun} of one of these {of} ran longer than one "
                    "scan reads, so these results cannot support a pass",
                )
            if failures:
                return TaskData(
                    data,
                    partial_reason=_per_resource_reason(
                        noun, of, failures, len(ids), (action, *also_actions)
                    ),
                )
            return TaskData(data)

        return CollectionTask(
            key=key,
            run=run,
            depends_on=(source,),
            actions=(action, *also_actions),
            endpoints=(endpoint, *also),
        )

    def _vm_backups_task(self) -> CollectionTask:
        """Which virtual machines Azure Backup protects (section 176).

        Two readings: the subscription's Recovery Services vaults, then the
        machines each one backs up. Kept as the list of protected items rather
        than a verdict per machine, because a vault can protect a machine in
        another subscription and a machine can be protected from one: the
        normalizer joins them on the machine's id.

        A vault whose items could not be read is named, and the task is
        partial, so a machine it might protect is UNKNOWN rather than
        unprotected.
        """
        sub = self.subscription_id
        if not sub:
            raise ValueError("The backup task reads one subscription")

        async def run(collected: dict[str, Any]) -> TaskData:
            arm = ArmClient(self.tokens, self._http, limiter=self._limiter)
            # The vault records themselves, not only their ids: since section
            # 177 each vault is an asset of its own.
            vaults = [v for v in await arm.list_recovery_vaults(sub) if v.get("id")]
            unread: list[str] = []

            async def items_of(vault_id: str) -> list[dict[str, Any]]:
                try:
                    return await arm.list_backup_protected_items(vault_id)
                except Exception as exc:
                    log.warning("azure.backup_items_failed", error=str(exc))
                    unread.append(vault_id)
                    return []

            found = await self._gather_limited([items_of(v["id"]) for v in vaults])
            data = {
                "vm_backups": {
                    "vaults": vaults,
                    "unread_vaults": unread,
                    "items": [item for items in found for item in items],
                }
            }
            reasons = []
            if unread:
                reasons.append(
                    f"protected items could not be read for {len(unread)} of "
                    f"{len(vaults)} Recovery Services vaults"
                )
            if arm.truncated:
                reasons.append("a vault protects more items than one scan reads")
            return TaskData(data, partial_reason="; ".join(reasons) if reasons else None)

        return CollectionTask(
            key=AzureEvidence.VM_BACKUPS,
            run=run,
            actions=(
                "Microsoft.RecoveryServices/Vaults/read",
                "Microsoft.RecoveryServices/Vaults/backupProtectedItems/read",
            ),
            endpoints=(RECOVERY_VAULTS_ENDPOINT, BACKUP_ITEMS_ENDPOINT),
        )

    def _backup_policies_task(self) -> CollectionTask:
        """How long each Recovery Services vault keeps its recovery points
        (section 177). Keyed by vault, with a failed read recorded against the
        vault as ``"error: ..."`` so it costs that vault's verdicts alone."""

        async def run(collected: dict[str, Any]) -> TaskData:
            arm = ArmClient(self.tokens, self._http, limiter=self._limiter)
            backups = collected.get(AzureEvidence.VM_BACKUPS.value) or {}
            ids = [
                str(v["id"])
                for v in backups.get("vaults") or []
                if isinstance(v, dict) and v.get("id")
            ]
            failures = 0

            async def for_vault(vault_id: str) -> tuple[str, Any]:
                nonlocal failures
                try:
                    return vault_id, await arm.list_backup_policies(vault_id)
                except Exception as exc:
                    failures += 1
                    return vault_id, f"error: {exc}"

            pairs = await self._gather_limited([for_vault(v) for v in ids])
            data = {AzureEvidence.BACKUP_POLICIES.value: dict(pairs)}
            if failures or arm.truncated:
                return TaskData(
                    data,
                    partial_reason=(
                        f"backup policies could not be read for {failures} of {len(ids)} vaults"
                        if failures
                        else "a vault holds more backup policies than one scan reads"
                    ),
                )
            return TaskData(data)

        return CollectionTask(
            key=AzureEvidence.BACKUP_POLICIES,
            run=run,
            depends_on=(AzureEvidence.VM_BACKUPS,),
            actions=("Microsoft.RecoveryServices/Vaults/backupPolicies/read",),
            endpoints=(BACKUP_POLICIES_ENDPOINT,),
        )

    def _sql_auditing_task(self) -> CollectionTask:
        """Whether each SQL server records who queried it.

        A dependent task rather than a third call inside the server listing,
        and the reason is what a key means. A rule declares the evidence its
        verdict rests on, and these two rest on different things: AZ-DB-001
        judges reachability from the servers and their firewall rules, AZ-DB-003
        judges the audit trail from this. Folded into one key, a 403 here --
        which is exactly what a role predating v4 produces -- cost the
        reachability rule its verdict too, over a call it never reads. That is
        the gap CloudGuard invents rather than finds, and it is the same mistake
        ``requires_evidence`` was introduced to stop one layer up.

        Keyed per server like the diagnostics task, and for the same reason: a
        server whose settings failed is one server's audit posture unknown, not
        every server's.
        """

        async def run(collected: dict[str, Any]) -> TaskData:
            arm = ArmClient(self.tokens, self._http, limiter=self._limiter)
            servers = [
                server["id"]
                for server in collected.get(AzureEvidence.SQL_SERVERS, [])
                if server.get("id")
            ]

            failures = 0

            async def for_server(server_id: str) -> tuple[str, dict | str]:
                nonlocal failures
                try:
                    return server_id, await arm.get_sql_auditing_settings(server_id)
                except Exception as exc:
                    failures += 1
                    return server_id, f"error: {exc}"

            pairs = await self._gather_limited([for_server(s) for s in servers])
            data = {"sql_auditing": dict(pairs)}

            if failures:
                return TaskData(
                    data,
                    partial_reason=(
                        f"auditing settings could not be read for {failures} of "
                        f"{len(servers)} servers. A scanner role deployed before "
                        f"{first_version_granting(SQL_AUDITING_ACTION)} does not "
                        "grant the permission this needs."
                    ),
                )
            return TaskData(data)

        return CollectionTask(
            key=AzureEvidence.SQL_AUDITING,
            run=run,
            depends_on=(AzureEvidence.SQL_SERVERS,),
            actions=(SQL_AUDITING_ACTION,),
            endpoints=(SQL_AUDITING_ENDPOINT,),
        )

    def _sql_tde_task(self) -> CollectionTask:
        """Whether what each database holds is encrypted where it sits.

        A dependent task like the auditing read, and for the same two reasons:
        it rests on the server listing, and it is separately deniable -- the
        permissions behind it arrive in role v6, so a customer who has not
        redeployed reads their servers and firewall rules perfectly well and is
        refused exactly this.

        The fan-out is two deep rather than one. Encryption is a property of a
        database, not of the server holding it, so there is no server-level
        answer to read instead: the databases are listed, then each is asked.

        ``master`` is skipped. It is the system database Azure creates and
        manages, it is always encrypted, and reporting it would put a row a
        customer cannot act on beside the ones they can.
        """

        async def run(collected: dict[str, Any]) -> TaskData:
            arm = ArmClient(self.tokens, self._http, limiter=self._limiter)
            servers = [
                server["id"]
                for server in collected.get(AzureEvidence.SQL_SERVERS, [])
                if server.get("id")
            ]

            failures = 0

            async def for_database(database: dict[str, Any]) -> dict[str, Any]:
                nonlocal failures
                try:
                    encryption = await arm.get_database_encryption(database["id"])
                except Exception as exc:
                    failures += 1
                    # Named per database rather than dropped: a database whose
                    # encryption state could not be read is not one known to be
                    # encrypted, and the rule reports UNKNOWN for that database
                    # alone rather than for the server.
                    return {
                        "database": database.get("name"),
                        "id": database["id"],
                        "state": None,
                        "error": str(exc),
                    }
                return {
                    "database": database.get("name"),
                    "id": database["id"],
                    "state": _encryption_state(encryption),
                }

            async def for_server(server_id: str) -> tuple[str, Any]:
                nonlocal failures
                try:
                    databases = await arm.list_sql_databases(server_id)
                except Exception as exc:
                    failures += 1
                    return server_id, f"error: {exc}"
                wanted = [
                    database
                    for database in databases
                    if database.get("id") and str(database.get("name", "")).lower() != "master"
                ]
                return server_id, await self._gather_limited(
                    [for_database(database) for database in wanted]
                )

            pairs = await self._gather_limited([for_server(s) for s in servers])
            data = {"sql_tde": dict(pairs)}

            if failures:
                return TaskData(
                    data,
                    partial_reason=(
                        f"encryption state could not be read for {failures} "
                        f"database(s) or server(s). A scanner role deployed "
                        f"before {first_version_granting(*SQL_TDE_ACTIONS)} does not "
                        f"grant the permissions "
                        f"this needs."
                    ),
                )
            return TaskData(data)

        return CollectionTask(
            key=AzureEvidence.SQL_TDE,
            run=run,
            depends_on=(AzureEvidence.SQL_SERVERS,),
            actions=SQL_TDE_ACTIONS,
            endpoints=(SQL_DATABASES_ENDPOINT, SQL_TDE_ENDPOINT),
        )

    def _role_group_members_task(self) -> CollectionTask:
        """Who is in each group that holds a role in this subscription.

        A role assigned to a group was drawn to a principal named "Group
        1a2b3c4d" and stopped there: the people it actually reaches were never
        read, so the access view could not name them and no route could pass
        through them (DECISIONS.md section 126).

        Graph, from a subscription's reading, because the assignments are what
        say which groups matter. Keyed by group id; a group whose read failed
        is absent rather than empty, because an empty member list would say
        "this role reaches nobody", which is the one wrong answer here.
        """

        async def run(collected: dict[str, Any]) -> TaskData:
            wanted = sorted(
                {
                    str(props["principalId"])
                    for assignment in collected.get("role_assignments") or []
                    if (props := assignment.get("properties") or {}).get("principalType") == "Group"
                    and props.get("principalId")
                }
            )
            if not wanted:
                return TaskData({"role_group_members": {}})

            graph = GraphClient(self.tokens, self._http, limiter=self._limiter)
            reading = wanted[:ROLE_GROUP_LIMIT]

            # Names first, fifteen to a call. A failed batch costs only the
            # names -- the group is still drawn, by its id -- so it is logged
            # rather than allowed to cost the members.
            names: dict[str, str] = {}
            for start in range(0, len(reading), GRAPH_IN_FILTER_LIMIT):
                batch = reading[start : start + GRAPH_IN_FILTER_LIMIT]
                try:
                    found_groups = await self._graph_call(graph.list_groups_by_id(batch))
                except Exception as exc:
                    log.warning("azure.role_group_names_failed", error=str(exc))
                    continue
                for group in found_groups:
                    if group.get("id") and group.get("displayName"):
                        names[str(group["id"])] = str(group["displayName"])

            async def read(group_id: str) -> tuple[str, dict[str, Any] | None]:
                try:
                    members = await self._graph_call(graph.list_group_transitive_members(group_id))
                except Exception as exc:
                    log.warning("azure.role_group_members_failed", error=str(exc))
                    return group_id, None
                return group_id, {
                    "display_name": names.get(group_id),
                    "members": [
                        {
                            "id": str(member["id"]),
                            "type": str(member.get("@odata.type") or ""),
                            "display_name": member.get("displayName"),
                        }
                        for member in members
                        if member.get("id")
                    ],
                }

            pairs = await self._gather_limited([read(group_id) for group_id in reading])
            found = {group_id: value for group_id, value in pairs if value is not None}
            data = {"role_group_members": found}
            missing = len(wanted) - len(found)
            if missing or graph.truncated:
                return TaskData(
                    data,
                    partial_reason=(
                        f"the members of {missing} of {len(wanted)} role-holding groups "
                        "could not be read"
                        if missing
                        else "a role-holding group has more members than one scan reads"
                    ),
                )
            return TaskData(data)

        return CollectionTask(
            key=AzureEvidence.ROLE_GROUP_MEMBERS,
            run=run,
            depends_on=(AzureEvidence.ROLE_ASSIGNMENTS,),
            endpoints=(GROUPS_ENDPOINT, GROUP_TRANSITIVE_MEMBERS_ENDPOINT),
        )

    def build_directory_plan(self) -> list[CollectionTask]:
        """Everything that is a reading of the tenant directory.

        Run once per scan, whatever the scan covers. Needs no subscription:
        Graph is scoped by the token, and the token is issued for the tenant
        the connection was consented in.
        """
        return self._identity_tasks()

    def _inventory_task(self) -> CollectionTask:
        """Everything in the subscription, read through Resource Graph.

        The only task that does not go to ARM, and the reason is what it asks
        for: not one provider's resources but all of them. ARM answers that
        with a paged listing whose completeness can only be inferred from
        whether the page cap was reached, while Resource Graph answers it in
        one query and states how many rows the query matched -- so a short
        read is detected by comparing counts rather than by noticing that
        paging stopped.

        It is also the task that scales worst on ARM as a tenant grows, and the
        one whose data no rule reads, which together make it the right first
        thing to move and the cheapest one to get wrong.
        """

        # Bound here rather than read off ``self`` inside the closure: this task
        # only ever appears in the account plan, which has already refused to
        # build without a subscription, and capturing it says so to the reader
        # and the type checker at once.
        sub = self.subscription_id
        if not sub:
            raise ValueError("The inventory task reads one subscription")

        async def run(collected: dict[str, Any]) -> TaskData:
            client = ResourceGraphClient(self.tokens, self._http, limiter=self._limiter)
            rows = await client.list_inventory(sub)
            data = {"resources": rows}
            if client.truncated:
                return TaskData(
                    data,
                    partial_reason=(
                        "the inventory query returned fewer resources than the "
                        "subscription holds, so these results are incomplete "
                        "and cannot support a pass"
                    ),
                )
            return TaskData(data)

        return CollectionTask(
            key=AzureEvidence.RESOURCES,
            run=run,
            actions=(
                "Microsoft.Resources/subscriptions/read",
                "Microsoft.Resources/subscriptions/resources/read",
                "Microsoft.ResourceGraph/resources/read",
            ),
            endpoints=(RESOURCE_GRAPH_ENDPOINT,),
        )

    def _diagnostics_task(self) -> CollectionTask:
        """Diagnostic settings for the resources AZ-LOG-001 covers.

        The only task with real dependencies, and the reason the executor sorts
        rather than just running everything at once: it needs the ids that the
        storage, SQL and NSG listings produce. That used to be expressed as
        "call it fifth".
        """
        sources = (
            AzureEvidence.STORAGE_ACCOUNTS,
            AzureEvidence.SQL_SERVERS,
            AzureEvidence.NETWORK_SECURITY_GROUPS,
            # Section 176: where each web app sends its HTTP logs. Same action,
            # same endpoint -- a site is a scope like any other.
            AzureEvidence.APP_SERVICES,
        )

        async def run(collected: dict[str, Any]) -> TaskData:
            arm = ArmClient(self.tokens, self._http, limiter=self._limiter)
            targets = [
                item["id"] for key in sources for item in collected.get(key, []) if item.get("id")
            ]
            # The subscription itself, which is where the activity log is
            # exported from. Every other target here is a resource whose own
            # logging is in question; this one is the record of who did what
            # across all of them, and it is the log an investigation starts
            # from. Read through the same action and the same endpoint -- a
            # subscription is a scope diagnostic settings apply to like any
            # other -- so it costs no customer a new permission.
            if self.subscription_id:
                targets.insert(0, f"/subscriptions/{self.subscription_id}")

            failures = 0

            async def for_resource(resource_id: str) -> tuple[str, list | str]:
                nonlocal failures
                try:
                    return resource_id, await arm.list_diagnostic_settings(resource_id)
                except Exception as exc:
                    failures += 1
                    return resource_id, f"error: {exc}"

            pairs = await self._gather_limited([for_resource(r) for r in targets])
            data = {"diagnostic_settings": dict(pairs)}

            # A resource whose settings could not be read is a resource whose
            # logging posture is unknown, and "most of them were fine" is not
            # an answer AZ-LOG-001 is allowed to give.
            if failures:
                return TaskData(
                    data,
                    partial_reason=(
                        f"diagnostic settings could not be read for {failures} of "
                        f"{len(targets)} resources"
                    ),
                )
            return TaskData(data)

        return CollectionTask(
            key=AzureEvidence.DIAGNOSTIC_SETTINGS,
            run=run,
            depends_on=sources,
            actions=("Microsoft.Insights/diagnosticSettings/read",),
            endpoints=(DIAGNOSTICS_ENDPOINT,),
        )

    def _name_missing_permissions(self) -> str:
        """Which directory permissions this tenant's consent did not grant.

        Empty when the answer cannot be established. Graph answers a missing
        application permission with "Insufficient privileges to complete the
        operation", which names neither the permission nor who can grant it,
        and the collector's own hint could only ever guess at which of eleven it
        was. The token knows: a client-credentials token lists its granted
        permissions in the ``roles`` claim, so the failure can be reported as a
        list an administrator can act on rather than as a category that went
        UNKNOWN for reasons.
        """
        from app.connectors.azure.auth import missing_permissions

        try:
            absent = missing_permissions(self.tokens.graph_token())
        except Exception:
            # A token that cannot be read or fetched says nothing about the
            # grant, and inventing eleven gaps would send someone to fix a
            # directory that is configured correctly.
            return ""
        if not absent:
            return ""
        return f" Consent in this tenant did not grant: {', '.join(absent)}."

    async def _graph_call(self, call: Awaitable[Any]) -> Any:
        """Await a Graph call, naming the missing permissions behind a 403."""
        try:
            return await call
        except AzureApiError as exc:
            if exc.azure_status_code != 403:
                raise
            named = self._name_missing_permissions()
            if not named:
                raise
            raise AzureApiError(f"{exc}{named}", status_code=403) from exc

    async def _licence_aware_call(self, call: Awaitable[Any], requirement: str) -> Any:
        """Await a Graph call whose refusal may be about a licence, not a grant.

        Wraps ``_graph_call`` rather than replacing it: a tenant that never
        consented gets the same list of missing permissions here as everywhere
        else, and only a refusal Graph itself attributes to the licence becomes
        ``requirement``, recorded as UNAVAILABLE rather than FAILED. The two
        are indistinguishable by status code and lead to entirely different
        people.
        """
        try:
            return await self._graph_call(call)
        except AzureApiError as exc:
            if not _refused_for_licence(exc):
                raise
            raise ReadingUnavailable(requirement) from exc

    def _identity_tasks(self) -> list[CollectionTask]:
        """Directory state. Graph, so no ARM action grants any of it."""

        async def users(collected: dict[str, Any]) -> TaskData:
            graph = GraphClient(self.tokens, self._http, limiter=self._limiter)
            found = await self._graph_call(graph.list_users())
            if graph.truncated:
                return TaskData(
                    {"users": found},
                    partial_reason="the directory is larger than one scan reads",
                )
            return TaskData({"users": found})

        async def roles(collected: dict[str, Any]) -> TaskData:
            graph = GraphClient(self.tokens, self._http, limiter=self._limiter)
            found = await self._graph_call(graph.list_directory_roles())
            return TaskData({"directory_roles": found})

        async def authorization_policy(collected: dict[str, Any]) -> TaskData:
            graph = GraphClient(self.tokens, self._http, limiter=self._limiter)
            policy = await self._graph_call(graph.get_authorization_policy())
            return TaskData({"authorization_policy": policy})

        async def authentication_methods_policy(collected: dict[str, Any]) -> TaskData:
            graph = GraphClient(self.tokens, self._http, limiter=self._limiter)
            policy = await self._graph_call(graph.get_authentication_methods_policy())
            return TaskData({"authentication_methods_policy": policy})

        async def group_settings(collected: dict[str, Any]) -> TaskData:
            graph = GraphClient(self.tokens, self._http, limiter=self._limiter)
            settings = await self._graph_call(graph.list_group_settings())
            return TaskData({"group_settings": settings})

        async def named_locations(collected: dict[str, Any]) -> TaskData:
            graph = GraphClient(self.tokens, self._http, limiter=self._limiter)
            found = await self._graph_call(graph.list_named_locations())
            return TaskData({"named_locations": found})

        # Section 204. Two Graph reads under the permissions that section added
        # to consent, and one ARM read at the tenant scope that needs no role.
        async def device_registration(collected: dict[str, Any]) -> TaskData:
            graph = GraphClient(self.tokens, self._http, limiter=self._limiter)
            policy = await self._graph_call(graph.get_device_registration_policy())
            return TaskData({"device_registration_policy": policy})

        async def access_reviews(collected: dict[str, Any]) -> TaskData:
            graph = GraphClient(self.tokens, self._http, limiter=self._limiter)
            found = await self._licence_aware_call(
                graph.list_access_review_definitions(), ACCESS_REVIEW_LICENCE
            )
            if graph.truncated:
                return TaskData(
                    {"access_reviews": found},
                    partial_reason="there are more access reviews than one scan reads",
                )
            return TaskData({"access_reviews": found})

        async def subscription_policy(collected: dict[str, Any]) -> TaskData:
            arm = ArmClient(self.tokens, self._http, limiter=self._limiter)
            return TaskData({"subscription_policy": await arm.get_subscription_policy()})

        async def security_defaults(collected: dict[str, Any]) -> TaskData:
            graph = GraphClient(self.tokens, self._http, limiter=self._limiter)
            policy = await self._graph_call(graph.get_security_defaults())
            return TaskData({"security_defaults": policy})

        async def conditional_access(collected: dict[str, Any]) -> TaskData:
            graph = GraphClient(self.tokens, self._http, limiter=self._limiter)
            found = await self._graph_call(graph.list_conditional_access_policies())

            # The groups those policies name, and only those. A policy that
            # excludes a break-glass group -- which is how essentially every
            # real tenant is configured -- cannot be reasoned about without
            # knowing who is in it: CloudGuard would be unable to rule out that
            # the account it is judging is the excluded one, and would have to
            # discard the policy. Reading every group in the tenant to answer
            # that would be a directory dump for a handful of ids.
            wanted: set[str] = set()
            for policy in found:
                users = (policy.get("conditions") or {}).get("users") or {}
                for key in ("includeGroups", "excludeGroups"):
                    wanted.update(str(g) for g in (users.get(key) or []) if g)

            async def members_of(group_id: str) -> tuple[str, list[str] | None]:
                try:
                    people = await graph.list_group_members(group_id)
                except Exception as exc:
                    # None, not [], and the normalizer drops any policy whose
                    # exclusions it could not read. An empty list would read as
                    # "nobody is excluded", which is the one wrong answer here.
                    log.warning("azure.group_members_failed", error=str(exc))
                    return group_id, None
                return group_id, [str(m["id"]) for m in people if m.get("id")]

            pairs = await self._gather_limited([members_of(g) for g in sorted(wanted)])
            data = {
                "conditional_access_policies": found,
                "group_members": {g: m for g, m in pairs if m is not None},
            }
            if graph.truncated:
                return TaskData(
                    data,
                    partial_reason=(
                        "there are more Conditional Access policies than one scan "
                        "reads, so a policy that would lower a finding's score may "
                        "be missing from this list"
                    ),
                )
            return TaskData(data)

        async def applications(collected: dict[str, Any]) -> TaskData:
            graph = GraphClient(self.tokens, self._http, limiter=self._limiter)
            found = await self._graph_call(graph.list_applications())
            if graph.truncated:
                return TaskData(
                    {"application_credentials": found},
                    partial_reason=(
                        "there are more application registrations than one scan "
                        "reads, so an expired credential may be missing from this "
                        "list"
                    ),
                )
            return TaskData({"application_credentials": found})

        async def directory_eligibilities(collected: dict[str, Any]) -> TaskData:
            """Directory roles a principal could activate (section 130)."""
            graph = GraphClient(self.tokens, self._http, limiter=self._limiter)
            found = await self._licence_aware_call(
                graph.list_directory_role_eligibilities(), PIM_LICENCE
            )
            data = {"directory_role_eligibilities": found}
            if graph.truncated:
                return TaskData(
                    data, partial_reason="there are more eligible roles than one scan reads"
                )
            return TaskData(data)

        async def sign_in_activity(collected: dict[str, Any]) -> TaskData:
            graph = GraphClient(self.tokens, self._http, limiter=self._limiter)
            found = await self._licence_aware_call(graph.list_sign_in_activity(), SIGN_IN_LICENCE)

            # Keyed by user id, because that is how it is read: the normalizer
            # merges each account's activity onto the account itself, and a
            # list would make that a scan of the whole directory per user.
            #
            # Accounts Graph returned with no ``signInActivity`` at all are kept
            # as None rather than dropped. An account that has never signed in
            # has no activity object, and that is the strongest form of the
            # thing this task exists to find -- dropping it would leave the
            # normalizer unable to tell it from an account this read missed.
            activity = {
                str(user["id"]): user.get("signInActivity") for user in found if user.get("id")
            }
            if graph.truncated:
                return TaskData(
                    {"user_sign_in_activity": activity},
                    partial_reason=(
                        "the directory is larger than one scan reads, so an "
                        "account's last sign-in may be missing from this list"
                    ),
                )
            return TaskData({"user_sign_in_activity": activity})

        return [
            CollectionTask(
                key=AzureEvidence.USERS,
                run=users,
                endpoints=(USERS_ENDPOINT,),
            ),
            CollectionTask(
                key=AzureEvidence.DIRECTORY_ROLES,
                run=roles,
                endpoints=(DIRECTORY_ROLES_ENDPOINT,),
            ),
            CollectionTask(
                key=AzureEvidence.USER_ROLE_MAP,
                run=self._role_membership,
                depends_on=(AzureEvidence.USERS, AzureEvidence.DIRECTORY_ROLES),
                # Two calls per user it judges: who holds each role, and what
                # each of those accounts can authenticate with.
                endpoints=(ROLE_MEMBERS_ENDPOINT, AUTH_METHODS_ENDPOINT),
            ),
            # The two defences. Independent tasks rather than one, because they
            # are separate readings that fail separately -- and because a tenant
            # on security defaults has no Conditional Access at all, so one
            # returning nothing must not cost the other its verdict.
            CollectionTask(
                key=AzureEvidence.SECURITY_DEFAULTS,
                run=security_defaults,
                endpoints=(SECURITY_DEFAULTS_ENDPOINT,),
            ),
            CollectionTask(
                key=AzureEvidence.AUTHORIZATION_POLICY,
                run=authorization_policy,
                endpoints=(AUTHORIZATION_POLICY_ENDPOINT,),
            ),
            CollectionTask(
                key=AzureEvidence.AUTHENTICATION_METHODS_POLICY,
                run=authentication_methods_policy,
                endpoints=(AUTH_METHODS_POLICY_ENDPOINT,),
            ),
            CollectionTask(
                key=AzureEvidence.GROUP_SETTINGS,
                run=group_settings,
                endpoints=(GROUP_SETTINGS_ENDPOINT,),
            ),
            # Section 176. ``Policy.Read.All`` again, already consented.
            CollectionTask(
                key=AzureEvidence.NAMED_LOCATIONS,
                run=named_locations,
                endpoints=(NAMED_LOCATIONS_ENDPOINT,),
            ),
            CollectionTask(
                key=AzureEvidence.CONDITIONAL_ACCESS_POLICIES,
                run=conditional_access,
                endpoints=(CONDITIONAL_ACCESS_ENDPOINT, GROUP_MEMBERS_ENDPOINT),
            ),
            # Section 204.
            CollectionTask(
                key=AzureEvidence.DEVICE_REGISTRATION_POLICY,
                run=device_registration,
                endpoints=(DEVICE_REGISTRATION_POLICY_ENDPOINT,),
            ),
            CollectionTask(
                key=AzureEvidence.ACCESS_REVIEWS,
                run=access_reviews,
                endpoints=(ACCESS_REVIEWS_ENDPOINT,),
            ),
            CollectionTask(
                key=AzureEvidence.SUBSCRIPTION_POLICY,
                run=subscription_policy,
                endpoints=(SUBSCRIPTION_POLICY_ENDPOINT,),
            ),
            # Both under permissions admin consent has requested since
            # onboarding existed and nothing has ever called
            # (``DECISIONS.md`` section 63): ``Application.Read.All`` for the
            # first, ``AuditLog.Read.All`` with ``User.Read.All`` for the
            # second. Neither costs a customer a redeploy or a re-consent.
            CollectionTask(
                key=AzureEvidence.APPLICATION_CREDENTIALS,
                run=applications,
                endpoints=(APPLICATIONS_ENDPOINT,),
            ),
            # Independent of USERS rather than dependent on it, though the
            # normalizer joins the two. A dependency would mean a licence this
            # task cannot have costs nothing extra -- but the reverse, a
            # directory listing that failed, already costs every identity rule
            # its verdict through its own key, and skipping this task would add
            # a second gap saying the same thing.
            CollectionTask(
                key=AzureEvidence.USER_SIGN_IN_ACTIVITY,
                run=sign_in_activity,
                endpoints=(SIGN_IN_ACTIVITY_ENDPOINT,),
            ),
            CollectionTask(
                key=AzureEvidence.DIRECTORY_ROLE_ELIGIBILITIES,
                run=directory_eligibilities,
                endpoints=(DIRECTORY_ROLE_ELIGIBILITIES_ENDPOINT,),
            ),
            CollectionTask(
                key=AzureEvidence.GRAPH_PERMISSION_GRANTS,
                run=self._graph_permission_grants,
                endpoints=(SERVICE_PRINCIPALS_ENDPOINT, APP_ROLE_ASSIGNED_TO_ENDPOINT),
            ),
            CollectionTask(
                key=AzureEvidence.APPLICATION_OWNERS,
                run=self._application_owners,
                depends_on=(AzureEvidence.APPLICATION_CREDENTIALS,),
                endpoints=(APPLICATION_OWNERS_ENDPOINT, SERVICE_PRINCIPALS_ENDPOINT),
            ),
        ]

    async def _graph_permission_grants(self, collected: dict[str, Any]) -> TaskData:
        """Who holds which Microsoft Graph application permission.

        Two readings: Graph's own catalogue of what each app role id means,
        from its service principal in this tenant, and every grant of one of
        those roles, read from Graph's side so a single listing covers every
        principal and managed identity (DECISIONS.md section 129).
        """
        graph = GraphClient(self.tokens, self._http, limiter=self._limiter)
        catalogue = await self._graph_call(graph.find_permission_catalogue(GRAPH_RESOURCE_APP_ID))
        if catalogue is None or not catalogue.get("id"):
            # A tenant always holds Graph's principal; not finding it is a
            # reading that failed to say anything, not a tenant with no grants.
            return TaskData(
                {"graph_app_roles": {}, "graph_permission_grants": []},
                partial_reason="Microsoft Graph's service principal was not found",
            )
        roles = {
            str(role["id"]): str(role["value"])
            for role in catalogue.get("appRoles") or []
            if role.get("id") and role.get("value")
        }
        grants = await self._graph_call(graph.list_app_role_assigned_to(str(catalogue["id"])))
        data = {"graph_app_roles": roles, "graph_permission_grants": grants}
        if graph.truncated:
            return TaskData(
                data, partial_reason="there are more Graph permission grants than one scan reads"
            )
        return TaskData(data)

    async def _application_owners(self, collected: dict[str, Any]) -> TaskData:
        """Who can sign in as each of this tenant's applications.

        Two readings. The owners of each registration, since an owner can add a
        credential and act as the registration's service principal. And that
        service principal's object id, which is what a subscription's role
        assignments name it by -- a registration knows only its app id
        (DECISIONS.md section 128).

        Keyed so an unread registration is absent rather than empty: "nobody
        owns this" and "nobody could say who owns this" are different answers.
        """
        applications = [
            app for app in collected.get("application_credentials") or [] if app.get("id")
        ]
        reading = applications[:APPLICATION_OWNER_LIMIT]
        graph = GraphClient(self.tokens, self._http, limiter=self._limiter)

        async def owners_of(app: dict[str, Any]) -> tuple[str, list[str] | None]:
            try:
                found = await self._graph_call(graph.list_application_owners(str(app["id"])))
            except Exception as exc:
                log.warning("azure.application_owners_failed", error=str(exc))
                return str(app["id"]), None
            return str(app["id"]), [str(owner["id"]) for owner in found if owner.get("id")]

        pairs = await self._gather_limited([owners_of(app) for app in reading])
        owners = {app_id: found for app_id, found in pairs if found is not None}

        principals: dict[str, str] = {}
        app_ids = sorted({str(app["appId"]) for app in reading if app.get("appId")})
        unmapped = 0
        for start in range(0, len(app_ids), GRAPH_IN_FILTER_LIMIT):
            batch = app_ids[start : start + GRAPH_IN_FILTER_LIMIT]
            try:
                found = await self._graph_call(graph.list_service_principals_by_app_id(batch))
            except Exception as exc:
                unmapped += len(batch)
                log.warning("azure.application_principals_failed", error=str(exc))
                continue
            for principal in found:
                if principal.get("appId") and principal.get("id"):
                    principals[str(principal["appId"])] = str(principal["id"])

        data = {"application_owners": owners, "application_service_principals": principals}
        missing = len(reading) - len(owners)
        reasons = []
        if len(applications) > len(reading):
            reasons.append(
                f"owners were read for {len(reading)} of {len(applications)} applications"
            )
        if missing:
            reasons.append(f"the owners of {missing} applications could not be read")
        if unmapped:
            reasons.append(f"the service principals of {unmapped} applications were not read")
        if graph.truncated:
            reasons.append("an application has more owners than one scan reads")
        return TaskData(data, partial_reason="; ".join(reasons) if reasons else None)

    async def _role_membership(self, collected: dict[str, Any]) -> TaskData:
        """Who holds which directory role, and whether they have MFA.

        Authentication methods cost one Graph call per user, so they are read
        only for members of the roles AZ-ID-001 actually applies to.
        """
        from app.connectors.azure.collector import PRIVILEGED_ROLE_NAMES

        graph = GraphClient(self.tokens, self._http, limiter=self._limiter)
        role_map: dict[str, list[str]] = {}
        # What kind of directory object each member is. A service principal or
        # a role-assignable group holding a directory role has no record in the
        # user listing, and without its kind the graph could not type the node
        # it needs (DECISIONS.md section 129).
        member_types: dict[str, str] = {}
        privileged: set[str] = set()
        failures = 0

        for role in collected.get("directory_roles", []):
            name = role.get("displayName", "")
            try:
                members = await graph.list_role_members(role["id"])
            except Exception as exc:
                failures += 1
                log.warning("azure.role_members_failed", role=name, error=str(exc))
                continue
            for member in members:
                member_id = member.get("id")
                if not member_id:
                    continue
                role_map.setdefault(member_id, []).append(name)
                member_types[member_id] = str(member.get("@odata.type") or "")
                if name.strip().lower() in PRIVILEGED_ROLE_NAMES:
                    privileged.add(member_id)

        async def methods_for(user_id: str) -> tuple[str, list | None]:
            try:
                return user_id, await graph.list_authentication_methods(user_id)
            except Exception as exc:
                # None, not [], so AZ-ID-001 reports UNKNOWN rather than
                # concluding this administrator has no MFA configured.
                log.warning("azure.auth_methods_failed", error=str(exc))
                return user_id, None

        pairs = await self._gather_limited([methods_for(u) for u in privileged])
        data = {
            "user_role_map": role_map,
            "directory_role_member_types": member_types,
            "authentication_methods": dict(pairs),
        }
        if failures:
            return TaskData(data, partial_reason=f"membership unreadable for {failures} role(s)")
        return TaskData(data)
