"""The readings section 204 added, reduced to the fields the rules judge.

The same shape as ``settings.py``: small pure functions over one reading, called
by the normalizer where each asset is built. ``None`` where a reading failed or
was never taken; a value where it arrived and said something. Where a service
documents what an unset field means, that value is written in here and said so.

Section 204 closed the compliance controls a native rule could answer and none
did. Most of what it needed was already collected -- a field the listing always
carried and nothing read -- and the rest is six reads under scanner role v13 and
two Graph permissions (DECISIONS.md section 204).
"""

from datetime import datetime
from typing import Any

from app.connectors.azure.settings import (
    ContextOf,
    _first,
    _has_destination,
    _read,
    _truthy,
    enabled_log_categories,
    subnets_without_nsg,
)
from app.core.enums import Level, Provider, ResourceType
from app.domain.resource import CloudResource


# ----------------------------------------------------------- Defender plans
def _plan(raw: Any, name: str) -> dict[str, Any] | None:
    if not isinstance(raw, list):
        return None
    return next(
        (p for p in raw if isinstance(p, dict) and str(p.get("name")).lower() == name.lower()),
        None,
    )


def plan_extension(raw: Any, plan_name: str, extension: str) -> bool | None:
    """Whether one extension of one Defender plan is on.

    Off whenever the plan is off. On only when the plan is on and lists the
    extension as enabled; a plan that is on and states no extensions is not read
    as either -- the reading ``container_image_scanning`` gives.
    """
    plan = _plan(raw, plan_name)
    if plan is None:
        return None
    if str(_first(plan, "properties", "pricingTier") or "").lower() != "standard":
        return False
    extensions = _first(plan, "properties", "extensions")
    if not isinstance(extensions, list):
        return None
    for entry in extensions:
        if str((entry or {}).get("name") or "").lower() == extension.lower():
            return _truthy(entry.get("isEnabled"))
    return False


def dns_threat_detection(raw: Any) -> bool | None:
    """Whether DNS queries are watched for threats.

    The standalone Defender for DNS plan was folded into Defender for Servers
    Plan 2 in August 2023, so either answers: the old plan on and not
    deprecated, or Servers on with Plan 2 -- or with no sub-plan, which the
    pricing API documents as the full plan.
    """
    if not isinstance(raw, list):
        return None
    dns = _plan(raw, "Dns")
    if (
        dns is not None
        and _first(dns, "properties", "deprecated") is not True
        and str(_first(dns, "properties", "pricingTier") or "").lower() == "standard"
    ):
        return True
    servers = _plan(raw, "VirtualMachines")
    if servers is None:
        return None
    if str(_first(servers, "properties", "pricingTier") or "").lower() != "standard":
        return False
    return str(_first(servers, "properties", "subPlan") or "P2").upper() == "P2"


# The built-in policy definitions that limit where resources may be created:
# "Allowed locations" and "Allowed locations for resource groups", by the ids
# Microsoft publishes for them in the built-in policy reference.
ALLOWED_LOCATIONS_DEFINITIONS = frozenset(
    {
        "e56962a6-4747-49cd-b67b-bf8b01975c4c",
        "e765b5de-1225-4ba3-bd56-1ac6695af988",
    }
)


def locations_restricted(raw: Any) -> bool | None:
    """Whether an enforced policy assignment limits the regions in use.

    Read from the policy assignments already collected (section 176). An
    assignment with enforcement off restricts nothing.
    """
    if not isinstance(raw, list):
        return None
    for assignment in raw:
        props = (assignment or {}).get("properties") or {}
        definition = str(props.get("policyDefinitionId") or "").lower().rsplit("/", 1)[-1]
        if definition not in ALLOWED_LOCATIONS_DEFINITIONS:
            continue
        if str(props.get("enforcementMode") or "Default").lower() == "default":
            return True
    return False


def policy_identities(raw: Any) -> dict[str, list[dict[str, Any]]]:
    """Which policy assignments each managed identity acts for, by principal id.

    A DeployIfNotExists or Modify assignment runs its remediation as a managed
    identity, granted the roles its definition names (DECISIONS.md section
    222). The listing already carries that identity: a system-assigned one as
    ``identity.principalId``, user-assigned ones under
    ``identity.userAssignedIdentities``. Read with ``$filter=atScope()``, the
    listing includes assignments inherited from management groups.
    """
    found: dict[str, list[dict[str, Any]]] = {}
    if not isinstance(raw, list):
        return found
    for assignment in raw:
        if not isinstance(assignment, dict):
            continue
        identity = assignment.get("identity") or {}
        principals = [identity.get("principalId")]
        for entry in (identity.get("userAssignedIdentities") or {}).values():
            principals.append((entry or {}).get("principalId"))
        props = assignment.get("properties") or {}
        record = {
            "id": assignment.get("id"),
            "name": props.get("displayName") or assignment.get("name"),
            "scope": props.get("scope"),
        }
        for principal in principals:
            if principal:
                found.setdefault(str(principal), []).append(record)
    return found


def basic_public_ips(raw: Any) -> list[str] | None:
    """Public IP addresses on the Basic SKU, which Azure retired on 30
    September 2025: no SLA, no availability zones, and open by default."""
    if not isinstance(raw, list):
        return None
    return sorted(
        str(address.get("name") or address.get("id"))
        for address in raw
        if isinstance(address, dict)
        and str(_first(address, "sku", "name") or "").lower() == "basic"
    )


def subscription_extras(data: dict[str, Any]) -> dict[str, Any]:
    """Everything section 204 reads about the subscription as a whole."""
    plans = data.get("defender_plans")
    return {
        "agentless_vm_scanning": plan_extension(plans, "VirtualMachines", "AgentlessVmScanning"),
        "file_integrity_monitoring": plan_extension(
            plans, "VirtualMachines", "FileIntegrityMonitoring"
        ),
        "container_sensor": plan_extension(plans, "Containers", "ContainerSensor"),
        "dns_threat_detection": dns_threat_detection(plans),
        "locations_restricted": locations_restricted(data.get("policy_assignments")),
        "basic_public_ips": basic_public_ips(data.get("public_ip_addresses")),
    }


# ------------------------------------------------------------------ storage
def key_age_days(props: dict[str, Any], collected_at: datetime) -> int | None:
    """Days since the older of the account's two access keys was created or
    regenerated, as of when the listing was read.

    Judged against the capture's own time, as runtime support is (section 177),
    so a replayed capture answers as of when it was taken. None where the
    listing carried no creation time for either key.
    """
    times = props.get("keyCreationTime")
    if not isinstance(times, dict):
        return None
    ages: list[int] = []
    for value in times.values():
        if not value:
            continue
        try:
            created = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            continue
        if created.tzinfo is None:
            continue
        ages.append(max(0, (collected_at - created).days))
    return max(ages) if ages else None


# The services beneath an account whose reads, writes and deletes CIS asks to
# be logged, and the account kinds that have no such service.
STORAGE_SERVICES = ("blob", "queue", "table")
_NO_QUEUE_OR_TABLE = frozenset({"blobstorage", "blockblobstorage", "filestorage"})
_NO_BLOB = frozenset({"filestorage"})
_STORAGE_LOG_CATEGORIES = frozenset({"storageread", "storagewrite", "storagedelete"})


def storage_services(account: dict[str, Any]) -> tuple[str, ...]:
    """Which of the three services this kind of account has."""
    kind = str(account.get("kind") or "").lower()
    return tuple(
        service
        for service in STORAGE_SERVICES
        if not (service == "blob" and kind in _NO_BLOB)
        and not (service != "blob" and kind in _NO_QUEUE_OR_TABLE)
    )


def _logs_storage_operations(settings: Any) -> bool | None:
    if not isinstance(settings, list):
        return None
    for setting in settings:
        if not isinstance(setting, dict) or not _has_destination(setting):
            continue
        categories = enabled_log_categories(setting)
        if "alllogs" in categories or categories >= _STORAGE_LOG_CATEGORIES:
            return True
    return False


def services_without_logging(account: dict[str, Any], readings: Any) -> list[str] | None:
    """Which of the account's services send no record of reads, writes and
    deletes anywhere.

    ``readings`` is the account's entry in the service diagnostics task: each
    service's settings by scope, or None where Azure said the service does not
    exist. None here if the account's settings were not read.
    """
    entry = _read(readings, str(account.get("id")))
    if not isinstance(entry, dict):
        return None
    missing: list[str] = []
    for service in storage_services(account):
        scope = f"{account['id']}/{service}Services/default"
        if scope not in entry:
            return None
        if entry[scope] is None:
            # The service does not exist on this account.
            continue
        logged = _logs_storage_operations(entry[scope])
        if logged is None:
            return None
        if not logged:
            missing.append(service)
    return missing


# ------------------------------------------------------------------- vaults
_CERTIFICATE_CONTENT_TYPES = frozenset({"application/x-pkcs12", "application/x-pem-file"})
# Twelve months, with a day's grace for the hours a certificate authority adds.
CERTIFICATE_MAX_DAYS = 367


def certificate_lifetimes(vault_id: str, secrets: Any) -> dict[str, Any]:
    """The vault's certificates valid for more than twelve months.

    A Key Vault certificate is stored beside a secret of the same name holding
    its key pair, and that secret carries the certificate's content type and
    validity window. The management plane lists secrets but not certificates,
    so the secrets are where a certificate's lifetime can be read without a
    data-plane permission. Whether ARM's listing includes those secrets is the
    first thing a live v13 read will show; until then a vault with none listed
    is not judged either way.
    """
    entries = _read(secrets, vault_id)
    if not isinstance(entries, list):
        return {
            "certificate_count": None,
            "holds_certificates": None,
            "long_lived_certificates": None,
        }
    long_lived: list[str] = []
    count = 0
    for secret in entries:
        if not isinstance(secret, dict):
            continue
        props = secret.get("properties") or {}
        if str(props.get("contentType") or "").lower() not in _CERTIFICATE_CONTENT_TYPES:
            continue
        attributes = props.get("attributes") or {}
        if attributes.get("enabled") is False:
            continue
        count += 1
        starts, ends = attributes.get("nbf"), attributes.get("exp")
        if (
            isinstance(starts, int | float)
            and isinstance(ends, int | float)
            and (ends - starts) / 86400 > CERTIFICATE_MAX_DAYS
        ):
            long_lived.append(str(secret.get("name")))
    return {
        "certificate_count": count,
        "holds_certificates": count > 0,
        "long_lived_certificates": sorted(long_lived),
    }


# ----------------------------------------------------------------- networks
def databricks_subnets_without_nsg(parameters: dict[str, Any], networks: Any) -> list[str] | None:
    """Which of a workspace's two subnets no network security group guards.

    Only a workspace in a customer-managed network names its subnets; one in
    Databricks' own network has none of its own to judge, and is an empty list
    here. None where the networks were not read or the named network or
    subnets are not among them.
    """

    def value(name: str) -> Any:
        entry = parameters.get(name)
        return entry.get("value") if isinstance(entry, dict) else None

    network_id = value("customVirtualNetworkId")
    if not network_id:
        return []
    if not isinstance(networks, list):
        return None
    network = next(
        (
            n
            for n in networks
            if isinstance(n, dict) and str(n.get("id") or "").lower() == str(network_id).lower()
        ),
        None,
    )
    if network is None:
        return None
    wanted = {
        str(name).lower()
        for name in (value("customPublicSubnetName"), value("customPrivateSubnetName"))
        if name
    }
    subnets = [
        s
        for s in _first(network, "properties", "subnets") or []
        if isinstance(s, dict) and str(s.get("name") or "").lower() in wanted
    ]
    if len(subnets) < len(wanted):
        return None
    return subnets_without_nsg(subnets)


# ----------------------------------------------------------------- machines
def patch_assessment_mode(props: dict[str, Any]) -> str | None:
    """How the machine is assessed for missing updates: ``AutomaticByPlatform``
    checks every 24 hours, ``ImageDefault`` only when asked.

    ARM leaves the field out when it was never set, and documents ImageDefault
    as the default, so an operating-system profile without it is ImageDefault.
    None where the record carries no operating-system configuration at all.
    """
    for configuration in ("windowsConfiguration", "linuxConfiguration"):
        os_config = _first(props, "osProfile", configuration)
        if isinstance(os_config, dict):
            return str(_first(os_config, "patchSettings", "assessmentMode") or "ImageDefault")
    return None


# ------------------------------------------------------------------- locks
_PROTECTING_LEVELS = frozenset({"cannotdelete", "readonly"})
_LOCK_MARKER = "/providers/microsoft.authorization/locks/"


def lock_scopes(raw: Any) -> list[str] | None:
    """Every scope a delete or read-only lock protects, lower-cased.

    A lock's id is its scope followed by ``/providers/Microsoft.Authorization/
    locks/<name>``, and a lock protects its scope and everything beneath it.
    """
    if not isinstance(raw, list):
        return None
    scopes: list[str] = []
    for lock in raw:
        if not isinstance(lock, dict):
            continue
        if str(_first(lock, "properties", "level") or "").lower() not in _PROTECTING_LEVELS:
            continue
        scope, marker, _ = str(lock.get("id") or "").lower().partition(_LOCK_MARKER)
        if marker and scope:
            scopes.append(scope.rstrip("/"))
    return scopes


def delete_locked(resource_id: str, scopes: list[str] | None) -> bool | None:
    """Whether a lock on the resource, its group or its subscription stops it
    being deleted. None where the locks were not read."""
    if scopes is None:
        return None
    target = resource_id.lower().rstrip("/")
    return any(target == scope or target.startswith(f"{scope}/") for scope in scopes)


# --------------------------------------------------------------- databases
def admits_azure_services(server_id: str, rules: Any) -> bool | None:
    """Whether a PostgreSQL server's firewall admits every Azure service.

    The portal's "Allow public access from any Azure service" is a firewall rule
    from 0.0.0.0 to 0.0.0.0, which admits any address inside Azure -- every
    other customer's machines included.
    """
    entries = _read(rules, server_id)
    if not isinstance(entries, list):
        return None
    return any(
        _first(rule, "properties", "startIpAddress") == "0.0.0.0"
        and _first(rule, "properties", "endIpAddress") == "0.0.0.0"
        for rule in entries
        if isinstance(rule, dict)
    )


# ---------------------------------------------------- application gateways
# Each predefined TLS policy and the lowest version it accepts, from the
# Application Gateway TLS policy reference.
PREDEFINED_TLS_POLICIES = {
    "appgwsslpolicy20150501": "TLSv1_0",
    "appgwsslpolicy20170401": "TLSv1_1",
    "appgwsslpolicy20170401s": "TLSv1_2",
    "appgwsslpolicy20220101": "TLSv1_2",
    "appgwsslpolicy20220101s": "TLSv1_2",
}


def gateway_min_tls(props: dict[str, Any]) -> str | None:
    """The lowest TLS version the gateway's listeners accept.

    None where the gateway states no TLS policy: its default depends on the API
    version the gateway was created under, which cannot be read back.
    """
    policy = props.get("sslPolicy")
    if not isinstance(policy, dict) or not policy:
        return None
    if policy.get("minProtocolVersion"):
        return str(policy["minProtocolVersion"])
    return PREDEFINED_TLS_POLICIES.get(str(policy.get("policyName") or "").lower())


_WAF_UNKNOWN: dict[str, Any] = {
    "waf_enabled": None,
    "waf_mode": None,
    "waf_request_body_check": None,
    "waf_bot_protection": None,
}


def gateway_waf(gateway: dict[str, Any], policies: Any) -> dict[str, Any]:
    """Whether a web application firewall inspects the gateway's traffic, and
    how.

    Two ways to have one: an attached WAF policy, read from the policy listing,
    or the older configuration written on the gateway itself. A policy the
    listing does not hold leaves every field unknown.
    """
    props = gateway.get("properties") or {}
    policy_id = str(_first(props, "firewallPolicy", "id") or "").lower()
    if policy_id:
        if not isinstance(policies, list):
            return dict(_WAF_UNKNOWN)
        policy = next(
            (
                p
                for p in policies
                if isinstance(p, dict) and str(p.get("id") or "").lower() == policy_id
            ),
            None,
        )
        if policy is None:
            return dict(_WAF_UNKNOWN)
        settings = _first(policy, "properties", "policySettings") or {}
        rule_sets = _first(policy, "properties", "managedRules", "managedRuleSets") or []
        return {
            "waf_enabled": str(settings.get("state") or "Enabled").lower() == "enabled",
            "waf_mode": settings.get("mode"),
            # Request body inspection is on unless switched off.
            "waf_request_body_check": settings.get("requestBodyCheck") is not False,
            "waf_bot_protection": any(
                str((rule_set or {}).get("ruleSetType") or "").lower()
                == "microsoft_botmanagerruleset"
                for rule_set in rule_sets
            ),
        }
    config = props.get("webApplicationFirewallConfiguration")
    if isinstance(config, dict):
        return {
            "waf_enabled": config.get("enabled") is True,
            "waf_mode": config.get("firewallMode"),
            "waf_request_body_check": config.get("requestBodyCheck") is not False,
            # Bot protection exists only as a managed rule set on a WAF policy.
            "waf_bot_protection": False,
        }
    return {**_WAF_UNKNOWN, "waf_enabled": False}


def application_gateways(data: dict[str, Any], context: ContextOf) -> list[CloudResource]:
    """Application gateways: the layer-7 front door, its firewall and its TLS."""
    found: list[CloudResource] = []
    policies = data.get("waf_policies")
    for gateway in data.get("application_gateways") or []:
        if not isinstance(gateway, dict) or not gateway.get("id"):
            continue
        props = gateway.get("properties") or {}
        public = any(
            _first(frontend, "properties", "publicIPAddress", "id")
            for frontend in props.get("frontendIPConfigurations") or []
            if isinstance(frontend, dict)
        )
        found.append(
            CloudResource(
                provider_resource_id=str(gateway["id"]),
                resource_type=ResourceType.APPLICATION_GATEWAY,
                name=gateway.get("name", "unnamed"),
                provider=Provider.AZURE,
                region=gateway.get("location"),
                **context(gateway, ResourceType.APPLICATION_GATEWAY).fields(),
                public_exposure=Level.HIGH if public else Level.LOW,
                metadata={
                    "sku_tier": _first(props, "sku", "tier"),
                    "public_frontend": public,
                    "http2_enabled": props.get("enableHttp2"),
                    "min_tls_version": gateway_min_tls(props),
                    **gateway_waf(gateway, policies),
                    "tags": gateway.get("tags") or {},
                },
            )
        )
    return found


VPN_GATEWAY_TYPE = "microsoft.network/virtualnetworkgateways"


def vpn_gateways(data: dict[str, Any], context: ContextOf) -> list[CloudResource]:
    """Virtual network gateways, read one by one from the ids the inventory
    lists, since ARM lists them only per resource group."""
    found: list[CloudResource] = []
    read = data.get("vpn_gateways")
    if not isinstance(read, dict):
        return found
    for gateway_id, gateway in read.items():
        if not isinstance(gateway, dict):
            continue
        props = gateway.get("properties") or {}
        client = props.get("vpnClientConfiguration")
        found.append(
            CloudResource(
                provider_resource_id=str(gateway.get("id") or gateway_id),
                resource_type=ResourceType.VPN_GATEWAY,
                name=gateway.get("name", "unnamed"),
                provider=Provider.AZURE,
                region=gateway.get("location"),
                **context(gateway, ResourceType.VPN_GATEWAY).fields(),
                # A gateway answers on a public address by design; what it
                # admits is the question its rule asks.
                public_exposure=Level.MEDIUM,
                metadata={
                    "gateway_type": props.get("gatewayType"),
                    "point_to_site": isinstance(client, dict),
                    "point_to_site_auth_types": (
                        [str(t) for t in client.get("vpnAuthenticationTypes") or []]
                        if isinstance(client, dict)
                        else []
                    ),
                    "tags": gateway.get("tags") or {},
                },
            )
        )
    return found


# ------------------------------------------------------------------ tenant
PASSWORD_RULE_SETTINGS = "Password Rule Settings"


def banned_password_list(settings: Any) -> bool | None:
    """Whether a custom banned-password list is enforced.

    The ``Password Rule Settings`` directory setting exists only once somebody
    changed it, and the default has no custom list -- so a tenant without it is
    not enforcing one.
    """
    if not isinstance(settings, list):
        return None
    entry = next(
        (
            s
            for s in settings
            if isinstance(s, dict) and str(s.get("displayName") or "") == PASSWORD_RULE_SETTINGS
        ),
        None,
    )
    if entry is None:
        return False
    values = {
        str(v.get("name")): str(v.get("value") or "")
        for v in entry.get("values") or []
        if isinstance(v, dict)
    }
    return values.get("EnableBannedPasswordCheck", "").strip().lower() == "true" and bool(
        values.get("BannedPasswordList", "").strip()
    )


def _enabled(policies: list[Any]) -> list[dict[str, Any]]:
    return [
        p
        for p in policies
        if isinstance(p, dict) and str(p.get("state") or "").lower() == "enabled"
    ]


def _grants(policy: dict[str, Any]) -> set[str]:
    return {str(c).lower() for c in _first(policy, "grantControls", "builtInControls") or []}


def _all_users(policy: dict[str, Any]) -> bool:
    users = _first(policy, "conditions", "users", "includeUsers") or []
    return "all" in {str(u).lower() for u in users}


def risky_sign_in_mfa(policies: Any) -> bool | None:
    """Whether an enabled policy challenges or blocks every user's risky
    sign-ins at medium risk or higher -- a policy on high alone lets the
    medium ones through."""
    if not isinstance(policies, list):
        return None
    for policy in _enabled(policies):
        levels = {
            str(level).lower() for level in _first(policy, "conditions", "signInRiskLevels") or []
        }
        if "medium" in levels and _all_users(policy) and _grants(policy) & {"mfa", "block"}:
            return True
    return False


def location_policy(policies: Any) -> bool | None:
    """Whether an enabled policy decides anything by where a sign-in comes
    from."""
    if not isinstance(policies, list):
        return None
    return any(
        bool(_first(policy, "conditions", "locations", "includeLocations"))
        for policy in _enabled(policies)
    )


def sign_in_frequency(policies: Any) -> bool | None:
    """Whether an enabled policy makes sessions sign in again after a set time,
    rather than keeping them for the token's sliding lifetime."""
    if not isinstance(policies, list):
        return None
    return any(
        _first(policy, "sessionControls", "signInFrequency", "isEnabled") is True
        for policy in _enabled(policies)
    )


REGISTER_DEVICE_ACTION = "urn:user:registerdevice"


def device_registration_mfa_by_policy(policies: Any) -> bool | None:
    """Whether an enabled policy requires a second factor to register or join a
    device -- the way Microsoft now recommends, which needs the tenant-wide
    setting off."""
    if not isinstance(policies, list):
        return None
    for policy in _enabled(policies):
        actions = {
            str(a).lower()
            for a in _first(policy, "conditions", "applications", "includeUserActions") or []
        }
        if REGISTER_DEVICE_ACTION in actions and "mfa" in _grants(policy):
            return True
    return False


_NO_CONTEXT: dict[str, Any] = {
    "authenticator_app_context": None,
    "authenticator_location_context": None,
}


def authenticator_context(policy: Any) -> dict[str, Any]:
    """Whether Microsoft Authenticator's push notifications show which
    application and where a sign-in is from.

    ``default`` hands the choice to Microsoft, which has shown both since 2023;
    only an explicit ``disabled`` hides them.
    """
    if not isinstance(policy, dict):
        return dict(_NO_CONTEXT)
    configurations = policy.get("authenticationMethodConfigurations")
    if not isinstance(configurations, list):
        return dict(_NO_CONTEXT)
    authenticator = next(
        (
            c
            for c in configurations
            if isinstance(c, dict) and str(c.get("id") or "").lower() == "microsoftauthenticator"
        ),
        None,
    )
    if authenticator is None or str(authenticator.get("state") or "").lower() != "enabled":
        # Not offered, so no push notification can be sent to tire anybody of.
        return {"authenticator_app_context": True, "authenticator_location_context": True}
    features = authenticator.get("featureSettings")
    if not isinstance(features, dict):
        return dict(_NO_CONTEXT)

    def shown(name: str) -> bool | None:
        state = _first(features, name, "state")
        return None if state is None else str(state).lower() != "disabled"

    return {
        "authenticator_app_context": shown("displayAppInformationRequiredState"),
        "authenticator_location_context": shown("displayLocationInformationRequiredState"),
    }


def device_registration(policy: Any) -> str | None:
    """Whether joining or registering a device asks for a second factor:
    ``required`` or ``notRequired``, in Graph's words."""
    if not isinstance(policy, dict) or not policy:
        return None
    value = policy.get("multiFactorAuthConfiguration")
    return str(value) if value is not None else None


def subscription_move_policy(policy: Any) -> dict[str, Any]:
    """Whether subscriptions may leave or enter the directory.

    Read from the tenant's subscription policy. An unset field is read as
    blocked: since 1 May 2026 Microsoft documents "Allow no users" as the
    default for a tenant that never set either policy.
    """
    if not isinstance(policy, dict) or not policy:
        return {"subscriptions_may_leave": None, "subscriptions_may_enter": None}
    props = _first(policy, "properties", "properties")
    if not isinstance(props, dict):
        props = policy.get("properties") or {}
    return {
        "subscriptions_may_leave": props.get("blockSubscriptionsLeavingTenant") is False,
        "subscriptions_may_enter": props.get("blockSubscriptionsIntoTenant") is False,
    }


def guest_access_reviews(definitions: Any) -> bool | None:
    """Whether an active access review covers guest accounts.

    A review's scope is a Graph query; one naming ``userType eq 'Guest'`` reaches
    guests, and so does one over every user with no user-type filter.
    """
    if not isinstance(definitions, list):
        return None
    for definition in definitions:
        if not isinstance(definition, dict):
            continue
        if str(definition.get("status") or "").lower() in {"completed", "deleted"}:
            continue
        text = str(definition.get("scope") or "").lower().replace(" ", "")
        if "usertypeeq'guest'" in text or ("/users" in text and "usertype" not in text):
            return True
    return False


def tenant_extras(data: dict[str, Any]) -> dict[str, Any]:
    """Everything section 204 reads about the tenant."""
    policies = data.get("conditional_access_policies")
    return {
        "banned_password_list": banned_password_list(data.get("group_settings")),
        "risky_sign_in_mfa": risky_sign_in_mfa(policies),
        "location_policy": location_policy(policies),
        "sign_in_frequency_limited": sign_in_frequency(policies),
        "device_registration_mfa_by_policy": device_registration_mfa_by_policy(policies),
        "device_registration_mfa": device_registration(data.get("device_registration_policy")),
        "guest_access_reviews": guest_access_reviews(data.get("access_reviews")),
        **authenticator_context(data.get("authentication_methods_policy")),
        **subscription_move_policy(data.get("subscription_policy")),
    }


def sends_logs(settings: Any) -> bool | None:
    """Whether any diagnostic setting sends any log category somewhere."""
    if not isinstance(settings, list):
        return None
    return any(
        enabled_log_categories(s) and _has_destination(s) for s in settings if isinstance(s, dict)
    )
