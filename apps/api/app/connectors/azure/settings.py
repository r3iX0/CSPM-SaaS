"""The readings role v11 added, reduced to the fields the rules judge.

Kept beside the normalizer rather than inside it because each is a small pure
function over one reading and the normalizer calls it where the asset is built
(DECISIONS.md section 176). Every one keeps the distinction the rest of the
normalizer draws: ``None`` where the reading failed or was never taken, and a
value -- often an empty list -- where it arrived and said so. A rule reads
``None`` as UNKNOWN; only the second can pass or fail.

Where a service documents what an unset field means, the documented value is
written in and said so, rather than left for each rule to remember: an SMB
setting nobody changed allows every SMB version, and a vault key with no expiry
attribute never expires.
"""

import re
from collections.abc import Callable
from datetime import UTC, date, datetime
from typing import Any

from app.context.engine import AssetContext
from app.core.enums import Level, Provider, ResourceType
from app.domain.resource import CloudResource

ContextOf = Callable[[dict[str, Any], ResourceType], AssetContext]


def _first(value: Any, *path: str, default: Any = None) -> Any:
    node = value
    for key in path:
        if not isinstance(node, dict) or key not in node:
            return default
        node = node[key]
    return node


def _read(entries: Any, resource_id: str) -> Any:
    """One resource's entry in a per-resource reading, or None if it failed.

    The collector records ``"error: ..."`` against a resource it could not
    read; that and absence are both "not read".
    """
    if not isinstance(entries, dict):
        return None
    entry = entries.get(resource_id)
    return None if entry is None or isinstance(entry, str) else entry


def _truthy(value: Any) -> bool:
    """ARM's booleans, which the pricing API spells as the strings "True" and
    "False"."""
    return value is True or str(value).strip().lower() == "true"


# ------------------------------------------------------------ diagnostics
def enabled_log_categories(setting: dict[str, Any]) -> set[str]:
    """The log categories one diagnostic setting sends, lower-cased.

    A category group is kept under its own name -- ``alllogs`` covers every
    category, and a rule asking for one category accepts it.
    """
    found: set[str] = set()
    for log in _first(setting, "properties", "logs") or []:
        if not isinstance(log, dict) or log.get("enabled") is False:
            continue
        name = log.get("category") or log.get("categoryGroup")
        if name:
            found.add(str(name).lower())
    return found


def _has_destination(setting: dict[str, Any]) -> bool:
    props = setting.get("properties") or {}
    return bool(
        props.get("workspaceId")
        or props.get("storageAccountId")
        or props.get("eventHubAuthorizationRuleId")
    )


def exported_categories(entry: Any) -> list[str] | None:
    """Every log category some setting with a destination sends."""
    if not isinstance(entry, list):
        return None
    return sorted(
        {
            category
            for setting in entry
            if isinstance(setting, dict) and _has_destination(setting)
            for category in enabled_log_categories(setting)
        }
    )


def activity_log_accounts(entry: Any) -> set[str] | None:
    """The storage accounts the subscription's activity log is exported to."""
    if not isinstance(entry, list):
        return None
    return {
        str(account).lower()
        for setting in entry
        if isinstance(setting, dict)
        and (account := _first(setting, "properties", "storageAccountId"))
    }


# ----------------------------------------------------------- subscription
# The Microsoft cloud security benchmark, which Defender for Cloud assigns to
# every subscription it is on as ``SecurityCenterBuiltIn``.
SECURITY_BENCHMARK_INITIATIVE = "1f3afdf9-d0c9-4c3d-847f-89da613e70a8"
SECURITY_BENCHMARK_ASSIGNMENT = "securitycenterbuiltin"
CONTAINER_IMAGE_SCANNING = "containerregistriesvulnerabilityassessments"
IOT_HUB_TYPE = "microsoft.devices/iothubs"


def security_contacts(raw: Any) -> dict[str, Any]:
    """Who Defender for Cloud emails, and about what.

    A disabled contact sends nothing, so it is read as no contact at all. With
    none enabled every notification is "off" -- stated rather than None,
    because the listing arrived and said so.
    """
    if not isinstance(raw, list):
        return {
            "security_contact_emails": None,
            "alert_notification_severity": None,
            "attack_path_notification_level": None,
            "notify_roles": None,
        }
    emails: list[str] = []
    alert = "off"
    attack_path = "off"
    roles: set[str] = set()
    for contact in raw:
        props = (contact or {}).get("properties") or {}
        if props.get("isEnabled") is False:
            continue
        emails.extend(e.strip() for e in str(props.get("emails") or "").split(";") if e.strip())
        for source in props.get("notificationsSources") or []:
            kind = str((source or {}).get("sourceType") or "").lower()
            if kind == "alert" and source.get("minimalSeverity"):
                alert = str(source["minimalSeverity"]).lower()
            if kind == "attackpath" and source.get("minimalRiskLevel"):
                attack_path = str(source["minimalRiskLevel"]).lower()
        by_role = props.get("notificationsByRole") or {}
        if str(by_role.get("state") or "").lower() == "on":
            roles.update(str(role).lower() for role in by_role.get("roles") or [])
    return {
        "security_contact_emails": emails,
        "alert_notification_severity": alert,
        "attack_path_notification_level": attack_path,
        "notify_roles": sorted(roles),
    }


def security_settings(raw: Any) -> dict[str, Any]:
    """Whether Defender for Cloud hands machines to Defender for Endpoint and
    shares its data with Defender for Cloud Apps. None where the listing did not
    name the setting."""
    by_name: dict[str, Any] = {}
    if isinstance(raw, list):
        by_name = {
            str(setting.get("name") or "").upper(): _first(setting, "properties", "enabled")
            for setting in raw
            if isinstance(setting, dict)
        }
    return {
        "defender_endpoint_integration": by_name.get("WDATP"),
        "cloud_apps_integration": by_name.get("MCAS"),
    }


def container_image_scanning(raw: Any) -> bool | None:
    """Whether Defender for Containers scans registry images for vulnerabilities.

    Off whenever the Containers plan is off. On only when the plan is on and
    lists the extension as enabled; a plan that is on and states no extensions
    is not read as either.
    """
    if not isinstance(raw, list):
        return None
    plan = next(
        (p for p in raw if isinstance(p, dict) and str(p.get("name")) == "Containers"), None
    )
    if plan is None:
        return None
    if str(_first(plan, "properties", "pricingTier") or "").lower() != "standard":
        return False
    extensions = _first(plan, "properties", "extensions")
    if not isinstance(extensions, list):
        return None
    for extension in extensions:
        if str((extension or {}).get("name") or "").lower() == CONTAINER_IMAGE_SCANNING:
            return _truthy(extension.get("isEnabled"))
    return False


def security_benchmark_enforcement(raw: Any) -> str | None:
    """How the Microsoft cloud security benchmark is assigned here.

    ``Default`` enforces it, ``DoNotEnforce`` assigns it in name only, and
    ``Unassigned`` means no assignment of it applies to this subscription.
    """
    if not isinstance(raw, list):
        return None
    for assignment in raw:
        if not isinstance(assignment, dict):
            continue
        props = assignment.get("properties") or {}
        definition = str(props.get("policyDefinitionId") or "").lower()
        if (
            definition.endswith(f"/{SECURITY_BENCHMARK_INITIATIVE}")
            or str(assignment.get("name") or "").lower() == SECURITY_BENCHMARK_ASSIGNMENT
        ):
            # ARM's own default when the field is left out.
            return str(props.get("enforcementMode") or "Default")
    return "Unassigned"


def _leaves(condition: Any) -> list[dict[str, Any]]:
    leaves: list[dict[str, Any]] = []
    for entry in _first(condition, "allOf") or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("field"):
            leaves.append(entry)
        leaves.extend(leaf for leaf in entry.get("anyOf") or [] if isinstance(leaf, dict))
    return leaves


def _values(leaf: dict[str, Any]) -> list[str]:
    found = [leaf["equals"]] if leaf.get("equals") else []
    found.extend(leaf.get("containsAny") or [])
    return [str(value).lower() for value in found]


def activity_log_alerts(raw: Any, subscription_node: str) -> dict[str, Any]:
    """Which control-plane operations, and whether Service Health, an enabled
    alert watches across this whole subscription.

    An alert scoped to one resource group is not counted: it watches that group
    and nothing created beside it.
    """
    if not isinstance(raw, list):
        return {"alerted_operations": None, "service_health_alert": None}
    operations: set[str] = set()
    service_health = False
    for alert in raw:
        props = (alert or {}).get("properties") or {}
        if props.get("enabled") is False:
            continue
        scopes = {str(scope).lower().rstrip("/") for scope in props.get("scopes") or []}
        if subscription_node.lower() not in scopes:
            continue
        for leaf in _leaves(props.get("condition")):
            field = str(leaf.get("field") or "").lower()
            if field == "operationname":
                operations.update(_values(leaf))
            if field == "category" and "servicehealth" in _values(leaf):
                service_health = True
    return {
        "alerted_operations": sorted(operations),
        "service_health_alert": service_health,
    }


def iot_coverage(resources: Any, solutions: Any) -> dict[str, Any]:
    """The subscription's IoT hubs, from the inventory, and which of them an
    enabled Defender for IoT solution watches."""
    hubs: list[str] | None = None
    if isinstance(resources, list):
        hubs = sorted(
            str(row["id"])
            for row in resources
            if isinstance(row, dict)
            and row.get("id")
            and str(row.get("type") or "").lower() == IOT_HUB_TYPE
        )
    watched: list[str] | None = None
    if isinstance(solutions, list):
        watched = sorted(
            {
                str(hub).lower()
                for solution in solutions
                if str(_first(solution, "properties", "status") or "Enabled").lower()
                == "enabled"
                for hub in _first(solution, "properties", "iotHubs") or []
            }
        )
    return {"iot_hubs": hubs, "iot_hubs_watched": watched}


def subscription_settings(
    data: dict[str, Any], subscription_node: str, diagnostics_entry: Any
) -> dict[str, Any]:
    """Everything v11 reads about the subscription as a whole."""
    bastions = data.get("bastion_hosts")
    return {
        **security_contacts(data.get("security_contacts")),
        **security_settings(data.get("security_settings")),
        "container_image_scanning": container_image_scanning(data.get("defender_plans")),
        "security_benchmark_enforcement": security_benchmark_enforcement(
            data.get("policy_assignments")
        ),
        **activity_log_alerts(data.get("activity_log_alerts"), subscription_node),
        "activity_log_categories": exported_categories(diagnostics_entry),
        "bastion_host_count": len(bastions) if isinstance(bastions, list) else None,
        **iot_coverage(data.get("resources"), data.get("iot_security_solutions")),
        # Section 177.
        "defender_cspm": defender_cspm(data.get("defender_plans")),
        "application_insights_count": inventory_count(
            data.get("resources"), "microsoft.insights/components"
        ),
    }


def defender_cspm(raw: Any) -> bool | None:
    """Whether the paid Defender CSPM plan (``CloudPosture``) is on. None where
    the plan listing was not read or did not name the plan."""
    if not isinstance(raw, list):
        return None
    for plan in raw:
        if isinstance(plan, dict) and str(plan.get("name")) == "CloudPosture":
            return str(_first(plan, "properties", "pricingTier") or "").lower() == "standard"
    return None


def inventory_count(resources: Any, azure_type: str) -> int | None:
    """How many resources of one type the inventory lists. None if unread."""
    if not isinstance(resources, list):
        return None
    return sum(
        1
        for row in resources
        if isinstance(row, dict) and str(row.get("type") or "").lower() == azure_type
    )


# ----------------------------------------------------------------- storage
# What Azure Files allows when nobody chose: every SMB version and every
# channel cipher (the "maximum compatibility" profile).
SMB_DEFAULT_VERSIONS = "SMB2.1;SMB3.0;SMB3.1.1"
SMB_DEFAULT_CHANNEL_ENCRYPTION = "AES-128-CCM;AES-128-GCM;AES-256-GCM"
# Kinds with no file service; the collector does not ask them for one.
NO_FILE_SERVICE = frozenset({"blobstorage", "blockblobstorage"})


def file_service(account: dict[str, Any], services: Any) -> dict[str, Any]:
    has_files = str(account.get("kind") or "").lower() not in NO_FILE_SERVICE
    raw = _read(services, account.get("id") or "") if has_files else None
    if raw is None:
        return {
            "has_file_service": has_files,
            "file_share_soft_delete": None,
            "file_share_retention_days": None,
            "smb_versions": None,
            "smb_channel_encryption": None,
        }
    props = raw.get("properties") or {}
    retention = props.get("shareDeleteRetentionPolicy") or {}
    smb = _first(props, "protocolSettings", "smb") or {}
    return {
        "has_file_service": True,
        # An enabled flag absent from a policy that did arrive is off, as for
        # the blob service.
        "file_share_soft_delete": retention.get("enabled") is True,
        "file_share_retention_days": retention.get("days"),
        "smb_versions": smb.get("versions") or SMB_DEFAULT_VERSIONS,
        "smb_channel_encryption": smb.get("channelEncryption") or SMB_DEFAULT_CHANNEL_ENCRYPTION,
    }


# ------------------------------------------------------------------ vaults
def _enabled(item: dict[str, Any]) -> bool:
    return _first(item, "properties", "attributes", "enabled") is not False


def vault_contents(vault_id: str, keys: Any, secrets: Any) -> dict[str, Any]:
    """Which of a vault's enabled keys and secrets never expire, and which keys
    do not rotate.

    Named rather than counted, so the finding says which to fix. A disabled key
    or secret is left out: it cannot be used, which is the risk an expiry date
    bounds.

    Rotation is read from the key's own record. Where an enabled key's record
    does not state a rotation policy at all, it is not judged either way, and
    the vault is None unless another key is known not to rotate.
    """
    key_list = _read(keys, vault_id)
    secret_list = _read(secrets, vault_id)
    result: dict[str, Any] = {
        "keys_without_expiry": None,
        "keys_without_rotation": None,
        "secrets_without_expiry": None,
    }
    if isinstance(key_list, list):
        enabled = [k for k in key_list if isinstance(k, dict) and _enabled(k)]
        result["keys_without_expiry"] = sorted(
            str(k.get("name"))
            for k in enabled
            if not _first(k, "properties", "attributes", "exp")
        )
        unstated = False
        no_rotation: list[str] = []
        for key in enabled:
            props = key.get("properties") or {}
            if not isinstance(props.get("rotationPolicy"), dict):
                unstated = True
                continue
            actions = _first(props, "rotationPolicy", "lifetimeActions") or []
            if not any(
                str(_first(a, "action", "type") or "").lower() == "rotate" for a in actions
            ):
                no_rotation.append(str(key.get("name")))
        result["keys_without_rotation"] = (
            sorted(no_rotation) if no_rotation or not unstated else None
        )
    if isinstance(secret_list, list):
        result["secrets_without_expiry"] = sorted(
            str(s.get("name"))
            for s in secret_list
            if isinstance(s, dict)
            and _enabled(s)
            and not _first(s, "properties", "attributes", "exp")
        )
    return result


# --------------------------------------------------------------------- SQL
def sql_defences(server_id: str, data: dict[str, Any]) -> dict[str, Any]:
    threat = _read(data.get("sql_threat_detection"), server_id)
    protector = _read(data.get("sql_encryption_protector"), server_id)
    assessment = _read(data.get("sql_vulnerability_assessment"), server_id)

    result: dict[str, Any] = {
        "threat_detection_enabled": (
            str(_first(threat, "properties", "state") or "").lower() == "enabled"
            if threat is not None
            else None
        ),
        "tde_customer_managed_key": (
            str(_first(protector, "properties", "serverKeyType") or "").lower()
            == "azurekeyvault"
            if protector is not None
            else None
        ),
        "vulnerability_assessment": None,
        "va_recurring_scans": None,
        "va_scan_emails": None,
        "va_email_admins": None,
    }
    if assessment is None:
        return result
    express = str(_first(assessment, "express", "properties", "state") or "").lower()
    classic = _first(assessment, "classic", "properties") or {}
    scans = classic.get("recurringScans") or {}
    if express == "enabled":
        # The express configuration scans weekly by design and keeps its own
        # results; its notifications go through Defender for Cloud's contacts.
        result["vulnerability_assessment"] = "express"
    elif classic.get("storageContainerPath"):
        result["vulnerability_assessment"] = "classic"
    else:
        result["vulnerability_assessment"] = "off"
    result["va_recurring_scans"] = scans.get("isEnabled") is True
    result["va_scan_emails"] = [str(e) for e in scans.get("emails") or []]
    # The contract's default is true.
    result["va_email_admins"] = scans.get("emailSubscriptionAdmins") is not False
    return result


# ---------------------------------------------------------------- machines
def vm_protection(vm_id: str, data: dict[str, Any]) -> dict[str, Any]:
    """Whether a machine is behind just-in-time access, and backed up.

    A machine no vault names is unprotected only when every vault's items were
    read; one that could not be read might be the one protecting it.
    """
    jit: bool | None = None
    policies = data.get("jit_policies")
    if isinstance(policies, list):
        covered = {
            str(machine.get("id") or "").lower()
            for policy in policies
            for machine in _first(policy, "properties", "virtualMachines") or []
            if isinstance(machine, dict)
        }
        jit = vm_id.lower() in covered

    backed_up: bool | None = None
    backups = data.get("vm_backups")
    if isinstance(backups, dict):
        protected = {
            str(
                _first(item, "properties", "virtualMachineId")
                or _first(item, "properties", "sourceResourceId")
                or ""
            ).lower()
            for item in backups.get("items") or []
            if isinstance(item, dict)
        }
        if vm_id.lower() in protected:
            backed_up = True
        elif not backups.get("unread_vaults"):
            backed_up = False
    return {
        "jit_protected": jit,
        "backed_up": backed_up,
        "backup_daily_retention_days": _machine_retention(vm_id, data),
    }


_DAYS_PER = {"days": 1, "weeks": 7, "months": 30, "years": 365}


def retention_days(policy: dict[str, Any]) -> int | None:
    """How many days a backup policy keeps a daily recovery point.

    The daily schedule of a long-term policy, or a simple policy's one
    duration. None for a policy that states neither -- a workload policy of
    sub-policies, or a weekly-only one -- which is not judged.
    """
    retention = _first(policy, "properties", "retentionPolicy") or {}
    duration = _first(retention, "dailySchedule", "retentionDuration") or retention.get(
        "retentionDuration"
    )
    if not isinstance(duration, dict) or not isinstance(duration.get("count"), int):
        return None
    unit = _DAYS_PER.get(str(duration.get("durationType") or "").lower())
    return duration["count"] * unit if unit else None


def _vault_of(item_id: str) -> str:
    return item_id.lower().split("/backupfabrics/")[0]


def _machine_retention(vm_id: str, data: dict[str, Any]) -> int | None:
    backups = data.get("vm_backups")
    policies = data.get("backup_policies")
    if not isinstance(backups, dict) or not isinstance(policies, dict):
        return None
    item = next(
        (
            i
            for i in backups.get("items") or []
            if isinstance(i, dict)
            and str(_first(i, "properties", "virtualMachineId") or "").lower() == vm_id.lower()
        ),
        None,
    )
    if item is None:
        return None
    policy_id = str(_first(item, "properties", "policyId") or "").lower()
    by_vault = {str(v).lower(): p for v, p in policies.items()}
    listed = by_vault.get(_vault_of(str(item.get("id") or "")))
    if not isinstance(listed, list):
        return None
    policy = next(
        (p for p in listed if isinstance(p, dict) and str(p.get("id") or "").lower() == policy_id),
        None,
    )
    return retention_days(policy) if policy else None


# ------------------------------------------------------------ app service
def app_authentication(site_id: str, data: dict[str, Any]) -> bool | None:
    """Whether App Service Authentication is on. Off where the settings arrived
    and did not say -- the platform's default."""
    raw = _read(data.get("app_service_auth"), site_id)
    if raw is None:
        return None
    return _first(raw, "properties", "platform", "enabled") is True


def http_logs_exported(entry: Any) -> bool | None:
    categories = exported_categories(entry)
    if categories is None:
        return None
    return bool({"appservicehttplogs", "alllogs"} & set(categories))


# ------------------------------------------------------------- runtimes
# When each language version's community support ends, which is when App
# Service stops patching it (App Service language support policy, read on
# 2026-09-30). Dated, and judged against when the snapshot was collected, so
# a version passing its date needs no release and a replay of an old capture
# answers as of that capture (section 177). A version newer than every entry
# here is supported: a newer version does not lose support before an older one.
# None is a version supported with no end date published.
END_OF_SUPPORT: dict[str, dict[tuple[int, ...], date | None]] = {
    # python.org release status.
    "python": {
        (3, 7): date(2023, 6, 27),
        (3, 8): date(2024, 10, 7),
        (3, 9): date(2025, 10, 31),
        (3, 10): date(2026, 10, 31),
        (3, 11): date(2027, 10, 31),
        (3, 12): date(2028, 10, 31),
        (3, 13): date(2029, 10, 31),
    },
    # php.net supported versions: the end of security support.
    "php": {
        (7, 4): date(2022, 11, 28),
        (8, 0): date(2023, 11, 26),
        (8, 1): date(2025, 12, 31),
        (8, 2): date(2026, 12, 31),
        (8, 3): date(2027, 12, 31),
        (8, 4): date(2028, 12, 31),
    },
    # App Service retired Java 7 on 29 July 2022 and supports 8, 11, 17, 21
    # and 25 with no end date published.
    "java": {(7,): date(2022, 7, 29), (8,): None, (11,): None, (17,): None, (21,): None,
             (25,): None},
    # Tomcat 8.5 and 10.0, which App Service still offers without patches.
    "tomcat": {(8, 5): date(2024, 3, 31), (9, 0): None, (10, 0): date(2022, 10, 31),
               (10, 1): None, (11, 0): None},
}

_LINUX_STACKS = {"python": "python", "php": "php", "java": "java", "tomcat": "tomcat",
                 "jbosseap": "java"}


def _version(text: str) -> tuple[int, ...] | None:
    match = re.match(r"\s*(\d+)(?:\.(\d+))?", text)
    if not match:
        return None
    major, minor = int(match.group(1)), match.group(2)
    # Java's old spelling: 1.8 is Java 8.
    if major == 1 and minor is not None:
        return (int(minor),)
    return (major, int(minor)) if minor is not None else (major,)


def _stacks(cfg: dict[str, Any]) -> list[tuple[str, tuple[int, ...]]]:
    """Every language and container version a site's configuration names."""
    found: list[tuple[str, tuple[int, ...]]] = []
    linux = str(cfg.get("linuxFxVersion") or "")
    if "|" in linux:
        stack, _, rest = linux.partition("|")
        language = _LINUX_STACKS.get(stack.strip().lower())
        if language == "tomcat":
            head, _, java = rest.partition("-java")
            if (v := _version(head)) is not None:
                found.append(("tomcat", v))
            if (v := _version(java)) is not None:
                found.append(("java", v))
        elif language == "java":
            _, _, java = rest.partition("-java")
            if (v := _version(java or rest)) is not None:
                found.append(("java", v))
        elif language and (v := _version(rest)) is not None:
            found.append((language, v))
    for field, language in (("pythonVersion", "python"), ("phpVersion", "php"),
                            ("javaVersion", "java")):
        value = str(cfg.get(field) or "")
        if value and value.lower() != "off" and (v := _version(value)) is not None:
            found.append((language, v))
    container = _version(str(cfg.get("javaContainerVersion") or ""))
    if str(cfg.get("javaContainer") or "").lower() == "tomcat" and container is not None:
        found.append(("tomcat", container))
    return found


def _supported(language: str, version: tuple[int, ...], on: date) -> bool | None:
    table = END_OF_SUPPORT[language]
    width = len(next(iter(table)))
    key = tuple(version[:width]) + (0,) * (width - len(version[:width]))
    if key in table:
        ends = table[key]
        return ends is None or on < ends
    # Unlisted: older than every listed version is out of support, newer than
    # every one is in, and one between two entries is not guessed at.
    if key < min(table):
        return False
    if key > max(table):
        return True
    return None


def web_runtime(cfg: dict[str, Any] | None, collected_at: datetime) -> dict[str, Any]:
    """Which languages a site runs and whether each is still supported, as of
    when the snapshot was taken. None throughout where the configuration was
    not read."""
    if cfg is None:
        return {"runtime_languages": None, "unsupported_runtimes": None}
    on = collected_at.astimezone(UTC).date()
    stacks = _stacks(cfg)
    verdicts = [(lang, version, _supported(lang, version, on)) for lang, version in stacks]
    return {
        "runtime_languages": sorted({"java" if lang == "tomcat" else lang for lang, _ in stacks}),
        "unsupported_runtimes": (
            None
            if any(ok is None for _, _, ok in verdicts)
            else sorted(
                f"{lang} {'.'.join(str(p) for p in version)}"
                for lang, version, ok in verdicts
                if ok is False
            )
        ),
    }


# ------------------------------------------------------------------ assets
def backup_vaults(data: dict[str, Any], context: ContextOf) -> list[CloudResource]:
    """Recovery Services vaults as assets (section 177): what each protects,
    and which of its policies keep recovery points under 30 days."""
    backups = data.get("vm_backups")
    if not isinstance(backups, dict):
        return []
    items = [i for i in backups.get("items") or [] if isinstance(i, dict)]
    unread = {str(v).lower() for v in backups.get("unread_vaults") or []}
    policies = data.get("backup_policies")
    found: list[CloudResource] = []
    for vault in backups.get("vaults") or []:
        if not isinstance(vault, dict) or not vault.get("id"):
            continue
        vault_id = str(vault["id"])
        listed = _read(policies, vault_id)
        short: list[str] | None = None
        if isinstance(listed, list):
            short = sorted(
                str(p.get("name"))
                for p in listed
                if isinstance(p, dict)
                and (days := retention_days(p)) is not None
                and days < 30
            )
        found.append(
            CloudResource(
                provider_resource_id=vault_id,
                resource_type=ResourceType.BACKUP_VAULT,
                name=vault.get("name", "unnamed"),
                provider=Provider.AZURE,
                region=vault.get("location"),
                **context(vault, ResourceType.BACKUP_VAULT).fields(),
                public_exposure=Level.LOW,
                metadata={
                    "protected_item_count": (
                        None
                        if vault_id.lower() in unread
                        else sum(
                            1
                            for i in items
                            if _vault_of(str(i.get("id") or "")) == vault_id.lower()
                        )
                    ),
                    "short_retention_policies": short,
                    "soft_delete": _first(
                        vault, "properties", "securitySettings", "softDeleteSettings",
                        "softDeleteState",
                    ),
                    "tags": vault.get("tags") or {},
                },
            )
        )
    return found


def scale_sets(data: dict[str, Any], context: ContextOf) -> list[CloudResource]:
    """Virtual machine scale sets (section 177): how many instances each runs
    and whether a load balancer or application gateway fronts it."""
    found: list[CloudResource] = []
    for scale_set in data.get("scale_sets") or []:
        if not isinstance(scale_set, dict) or not scale_set.get("id"):
            continue
        props = scale_set.get("properties") or {}
        profile = props.get("virtualMachineProfile")
        balanced: bool | None = None
        public = False
        if isinstance(profile, dict):
            balanced = False
            for nic in _first(profile, "networkProfile", "networkInterfaceConfigurations") or []:
                for ip in _first(nic, "properties", "ipConfigurations") or []:
                    ip_props = (ip or {}).get("properties") or {}
                    if ip_props.get("loadBalancerBackendAddressPools") or ip_props.get(
                        "applicationGatewayBackendAddressPools"
                    ):
                        balanced = True
                    if ip_props.get("publicIPAddressConfiguration"):
                        public = True
        capacity = _first(scale_set, "sku", "capacity")
        found.append(
            CloudResource(
                provider_resource_id=str(scale_set["id"]),
                resource_type=ResourceType.SCALE_SET,
                name=scale_set.get("name", "unnamed"),
                provider=Provider.AZURE,
                region=scale_set.get("location"),
                **context(scale_set, ResourceType.SCALE_SET).fields(),
                # Instances with their own public address answer the internet;
                # otherwise what fronts the set is judged on its own asset.
                public_exposure=Level.HIGH if public else Level.LOW,
                metadata={
                    "capacity": capacity if isinstance(capacity, int) else None,
                    "orchestration_mode": props.get("orchestrationMode"),
                    "load_balanced": balanced,
                    "instance_public_ips": public,
                    "tags": scale_set.get("tags") or {},
                },
            )
        )
    return found


_CUSTOMER_KEY_TYPES = frozenset(
    {"encryptionatrestwithcustomerkey", "encryptionatrestwithplatformandcustomerkeys"}
)


def disks(data: dict[str, Any], context: ContextOf) -> list[CloudResource]:
    """Managed disks, as assets of their own.

    Before v11 they were unchecked inventory rows. No network endpoint answers
    for a disk, so exposure is LOW: its contents leave only through an export
    somebody authorized.
    """
    found: list[CloudResource] = []
    for disk in data.get("disks") or []:
        if not isinstance(disk, dict) or not disk.get("id"):
            continue
        props = disk.get("properties") or {}
        encryption = props.get("encryption") or {}
        # The platform key is the documented default when no type is stated.
        kind = str(encryption.get("type") or "EncryptionAtRestWithPlatformKey")
        found.append(
            CloudResource(
                provider_resource_id=disk["id"],
                resource_type=ResourceType.DISK,
                name=disk.get("name", "unnamed"),
                provider=Provider.AZURE,
                region=disk.get("location"),
                **context(disk, ResourceType.DISK).fields(),
                public_exposure=Level.LOW,
                metadata={
                    "disk_state": props.get("diskState"),
                    "attached_to": disk.get("managedBy"),
                    "encryption_type": kind,
                    "customer_managed_key": kind.lower() in _CUSTOMER_KEY_TYPES,
                    "disk_encryption_set": encryption.get("diskEncryptionSetId"),
                    "network_access_policy": props.get("networkAccessPolicy"),
                    "public_network_access": props.get("publicNetworkAccess"),
                    "size_gb": props.get("diskSizeGB"),
                    "tags": disk.get("tags") or {},
                },
            )
        )
    return found


def _watchers_by_region(data: dict[str, Any]) -> dict[str, str] | None:
    watchers = data.get("network_watchers")
    if not isinstance(watchers, list):
        return None
    return {
        str(w.get("location") or "").lower(): str(w["id"])
        for w in watchers
        if isinstance(w, dict) and w.get("id")
    }


def _flow_log(entry: dict[str, Any]) -> dict[str, Any]:
    props = entry.get("properties") or {}
    retention = props.get("retentionPolicy") or {}
    analytics = (
        _first(props, "flowAnalyticsConfiguration", "networkWatcherFlowAnalyticsConfiguration")
        or {}
    )
    return {
        "id": entry.get("id"),
        "target": props.get("targetResourceId"),
        "enabled": props.get("enabled") is True,
        "retention_enabled": retention.get("enabled") is True,
        "retention_days": retention.get("days"),
        "traffic_analytics": analytics.get("enabled") is True
        and bool(analytics.get("workspaceResourceId") or analytics.get("workspaceId")),
    }


def _covers(entry: dict[str, Any], network_id: str, subnet_nsgs: set[str]) -> bool:
    target = str(_first(entry, "properties", "targetResourceId") or "").lower()
    return (
        target == network_id
        or target.startswith(f"{network_id}/subnets/")
        or target in subnet_nsgs
    )


def virtual_networks(data: dict[str, Any], context: ContextOf) -> list[CloudResource]:
    """Virtual networks, with the watcher and flow logs that observe each one.

    A flow log covers a network when it targets the network, one of its
    subnets, or a network security group on one of its subnets -- the older
    NSG flow logs, now retiring, record the same traffic. Flow logs live in the
    watcher of the target's region, so a network in a region with no watcher
    has none.
    """
    watchers = _watchers_by_region(data)
    logs_by_watcher = data.get("flow_logs")
    found: list[CloudResource] = []
    for network in data.get("virtual_networks") or []:
        if not isinstance(network, dict) or not network.get("id"):
            continue
        props = network.get("properties") or {}
        network_id = str(network["id"])
        region = str(network.get("location") or "").lower()
        subnets = [s for s in props.get("subnets") or [] if isinstance(s, dict)]
        subnet_nsgs = {
            str(nsg).lower()
            for s in subnets
            if (nsg := _first(s, "properties", "networkSecurityGroup", "id"))
        }

        in_region: bool | None = None
        flow_logs: list[dict[str, Any]] | None = None
        if watchers is not None:
            watcher = watchers.get(region)
            in_region = watcher is not None
            entries = _read(logs_by_watcher, watcher) if watcher else []
            if isinstance(entries, list):
                flow_logs = [
                    _flow_log(e)
                    for e in entries
                    if isinstance(e, dict) and _covers(e, network_id.lower(), subnet_nsgs)
                ]

        found.append(
            CloudResource(
                provider_resource_id=network_id,
                resource_type=ResourceType.VIRTUAL_NETWORK,
                name=network.get("name", "unnamed"),
                provider=Provider.AZURE,
                region=network.get("location"),
                **context(network, ResourceType.VIRTUAL_NETWORK).fields(),
                # A network is not an endpoint; what answers in it is judged on
                # its own asset.
                public_exposure=Level.LOW,
                metadata={
                    "address_space": _first(props, "addressSpace", "addressPrefixes") or [],
                    "subnets": [str(s.get("id")) for s in subnets if s.get("id")],
                    "ddos_protection": props.get("enableDdosProtection"),
                    "ddos_protection_plan": _first(props, "ddosProtectionPlan", "id"),
                    "network_watcher_in_region": in_region,
                    "flow_logs": flow_logs,
                    "tags": network.get("tags") or {},
                },
            )
        )
    return found
