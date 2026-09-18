"""Build ``snapshot_demo.json``: the recording the demo organization is seeded from.

The mixed recording is ten assets and two routes -- enough for the rules it was
written to exercise, and too little to show what the graph is for. This is that
recording with an estate added around it, in the same raw ARM shape the
collector produces, so the demo still runs the real normalizer, rules and risk
engine rather than showing fabricated rows.

Built from code rather than written by hand because what it adds is easier to
review as intent than as four thousand lines of JSON. The committed JSON is the
fixture; ``test_demo_recording.py`` fails when it and this script disagree.

    python tests/fixtures/azure_raw/build_snapshot_demo.py

What it adds, and which part of the graph view each piece exercises:

* **A payments service** (``rg-payments``). An internet-facing app whose
  managed identity can write the payments ledger and read the payments vault:
  a two-hop route, and a key vault on the canvas.
* **A build agent** (``rg-build``). A VM with a public IP and SSH open to the
  internet, whose identity holds User Access Administrator over ``rg-payments``. It can grant
  itself any role there, so it is an escalation chain as well as a route.
* **A data resource group** (``rg-data``). Sixteen log archives and one account
  of customer records. More than a canvas draws, so it folds, and the one
  sensitive account is drawn out of the fold. Three routes from two entry
  points reach it, so no single cut closes every way to it -- which is what
  makes the choke points worth asking about.

Every asset the mixed recording already had is kept unchanged, so the demo's
``--fix`` replay and every finding it used to show still apply.
"""

import copy
import json
from pathlib import Path
from typing import Any

HERE = Path(__file__).parent
SOURCE = HERE / "snapshot_mixed.json"
TARGET = HERE / "snapshot_demo.json"

SUB = "/subscriptions/00000000-0000-0000-0000-000000000001"
LOCATION = "westeurope"

# Built-in role definitions, with their real ids and permissions. The graph
# only needs the id to resolve; the permissions are what decide whether a role
# can grant roles, which is the escalation edge.
ROLES: dict[str, tuple[str, list[str]]] = {
    "ba92f5b4-2d11-453d-a403-e96b0029c9fe": (
        "Storage Blob Data Contributor",
        [
            "Microsoft.Storage/storageAccounts/blobServices/containers/delete",
            "Microsoft.Storage/storageAccounts/blobServices/containers/read",
            "Microsoft.Storage/storageAccounts/blobServices/containers/write",
            "Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action",
        ],
    ),
    "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1": (
        "Storage Blob Data Reader",
        [
            "Microsoft.Storage/storageAccounts/blobServices/containers/read",
            "Microsoft.Storage/storageAccounts/blobServices/generateUserDelegationKey/action",
        ],
    ),
    "4633458b-17de-408a-b874-0445c86b69e6": ("Key Vault Secrets User", []),
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9": (
        "User Access Administrator",
        ["*/read", "Microsoft.Authorization/*", "Microsoft.Support/*"],
    ),
    "acdd72a7-3385-48ef-bd42-f606fba81ae7": ("Reader", ["*/read"]),
}


def arm(group: str, provider: str, name: str) -> str:
    return f"{SUB}/resourceGroups/{group}/providers/{provider}/{name}"


def role_definition(role_id: str) -> dict[str, Any]:
    name, actions = ROLES[role_id]
    return {
        "id": f"{SUB}/providers/Microsoft.Authorization/roleDefinitions/{role_id}",
        "name": role_id,
        "properties": {
            "roleName": name,
            "type": "BuiltInRole",
            "permissions": [{"actions": actions, "notActions": []}],
        },
    }


def role_assignment(key: str, principal_id: str, role_id: str, scope: str) -> dict[str, Any]:
    return {
        "id": f"{SUB}/providers/Microsoft.Authorization/roleAssignments/{key}",
        "name": key,
        "type": "Microsoft.Authorization/roleAssignments",
        "properties": {
            "roleDefinitionId": role_definition(role_id)["id"],
            "principalId": principal_id,
            "principalType": "ServicePrincipal",
            "scope": scope,
        },
    }


def storage_account(group: str, name: str, tags: dict[str, str]) -> dict[str, Any]:
    """A storage account closed to the internet: sensitive or not, never a way in."""
    return {
        "id": arm(group, "Microsoft.Storage", f"storageAccounts/{name}"),
        "name": name,
        "location": LOCATION,
        "tags": tags,
        "properties": {
            "allowBlobPublicAccess": False,
            "supportsHttpsTrafficOnly": True,
            "minimumTlsVersion": "TLS1_2",
            "allowSharedKeyAccess": False,
            "allowCrossTenantReplication": False,
            "publicNetworkAccess": "Disabled",
            "networkAcls": {"defaultAction": "Deny", "ipRules": [], "virtualNetworkRules": []},
            "encryption": {"requireInfrastructureEncryption": True},
        },
    }


def blob_service(account_id: str) -> dict[str, Any]:
    return {
        "id": f"{account_id}/blobServices/default",
        "name": "default",
        "type": "Microsoft.Storage/storageAccounts/blobServices",
        "properties": {
            "deleteRetentionPolicy": {"enabled": True, "days": 14},
            "containerDeleteRetentionPolicy": {"enabled": True, "days": 14},
            "isVersioningEnabled": True,
        },
    }


def diagnostics() -> list[dict[str, Any]]:
    return [{"name": "to-workspace", "properties": {"workspaceId": "/ws/1"}}]


def web_app(group: str, name: str, principal_id: str, tenant: str, public: bool) -> dict[str, Any]:
    return {
        "id": arm(group, "Microsoft.Web", f"sites/{name}"),
        "name": name,
        "type": "Microsoft.Web/sites",
        "kind": "app,linux",
        "location": LOCATION,
        "tags": {"environment": "production"},
        "properties": {
            "httpsOnly": True,
            "clientCertEnabled": False,
            "publicNetworkAccess": "Enabled" if public else "Disabled",
            "state": "Running",
        },
        "identity": {"type": "SystemAssigned", "principalId": principal_id, "tenantId": tenant},
    }


def build() -> dict[str, Any]:
    snapshot = copy.deepcopy(json.loads(SOURCE.read_text()))
    data = snapshot["data"]
    tenant = snapshot["tenant_id"]

    # The subscription's own record, as ARM returns it, so the node every
    # subscription-wide role lands on reads as a name rather than a GUID.
    data["subscription"] = {
        "id": SUB,
        "subscriptionId": snapshot["subscription_id"],
        "tenantId": tenant,
        "displayName": "Production",
        "state": "Enabled",
    }

    # ------------------------------------------------------------- payments
    ledger = storage_account(
        "rg-payments",
        "stpaymentsledger",
        {"environment": "production", "data_classification": "confidential"},
    )
    vault_id = arm("rg-payments", "Microsoft.KeyVault", "vaults/kv-payments")
    payments_app = web_app(
        "rg-payments", "app-payments-api", "22222222-0000-0000-0000-000000000001", tenant, True
    )
    payments_app["tags"]["criticality"] = "critical"

    # ---------------------------------------------------------------- build
    build_nic_id = arm("rg-build", "Microsoft.Network", "networkInterfaces/nic-build-agent")
    build_nsg_id = arm("rg-build", "Microsoft.Network", "networkSecurityGroups/nsg-build-agent")
    build_pip_id = arm("rg-build", "Microsoft.Network", "publicIPAddresses/pip-build-agent")
    build_agent = {
        "id": arm("rg-build", "Microsoft.Compute", "virtualMachines/vm-build-agent"),
        "name": "vm-build-agent",
        "location": LOCATION,
        "tags": {"environment": "production", "criticality": "medium"},
        "properties": {
            "hardwareProfile": {"vmSize": "Standard_D4s_v5"},
            "storageProfile": {
                "osDisk": {
                    "osType": "Linux",
                    "managedDisk": {
                        "id": arm("rg-build", "Microsoft.Compute", "disks/vm-build-agent-os"),
                        "storageAccountType": "Premium_LRS",
                    },
                }
            },
            "networkProfile": {"networkInterfaces": [{"id": build_nic_id}]},
        },
        "identity": {
            "type": "SystemAssigned",
            "principalId": "33333333-0000-0000-0000-000000000001",
            "tenantId": tenant,
        },
    }

    # ----------------------------------------------------------------- data
    archives = [
        storage_account(
            "rg-data",
            f"starchive{index:02d}",
            {"environment": "production", "data_classification": "internal"},
        )
        for index in range(1, 17)
    ]
    customer_records = storage_account(
        "rg-data",
        "stcustomerrecords",
        {"environment": "production", "data_classification": "restricted"},
    )
    # Not reachable from the internet: its identity reaches the data, but it
    # is not a way in, so it never starts a route.
    reporting_app = web_app(
        "rg-data", "app-reporting", "44444444-0000-0000-0000-000000000001", tenant, False
    )

    storages = [ledger, customer_records, *archives]
    data["storage_accounts"].extend(storages)
    for account in storages:
        data["storage_blob_services"][account["id"]] = blob_service(account["id"])
        data["diagnostic_settings"][account["id"]] = diagnostics()

    data["app_services"].extend([payments_app, reporting_app])
    for site in (payments_app, reporting_app):
        data["app_service_configs"][site["id"]] = {
            "id": f"{site['id']}/config/web",
            "name": "web",
            "type": "Microsoft.Web/sites/config",
            "properties": {
                "minTlsVersion": "1.2",
                "scmMinTlsVersion": "1.2",
                "ftpsState": "Disabled",
                "remoteDebuggingEnabled": False,
                "http20Enabled": True,
            },
        }

    data["virtual_machines"].append(build_agent)
    data["network_interfaces"].append(
        {
            "id": build_nic_id,
            "name": "nic-build-agent",
            "properties": {
                "networkSecurityGroup": {"id": build_nsg_id},
                "ipConfigurations": [
                    {
                        "name": "ipconfig1",
                        "properties": {
                            "publicIPAddress": {"id": build_pip_id},
                            "subnet": {
                                "id": arm(
                                    "rg-build",
                                    "Microsoft.Network",
                                    "virtualNetworks/vnet-build/subnets/agents",
                                )
                            },
                        },
                    }
                ]
            },
        }
    )
    data["network_security_groups"].append(
        {
            "id": build_nsg_id,
            "name": "nsg-build-agent",
            "location": LOCATION,
            "tags": {"environment": "production"},
            "properties": {
                "securityRules": [
                    {
                        "name": "AllowSSH",
                        "properties": {
                            "direction": "Inbound",
                            "access": "Allow",
                            "protocol": "Tcp",
                            "sourceAddressPrefix": "*",
                            "destinationPortRange": "22",
                            "priority": 100,
                        },
                    }
                ],
                "defaultSecurityRules": [{"name": "DenyAllInBound"}],
                "networkInterfaces": [{"id": build_nic_id}],
            },
        }
    )
    data["diagnostic_settings"][build_nsg_id] = diagnostics()
    data["public_ip_addresses"].append(
        {"id": build_pip_id, "name": "pip-build-agent", "properties": {"ipAddress": "20.50.10.20"}}
    )

    data["key_vaults"] = [
        {
            "id": vault_id,
            "name": "kv-payments",
            "location": LOCATION,
            "tags": {"environment": "production"},
            "properties": {
                "enablePurgeProtection": True,
                "enableSoftDelete": True,
                "softDeleteRetentionInDays": 90,
                "publicNetworkAccess": "Disabled",
                "networkAcls": {"defaultAction": "Deny", "ipRules": [], "virtualNetworkRules": []},
                "enableRbacAuthorization": True,
                "accessPolicies": [],
            },
        }
    ]
    data["diagnostic_settings"][vault_id] = diagnostics()

    # -------------------------------------------------------------- access
    known_roles = {definition["id"] for definition in data["role_definitions"]}
    for role_id in ROLES:
        definition = role_definition(role_id)
        if definition["id"] not in known_roles:
            data["role_definitions"].append(definition)

    payments = payments_app["identity"]["principalId"]
    builder = build_agent["identity"]["principalId"]
    reporting = reporting_app["identity"]["principalId"]
    data_group = f"{SUB}/resourceGroups/rg-data"
    data["role_assignments"].extend(
        [
            role_assignment(
                "pay-ledger", payments, "ba92f5b4-2d11-453d-a403-e96b0029c9fe", ledger["id"]
            ),
            role_assignment(
                "pay-vault", payments, "4633458b-17de-408a-b874-0445c86b69e6", vault_id
            ),
            role_assignment(
                "pay-records", payments, "2a2b9908-6ea1-4ae2-8e65-a410df84e7d1", data_group
            ),
            role_assignment(
                "build-uaa",
                builder,
                "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",
                f"{SUB}/resourceGroups/rg-payments",
            ),
            role_assignment(
                "reporting-reader", reporting, "acdd72a7-3385-48ef-bd42-f606fba81ae7", data_group
            ),
        ]
    )

    # ------------------------------------------------------------ coverage
    coverage = snapshot["coverage"]
    for key, category in (
        ("storage_accounts", "storage"),
        ("virtual_machines", "compute"),
        ("network_interfaces", "network"),
        ("network_security_groups", "network"),
        ("public_ip_addresses", "network"),
        ("app_services", "compute"),
        ("role_assignments", "authorization"),
        ("role_definitions", "authorization"),
        ("key_vaults", "secrets"),
        ("subscription", "resources"),
    ):
        entry = coverage.setdefault(
            key, {"category": category, "outcome": "COMPLETE", "detail": "", "item_count": 0}
        )
        entry["item_count"] = len(data[key]) if isinstance(data[key], list) else 1

    return snapshot


def render() -> str:
    return json.dumps(build(), indent=2) + "\n"


if __name__ == "__main__":
    TARGET.write_text(render())
    print(f"wrote {TARGET}")
