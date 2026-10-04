"""What a vault holds, as far as its management plane says (DECISIONS.md section 176).

Whether each enabled key and secret expires, and whether keys rotate. Read
through ARM's keys and secrets listings, which return attributes and never a
secret's value or a key's private material -- the role still holds no data
action. One rule each rather than one per access model: the catalogue split
every check by whether the vault uses Azure RBAC or access policies, and an
expiry date means the same thing under both.

A finding names the keys and secrets, so it says what to fix.
"""

from typing import Any

from app.connectors.azure.evidence import AzureEvidence
from app.core.enums import ResourceType, Severity
from app.rules.property import PropertySpec, property_rule

_KEY_LIFECYCLE = {
    "ISO_27001": ["A.8.24"],
    "NIST_CSF_2.0": ["PR.DS-01", "PR.AA-01"],
    "GDPR": ["32(1)(a)"],
    "NIST_800_53": ["SC-12", "IA-5"],
    "SOC2": ["CC6.1"],
    "PCI_DSS_4": ["3.6.1"],
}


def _none(names: Any) -> bool:
    return not names


_NAMES = (
    "The check passes when no enabled item lacks the setting, and the failing items "
    "are named in the finding, so there is no one value to expect."
)

SPECS = (
    PropertySpec(
        rule_id="AZ-KV-004",
        name="Key vault holds keys that never expire",
        description=(
            "An enabled key in the vault has no expiration date, so it stays usable "
            "indefinitely however long ago it was meant to be replaced."
        ),
        rationale=(
            "An expiry date bounds how long a key that leaked stays useful, and forces "
            "the rotation that a key nobody remembers creating never gets."
        ),
        remediation=(
            "Set an expiration date on each key named in the finding, or give it a "
            "rotation policy that sets one.\n\n"
            "Azure CLI:\n"
            "  az keyvault key set-attributes --vault-name <vault> --name <key> \\\n"
            "    --expires <YYYY-MM-DDThh:mm:ssZ>"
        ),
        cli=(
            "az keyvault key set-attributes --vault-name <vault> --name <key> "
            "--expires <YYYY-MM-DDThh:mm:ssZ>",
        ),
        severity=Severity.MEDIUM,
        exploitability=1,
        category="secrets",
        resource_type=ResourceType.KEY_VAULT,
        evidence=(AzureEvidence.KEY_VAULTS, AzureEvidence.KEY_VAULT_KEYS),
        field="keys_without_expiry",
        passes=_none,
        why_no_expected_state=_NAMES,
        describes="Every enabled key has an expiration date",
        failure="holds enabled keys with no expiration date",
        mappings={**_KEY_LIFECYCLE, "PCI_DSS_4": ["3.6.1", "3.7"]},
    ),
    PropertySpec(
        rule_id="AZ-KV-005",
        name="Key vault holds secrets that never expire",
        description=(
            "An enabled secret in the vault has no expiration date, so a password or "
            "connection string stored there is never forced to change."
        ),
        rationale=(
            "Secrets leak -- into logs, repositories, laptops. An expiry date is what "
            "makes a leaked one stop working without anyone noticing it leaked."
        ),
        remediation=(
            "Set an expiration date on each secret named in the finding.\n\n"
            "Azure CLI:\n"
            "  az keyvault secret set-attributes --vault-name <vault> --name <secret> \\\n"
            "    --expires <YYYY-MM-DDThh:mm:ssZ>"
        ),
        cli=(
            "az keyvault secret set-attributes --vault-name <vault> --name <secret> "
            "--expires <YYYY-MM-DDThh:mm:ssZ>",
        ),
        severity=Severity.MEDIUM,
        exploitability=1,
        category="secrets",
        resource_type=ResourceType.KEY_VAULT,
        evidence=(AzureEvidence.KEY_VAULTS, AzureEvidence.KEY_VAULT_SECRETS),
        field="secrets_without_expiry",
        passes=_none,
        why_no_expected_state=_NAMES,
        describes="Every enabled secret has an expiration date",
        failure="holds enabled secrets with no expiration date",
        mappings={**_KEY_LIFECYCLE, "PCI_DSS_4": ["3.6.1", "8.6"]},
    ),
    PropertySpec(
        rule_id="AZ-KV-006",
        name="Key vault holds keys that never rotate",
        description=(
            "An enabled key's rotation policy has no rotate action, so Key Vault never "
            "issues a new version of it."
        ),
        rationale=(
            "Automatic rotation replaces key material on a schedule without anyone "
            "having to remember, and services reading the key's latest version follow "
            "it without a deployment."
        ),
        remediation=(
            "Give each key named in the finding a rotation policy that rotates it.\n\n"
            "Azure CLI:\n"
            "  az keyvault key rotation-policy update --vault-name <vault> --name <key> \\\n"
            "    --value @rotation-policy.json"
        ),
        cli=(
            "az keyvault key rotation-policy update --vault-name <vault> --name <key> "
            "--value @rotation-policy.json",
        ),
        severity=Severity.MEDIUM,
        exploitability=1,
        category="secrets",
        resource_type=ResourceType.KEY_VAULT,
        evidence=(AzureEvidence.KEY_VAULTS, AzureEvidence.KEY_VAULT_KEYS),
        field="keys_without_rotation",
        passes=_none,
        why_no_expected_state=_NAMES,
        describes="Every enabled key has a rotation policy that rotates it",
        failure="holds enabled keys that never rotate",
        mappings={**_KEY_LIFECYCLE, "PCI_DSS_4": ["3.6.1", "3.7"]},
    ),
)

RULES = tuple(property_rule(spec) for spec in SPECS)
