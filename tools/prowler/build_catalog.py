"""Generate Cleave's posture catalogue from the pinned Prowler release.

    python tools/prowler/build_catalog.py            # write the catalogue
    python tools/prowler/build_catalog.py --check    # fail if it is stale

Run with the interpreter of an environment that has exactly the Prowler
version ``curation.json`` pins -- the scanner image's, or a local venv built
from ``apps/scanner/requirements.txt``. The script refuses any other version,
because the catalogue is the contract between the two engines: the API reads
it to know what a Prowler result means, and the scanner reads it to know which
checks to run. A catalogue built from one release and a scanner running another
would disagree about check ids without either noticing.

What it writes, to ``apps/api/app/prowler/data/catalog.json``:

* one entry per Prowler check for the providers Cleave supports, with the
  metadata the API needs to raise a finding (title, severity, remediation,
  exploitability) and the decisions ``curation.json`` records about it
  (excluded and why, which native rule already answers it);
* the compliance mappings, translated into the control ids of Cleave's own
  frameworks where the two name the same control;
* the frameworks Cleave did not have before, built from Prowler's compliance
  files.

Edit ``curation.json`` or this script and rerun it. Never edit the output: the
next run overwrites it, and the ``--check`` step in CI fails on a hand edit.
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
CURATION = HERE / "curation.json"
OUTPUT = ROOT / "apps" / "api" / "app" / "prowler" / "data" / "catalog.json"

SCHEMA_VERSION = 1

PROVIDER_PREFIX = {"azure": "AZ", "aws": "AWS"}

# Prowler's severity words onto Cleave's scale. ``informational`` has no
# counterpart and is excluded by curation.json rather than mapped to LOW,
# because a finding that says nothing is wrong is not a finding.
SEVERITY = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
}

# Prowler's resource types onto Cleave's neutral ones, where one exists. The
# mapping is informational -- a posture rule never evaluates a resource itself,
# Prowler did -- and is what the rules page and the asset view use to say what
# a check is about. Anything unlisted is an empty ``applies_to``.
RESOURCE_TYPES: dict[str, str] = {
    # Azure
    "microsoft.storage/storageaccounts": "storage_account",
    "microsoft.web/sites": "app_service",
    "microsoft.web/sites/config": "app_service",
    "microsoft.sql/servers": "sql_server",
    "microsoft.sql/servers/databases": "sql_database",
    "microsoft.dbforpostgresql/flexibleservers": "postgresql_server",
    "microsoft.compute/virtualmachines": "virtual_machine",
    "microsoft.keyvault/vaults": "key_vault",
    "microsoft.keyvault/vaults/keys": "key_vault",
    "microsoft.keyvault/vaults/secrets": "key_vault",
    "microsoft.network/networksecuritygroups": "network_security_group",
    "microsoft.network/publicipaddresses": "public_ip",
    "microsoft.network/virtualnetworks": "virtual_network",
    "microsoft.network/virtualnetworks/subnets": "subnet",
    "microsoft.resources/subscriptions": "subscription",
    "microsoft.security/pricings": "subscription",
    "microsoft.insights/activitylogalerts": "subscription",
    "microsoft.authorization/roleassignments": "role_assignment",
    # AWS
    "AwsS3Bucket": "storage_account",
    "AwsEc2Instance": "virtual_machine",
    "AwsEc2SecurityGroup": "network_security_group",
    "AwsEc2NetworkInterface": "network_interface",
    "AwsEc2Eip": "public_ip",
    "AwsEc2Vpc": "virtual_network",
    "AwsEc2Subnet": "subnet",
    "AwsIamUser": "user",
    "AwsIamRole": "service_principal",
    "AwsKmsKey": "key_vault",
    "AwsRdsDbInstance": "sql_server",
    "AwsRdsDbCluster": "sql_server",
}

# Frameworks Cleave already catalogues, and which of Prowler's compliance files
# speak about them. A mapping is only ever emitted in Cleave's spelling of the
# control id; the API then keeps the ones its own catalogue lists, so a Prowler
# id Cleave does not recognise can never become a control nobody defined.
EXISTING = {
    "CIS_AZURE_2.0": {"azure": "cis_2.0_azure"},
    "CIS_AWS_3.0": {"aws": "cis_3.0_aws"},
    "ISO_27001": {"azure": "iso27001_2022_azure", "aws": "iso27001_2022_aws"},
    "SOC2": {"azure": "soc2_azure", "aws": "soc2_aws"},
    "PCI_DSS_4": {"azure": "pci_4.0_azure", "aws": "pci_4.0_aws"},
    "NIST_800_53": {"aws": "nist_800_53_revision_5_aws"},
    "GDPR": {"aws": "gdpr_aws"},
}

# Frameworks Cleave did not have, taken from Prowler's compliance files. Each is
# built from the files named, merged by requirement id where a framework exists
# for both clouds.
ADDED: dict[str, dict[str, Any]] = {
    "CIS_AZURE_6.0": {
        "files": {"azure": "cis_6.0_azure"},
        "name": "CIS Microsoft Azure Foundations Benchmark",
        "short_name": "CIS Azure 6.0",
        "version": "6.0",
        "authority": "Center for Internet Security",
        "url": "https://www.cisecurity.org/benchmark/azure",
        "provider": "azure",
    },
    "CIS_AWS_7.0": {
        "files": {"aws": "cis_7.0_aws"},
        "name": "CIS Amazon Web Services Foundations Benchmark",
        "short_name": "CIS AWS 7.0",
        "version": "7.0",
        "authority": "Center for Internet Security",
        "url": "https://www.cisecurity.org/benchmark/amazon_web_services",
        "provider": "aws",
    },
    "AWS_FSBP": {
        "files": {"aws": "aws_foundational_security_best_practices_aws"},
        "name": "AWS Foundational Security Best Practices",
        "short_name": "AWS FSBP",
        "version": "1.0",
        "authority": "Amazon Web Services",
        "url": "https://docs.aws.amazon.com/securityhub/latest/userguide/fsbp-standard.html",
        "provider": "aws",
    },
    "NIS2": {
        "files": {"azure": "nis2_azure", "aws": "nis2_aws"},
        "name": "NIS2 Directive technical and methodological requirements",
        "short_name": "NIS2",
        "version": "2024/2690",
        "authority": "European Union",
        "url": "https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj",
        "provider": None,
    },
    "HIPAA": {
        "files": {"azure": "hipaa_azure", "aws": "hipaa_aws"},
        "name": "HIPAA Security Rule",
        "short_name": "HIPAA",
        "version": "45 CFR 164",
        "authority": "U.S. Department of Health and Human Services",
        "url": "https://www.hhs.gov/hipaa/for-professionals/security/index.html",
        "provider": None,
    },
    "MITRE_ATTACK": {
        "files": {"azure": "mitre_attack_azure", "aws": "mitre_attack_aws"},
        "name": "MITRE ATT&CK techniques",
        "short_name": "ATT&CK",
        "version": "Enterprise",
        "authority": "MITRE",
        "url": "https://attack.mitre.org/",
        "provider": None,
    },
}


def _soc2(identifier: str) -> str:
    # cc_6_1 -> CC6.1, a_1_2 -> A1.2
    parts = identifier.split("_")
    if len(parts) == 3 and parts[1].isdigit() and parts[2].isdigit():
        return f"{parts[0].upper()}{parts[1]}.{parts[2]}"
    return identifier.upper()


def _nist_800_53(identifier: str) -> str:
    # ac_2 -> AC-2, ac_2_1 -> AC-2(1)
    parts = identifier.split("_")
    if len(parts) == 2:
        return f"{parts[0].upper()}-{parts[1]}"
    if len(parts) == 3:
        return f"{parts[0].upper()}-{parts[1]}({parts[2]})"
    return identifier.upper()


def _gdpr(identifier: str) -> str:
    # article_25 -> 25
    return identifier.removeprefix("article_")


def _same(identifier: str) -> str:
    return identifier


TRANSLATE: dict[str, Callable[[str], str]] = {
    "SOC2": _soc2,
    "NIST_800_53": _nist_800_53,
    "GDPR": _gdpr,
}


def load_curation() -> dict[str, Any]:
    return dict(json.loads(CURATION.read_text()))


def _prowler_version() -> str:
    return importlib.metadata.version("prowler")


def _compliance_dir() -> Path:
    import prowler

    return Path(prowler.__file__).resolve().parent / "compliance"


def _load_compliance(provider: str, name: str) -> dict[str, Any]:
    return dict(json.loads((_compliance_dir() / provider / f"{name}.json").read_text()))


def _exploitability(metadata: Any, severity: str, overrides: dict[str, int]) -> int:
    """How exploitable the worst instance of this check's failure is, 0-5.

    Same scale as ``SecurityRule.exploitability`` (RISK_ENGINE.md section 1):
    what an attacker must already hold. Derived from Prowler's categories,
    which say what kind of weakness a check finds, with the severity as the
    floor -- and overridden per check in curation.json where the derivation
    is wrong.
    """
    if metadata.CheckID in overrides:
        return int(overrides[metadata.CheckID])
    base = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 1}[severity]
    categories = set(metadata.Categories)
    if "internet-exposed" in categories:
        base = max(base, 4)
    if "privilege-escalation" in categories:
        base = max(base, 3)
    if "identity-access" in categories and severity in {"CRITICAL", "HIGH"}:
        base = max(base, 3)
    if {"secrets", "trust-boundaries"} & categories:
        base = max(base, 2)
    return min(base, 5)


def _remediation(metadata: Any) -> dict[str, str]:
    code = metadata.Remediation.Code
    recommendation = metadata.Remediation.Recommendation
    return {
        "text": (recommendation.Text or "").strip(),
        "url": (recommendation.Url or "").strip(),
        "cli": (code.CLI or "").strip(),
        "terraform": (code.Terraform or "").strip(),
        "native_iac": (code.NativeIaC or "").strip(),
        "other": (code.Other or "").strip(),
    }


def _excluded(metadata: Any, severity_word: str, curation: dict[str, Any]) -> str | None:
    check_id = metadata.CheckID
    if check_id in curation["exclude"]:
        return str(curation["exclude"][check_id])
    if severity_word in curation["exclude_severities"]:
        return "Informational: Prowler reports it without saying anything is wrong."
    for category, reason in curation["exclude_categories"].items():
        if category in metadata.Categories:
            return str(reason)
    for entry in curation["exclude_patterns"]:
        if re.search(entry["pattern"], check_id):
            return str(entry["reason"])
    return None


def build() -> dict[str, Any]:
    from prowler.lib.check.models import CheckMetadata

    curation = load_curation()
    installed = _prowler_version()
    if installed != curation["prowler_version"]:
        raise SystemExit(
            f"curation.json pins Prowler {curation['prowler_version']} but "
            f"{installed} is installed. Build from the pinned release."
        )

    covered_by: dict[str, list[str]] = {}
    for rule_id, rule_checks in curation["covered_by"].items():
        for check in rule_checks:
            covered_by.setdefault(check, []).append(rule_id)

    checks: dict[str, dict[str, Any]] = {}
    for provider in curation["providers"]:
        directory = set(curation["directory_services"].get(provider, []))
        for check_id, metadata in sorted(CheckMetadata.get_bulk(provider).items()):
            if check_id in checks:
                raise SystemExit(f"{check_id} exists for two providers; rule ids would collide")
            severity_word = str(getattr(metadata.Severity, "value", metadata.Severity))
            excluded = _excluded(metadata, severity_word, curation)
            severity = SEVERITY.get(severity_word, "LOW")
            checks[check_id] = {
                "rule_id": f"PRW-{PROVIDER_PREFIX[provider]}-{check_id}",
                "provider": provider,
                "service": metadata.ServiceName,
                "title": metadata.CheckTitle,
                "description": metadata.Description,
                "risk": metadata.Risk,
                "severity": severity,
                "resource_type": metadata.ResourceType,
                "applies_to": (
                    [RESOURCE_TYPES[metadata.ResourceType]]
                    if metadata.ResourceType in RESOURCE_TYPES
                    else []
                ),
                "categories": sorted(metadata.Categories),
                "scope": "directory" if metadata.ServiceName in directory else "account",
                "remediation": _remediation(metadata),
                "additional_urls": list(getattr(metadata, "AdditionalURLs", None) or []),
                "exploitability": _exploitability(
                    metadata, severity, curation["exploitability"]
                ),
                "enabled": excluded is None,
                "excluded_reason": excluded,
                "covered_by": sorted(covered_by.get(check_id, [])),
                "compliance": {},
            }

    missing = sorted(set(covered_by) - set(checks))
    if missing:
        raise SystemExit(
            "curation.json names checks this Prowler release does not have: "
            + ", ".join(missing)
        )

    # Existing frameworks: map each check onto Cleave's own control ids.
    for framework_id, files in EXISTING.items():
        translate = TRANSLATE.get(framework_id, _same)
        for provider, name in files.items():
            for requirement in _load_compliance(provider, name)["Requirements"]:
                control = translate(str(requirement["Id"]))
                for check_id in requirement.get("Checks") or []:
                    entry = checks.get(check_id)
                    if entry is None or entry["provider"] != provider:
                        continue
                    controls = entry["compliance"].setdefault(framework_id, [])
                    if control not in controls:
                        controls.append(control)

    # Added frameworks: the framework itself, and each check's mapping into it.
    frameworks = []
    for framework_id, spec in ADDED.items():
        catalogued: dict[str, dict[str, Any]] = {}
        for provider, name in spec["files"].items():
            for requirement in _load_compliance(provider, name)["Requirements"]:
                identifier = str(requirement["Id"])
                attributes = (requirement.get("Attributes") or [{}])[0]
                group = str(
                    attributes.get("Section")
                    or attributes.get("SubSection")
                    or attributes.get("Service")
                    or requirement.get("Name")
                    or framework_id
                )
                title = (
                    str(requirement.get("Description") or requirement.get("Name") or identifier)
                    .strip()
                    .split("\n")[0]
                )
                manual = str(attributes.get("AssessmentStatus", "")).lower() == "manual"
                if identifier not in catalogued:
                    catalogued[identifier] = {
                        "id": identifier,
                        "title": title[:300],
                        "group": group[:120],
                        "technically_assessable": not manual,
                    }
                for check_id in requirement.get("Checks") or []:
                    entry = checks.get(check_id)
                    if entry is None or entry["provider"] != provider:
                        continue
                    mapped = entry["compliance"].setdefault(framework_id, [])
                    if identifier not in mapped:
                        mapped.append(identifier)
        frameworks.append(
            {
                "id": framework_id,
                "name": spec["name"],
                "short_name": spec["short_name"],
                "version": spec["version"],
                "authority": spec["authority"],
                "url": spec["url"],
                "provider": spec["provider"],
                "source": sorted(spec["files"].values()),
                "controls": list(catalogued.values()),
            }
        )

    for entry in checks.values():
        entry["compliance"] = {
            framework: sorted(ids) for framework, ids in sorted(entry["compliance"].items())
        }

    return {
        "schema": SCHEMA_VERSION,
        "prowler_version": installed,
        "generated_by": "tools/prowler/build_catalog.py",
        "divergence_notes": curation["divergence_notes"],
        "checks": checks,
        "frameworks": frameworks,
    }


def render(catalog: dict[str, Any]) -> str:
    return json.dumps(catalog, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the posture catalogue.")
    parser.add_argument("--check", action="store_true", help="fail if the catalogue is stale")
    args = parser.parse_args()

    text = render(build())
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_text() != text:
            print(
                f"{OUTPUT.relative_to(ROOT)} is out of date. "
                "Run python tools/prowler/build_catalog.py.",
                file=sys.stderr,
            )
            return 1
        return 0

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(text)
    enabled = sum(1 for check in json.loads(text)["checks"].values() if check["enabled"])
    print(f"wrote {OUTPUT.relative_to(ROOT)}: {enabled} enabled checks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
