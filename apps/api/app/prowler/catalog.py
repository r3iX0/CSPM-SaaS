"""The posture catalogue: what each Prowler check is, as Cleave understands it.

Generated, never hand-edited: ``tools/prowler/build_catalog.py`` reads the
pinned Prowler release beside ``tools/prowler/curation.json`` and writes
``data/catalog.json``. This module only reads it. It imports nothing but the
enums, because two unrelated parts of the API need it -- the rule registry and
the compliance catalogue -- and the second must not reach the first through it.

The catalogue is the contract between the two halves of the second engine. The
scanner service reads the same file to decide which checks to run for a scope,
and this side reads it to know what a result means. A check the catalogue does
not list is a result nobody can interpret, and :func:`check` answers ``None``
for it rather than guessing.
"""

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from app.core.enums import Provider, ResourceType, Severity

CATALOG_PATH = Path(__file__).resolve().parent / "data" / "catalog.json"

# The layout this module reads. Bumped by the builder when the shape changes, so
# an API deployed ahead of or behind its catalogue fails at import rather than
# reading a field under the wrong meaning.
SCHEMA_VERSION = 1


@dataclass(frozen=True)
class Remediation:
    text: str = ""
    url: str = ""
    cli: str = ""
    terraform: str = ""
    native_iac: str = ""
    other: str = ""


@dataclass(frozen=True)
class PostureCheck:
    """One Prowler check.

    ``scope`` says which scan step runs it. ``directory`` checks read the
    tenant rather than one subscription -- Entra ID -- and run once per scan in
    the directory step; running them in every subscription's step would repeat
    one tenant's verdict once per subscription.

    ``covered_by`` names the native rules that already answer the same question.
    Where one does, the native rule's verdict is the finding and this check's is
    evidence about the native rule (``app/prowler/ingest.py``).
    """

    check_id: str
    rule_id: str
    provider: Provider
    service: str
    title: str
    description: str
    risk: str
    severity: Severity
    resource_type: str
    applies_to: tuple[ResourceType, ...]
    categories: tuple[str, ...]
    scope: str
    remediation: Remediation
    exploitability: int
    enabled: bool
    excluded_reason: str | None
    covered_by: tuple[str, ...]
    compliance: dict[str, tuple[str, ...]] = field(default_factory=dict)
    additional_urls: tuple[str, ...] = ()

    @property
    def is_directory(self) -> bool:
        return self.scope == "directory"


@dataclass(frozen=True)
class CatalogControl:
    id: str
    title: str
    group: str
    technically_assessable: bool = True


@dataclass(frozen=True)
class CatalogFramework:
    """A framework taken from Prowler's compliance files, not written by hand."""

    id: str
    name: str
    short_name: str
    version: str
    authority: str
    url: str
    provider: Provider | None
    source: tuple[str, ...]
    controls: tuple[CatalogControl, ...]


@dataclass(frozen=True)
class Catalog:
    prowler_version: str
    checks: dict[str, PostureCheck]
    frameworks: tuple[CatalogFramework, ...]
    divergence_notes: dict[str, str]

    def by_rule_id(self) -> dict[str, PostureCheck]:
        return {entry.rule_id: entry for entry in self.checks.values()}


def _check(check_id: str, raw: dict[str, Any]) -> PostureCheck:
    return PostureCheck(
        check_id=check_id,
        rule_id=str(raw["rule_id"]),
        provider=Provider(raw["provider"]),
        service=str(raw["service"]),
        title=str(raw["title"]),
        description=str(raw["description"]),
        risk=str(raw["risk"]),
        severity=Severity(raw["severity"]),
        resource_type=str(raw["resource_type"]),
        applies_to=tuple(ResourceType(value) for value in raw["applies_to"]),
        categories=tuple(raw["categories"]),
        scope=str(raw["scope"]),
        remediation=Remediation(**raw["remediation"]),
        exploitability=int(raw["exploitability"]),
        enabled=bool(raw["enabled"]),
        excluded_reason=raw.get("excluded_reason"),
        covered_by=tuple(raw["covered_by"]),
        compliance={key: tuple(ids) for key, ids in raw["compliance"].items()},
        additional_urls=tuple(raw.get("additional_urls") or ()),
    )


def _framework(raw: dict[str, Any]) -> CatalogFramework:
    return CatalogFramework(
        id=str(raw["id"]),
        name=str(raw["name"]),
        short_name=str(raw["short_name"]),
        version=str(raw["version"]),
        authority=str(raw["authority"]),
        url=str(raw["url"]),
        provider=Provider(raw["provider"]) if raw.get("provider") else None,
        source=tuple(raw["source"]),
        controls=tuple(CatalogControl(**control) for control in raw["controls"]),
    )


@lru_cache(maxsize=1)
def load() -> Catalog:
    """The catalogue, parsed once per process."""
    raw = json.loads(CATALOG_PATH.read_text())
    if raw.get("schema") != SCHEMA_VERSION:
        raise RuntimeError(
            f"{CATALOG_PATH.name} is schema {raw.get('schema')}, this API reads "
            f"{SCHEMA_VERSION}. Rebuild it with tools/prowler/build_catalog.py."
        )
    return Catalog(
        prowler_version=str(raw["prowler_version"]),
        checks={check_id: _check(check_id, entry) for check_id, entry in raw["checks"].items()},
        frameworks=tuple(_framework(entry) for entry in raw["frameworks"]),
        divergence_notes=dict(raw.get("divergence_notes") or {}),
    )


def check(check_id: str) -> PostureCheck | None:
    return load().checks.get(check_id)


def enabled_checks() -> list[PostureCheck]:
    return [entry for entry in load().checks.values() if entry.enabled]


def prowler_frameworks() -> tuple[CatalogFramework, ...]:
    return load().frameworks
