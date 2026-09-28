"""Which checks to run for a scope, as the catalogue says.

The same file the API reads (``apps/api/app/prowler/data/catalog.json``), so the
set of checks a step runs is exactly the set the API knows how to interpret. A
check the catalogue excludes -- one that reads secret material, or talks to a
third party -- is never requested, which is a stronger guarantee than
filtering its results afterwards: it never executes.
"""

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ScannerCatalog:
    prowler_version: str
    checks: dict[str, dict[str, Any]]

    def checks_for(self, provider: str, *, directory: bool) -> list[str]:
        """Enabled checks for one cloud and one kind of scope, sorted.

        The directory step runs the tenant-level checks (Entra ID) and nothing
        else; an account step runs everything but those. Each check therefore
        runs once per scan however many subscriptions the tenant has.
        """
        scope = "directory" if directory else "account"
        return sorted(
            check_id
            for check_id, entry in self.checks.items()
            if entry["enabled"] and entry["provider"] == provider and entry["scope"] == scope
        )


@lru_cache(maxsize=4)
def load(path: Path) -> ScannerCatalog:
    raw = json.loads(path.read_text())
    return ScannerCatalog(
        prowler_version=str(raw["prowler_version"]),
        checks={
            check_id: {
                "enabled": bool(entry["enabled"]),
                "provider": str(entry["provider"]),
                "scope": str(entry["scope"]),
                "service": str(entry["service"]),
            }
            for check_id, entry in raw["checks"].items()
        },
    )
