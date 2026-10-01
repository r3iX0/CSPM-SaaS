"""Refuse a Ruff hook pinned to a different version than apps/api/pyproject.toml.

The commit hook runs Ruff from astral-sh/ruff-pre-commit so it works before a
clone has a virtualenv, while CI's API job and every editor run the version in
pyproject.toml. Two Ruff versions format differently and know different rules,
so a drift between them shows up as a file that passes on commit and fails in
CI. This keeps the two in step: bump both, or the hook refuses.

Standard library only, because pre-commit runs it before anything is installed.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONFIG = ROOT / ".pre-commit-config.yaml"
PYPROJECT = ROOT / "apps" / "api" / "pyproject.toml"


def hook_version() -> str | None:
    match = re.search(
        r"repo: https://github\.com/astral-sh/ruff-pre-commit\s+rev: \S+\s+# frozen: v(\S+)",
        CONFIG.read_text(encoding="utf-8"),
    )
    return match.group(1) if match else None


def pinned_version() -> str | None:
    match = re.search(r'"ruff==([^"]+)"', PYPROJECT.read_text(encoding="utf-8"))
    return match.group(1) if match else None


def main() -> int:
    hook, pinned = hook_version(), pinned_version()
    if hook is None or pinned is None:
        print("error: could not read the Ruff version from the hook config or pyproject.toml")
        return 1
    if hook != pinned:
        print(
            f"error: .pre-commit-config.yaml runs Ruff {hook}, "
            f"apps/api/pyproject.toml pins {pinned}. Bump both together."
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
