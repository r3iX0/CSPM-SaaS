"""Check documentation coverage across CloudGuard Python codebase.

Uses Python's AST to analyze classes, functions, route handlers, and security rules
for presence of docstrings, summaries, and descriptions.

Usage:
    python apps/api/scripts/check_doc_coverage.py
    python apps/api/scripts/check_doc_coverage.py --fail-under 80
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path
from typing import NamedTuple

REPO_ROOT = Path(__file__).resolve().parents[3]
APP_DIR = REPO_ROOT / "apps" / "api" / "app"


class ItemReport(NamedTuple):
    file_path: str
    line: int
    name: str
    kind: str


class DocStats:
    def __init__(self) -> None:
        self.total_modules = 0
        self.documented_modules = 0

        self.total_classes = 0
        self.documented_classes = 0

        self.total_functions = 0
        self.documented_functions = 0

        self.missing: list[ItemReport] = []

    @property
    def class_coverage(self) -> float:
        if not self.total_classes:
            return 100.0
        return self.documented_classes / self.total_classes * 100

    @property
    def function_coverage(self) -> float:
        if not self.total_functions:
            return 100.0
        return self.documented_functions / self.total_functions * 100

    @property
    def module_coverage(self) -> float:
        if not self.total_modules:
            return 100.0
        return self.documented_modules / self.total_modules * 100

    @property
    def overall_coverage(self) -> float:
        total = self.total_classes + self.total_functions + self.total_modules
        doc = self.documented_classes + self.documented_functions + self.documented_modules
        return (doc / total * 100) if total else 100.0


def analyze_file(file_path: Path, stats: DocStats) -> None:
    try:
        content = file_path.read_text(encoding="utf-8")
        tree = ast.parse(content, filename=str(file_path))
    except Exception as exc:
        print(f"Warning: Failed to parse {file_path}: {exc}", file=sys.stderr)
        return

    rel_path = str(file_path.relative_to(REPO_ROOT))

    stats.total_modules += 1
    if ast.get_docstring(tree):
        stats.documented_modules += 1
    else:
        stats.missing.append(ItemReport(rel_path, 1, file_path.stem, "module"))

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            stats.total_classes += 1
            if ast.get_docstring(node):
                stats.documented_classes += 1
            else:
                stats.missing.append(ItemReport(rel_path, node.lineno, node.name, "class"))

        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            # Skip private/dunder methods from mandatory check unless __init__
            if node.name.startswith("_") and not node.name.startswith("__init__"):
                continue

            stats.total_functions += 1
            if ast.get_docstring(node):
                stats.documented_functions += 1
            else:
                stats.missing.append(ItemReport(rel_path, node.lineno, node.name, "function"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Check documentation coverage.")
    parser.add_argument(
        "--path",
        type=Path,
        default=APP_DIR,
        help="Directory path to inspect (defaults to apps/api/app)",
    )
    parser.add_argument(
        "--fail-under",
        type=float,
        default=0.0,
        help="Minimum overall coverage percentage required to pass",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="List all missing documentation items",
    )

    args = parser.parse_args()
    target_dir: Path = args.path

    if not target_dir.exists():
        print(f"Error: Target directory {target_dir} not found.", file=sys.stderr)
        return 1

    stats = DocStats()
    py_files = sorted(target_dir.rglob("*.py"))

    for py_file in py_files:
        if "__pycache__" in py_file.parts or ".pytest_cache" in py_file.parts:
            continue
        analyze_file(py_file, stats)

    print("\n" + "=" * 50)
    print("📊 CloudGuard Documentation Coverage Report")
    print("=" * 50)
    print(f"Analyzed files: {len(py_files)}")
    m_cov = f"{stats.documented_modules}/{stats.total_modules} ({stats.module_coverage:.1f}%)"
    c_cov = f"{stats.documented_classes}/{stats.total_classes} ({stats.class_coverage:.1f}%)"
    f_cov = f"{stats.documented_functions}/{stats.total_functions} ({stats.function_coverage:.1f}%)"
    print(f"Modules:        {m_cov}")
    print(f"Classes:        {c_cov}")
    print(f"Functions:      {f_cov}")
    print("-" * 50)
    print(f"Overall Coverage: {stats.overall_coverage:.1f}%")
    print("=" * 50 + "\n")

    if args.verbose and stats.missing:
        print("Missing Documentation Items:")
        for item in stats.missing[:40]:
            print(f"  {item.file_path}:{item.line} [{item.kind}] {item.name}")
        if len(stats.missing) > 40:
            print(f"  ... and {len(stats.missing) - 40} more items.")
        print()

    if stats.overall_coverage < args.fail_under:
        msg = f"FAIL: Coverage {stats.overall_coverage:.1f}% is below {args.fail_under:.1f}%"
        print(msg, file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
