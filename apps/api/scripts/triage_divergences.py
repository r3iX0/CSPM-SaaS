"""Replay both engines over stored captures and print a case file per divergence.

The deterministic half of divergence triage (DECISIONS.md section 167). It never
decides which engine is right -- it gathers what each engine read and said, so a
person or the ``triage-divergences`` skill can, and it re-runs the replay after a
fix to show whether the divergence is gone.

Usage:
    python apps/api/scripts/triage_divergences.py \\
        --snapshot apps/api/tests/fixtures/azure_raw/snapshot_mixed.json \\
        --prowler apps/api/tests/fixtures/prowler/azure_mixed_run.json
    ... --rule AZ-STO-003            # only divergences on one native rule
    ... --case 3f2a9c1d0b7e          # one case, by id
    ... --include-expected           # also pairs curation.json expects to differ
    ... --format json                # machine-readable, for an agent
    ... --out /tmp/triage            # one file per case plus summary.json

Exit status: 0 when no unexpected divergence remains, 1 when one does, 2 when
the input could not be read. ``--rule``/``--case`` narrow the status too, so a
fix can be verified against the one case it was meant to settle.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("SUPABASE_JWT_SECRET", "triage-offline")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://cloudguard_app:x@localhost:5432/cg")
os.environ.setdefault(
    "DATABASE_OWNER_URL", "postgresql+asyncpg://cloudguard:x@localhost:5432/cg"
)

API_DIR = Path(__file__).resolve().parents[1]
if str(API_DIR) not in sys.path:
    sys.path.insert(0, str(API_DIR))

from app.prowler import triage  # noqa: E402  (the path above has to be set first)


def _load(path: Path) -> Any:
    return json.loads(path.read_text())


def _runs(document: Any) -> list[dict[str, Any]]:
    """A file holding ``{"runs": [...]}``, a bare list of runs, or one run."""
    if isinstance(document, dict) and "runs" in document:
        return list(document["runs"])
    if isinstance(document, list):
        return document
    return [document]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument("--snapshot", type=Path, required=True, help="a stored RawSnapshot JSON")
    parser.add_argument("--prowler", type=Path, required=True, help="the Prowler run(s) JSON")
    parser.add_argument("--rule", help="only divergences on this native rule id")
    parser.add_argument("--case", help="only the case with this id")
    parser.add_argument("--include-expected", action="store_true")
    parser.add_argument("--format", choices=("md", "json"), default="md")
    parser.add_argument("--out", type=Path, help="write one file per case into this directory")
    args = parser.parse_args(argv)

    try:
        result = triage.replay(_load(args.snapshot), _runs(_load(args.prowler)))
    except (OSError, ValueError, KeyError) as exc:
        print(f"could not replay: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2

    cases = [
        case
        for case in triage.build_cases(result, include_expected=args.include_expected)
        if (args.rule is None or case.rule["rule_id"] == args.rule)
        and (args.case is None or case.case_id == args.case)
    ]
    summary = triage.summary(result)
    summary["shown"] = len(cases)
    unresolved = [case for case in cases if not case.expected]

    if args.out is not None:
        args.out.mkdir(parents=True, exist_ok=True)
        for case in cases:
            (args.out / f"{case.case_id}.md").write_text(triage.render_markdown(case))
            (args.out / f"{case.case_id}.json").write_text(
                json.dumps(case.to_dict(), indent=2, sort_keys=True, default=str) + "\n"
            )
        (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(f"{len(cases)} case(s) written to {args.out}", file=sys.stderr)
    elif args.format == "json":
        payload = {"summary": summary, "cases": [case.to_dict() for case in cases]}
        print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    else:
        print(f"<!-- {json.dumps(summary)} -->\n")
        for case in cases:
            print(triage.render_markdown(case))

    return 1 if unresolved else 0


if __name__ == "__main__":
    sys.exit(main())
