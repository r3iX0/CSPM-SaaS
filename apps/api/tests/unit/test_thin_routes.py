"""A route parses, authorizes, calls a service and shapes the answer; it does not query.

Queries in a route cannot be reached from a worker, cannot be tested without the HTTP stack, and
spread one resource's rules across two layers (API_GUIDELINES.md section 11). The check is the
same shape as ``test_request_transaction``, which holds services to the other half of the
contract: a route may end the request's transaction (``session.commit()``), and nothing else on
the session.

``PENDING`` is the routes that still query, and it only shrinks: a module comes off the list in
the change that moves its queries into ``app/services/``, and one that is not on the list fails
here the moment it grows a query. A module that is clean but still listed fails too, so the list
cannot go stale.
"""

import ast
from pathlib import Path

import pytest

ROUTES = Path(__file__).resolve().parents[2] / "app" / "api" / "routes"

# SQLAlchemy constructs that build a statement, and the session calls that run or change one.
STATEMENTS = {"select", "update", "delete", "insert", "text"}
SESSION_CALLS = {
    "execute",
    "add",
    "add_all",
    "delete",
    "flush",
    "scalar",
    "scalars",
    "get",
    "refresh",
    "merge",
}

PENDING = {
    "assets.py",
    "findings.py",
    "risks.py",
    "scans.py",
}


def queries_in(path: Path) -> list[str]:
    """Each statement built and each session call made directly in this module."""
    found: list[str] = []
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("sqlalchemy"):
            found += [f"import {a.name}" for a in node.names if a.name in STATEMENTS]
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in SESSION_CALLS
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in {"session", "db"}
        ):
            found.append(f"{node.func.value.id}.{node.func.attr} (line {node.lineno})")
    return found


MODULES = sorted(p.name for p in ROUTES.glob("*.py") if p.name != "__init__.py")


@pytest.mark.parametrize("module", MODULES)
def test_a_route_module_does_not_query(module: str) -> None:
    found = queries_in(ROUTES / module)
    if module in PENDING:
        assert found, f"{module} no longer queries -- take it off PENDING"
    else:
        assert not found, f"{module} queries from a route; move it into app/services/: {found}"
