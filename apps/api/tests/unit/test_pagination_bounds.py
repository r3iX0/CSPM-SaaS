"""A page size the API does not accept is a 422, never a database error.

``limit`` and ``offset`` reach PostgreSQL's ``LIMIT`` and ``OFFSET`` directly,
and PostgreSQL refuses a negative one -- so an unbounded parameter turned
``?limit=-1`` into a 500, and where the page is sliced in Python instead,
``paths[:-1]`` quietly dropped the last route. The bounds are declared on the
parameter, so the check reads them off the published schema: a new list
endpoint that forgets them fails here rather than in production.
"""

from typing import Any

from app.main import app
from app.services.findings import SORTS


def _query_params(name: str) -> list[tuple[str, dict[str, Any]]]:
    found = []
    for path, operations in app.openapi()["paths"].items():
        for method, operation in operations.items():
            for param in operation.get("parameters", []):
                if param["in"] == "query" and param["name"] == name:
                    found.append((f"{method.upper()} {path}", param["schema"]))
    return found


def test_every_limit_is_bounded_both_ways() -> None:
    limits = _query_params("limit")
    assert limits, "no endpoint takes a limit -- the check has stopped looking"
    for route, schema in limits:
        assert schema.get("minimum", 0) >= 1, f"{route}: limit accepts {schema.get('minimum')}"
        assert "maximum" in schema, f"{route}: limit has no ceiling"


def test_every_offset_refuses_a_negative() -> None:
    offsets = _query_params("offset")
    assert offsets, "no endpoint takes an offset -- the check has stopped looking"
    for route, schema in offsets:
        assert schema.get("minimum") == 0, f"{route}: offset accepts a negative"


def test_every_findings_sort_ends_on_the_id() -> None:
    # Scores and detection times tie across a whole scan; only the id makes an
    # offset land on the same row twice.
    for name, ordering in SORTS.items():
        assert "findings.id" in str(ordering[-1]), f"sort {name!r} has no unique tiebreaker"
