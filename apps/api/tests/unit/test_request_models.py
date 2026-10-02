"""A request body refuses a field it does not know, and says which.

Pydantic drops an unknown key by default, so ``{"severty": "HIGH"}`` was a ``200`` that filtered
nothing, and ``{"organization_id": ...}`` was silently ignored rather than refused. Request models
derive from ``RequestModel`` (``extra="forbid"``), which the published schema shows as
``additionalProperties: false``. The check reads that off the schema, as
``test_pagination_bounds`` does for page sizes: a new endpoint that takes a plain ``BaseModel``
fails here rather than in a client's hands (API_GUIDELINES.md section 4).
"""

from typing import Any

from app.main import app

JSON = "application/json"


def _resolve(spec: dict[str, Any], schema: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    ref = schema.get("$ref")
    if ref is None:
        return "inline", schema
    name = ref.rsplit("/", 1)[-1]
    return name, spec["components"]["schemas"][name]


def _objects(spec: dict[str, Any], schema: dict[str, Any], seen: set[str]) -> list[tuple[str, Any]]:
    """Every object schema reachable from a request body, with its ``additionalProperties``."""
    name, resolved = _resolve(spec, schema)
    if name in seen:
        return []
    seen.add(name)
    found: list[tuple[str, Any]] = []
    if resolved.get("type") == "object" and "properties" in resolved:
        found.append((name, resolved.get("additionalProperties")))
    children = list(resolved.get("properties", {}).values())
    children += resolved.get("anyOf", []) + resolved.get("allOf", [])
    if "items" in resolved:
        children.append(resolved["items"])
    for child in children:
        found += _objects(spec, child, seen)
    return found


def _request_bodies() -> list[tuple[str, dict[str, Any]]]:
    spec = app.openapi()
    bodies = []
    for path, operations in spec["paths"].items():
        for method, operation in operations.items():
            content = operation.get("requestBody", {}).get("content", {})
            if JSON in content:
                bodies.append((f"{method.upper()} {path}", content[JSON]["schema"]))
    return bodies


def test_every_json_request_body_forbids_unknown_fields() -> None:
    spec = app.openapi()
    bodies = _request_bodies()
    assert bodies, "no endpoint takes a JSON body -- the check has stopped looking"
    for route, schema in bodies:
        for name, additional in _objects(spec, schema, set()):
            assert additional is False, f"{route}: {name} accepts and drops unknown fields"
