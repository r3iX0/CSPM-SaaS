"""What a client learns from the published document before it sends a request.

A generated client needs three things the routes alone do not give it: how to authenticate, a
stable name for each operation, and which routes are going away. The security scheme is declared
once on ``get_current_user``, so every route that needs a person carries it and the open ones do
not; a route that forgets to depend on a user shows up here as one without it
(API_GUIDELINES.md sections 8, 10 and 14).
"""

import ast
import inspect
import textwrap
from datetime import date
from typing import Any
from uuid import uuid4

import httpx
from fastapi import Depends, FastAPI, Request, Response
from fastapi.routing import APIRoute

from app.api.links import POLL_SECONDS, accepted, created
from app.core.openapi import TAGS, deprecation
from app.main import app

METHODS = ("get", "post", "put", "patch", "delete")

# Open on purpose. The health checks answer a platform probe; the permissions list is what
# Cleave will be able to see, shown before anyone has signed in to consent. The cloud event
# receivers, the consent callback and the template link are authenticated by a signed token
# and are not in the published document at all. Adding a path here is the review that says it
# is meant to be open.
OPEN_PATHS = {
    "/health",
    "/health/ready",
    "/api/v1/cloud-accounts/azure/permissions",
}


def _operations() -> list[tuple[str, str, dict[str, Any]]]:
    found = []
    for path, item in app.openapi()["paths"].items():
        for method in METHODS:
            if method in item:
                found.append((method, path, item[method]))
    return found


def test_the_document_declares_a_bearer_scheme() -> None:
    scheme = app.openapi()["components"]["securitySchemes"]["bearerAuth"]
    assert scheme["type"] == "http"
    assert scheme["scheme"] == "bearer"


def test_only_the_listed_routes_are_open() -> None:
    unsecured = {path for _, path, op in _operations() if "security" not in op}
    assert unsecured == OPEN_PATHS, f"routes with no security scheme: {sorted(unsecured)}"


def test_operation_ids_are_unique_and_do_not_embed_the_path() -> None:
    ids = [op["operationId"] for _, _, op in _operations()]
    assert len(ids) == len(set(ids)), "two operations share an operationId"
    for operation_id in ids:
        assert "_api_v1_" not in operation_id, f"{operation_id} still carries its path"


def test_every_tag_in_use_is_described() -> None:
    described = {tag["name"] for tag in TAGS}
    used = {tag for _, _, op in _operations() for tag in op.get("tags", [])}
    assert used <= described, f"tags with no description: {sorted(used - described)}"


def _routes_answering(*statuses: int) -> list[APIRoute]:
    return [r for r in app.routes if isinstance(r, APIRoute) and r.status_code in statuses]


def test_every_route_that_creates_or_queues_says_where_to_look() -> None:
    """A ``201`` names the new resource and a ``202`` the one that tracks the work."""
    routes = _routes_answering(201, 202)
    assert len(routes) >= 8, "the creating and queuing routes have gone missing"
    for route in routes:
        helper = "accepted(" if route.status_code == 202 else "created("
        assert helper in inspect.getsource(route.endpoint), (
            f"{route.path} answers {route.status_code} without calling {helper[:-1]}"
        )


def test_every_location_names_a_route_that_exists() -> None:
    """The route names handed to ``created`` and ``accepted`` are real, so a rename breaks here."""
    names = {r.name for r in app.routes if isinstance(r, APIRoute)}
    used: set[str] = set()
    for route in _routes_answering(201, 202):
        for node in ast.walk(ast.parse(textwrap.dedent(inspect.getsource(route.endpoint)))):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in ("created", "accepted")
            ):
                target = node.args[2]
                assert isinstance(target, ast.Constant), (
                    f"{route.path}: route name is not a literal"
                )
                used.add(str(target.value))
    assert used, "no route names found -- the check has stopped looking"
    assert used <= names, f"Location points at routes that do not exist: {sorted(used - names)}"


def test_a_location_is_a_relative_path_and_a_queued_one_says_when_to_look() -> None:
    scan_id = uuid4()
    request = Request({"type": "http", "app": app, "headers": []})
    response = Response()

    accepted(request, response, "get_scan_detail", scan_id=scan_id)

    assert response.headers["Location"] == f"/api/v1/scans/{scan_id}/detail"
    assert response.headers["Retry-After"] == str(POLL_SECONDS)

    plain = Response()
    created(request, plain, "get_scan_detail", scan_id=scan_id)
    assert "Retry-After" not in plain.headers


async def test_the_headers_reach_the_wire_beside_the_body() -> None:
    """FastAPI merges what a handler puts on its ``Response`` into the one it builds."""
    things = FastAPI()

    @things.get("/things/{thing_id}")
    async def get_thing(thing_id: str) -> dict[str, str]:
        return {"id": thing_id}

    @things.post("/things", status_code=202)
    async def queue_thing(request: Request, response: Response) -> dict[str, str]:
        accepted(request, response, "get_thing", thing_id="abc")
        return {"id": "abc"}

    transport = httpx.ASGITransport(app=things)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        queued = await client.post("/things")

    assert queued.status_code == 202
    assert queued.json() == {"id": "abc"}
    assert queued.headers["Location"] == "/things/abc"
    assert queued.headers["Retry-After"] == str(POLL_SECONDS)


async def test_a_deprecated_route_announces_its_sunset_and_its_replacement() -> None:
    old = FastAPI()
    announce = deprecation(
        deprecated_on=date(2027, 1, 1), sunset=date(2027, 7, 1), replacement="/api/v2/new"
    )

    @old.get("/old", deprecated=True, dependencies=[Depends(announce)])
    async def old_route() -> dict[str, str]:
        return {"ok": "yes"}

    transport = httpx.ASGITransport(app=old)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/old")

    assert response.headers["Deprecation"] == "@1798761600"
    assert response.headers["Sunset"] == "Thu, 01 Jul 2027 00:00:00 GMT"
    assert response.headers["Link"] == '</api/v2/new>; rel="successor-version"'
    assert old.openapi()["paths"]["/old"]["get"]["deprecated"] is True
