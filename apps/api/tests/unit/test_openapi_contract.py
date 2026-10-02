"""What a client learns from the published document before it sends a request.

A generated client needs three things the routes alone do not give it: how to authenticate, a
stable name for each operation, and which routes are going away. The security scheme is declared
once on ``get_current_user``, so every route that needs a person carries it and the open ones do
not; a route that forgets to depend on a user shows up here as one without it
(API_GUIDELINES.md sections 8, 10 and 14).
"""

from datetime import date
from typing import Any

import httpx
from fastapi import Depends, FastAPI

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
