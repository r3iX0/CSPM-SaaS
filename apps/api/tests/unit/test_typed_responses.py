"""Every route answers with a typed envelope, and documents the errors it sends
(DECISIONS.md section 157).

The routers were converted one at a time; now every route in the app is
checked. A route returning a bare ``dict`` would publish ``{}`` as its schema
again without anything else failing, and one taking a parameter without the
error responses would publish FastAPI's ``HTTPValidationError`` -- a shape this
API never sends.
"""

import pytest
from fastapi.routing import APIRoute
from pydantic import ValidationError

from app.main import app
from app.schemas.common import Envelope
from app.schemas.dashboard import CoverageCategoryOut

# Routes that answer with something other than an envelope: a document the
# caller is saving, an event stream, or a provider's own protocol. Each
# declares its media type where it is in the schema, and each is listed here by
# name, so a new one is a decision somebody writes down.
NOT_ENVELOPED = {
    ("GET", "/api/v1/compliance/{framework_id}/export"),
    ("GET", "/api/v1/reports/{kind}"),
    ("GET", "/api/v1/scans/{scan_id}/events"),
    # Fetched by Azure Portal from any origin, and Entra's redirect back.
    ("GET", "/api/v1/cloud-connections/{connection_id}/template"),
    ("GET", "/api/v1/cloud-connections/azure/consent/callback"),
    # A provider's change-event webhook, answered in its terms.
    ("POST", "/api/v1/events/{provider}/{connection_id}"),
}


def _routes() -> list[APIRoute]:
    return [route for route in app.routes if isinstance(route, APIRoute)]


def test_every_route_declares_its_envelope() -> None:
    routes = _routes()
    assert len(routes) > 80, "the check has stopped seeing the API"
    for route in routes:
        if any((method, route.path) in NOT_ENVELOPED for method in route.methods):
            continue
        model = route.response_model
        assert isinstance(model, type) and issubclass(model, Envelope), (
            f"{sorted(route.methods)} {route.path} returns {model!r}, not an Envelope"
        )


def test_every_route_left_out_of_the_envelope_still_exists() -> None:
    # A stale entry would quietly exempt whatever is added at that path next.
    present = {(method, route.path) for route in _routes() for method in route.methods}
    assert present >= NOT_ENVELOPED, NOT_ENVELOPED - present


def test_every_documented_error_is_the_error_envelope() -> None:
    schema = app.openapi()
    # FastAPI adds this the moment one route with a parameter leaves 422 to it.
    assert "HTTPValidationError" not in schema["components"]["schemas"]
    for path, operations in schema["paths"].items():
        for method, operation in operations.items():
            for code, response in operation["responses"].items():
                if int(code) < 400:
                    continue
                ref = response["content"]["application/json"]["schema"]["$ref"]
                assert ref.endswith("/ErrorEnvelope"), f"{method.upper()} {path} {code}: {ref}"


def test_a_closed_model_refuses_a_key_it_does_not_declare() -> None:
    # Where a service builds a dict and the route validates it, a field the
    # service adds and the schema forgets must fail rather than vanish.
    with pytest.raises(ValidationError, match="extra"):
        CoverageCategoryOut.model_validate(
            {"name": "storage", "readings": 3, "incomplete": 0, "added_later": 1}
        )
