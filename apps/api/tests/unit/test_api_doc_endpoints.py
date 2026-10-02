"""``docs/API.md`` lists every route the application serves, and only those.

The list is written by hand, and it had drifted: the Fix-as-Code endpoint, the demo organization's
join and leave, the provider list and the health checks were all served and none was documented,
while the change-event receiver was documented for one cloud and served for two. The generated
OpenAPI document cannot catch that, because the receivers and the signed links are left out of it
on purpose. This reads the route table itself, so a route added without a line in the guide fails
here, as does a line for a route that is gone.
"""

import re
from pathlib import Path

from fastapi.routing import APIRoute

from app.main import app

GUIDE = Path(__file__).resolve().parents[4] / "docs" / "API.md"
VERBS = r"(GET|POST|PUT|PATCH|DELETE)"


def _shape(path: str) -> str:
    """A path with its query string dropped and every parameter named alike."""
    return re.sub(r"\{[^}]+\}", "{}", path.split("?")[0])


def _documented() -> set[tuple[str, str]]:
    """The endpoints in the first text block under "Endpoints", with their full paths."""
    text = GUIDE.read_text(encoding="utf-8")
    section = text.split("## 1. Endpoints", 1)[1]
    block = section.split("```text", 1)[1].split("```", 1)[0]
    found = set()
    for verb, path in re.findall(rf"{VERBS}\s+(/\S+)", block):
        # The health checks answer outside the versioned prefix; every other path is under it.
        full = path if path.startswith("/health") else f"/api/v1{path}"
        found.add((verb, _shape(full)))
    return found


def _served() -> set[tuple[str, str]]:
    return {
        (method, _shape(route.path))
        for route in app.routes
        if isinstance(route, APIRoute)
        for method in route.methods - {"HEAD", "OPTIONS"}
    }


def test_every_served_route_is_in_the_guide() -> None:
    missing = sorted(_served() - _documented())
    assert not missing, f"served but not in docs/API.md section 1: {missing}"


def test_every_documented_route_is_served() -> None:
    stale = sorted(_documented() - _served())
    assert not stale, f"in docs/API.md section 1 but not served: {stale}"
