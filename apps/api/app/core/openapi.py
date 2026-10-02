"""What the published OpenAPI document says beyond the routes themselves.

Three things a client reads that no route declares: the stable name of each operation, what each
tag means, and how a route announces that it is going away (API_GUIDELINES.md sections 8 and 14).
"""

from collections.abc import Awaitable, Callable
from datetime import UTC, date, datetime
from email.utils import format_datetime
from typing import Any

from fastapi import Response
from fastapi.routing import APIRoute


def operation_id(route: APIRoute) -> str:
    """The tag, then the handler's name: ``findings_list_findings``.

    FastAPI's default appends the path and the method (``list_organizations_api_v1_
    organizations_get``), which is unique but changes whenever a URL does, and a generated client
    names its methods from it. This one changes only when a handler is renamed, which shows in
    review. Hyphens in a tag become underscores so the result is a valid identifier.
    """
    tag = str(route.tags[0]) if route.tags else "api"
    return f"{tag.replace('-', '_')}_{route.name}"


TAGS: list[dict[str, Any]] = [
    {"name": "organizations", "description": "The caller's organizations and the shared demo."},
    {"name": "team", "description": "Members, roles and invitations to an organization."},
    {"name": "audit", "description": "The append-only record of every change a person made."},
    {
        "name": "webhooks",
        "description": "Endpoints that receive notifications, and their deliveries.",
    },
    {"name": "notifications", "description": "In-app notifications for the signed-in member."},
    {"name": "cloud-accounts", "description": "Single-subscription accounts and what is declared."},
    {"name": "cloud-connections", "description": "Connecting a cloud: consent, scope, schedule."},
    {"name": "scans", "description": "Starting, following, cancelling and replaying scans."},
    {
        "name": "assets",
        "description": "Discovered resources, how they connect and who reaches them.",
    },
    {"name": "changes", "description": "Changes the cloud reported since the last scan."},
    {"name": "attack-paths", "description": "Routes to an asset, and what closing them would do."},
    {"name": "findings", "description": "Rule failures on one asset, with evidence and a fix."},
    {"name": "risks", "description": "Findings and routes scored as business risks, and triage."},
    {"name": "remediation", "description": "The queue of fixes being worked, and who owns each."},
    {"name": "rules", "description": "The rules that run, and how each one is judged."},
    {"name": "compliance", "description": "Framework controls and the evidence each rests on."},
    {"name": "dashboard", "description": "One summary of the estate for the first screen."},
    {"name": "reports", "description": "Rendered reports and exports."},
    {"name": "events", "description": "Receivers a cloud provider calls; not for browsers."},
    {"name": "meta", "description": "Health checks for the platform; no authentication."},
]


def deprecation(
    *, deprecated_on: date, sunset: date, replacement: str
) -> Callable[[Response], Awaitable[None]]:
    """A dependency that tells a client this route is going away, and what replaces it.

    Pair it with ``deprecated=True`` on the route so the document says so too:

        @router.get("/old", deprecated=True, dependencies=[Depends(deprecation(...))])

    ``Deprecation`` carries the date it was deprecated (RFC 9745), ``Sunset`` the date it stops
    answering (RFC 8594), and ``Link`` points at the replacement. The date and the replacement
    also go in ``docs/API.md``.
    """

    def _at_midnight(day: date) -> datetime:
        return datetime(day.year, day.month, day.day, tzinfo=UTC)

    headers = {
        "Deprecation": f"@{int(_at_midnight(deprecated_on).timestamp())}",
        "Sunset": format_datetime(_at_midnight(sunset), usegmt=True),
        "Link": f'<{replacement}>; rel="successor-version"',
    }

    async def announce(response: Response) -> None:
        response.headers.update(headers)

    return announce
