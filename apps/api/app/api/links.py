"""Where a created thing lives, and when to look again at a queued one.

A ``201`` names the new resource in ``Location`` and a ``202`` names the resource that tracks the
work, with ``Retry-After`` saying how soon to look (API_GUIDELINES.md sections 3 and 7). The path
is built from the route's own name, so it follows the URL when the URL moves, and it is relative:
behind the platform's proxy the API cannot say which scheme and host the caller used.
"""

from fastapi import Request, Response

#: Seconds before a client should ask again about queued work. The web app polls a running scan
#: every two and a half seconds when its event stream is down; this is the same order.
POLL_SECONDS = 3


def created(request: Request, response: Response, route: str, **params: object) -> None:
    """Point ``Location`` at the route named ``route``, filled in with ``params``."""
    response.headers["Location"] = str(request.app.url_path_for(route, **params))


def accepted(request: Request, response: Response, route: str, **params: object) -> None:
    """Point ``Location`` at what tracks the work, and say how soon to look."""
    created(request, response, route, **params)
    response.headers["Retry-After"] = str(POLL_SECONDS)
