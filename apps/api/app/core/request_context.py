"""What is known about the request in progress, readable from anywhere inside it.

Two values, set once by ``RequestContextMiddleware`` for the length of one
request and read by whatever needs them further in -- the audit trail above
all, which records where a change came from without every service function
having to be handed the request (DECISIONS.md section 161). A third runs the
other way: the rate limit's counters write what is left of each allowance, and
the middleware reads the tightest back when the response starts.

Context variables rather than ``request.state``, because the code that needs
them is service code that is also called from the worker, where there is no
request: there the values are simply ``None``, which is the true answer.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass

# The response header that carries it back, so a customer quoting an error to
# support hands over the one string that finds every log line it produced.
REQUEST_ID_HEADER = "X-Request-ID"

_request_id: ContextVar[str | None] = ContextVar("request_id", default=None)
_client_ip: ContextVar[str | None] = ContextVar("client_ip", default=None)


@dataclass(frozen=True)
class RateLimitReading:
    """One counter's answer: its ceiling, what is left of it, and when it resets."""

    limit: int
    remaining: int
    #: When the window ends, in seconds since the epoch.
    reset: int

    def headers(self) -> dict[str, str]:
        """The three ``X-RateLimit-*`` headers a client slows down by."""
        return {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(self.remaining),
            "X-RateLimit-Reset": str(self.reset),
        }


# A holder rather than a value, so a counter read deep inside a dependency -- possibly in a
# thread, on a copy of the context -- lands where the outermost middleware can read it when
# the response starts. ``None`` outside a request.
_rate_limit: ContextVar[list[RateLimitReading] | None] = ContextVar("rate_limit", default=None)


def note_rate_limit(reading: RateLimitReading) -> None:
    """Record a counter's reading; the response reports the tightest one it saw.

    A signed-in request is counted by address, by person and sometimes as costly. Reporting only
    the first would tell a client it has a thousand requests left while its own allowance is
    about to run out, so the reading with the least remaining wins.
    """
    held = _rate_limit.get()
    if held is None:
        return
    if not held or reading.remaining < held[0].remaining:
        held[:] = [reading]


def tightest_rate_limit() -> RateLimitReading | None:
    """The reading closest to refusing this request, or ``None`` if nothing was counted."""
    held = _rate_limit.get()
    return held[0] if held else None


def current_request_id() -> str | None:
    """This request's id, or ``None`` outside one (a worker task, a test)."""
    return _request_id.get()


def current_client_ip() -> str | None:
    """The caller's address as the rate limit sees it, or ``None`` if unknown."""
    return _client_ip.get()


@contextmanager
def bound(request_id: str, client_ip: str | None) -> Iterator[None]:
    """Hold both values for the length of a block, and put back what was there."""
    id_token = _request_id.set(request_id)
    ip_token = _client_ip.set(client_ip)
    rate_token = _rate_limit.set([])
    try:
        yield
    finally:
        _request_id.reset(id_token)
        _client_ip.reset(ip_token)
        _rate_limit.reset(rate_token)
