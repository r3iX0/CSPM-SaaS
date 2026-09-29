"""What is known about the request in progress, readable from anywhere inside it.

Two values, set once by ``RequestContextMiddleware`` for the length of one
request and read by whatever needs them further in -- the audit trail above
all, which records where a change came from without every service function
having to be handed the request (DECISIONS.md section 161).

Context variables rather than ``request.state``, because the code that needs
them is service code that is also called from the worker, where there is no
request: there the values are simply ``None``, which is the true answer.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar

# The response header that carries it back, so a customer quoting an error to
# support hands over the one string that finds every log line it produced.
REQUEST_ID_HEADER = "X-Request-ID"

_request_id: ContextVar[str | None] = ContextVar("request_id", default=None)
_client_ip: ContextVar[str | None] = ContextVar("client_ip", default=None)


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
    try:
        yield
    finally:
        _request_id.reset(id_token)
        _client_ip.reset(ip_token)
