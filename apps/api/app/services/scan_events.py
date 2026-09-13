"""A running scan, pushed to the browser as server-sent events.

The scan wizard polled ``GET /scans/{id}/detail`` every few seconds. Polling is
correct and it is coarse: a lane that finished a second after a poll waited the
rest of the interval to say so, and every open wizard paid a full request per
tick whether or not anything had moved.

This stream is deliberately the *same read*, done on the server. Each tick opens
a fresh, row-level-secured session, builds exactly the payload the detail
endpoint returns, and sends it only when it differs from the last one sent. The
database stays the one source of truth -- the worker writes nothing new, and no
broker message has to be trusted to agree with the rows -- so the stream cannot
tell the browser anything a refetch would not.

The loop is a pure async generator over injected functions, so its rules --
send on change, keep the connection alive, stop when the scan settles, stop when
the reader leaves, stop after a ceiling -- are tested without a database or a
server.
"""

import asyncio
import json
import time
from collections.abc import AsyncIterator, Awaitable, Callable

from app.core.enums import ScanStatus

# The statuses after which nothing about a scan changes. Once one is sent the
# stream ends: holding a connection open over a finished scan would be a
# request that can only ever report the same thing.
SETTLED = frozenset(
    {
        ScanStatus.COMPLETED.value,
        ScanStatus.PARTIAL.value,
        ScanStatus.FAILED.value,
        ScanStatus.CANCELLED.value,
    }
)

# Often enough that a lane finishing reads as immediate; rare enough that an
# idle wizard costs one small query batch a second and a half.
TICK_SECONDS = 1.5
# Under the idle timeouts proxies commonly apply to a quiet connection.
HEARTBEAT_SECONDS = 15.0
# A ceiling, not an expected duration. The browser falls back to polling when a
# stream ends, so this bounds what one forgotten tab can hold open.
MAX_SECONDS = 30 * 60


def event(name: str, payload: object) -> str:
    """One server-sent event. Data is a single line of JSON, so no escaping."""
    return f"event: {name}\ndata: {json.dumps(payload, separators=(',', ':'))}\n\n"


async def stream_scan(
    load: Callable[[], Awaitable[dict | None]],
    *,
    is_disconnected: Callable[[], Awaitable[bool]],
    tick: float = TICK_SECONDS,
    heartbeat: float = HEARTBEAT_SECONDS,
    max_seconds: float = MAX_SECONDS,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
) -> AsyncIterator[str]:
    """Yield a scan's state as it changes, until there is nothing left to say.

    ``load`` returns the detail payload, or None when the scan is gone -- deleted
    mid-run, or no longer visible to this reader.
    """
    started = clock()
    last_sent = started
    previous: str | None = None

    while True:
        if await is_disconnected():
            return

        payload = await load()
        if payload is None:
            yield event("gone", {})
            return

        body = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        if body != previous:
            previous = body
            last_sent = clock()
            yield event("scan", payload)
        elif clock() - last_sent >= heartbeat:
            last_sent = clock()
            # A comment line: keeps intermediaries from closing an idle
            # connection, and every SSE parser ignores it.
            yield ": keep-alive\n\n"

        if payload.get("status") in SETTLED:
            yield event("end", {})
            return

        if clock() - started >= max_seconds:
            yield event("timeout", {})
            return

        await sleep(tick)
