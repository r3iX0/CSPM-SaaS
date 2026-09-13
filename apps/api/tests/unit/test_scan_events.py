"""The rules of the scan event stream, without a database or a server.

The stream is a loop over a loader, so every rule it keeps is observable from
the events it yields: it speaks only when the scan changed, it keeps an idle
connection alive, and it stops -- when the scan settles, when the scan is gone,
when the reader leaves, and at a ceiling.
"""

import json
from collections.abc import Awaitable, Callable, Iterator
from contextlib import suppress

from app.services.scan_events import event, stream_scan


class FakeClock:
    """Time that moves only when the stream sleeps."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.now += seconds


def loader(states: list[dict | None]) -> Callable[[], Awaitable[dict | None]]:
    """Returns each state in turn, then repeats the last one."""
    remaining: Iterator[dict | None] = iter(states)
    last: list[dict | None] = [None]

    async def load() -> dict | None:
        with suppress(StopIteration):
            last[0] = next(remaining)
        return last[0]

    return load


async def connected() -> bool:
    return False


async def collect(stream: object, limit: int = 50) -> list[str]:
    out: list[str] = []
    async for chunk in stream:  # type: ignore[attr-defined]
        out.append(chunk)
        if len(out) >= limit:
            break
    return out


def names(chunks: list[str]) -> list[str]:
    """The event names, with keep-alive comments shown as ':'."""
    result = []
    for chunk in chunks:
        if chunk.startswith(":"):
            result.append(":")
        else:
            result.append(chunk.split("\n", 1)[0].removeprefix("event: "))
    return result


async def test_sends_a_state_only_when_it_changed() -> None:
    """A tick that reads the same scan says nothing: the reader has it already."""
    clock = FakeClock()
    running = {"id": "s", "status": "DISCOVERING", "stages": [1]}
    moved = {"id": "s", "status": "DISCOVERING", "stages": [1, 2]}
    done = {"id": "s", "status": "COMPLETED", "stages": [1, 2]}

    chunks = await collect(
        stream_scan(
            loader([running, running, moved, done]),
            is_disconnected=connected,
            clock=clock,
            sleep=clock.sleep,
        )
    )

    assert names(chunks) == ["scan", "scan", "scan", "end"]
    assert json.loads(chunks[1].split("data: ", 1)[1])["stages"] == [1, 2]


async def test_ends_once_the_scan_settles() -> None:
    """A finished scan cannot change, so the connection is not held over it."""
    clock = FakeClock()
    chunks = await collect(
        stream_scan(
            loader([{"status": "PARTIAL"}]),
            is_disconnected=connected,
            clock=clock,
            sleep=clock.sleep,
        )
    )
    assert names(chunks) == ["scan", "end"]


async def test_keeps_an_idle_connection_alive() -> None:
    """Minutes of one subscription collecting must not look like a dead socket
    to a proxy between here and the browser."""
    clock = FakeClock()
    chunks = await collect(
        stream_scan(
            loader([{"status": "DISCOVERING"}]),
            is_disconnected=connected,
            tick=5,
            heartbeat=15,
            max_seconds=40,
            clock=clock,
            sleep=clock.sleep,
        )
    )
    assert names(chunks) == ["scan", ":", ":", "timeout"]


async def test_says_so_when_the_scan_is_gone() -> None:
    clock = FakeClock()
    chunks = await collect(
        stream_scan(
            loader([{"status": "DISCOVERING"}, None]),
            is_disconnected=connected,
            clock=clock,
            sleep=clock.sleep,
        )
    )
    assert names(chunks) == ["scan", "gone"]


async def test_stops_when_the_reader_leaves() -> None:
    """A closed tab must stop the database reads it was causing."""
    clock = FakeClock()
    ticks = {"n": 0}

    async def left_after_two() -> bool:
        ticks["n"] += 1
        return ticks["n"] > 2

    chunks = await collect(
        stream_scan(
            loader([{"status": "DISCOVERING", "n": 1}, {"status": "DISCOVERING", "n": 2}]),
            is_disconnected=left_after_two,
            clock=clock,
            sleep=clock.sleep,
        )
    )
    assert names(chunks) == ["scan", "scan"]


def test_an_event_is_one_json_line() -> None:
    """Data on one line, so a payload never needs SSE's multi-line escaping."""
    chunk = event("scan", {"error": "line one\nline two"})
    assert chunk.count("\n") == 3
    assert chunk.endswith("\n\n")
