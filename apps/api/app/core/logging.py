import logging
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import structlog

from app.core.config import settings
from app.core.redaction import AccessLogRedactor


def configure_logging() -> None:
    logging.basicConfig(
        format="%(message)s", stream=sys.stdout, level=getattr(logging, settings.log_level, 20)
    )
    # Uvicorn writes the request target, query string included, into its access log, and two
    # routes carry a credential there (``?token=``). Attached once however often this runs.
    access = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, AccessLogRedactor) for f in access.filters):
        access.addFilter(AccessLogRedactor())
    # httpx writes ``HTTP Request: POST <url>`` at INFO for every call, and a Slack or Teams
    # webhook keeps its credential in the URL's path, where no query redaction reaches. The
    # caller records how a delivery went; the client's own line adds only the URL
    # (DECISIONS.md §198).
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer()
            if settings.is_production
            else structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, settings.log_level, 20)
        ),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)


@contextmanager
def log_context(**values: Any) -> Iterator[None]:
    """Bind ids for the length of a block, so every line inside carries them.

    This is what a trace is, on a stack whose telemetry is structured logs.
    "Why was this scan slow" is already answerable from the per-stage durations;
    what was missing is the other half of the same question -- given a line,
    which scan, which step and which task produced it. A scan runs as several
    Celery tasks across several workers, so without this the lines from one
    scan's collection are interleaved with every other tenant's and joined only
    by whichever ids each call site remembered to pass.

    Deliberately not OpenTelemetry. Spans would need a collector to send them
    to, and this deployment has none: an exporter writing into a socket nobody
    reads is not observability, it is the appearance of it. The ids are the part
    that makes the logs joinable, and they are free.

    ``None`` values are dropped rather than bound, because a log line saying
    ``step_id=None`` reads as a step that has no id rather than as a line from
    outside any step.
    """
    bound = {key: value for key, value in values.items() if value is not None}
    with structlog.contextvars.bound_contextvars(**bound):
        yield
