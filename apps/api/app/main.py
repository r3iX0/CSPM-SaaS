"""CloudGuard API -- modular monolith.

Everything the product does lives in this one process (plus a Celery worker
sharing the same codebase). That is a deliberate choice: the product is a
scanner, a rule engine and a risk engine that all operate on the same data, and
splitting them across services would buy distributed-systems problems in
exchange for nothing the MVP needs.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import settings
from app.core.db import dispose_engines, ping
from app.core.errors import (
    AppError,
    DatabaseUnavailable,
    QueueUnavailable,
    UnhandledErrorMiddleware,
    app_error_handler,
    http_error_handler,
    validation_error_handler,
)
from app.core.logging import configure_logging, get_logger
from app.core.middleware import (
    RateLimitMiddleware,
    RequestContextMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
    ping_redis,
)
from app.core.openapi import TAGS, operation_id
from app.core.sentry import init_sentry
from app.schemas.common import Envelope, NoMeta, error_responses
from app.schemas.health import HealthOut, ReadyOut

log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    configure_logging()

    # Configuration is validated at import (app.core.config.get_settings), so
    # reaching this point already means the environment is complete. Logged so
    # a healthy boot is visible in the deploy logs, not just a failed one.
    log.info("config.validated", environment=settings.app_env)

    # Azure misconfiguration deliberately does not stop the API booting — it
    # breaks consent and nothing else, and refusing to start would cost the
    # whole dashboard to fix one button. But it was previously invisible until
    # a customer walked into it, so the operator who can actually fix it never
    # saw it. Warned here, where deploy logs are read.
    if settings.azure_configured and (problem := settings.azure_consent_problem):
        log.warning("azure.consent_misconfigured", problem=problem)

    if settings.sentry_dsn:
        init_sentry(settings.sentry_dsn, settings.app_env)

    # Keep the rules table in step with the Python registry. The registry is the
    # source of truth; the table is a read-mirror for joins and the UI.
    from app.services.rule_sync import sync_rules_to_database

    try:
        synced = await sync_rules_to_database()
        log.info("rules.synced", count=synced)
    except Exception as exc:  # pragma: no cover -- never block startup on this
        log.warning("rules.sync_failed", error=str(exc))

    yield

    # Close the pools while the loop is still alive, so a redeploy hands its
    # connections back rather than leaving each one held open in the Session
    # pooler until it notices the process has gone -- the pooler's slots are
    # shared with the worker and the scanner.
    await dispose_engines()


app = FastAPI(
    title="Cleave API",
    version="0.1.0",
    description=(
        "Azure-first cloud security posture management. Every response is the envelope "
        "`{data, error, meta}`; a failure carries a stable `error.code` to branch on. Send a "
        "Supabase access token as `Authorization: Bearer`. The organization comes from the token, "
        "never from the path or the body, and a request body refuses a field it does not know."
    ),
    openapi_tags=TAGS,
    generate_unique_id_function=operation_id,
    lifespan=lifespan,
)

# The order below is load-bearing, and it reads backwards.
# ``add_middleware`` inserts at the front, so the **last one added is the
# outermost** and the first one added wraps the router directly.
#
# Innermost first:
#
# 1. ``RequestSizeLimitMiddleware`` -- innermost because it refuses an oversized
#    body by raising from inside ``receive``, where the handler is reading it.
#    Anything between it and the router would see that exception first; the
#    unhandled-error middleware in particular would turn a 413 into a 500.
# 2. ``UnhandledErrorMiddleware`` -- inside CORS, so the response it writes
#    still picks up the access-control headers on the way back out. A bare
#    ``Exception`` handler cannot do this: Starlette hands that to
#    ``ServerErrorMiddleware``, outside everything, and the browser then refuses
#    to read the 500 and reports a network failure instead.
# 3. ``RateLimitMiddleware`` -- also inside CORS, for the same reason: a 429 a
#    browser cannot read is indistinguishable from the API being down.
# 4. ``CORSMiddleware``.
# 5. ``SecurityHeadersMiddleware`` -- so every response carries the headers,
#    including CORS preflights and anything raised further in.
# 6. ``RequestContextMiddleware`` -- outermost, so the id it mints is bound
#    before anything else logs, and every response carries it back, refusals
#    included.
app.add_middleware(RequestSizeLimitMiddleware, max_bytes=settings.max_request_bytes)

app.add_middleware(UnhandledErrorMiddleware)

app.add_middleware(
    RateLimitMiddleware,
    authenticated_limit=settings.rate_limit_authenticated,
    anonymous_limit=settings.rate_limit_anonymous,
    window_seconds=settings.rate_limit_window_seconds,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    # No cookies and no HTTP auth: the token travels in ``Authorization``, which a page sends
    # because it chose to. Credentialed mode would also have the browser attach cookies and
    # client certificates to a cross-origin call this API has no use for them in.
    allow_credentials=False,
    # Exactly what the web app sends, so a page on an allowed origin still cannot ask for more
    # than it uses. The request headers the browser always allows (Accept, Content-Type for a
    # simple type) need no entry; ``Authorization`` and ``X-Organization-Id`` do.
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Organization-Id"],
    # Readable by the frontend: the request id so an error it shows can name the request, the
    # rate limit so it can slow down, and the headers a created or queued answer points by.
    expose_headers=[
        "X-Request-ID",
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "X-RateLimit-Reset",
        "Retry-After",
        "Location",
        "Content-Disposition",
    ],
)

app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(RequestContextMiddleware)

app.add_exception_handler(AppError, app_error_handler)  # type: ignore[arg-type]
app.add_exception_handler(HTTPException, http_error_handler)  # type: ignore[arg-type]
app.add_exception_handler(RequestValidationError, validation_error_handler)  # type: ignore[arg-type]

app.include_router(api_router)


@app.get("/health", tags=["meta"])
async def health() -> Envelope[HealthOut, NoMeta]:
    """The platform's liveness probe, and nothing else.

    Answers whether this process is up, and says nothing about what it is: the
    endpoint is unauthenticated and rate-limit exempt, so every field on it is
    a field anybody can read. Which environment a deployment is tells a
    stranger nothing they need and one thing they might use.
    """
    return Envelope(data=HealthOut(status="ok"), meta=NoMeta())


@app.get("/health/ready", tags=["meta"], responses=error_responses(503))
async def ready() -> Envelope[ReadyOut, NoMeta]:
    """Whether this instance can do its work: the database and the task broker both answer.

    Unlike ``/health`` this touches both dependencies, so it is rate limited and is for an
    operator or a deploy check, not for the platform's probe. A dependency that does not answer
    is a ``503`` in the envelope, naming which one, and never the dependency's own error: that
    can carry an address or a credential. The detail goes to the log.
    """
    try:
        await ping()
    except Exception as exc:
        log.warning("ready.database_unavailable", error=type(exc).__name__)
        raise DatabaseUnavailable("The database did not answer.") from exc
    try:
        await ping_redis()
    except Exception as exc:
        log.warning("ready.queue_unavailable", error=type(exc).__name__)
        raise QueueUnavailable("The task broker did not answer.") from exc
    return Envelope(data=ReadyOut(status="ready", database="ok", queue="ok"), meta=NoMeta())
