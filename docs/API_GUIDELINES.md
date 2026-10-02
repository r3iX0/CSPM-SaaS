# API guidelines

How HTTP APIs are designed and built in this repository: the REST contract a client sees, and the
FastAPI code behind it in `apps/api`. It condenses four sources and holds them against what this
API already does:

- [Microsoft: Web API design best practices](https://learn.microsoft.com/en-us/azure/architecture/best-practices/api-design),
  for resources, methods, status codes, asynchronous operations, versioning and multitenancy;
- [Postman: REST API best practices](https://blog.postman.com/rest-api-best-practices/), for
  errors, pagination, security, idempotency and compatibility;
- [Auth0: FastAPI best practices](https://auth0.com/blog/fastapi-best-practices/), for structure,
  validation, dependencies and async code;
- [FastLaunchAPI: FastAPI best practices for production](https://fastlaunchapi.dev/blog/fastapi-best-practices-production-2026),
  for configuration, sessions, observability, background work and deployment.

Read `docs/API.md` for the endpoints themselves and `docs/api/openapi.json` for the generated
contract. Where this document cites `DECISIONS.md §N`, that section holds the reasoning.

Each practice is marked with where this API stands:

- **In place**: the codebase already does this; the reference says where. Keep it so.
- **Adopt**: the codebase does not do this yet. New work follows it; existing endpoints move to
  it when they are next changed.
- **Not here**: a source recommends it, and this API deliberately does not; the reason is given.

## Contents

1. [Principles](#1-principles)
2. [Resources and URIs](#2-resources-and-uris)
3. [Methods and status codes](#3-methods-and-status-codes)
4. [Requests and responses](#4-requests-and-responses)
5. [Errors](#5-errors)
6. [Collections: paging, filtering, sorting](#6-collections-paging-filtering-sorting)
7. [Long-running operations](#7-long-running-operations)
8. [Versioning and evolution](#8-versioning-and-evolution)
9. [Idempotency and concurrency](#9-idempotency-and-concurrency)
10. [Security](#10-security)
11. [FastAPI implementation](#11-fastapi-implementation)
12. [Data access from a request](#12-data-access-from-a-request)
13. [Observability and health](#13-observability-and-health)
14. [Contract and documentation](#14-contract-and-documentation)
15. [Testing](#15-testing)
16. [Performance](#16-performance)
17. [Checklist for a new endpoint](#17-checklist-for-a-new-endpoint)

## 1. Principles

1. **Model the business, not the database.** A resource is something a customer reasons about (a
   finding, a scan, an attack path), not a table. Never expose join tables, internal ids of other
   systems, or columns a client has no use for. _(Microsoft, Postman)_
2. **One shape everywhere.** Every endpoint answers in the same envelope, names fields the same
   way, pages the same way and fails the same way. A client learns the API once. _(Postman)_
3. **The contract is code.** Request and response models are typed Pydantic models; the OpenAPI
   document is generated from them and checked into the repository; CI fails when they drift.
   **In place** (§157, `docs/api/openapi.json`).
4. **Stateless requests.** A request carries everything needed to answer it: the token, the ids,
   the filters. No server-side session between calls. _(Microsoft)_
5. **Secure by default.** Authentication, tenant isolation, input validation, size and rate
   limits apply to every route unless it is explicitly listed as open. **In place**.
6. **Start simple.** Add a pattern (cursor paging, ETags, field selection) when a real client
   needs it, not before. _(Auth0)_

## 2. Resources and URIs

- **Nouns, plural, lowercase, hyphenated.** `/api/v1/findings`, `/api/v1/attack-paths`,
  `/api/v1/audit-log`. Never a verb for a create, read, update or delete: `POST /findings`, not
  `/create-finding`. **In place**.
- **Collection, item, sub-collection, no deeper.** `/scans/{scan_id}/events` is the limit:
  `collection/item/collection` (Microsoft). Reach a deeper thing through its own collection,
  filtered: `/findings?resource_id=...`, not `/assets/{id}/findings/{id}/evidence`.
- **Ids are opaque UUIDs** in the path, and are never sequential or guessable. **In place**.
- **The tenant is not in the URI.** The organization comes from the verified token, never from a
  path segment or a body field a client could change (see §10). **In place**.
- **An operation that is not create, read, update or delete is a `POST` to a named action under
  the item it changes**: `POST /scans/{id}/cancel`, `POST /findings/{id}/accept-risk`,
  `POST /webhooks/{id}/test`. Use these sparingly, for state transitions with their own rules and
  audit trail; prefer `PATCH` when the change is just a field. **In place**; Microsoft allows
  such "nonresource" operations sparingly.
- **Avoid chatty APIs.** If every screen needs the same five calls, give it one resource that
  answers them together (`/dashboard`). _(Microsoft)_ **In place**.

## 3. Methods and status codes

### Method semantics

| Method | Use for | Safe | Idempotent | Success |
|---|---|---|---|---|
| `GET` | Read a resource or a collection | yes | yes | `200` |
| `POST` | Create in a collection; run an action | no | no | `201` created, `202` accepted, `200` action done |
| `PUT` | Replace a whole resource at a known URI | no | yes | `200` |
| `PATCH` | Change some fields of a resource | no | no | `200` |
| `DELETE` | Remove a resource | no | yes | `200` with the envelope (see below) |

- **`GET` never changes state.** Not a counter, not a "last viewed", not a lazy migration. A
  crawler, a prefetch or a retry must be harmless. _(Postman, Microsoft)_
- **`POST` to a collection creates**, the server assigns the id, and the response is `201` with
  the created resource in `data` and a `Location` header with its URI (Microsoft, Postman).
  **In place** (`created` in `app/api/links.py`).
- **`PATCH` uses merge semantics**: a field absent from the body is left unchanged; a field
  present is set. Clearing a field with `null` is allowed only where the model documents it.
  Model the body with every field optional and apply `model_dump(exclude_unset=True)`.
- **`PUT` replaces the whole resource** and is used only where a client owns the complete
  representation (a settings document). Most updates here are `PATCH`.
- **`DELETE` answers `200` with the envelope**, not `204`. **Not here**: Microsoft and Postman
  suggest `204 No Content`; every response in this API carries the `{data, error, meta}` envelope
  (§157), and the body says what was removed (counts, cascades). Deleting something already gone
  is `404`.

### Status codes

| Code | Meaning here | Raised by |
|---|---|---|
| `200 OK` | Read, update, delete or action succeeded | the route's return |
| `201 Created` | A resource was created | `status_code=status.HTTP_201_CREATED` |
| `202 Accepted` | Work was queued; poll the returned resource | e.g. `POST /scans` |
| `400 Bad Request` | The request is malformed in a way validation cannot name | rare; prefer `422` |
| `401 Unauthorized` | No token, or an invalid or expired one | `NotAuthenticated` |
| `403 Forbidden` | Authenticated, but not allowed (role, demo organization) | `PermissionDenied` |
| `404 Not Found` | No such resource **in this tenant** | `NotFound` and its subclasses |
| `405 Method Not Allowed` | The URI exists; the method does not | FastAPI |
| `409 Conflict` | Valid request, but the resource's state forbids it | `ConflictError` |
| `413 Content Too Large` | Body over the size limit | `PayloadTooLarge`, middleware |
| `422 Unprocessable Content` | Validation failed; every failing field is listed | `ValidationFailed`, Pydantic |
| `429 Too Many Requests` | Rate limit hit; `Retry-After` says when to retry | `RateLimitMiddleware` |
| `500 Internal Server Error` | A bug; the body says no more than that, plus the request id | `UnhandledErrorMiddleware` |
| `502 Bad Gateway` | A cloud provider or other upstream failed | `CloudConnectionError` |
| `503 Service Unavailable` | A dependency (the task queue) is down | `QueueUnavailable` |

- **`404` for another tenant's resource, never `403`.** Saying "forbidden" confirms the id
  exists. Every lookup is scoped to the tenant first, so the answer is naturally `404`.
- **`401` versus `403`.** `401` means "who are you?"; `403` means "I know who you are, and no".
- **Never `200` with an error inside**, and never `500` for a client's mistake.

## 4. Requests and responses

### The envelope

Every JSON response has the same three keys (`docs/API.md` §2, §157). **In place**.

```json
{ "data": { "id": "6b1e…", "status": "OPEN" }, "error": null, "meta": {} }
```

- A route declares its response as `-> Envelope[ItsData, ItsMeta]`
  (`app/schemas/common.py`). FastAPI validates the body on the way out and publishes the exact
  schema. Use `NoMeta` when there is nothing to say, `PageMeta` for a page, `TotalMeta` for a
  capped list.
- Where a service builds its answer as a dict that other code also reads, validate it against a
  `ClosedModel`, which refuses an undeclared key instead of silently dropping it.
- The only responses outside the envelope are files, event streams and endpoints that speak a
  provider's protocol (cloud event receivers). `tests/unit/test_typed_responses.py` lists them
  and fails on any other.

### Fields and values

- **JSON only**, `Content-Type: application/json`. **In place**.
- **`snake_case` field names**, matching the Python models. Don't mix styles.
- **Timestamps are ISO 8601 in UTC with an offset**: `"2026-10-01T09:30:00Z"`. Never a local
  time, never epoch seconds in one place and strings in another.
- **Enumerations are upper-case strings** (`"CRITICAL"`, `"RESOLVED"`), declared as `StrEnum`,
  never integers. The one exception is `Provider` (`azure`, `aws`, `gcp`), an existing contract
  that stays; a new enumeration follows the rule.
- **Ids are UUID strings.** Money, if it ever appears, is an integer of minor units plus a
  currency, never a float.
- **`null` means "known to be absent"; an omitted field means "not part of this
  representation".** Don't mix the two for one field across endpoints.
- **Flat over nested.** Nest only what is part of the resource (a finding's evidence), and link
  to the rest by id. _(Postman)_
- **Separate models per direction.** `FooCreate` (what a client may send), `FooUpdate` (all
  optional, for `PATCH`), `FooOut` (what the server returns). A client can never set `id`,
  `organization_id`, `created_at` or a status the server owns. _(FastLaunchAPI)_
- **A request body refuses a field it does not know.** Request models derive from
  `RequestModel` (`extra="forbid"`), so a misspelt field or one the server owns answers `422`
  naming it instead of being dropped. **In place**, held by `tests/unit/test_request_models.py`.
- **Validate at the edge with `Field` constraints**: lengths, ranges, patterns, `EmailStr`,
  `HttpUrl`. Business rules that need the database are checked in the service, and fail with a
  domain error. _(Auth0)_

## 5. Errors

Errors use the same envelope, with `data: null` and an `error` object. **In place**.

```json
{
  "data": null,
  "error": { "code": "VALIDATION_FAILED", "message": "The request did not validate." },
  "meta": { "errors": ["…one entry per failing field…"] }
}
```

- **`code` is a stable, machine-readable `SCREAMING_SNAKE` string** (`FINDING_NOT_FOUND`,
  `CONFLICT`, `RATE_LIMITED`). Clients branch on `code`, never on `message`. A code, once
  published, keeps its meaning. _(Postman)_
- **`message` is one human sentence**, safe to show a customer: what went wrong and, where
  possible, what to do. Use the domain vocabulary (§78), not Azure's internal names.
- **A `422` lists every failing field at once** in `meta.errors`, not only the first. _(Postman)_
  **In place** (`validation_error_handler`).
- **Raise a domain error, not a bare `HTTPException`.** Services raise the subclasses of
  `AppError` in `app/core/errors.py` (`NotFound`, `PermissionDenied`, `ConflictError`,
  `ValidationFailed`…); the handlers turn them into the envelope. A new failure mode is a new
  subclass with its own `code` and status, not an inline status number. _(Auth0, FastLaunchAPI)_
- **Never leak internals**: no stack traces, SQL, file paths, provider tokens, or another
  tenant's data in an error. An unhandled exception becomes `INTERNAL_ERROR` with the request id
  in `meta`, and the detail goes to the logs and Sentry. **In place** (`UnhandledErrorMiddleware`).
- **Document every error a route can answer** with `responses=error_responses(403, 409)`, so
  the published contract shows the envelope rather than FastAPI's default. **In place**.

## 6. Collections: paging, filtering, sorting

- **Every collection is paged.** `?limit=&offset=`, with a default and a hard maximum declared on
  the parameter: `limit: int = Query(default=100, ge=1, le=500)`. Over the cap is a `422`, not a
  silent truncation. **In place**.
- **The page says how big the whole set is**: `meta` is `PageMeta` (`total`, `limit`, `offset`).
  **In place**.
- **Filter with one query parameter per field**, named as the field: `?severity=HIGH&status=OPEN`.
  Ranges use `_min`/`_max` suffixes (`?risk_min=70`). Free text is `?search=`. _(Postman,
  Microsoft)_
- **Sort with an enumerated `?sort=`**, validated by a pattern or a `Literal`, never passed to SQL
  as a raw column name. **In place**:

  ```python
  sort: str = Query(default="risk", pattern="^(risk|severity|recent)$")
  ```

- **Filter, sort and page in the database, never in Python and never in the browser.** A page
  that filters only the rows it holds reports "nothing matches" for the rest of the estate.
  **In place** (`findings.list_findings`).
- **Use cursor paging for append-heavy feeds** (events, the audit log) when offsets drift as rows
  arrive: an opaque `?cursor=`, and `meta.next_cursor`. **Adopt** when such a feed is paged
  deeply.
- **Field selection (`?fields=`) is not offered.** **Not here**: responses are small and typed;
  add it only for a proven bandwidth problem, and then validate the field list against what the
  caller may see (Microsoft).

## 7. Long-running operations

- **Anything that takes longer than a request should not block one.** Accept it, queue it, and
  answer `202 Accepted` with the resource that tracks it. **In place**: `POST /scans` returns the
  scan; the client follows `GET /scans/{id}/detail` or the `GET /scans/{id}/events` stream.
- A `202` also sends `Location` pointing at the status resource and `Retry-After` with the poll
  interval, as Microsoft's asynchronous request-reply pattern describes. **In place**
  (`accepted` in `app/api/links.py`).
- **Durable work goes to Celery**, never FastAPI's `BackgroundTasks`, which die with the process
  and cannot be retried or observed. _(FastLaunchAPI)_ **In place**.
- **The status resource tells the truth**: real phases from the database, no simulated progress
  (§87, §88).
- **Make a queued operation cancellable** where it is costly: `POST /scans/{id}/cancel`.
  **In place**.

## 8. Versioning and evolution

- **The version is in the path**: `/api/v1`, set once on the root router
  (`app/api/router.py`). URI versioning is simple and cache-friendly (Microsoft). **In place**.
- **Additive changes are not breaking**, and do not need a new version: a new endpoint, a new
  optional request field, a new response field, a new enum value _where clients were told to
  expect new values_. Clients must ignore fields they do not know. _(Microsoft, Postman)_
- **Breaking changes need `/api/v2` for the affected routes**, served in parallel with v1 until
  clients have moved: removing or renaming a field, changing a type or a meaning, tightening
  validation, changing a status code or an error `code`.
- **Never repurpose a field.** A changed meaning is a new field.
- **Deprecate in the open.** Mark the operation `deprecated=True` in OpenAPI, send `Deprecation`
  and `Sunset` headers (RFC 9745, RFC 8594), and write the date and the replacement in
  `docs/API.md`. The `deprecation()` dependency in `app/core/openapi.py` sends both headers and a
  `Link` to the replacement; no route uses it yet. **Adopt** when the first route is deprecated.

## 9. Idempotency and concurrency

- **`GET`, `PUT` and `DELETE` are idempotent by design**: repeating them changes nothing more.
  Keep it so; a `DELETE` that also sends an email on every call is not idempotent.
- **Retries of a create must not create twice.** **Adopt** for endpoints a client may retry after
  a timeout and where a duplicate costs something (starting a scan, creating a webhook, sending
  an invitation): accept an `Idempotency-Key` header, store the key with the first response for
  24 hours, and replay that response for a repeat. _(Postman)_ Until then, these endpoints refuse
  a duplicate with `409` where a rule makes it one (one running scan per target).
- **State conflicts are `409`**, with a message that says which state stands in the way.
  **In place**.
- **Optimistic concurrency for documents edited by more than one person.** **Adopt** where two
  members can edit the same thing (organization settings, a risk's triage note): return an `ETag`
  (a version or hash) on `GET`, require `If-Match` on `PATCH`/`PUT`, and answer
  `412 Precondition Failed` when it no longer matches. _(Microsoft)_

## 10. Security

Security here follows the [OWASP API Security Top 10](https://owasp.org/API-Security/); the items
below are where each is answered.

### Authentication and authorization

- **Every route requires a verified token** (Supabase JWT, ES256/RS256/HS256, signing keys
  fetched asynchronously and cached), except the few listed as open, such as the health checks
  and the cloud event receivers. The scheme is declared once (`bearer_scheme` in
  `app/core/deps.py`), so the OpenAPI document carries `bearerAuth` and each such route says it
  needs it; `tests/unit/test_openapi_contract.py` lists the open ones. **In place**
  (`app/core/security.py`).
- **Tokens travel only in `Authorization: Bearer`.** Never in a query string, which ends up in
  logs and browser history. A single-use link token goes in the URL fragment, which servers never
  see (§162).
- **The tenant comes from the token.** `Tenant` (`app/core/deps.py`) derives the organization
  from the verified user's membership; a body or query field never decides it. **In place**.
- **Object-level authorization on every lookup** (OWASP API1, BOLA): every query is filtered by
  the tenant's `organization_id`, and PostgreSQL row-level security enforces the same rule again
  under the `cloudguard_app` role. Two layers, so one bug is not a breach. **In place**.
- **Function-level authorization is explicit** (OWASP API5): a write calls
  `tenant.require_write()`; owner-only actions check the owner role; the demo organization is
  refused every write by flag as well as role (§99). **In place**.
- **Signed tokens name their purpose**, and the verifier checks it, so a token minted for one
  flow cannot be replayed in another (§147). **In place**.

### Input, limits and transport

- **Validate everything a client sends** with Pydantic: types, lengths, ranges, patterns. Never
  build SQL from strings; never pass a client value to a shell, a template or a file path.
- **Bodies are size-limited** (`RequestSizeLimitMiddleware`, `413`). **In place**.
- **Rate limits per verified user**, with a smaller allowance on expensive routes marked
  `dependencies=[Costly]`; over the limit is `429` with `Retry-After` (§161). Every counted
  response carries `X-RateLimit-Limit`, `-Remaining` and `-Reset` for the tightest counter that
  spoke, so a client can slow down before it is refused (Postman). **In place**.
- **HTTPS only**, with HSTS. **In place** (`SecurityHeadersMiddleware`).
- **Security headers on every response**, including errors and preflights: CSP,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`. **In place**.
- **CORS lists origins explicitly**, never `*` with credentials, names the methods and request
  headers the web app sends rather than `*`, and exposes only the response headers a client
  reads (`X-Request-ID`, `X-RateLimit-*`, `Retry-After`, `Location`, `Content-Disposition`).
  **In place**.
- **Outbound requests to a URL a customer typed** go only through `core/outbound.post_json`:
  HTTPS on 443, public addresses only, the connection pinned to the checked IP, no redirects
  (§164; OWASP API7, server-side request forgery). **In place**.
- **Tenant data is not cached by intermediaries**: every response under `/api/` carries
  `Cache-Control: private, no-store` unless a route chose its own policy (the event stream, a
  download). **In place** (`SecurityHeadersMiddleware`).

### Secrets and audit

- **Secrets come from the environment through `pydantic-settings`**, validated at startup; the
  app refuses to boot with a missing one. Never in code, never in a response, never in a log.
  **In place** (`app/core/config.py`).
- **Every change a person makes is audited** through `services/audit.record`, which stamps the
  caller and the request id (§163). **In place**.

## 11. FastAPI implementation

### Layout

```text
app/
  api/router.py          # /api/v1, includes every router
  api/routes/<area>.py   # thin: parse, authorize, call a service, shape the envelope
  services/<area>.py     # business rules, transactions, raises domain errors
  repositories/          # queries reused across services
  models/                # SQLAlchemy tables
  schemas/<area>.py      # Pydantic: <Thing>Create / <Thing>Update / <Thing>Out
  core/                  # config, deps, errors, middleware, security, logging
```

- **Routes are thin.** A route parses input, authorizes, calls one service function and returns
  the envelope. Business rules, multi-step writes and anything a worker also needs live in a
  service. _(Auth0, FastLaunchAPI)_ **In place**, held by `tests/unit/test_thin_routes.py`: a route
  module that builds a statement or calls the session (other than `commit`) fails it.
- **One router per area**, `APIRouter(prefix="/findings", tags=["findings"])`, included once in
  `app/api/router.py`.

### Dependencies

- **Inject with `Depends` through `Annotated` aliases**: `session: DbSession, tenant: Tenant`.
  Never reach for a module-level session, client or user. _(Auth0)_
- **Chain dependencies** for what builds on what (the token, then the user, then the tenant);
  FastAPI caches each per request.
- **Put reusable checks in dependencies** (`Costly`, an object's existence in the tenant) so a
  route cannot forget them.
- **Override dependencies in tests** with `app.dependency_overrides`, never by patching modules.

### Async

- **`async def` only when everything inside awaits.** One blocking call (`requests`,
  `time.sleep`, sync file or database I/O, a CPU-heavy loop) freezes every request on the worker.
  _(Auth0)_
- **Blocking or CPU work runs in a thread**: `graph_service.off_loop`,
  `anyio.to_thread.run_sync`. Reports render in a thread after the session is closed (§158,
  §161).
- **Never hold a pooled connection while waiting on something slow.** Close the session first, or
  open a fresh `rls_session` for the write after (§158).

### Configuration and lifecycle

- **Settings are one `pydantic-settings` class**, read once, validated at startup, imported from
  `app.core.config`; no `os.getenv` scattered in code. _(FastLaunchAPI)_
- **Startup and shutdown go in the `lifespan` context manager** (engines, clients), not
  module-level side effects or the deprecated `on_event` hooks. **In place**.
- **Middleware order is deliberate and documented** where it is added (`app/main.py`): request
  context outermost, then security headers, CORS, rate limiting, unhandled errors, and the size
  limit innermost. A new middleware goes in with a comment saying why it sits where it does.
  **In place**.

## 12. Data access from a request

- **Async SQLAlchemy through the request's session** (`DbSession`), under the RLS-constrained
  `cloudguard_app` role; the owner connection is for migrations only. **In place**.
- **One transaction per request, ended by the route.** `rls_session` keeps the caller's RLS
  claims in the transaction, so a commit inside a service would tear them down for whatever the
  route does next. A service flushes and never calls `session.commit()`
  (`tests/unit/test_request_transaction.py`); the route commits once, after the service returns
  and before it queues any work. The scan pipeline commits only through `ScanWriter.commit`
  (CLAUDE.md).
- **Load what the response needs in one query or a fixed few**: `selectinload`/`joinedload` for
  relationships, never a query per row (N+1). _(FastLaunchAPI)_
- **Page, filter and sort in SQL** (§6 of this document).
- **Workers use their own sessions and their own role**, never a request's.

## 13. Observability and health

- **Every request has an id.** The server mints `X-Request-ID`, binds it to every log line,
  returns it on the response, and services read it through `core/request_context.py` (§161).
  **In place**. A client quoting it in a support request finds every line of that request.
- **Logs are structured** (structlog, JSON): a constant event name (`ratelimit.refused`), fields
  for the values, never an f-string message. Never log a token, a secret or a customer's cloud
  payloads. **In place**.
- **Unhandled errors go to Sentry**; the client sees only the envelope.
- **Two health endpoints**, both unauthenticated and both saying nothing about the deployment:
  `GET /health` (liveness: the process answers) and `GET /health/ready` (readiness: the database
  and the task broker both answer, or a `503` in the envelope names the one that does not,
  without its own error text). **In place** (FastLaunchAPI).
- **Adopt** when there is a place to send them: request rate, error rate and latency per route,
  and trace context (`traceparent`) carried through to the workers.

## 14. Contract and documentation

- **The OpenAPI document is generated, committed and checked**: `docs/api/openapi.json`, rebuilt
  by `scripts/generate_openapi.py`; CI fails when the code and the file disagree. **In place**.
- **Every route is typed and documented**: tags, the response model through the return
  annotation, the errors through `responses=error_responses(...)`, and a docstring that says what
  the endpoint is for and why it is shaped that way. `tests/unit/test_typed_responses.py` walks
  every route (§157). **In place**.
- **The document says how to authenticate and names each operation**: a `bearerAuth` scheme,
  stable `operationId`s of the form `<tag>_<handler>`, and a description for every tag
  (`app/core/openapi.py`). **In place**, held by `tests/unit/test_openapi_contract.py`.
- **Give examples** on request and response models (`json_schema_extra={"examples": [...]}`),
  so the generated docs show a realistic call. _(Auth0)_ **In place** for request models, where
  `test_request_models` validates each example against its own model; **Adopt** for response
  models.
- **`docs/API.md` is the human guide**: the endpoints by area, the envelope, authentication. A
  change to a route updates it in the same pull request.

## 15. Testing

- **Unit tests for every route's behaviour**, through the ASGI app (`httpx.AsyncClient` with
  `ASGITransport`, or `TestClient`), with dependencies overridden. Fast, no network. _(Auth0)_
- **Integration tests against a live PostgreSQL** (`@pytest.mark.integration`), run as the
  RLS-constrained role, as production does. A tenant-isolation test run as the owner proves
  nothing. **In place** (CI).
- **Test the unhappy paths as hard as the happy one**: no token, a wrong role, another tenant's
  id (`404`), invalid input (`422` with every field), a state conflict (`409`), the rate limit
  (`429`), an upstream failure (`502`). _(Postman)_
- **Assert on the contract**: status, `error.code`, the envelope's shape; not on a message's
  wording.
- **Mock only what leaves the process**: Azure, AWS, email, webhooks. Use the fixture captures
  under `tests/fixtures/`, never a mock connector in `app/` (CLAUDE.md).

## 16. Performance

- **Cap every list** (§6 of this document) and every expensive route (`Costly`).
- **Aggregate for screens** rather than making the browser fan out (`/dashboard`).
- **Measure before optimizing**; add caching only with a clear key, a TTL and an invalidation on
  write, and never across tenants (a cache key always includes the organization).
  _(FastLaunchAPI)_
- **Large files (PDF reports) are rendered off the event loop** and returned with a
  `Content-Disposition` naming the file. **In place**.

## 17. Checklist for a new endpoint

Before opening the pull request:

- [ ] The URI is a plural noun under `/api/v1`, at most `collection/item/collection` deep; an
      action is a `POST` to a named sub-resource.
- [ ] The method and success status match §3 (`201` create, `202` queued, `200` otherwise).
- [ ] `session: DbSession, tenant: Tenant` are injected; a write calls `tenant.require_write()`.
- [ ] Every query is scoped to `tenant.organization_id`; another tenant's id is `404`.
- [ ] Input is a `…Create`/`…Update` model deriving from `RequestModel`, with `Field`
      constraints and an example; the client cannot set server-owned fields.
- [ ] A `201` calls `created` and a `202` calls `accepted`, so the answer says where to look.
- [ ] The return annotation is `Envelope[…Out, …Meta]`; a list is paged with a capped `limit` and
      returns `PageMeta`.
- [ ] Failures raise `AppError` subclasses, and `responses=error_responses(...)` lists them.
- [ ] Anything slow is queued (`202`) or run off the loop; no blocking call in `async def`.
- [ ] Expensive work carries `dependencies=[Costly]`.
- [ ] A change a person makes is recorded with `services/audit.record`.
- [ ] Tests cover success, no token, wrong role, other tenant, invalid input and conflicts.
- [ ] `docs/api/openapi.json` is regenerated and `docs/API.md` updated.

---

## Where this API departs from the sources

| Topic | Sources | Here | Why |
|---|---|---|---|
| `DELETE` success | `204 No Content` | `200` with the envelope | Every response has one shape (§157); the body reports what went with it |
| Error body | `{ "error": { … } }`, or RFC 9457 problem details | `{ data: null, error: {code, message}, meta }` | Same envelope as success; one parser on the client |
| Actions in URIs | Avoid verbs | `POST /{collection}/{id}/{action}` for state transitions | Microsoft allows nonresource operations sparingly; each is audited |
| Versioning | URI, header or media type | URI (`/api/v1`) | Simple, visible, cache-friendly |
| HATEOAS links | Microsoft: maturity level 3 | Not used | One first-party client; the OpenAPI contract is the map |
| Field selection | `?fields=` | Not offered | Small typed responses; it adds an authorization surface |
| `422` versus `400` | Postman lists both | `422` for every validation failure | FastAPI's convention, with all fields listed |
| Background work | `BackgroundTasks` for small jobs | Celery for anything durable | Work must survive restarts and be retried |
