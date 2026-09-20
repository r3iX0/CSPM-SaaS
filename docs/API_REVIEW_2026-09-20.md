# API Design Review — CloudGuard HTTP surface

**Date:** 20 September 2026
**Scope:** `apps/api` HTTP surface at commit `89b4391` (branch `develop-eh`) — all sixteen
route modules under `app/api/routes/`, the dependency chain in `app/core/deps.py`, the error
taxonomy in `app/core/errors.py`, the middleware stack in `app/core/middleware.py`, the
session contract in `app/core/db.py`, the request/response schemas in `app/schemas/`, and the
generated specification at `docs/api/openapi.json`. Client polling behaviour in `apps/web` was
read where it determines a route's real load.
**Method:** Static review against REST design practice — resource semantics, HTTP method
contracts, pagination, error modelling, versioning, specification completeness — and against
the runtime cost each route actually carries. No live traffic was sent; no deployed
environment was touched. Claims about SQL emission were checked by compiling the statement
against the PostgreSQL dialect.
**Assessed by:** Claude Opus 5, at the request of the repository owner.
**Companion reviews:** [`SECURITY_REVIEW_2026-09-20.md`](SECURITY_REVIEW_2026-09-20.md),
[`ARCHITECTURE_REVIEW_2026-09-20.md`](ARCHITECTURE_REVIEW_2026-09-20.md),
[`TESTING_REVIEW_2026-09-20.md`](TESTING_REVIEW_2026-09-20.md). The design decisions this
review measures against are `API.md` and `DECISIONS.md`.

---

## 1. Summary

The surface is coherent. One envelope, one error taxonomy with stable machine-readable codes,
one versioned prefix, tenancy derived from the token rather than from the request, and a
middleware order that is both correct and documented at the point where it is easy to get
wrong. Most of what follows is not a disagreement with the design — it is the design not
reaching the wire.

Three findings matter more than the rest.

The first is a reachable 500. No list endpoint bounds its `offset` or `limit` below zero, and
PostgreSQL refuses a negative `LIMIT` or `OFFSET` outright, so `GET /api/v1/findings?offset=-1`
raises inside asyncpg and surfaces as `INTERNAL_ERROR`. Eight endpoints are affected. The fix
is already written and never wired: `app/schemas/common.py` defines a `Page` model with the
correct bounds and nothing in the codebase imports it.

The second is that the specification describes none of the contract a client needs. Every one
of the seventy-nine operations returns `{"type": "object"}` for its success body, none
declares an authentication scheme, and none documents a non-2xx response other than the 422
FastAPI generates on its own. The response schemas exist — `FindingOut`, `RiskOut`, `ScanOut`,
`CoverageOut` — and are serialised into untyped dictionaries before FastAPI can see them. So
does the generic `Envelope`, also never imported. A generated client can type nothing and
authenticates with nothing.

The third is two blocking calls inside `async def` handlers. WeasyPrint renders a report and
Celery pings the broker, both synchronously, on the event loop that is serving every other
request in the process.

Beneath those: a GET that writes and calls Azure while a background tab polls it every five
seconds, CSV export that does not neutralise spreadsheet formulas, a database transaction held
open across provider round trips, and a set of consistency gaps in pagination metadata.

| # | Finding | Area | Severity |
|---|---------|------|----------|
| 1 | Negative `offset`/`limit` raises a 500 on eight list endpoints | Robustness | High |
| 2 | No `response_model` anywhere: the specification types no success body | Clarity / DX | High |
| 3 | WeasyPrint and Celery `ping` block the event loop | Performance | High |
| 4 | CSV export does not neutralise spreadsheet formulas | Security | Medium |
| 5 | `GET /cloud-connections/{id}` writes and calls Azure, and is polled in background tabs | Semantics / Security | Medium |
| 6 | OpenAPI declares no security scheme | Clarity / DX | Medium |
| 7 | The RLS transaction is held open across provider HTTP calls | Performance | Medium |
| 8 | No error responses documented on any operation | Clarity / DX | Medium |
| 9 | Rate limiting is keyed on address only, and does not tier by cost | Security | Medium |
| 10 | `get_tenant` issues a membership query on every request | Performance | Low-Medium |
| 11 | `GET /dashboard` and `GET /assets` are expensive and polled | Performance | Low-Medium |
| 12 | No conditional GET on pollable reads | Performance | Low |
| 13 | `meta.total` means two different things | Consistency | Low |
| 14 | Request models accept unknown fields silently | Robustness | Low |
| 15 | No `servers` block and no stable `operationId` | Clarity / DX | Low |

---

## 2. Findings

### Finding 1 — Negative `offset` or `limit` raises a 500 on eight list endpoints

**Severity:** High · **Area:** Robustness
**Locations:** `apps/api/app/api/routes/findings.py:67`, `assets.py:69`, `risks.py:32`,
`changes.py:35`, `attack_paths.py:48` and `:149`, `notifications.py:17`, `scans.py:188`

Every list endpoint bounds its page size from above and none bounds it from below:

```python
limit: int = Query(default=100, le=500),
offset: int = 0,
```

`le=500` without `ge=1`, and an `offset` with no constraint at all. SQLAlchemy passes both
through unchanged — compiled against the PostgreSQL dialect:

```
SELECT f.id FROM f  LIMIT -1 OFFSET -5
```

PostgreSQL answers `ERROR: OFFSET must not be negative`. asyncpg raises, nothing in the route
catches it, and `UnhandledErrorMiddleware` renders a 500 `INTERNAL_ERROR`. A request that is
wrong in an entirely ordinary way is reported as a server fault, logged as one, and counted as
one in Sentry.

`scans.py:188` is a variant of the same thing. It declares `limit: int = 25` with no `Query`
constraint and clamps with `min(limit, 100)`, which bounds the top and lets every negative
value through.

**Fix.** `app/schemas/common.py:16` already defines exactly the right thing:

```python
class Page(BaseModel):
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)
```

It has no importers. Promote it to a dependency and apply it to all eight endpoints, keeping
each route's own ceiling where it differs from the default. A rejected page request then
becomes the 422 it always was, in the envelope, with the failing constraint named.

---

### Finding 2 — No `response_model` anywhere: the specification types no success body

**Severity:** High · **Area:** Clarity / developer experience
**Locations:** every route module; `apps/api/app/schemas/common.py:8`

`grep -rn response_model apps/api/app/` returns nothing. Every handler is annotated `-> dict`
and returns `envelope(...)` over dictionaries produced by `.model_dump(mode="json")`. The
schemas are applied — and then discarded before FastAPI can read them.

The generated specification at `docs/api/openapi.json` reflects it. Across 67 paths and 79
operations:

- 76 operations document a 422 referencing `HTTPValidationError`, which FastAPI generates.
- Every success response is `{"type": "object"}` with a title derived from the function name,
  or `{}`.
- `components.schemas` holds 25 entries. All of them are request bodies or enums. Not one
  response body is described.

`app/schemas/common.py:8` defines `Envelope(BaseModel, Generic[T])` — the exact generic this
needs — and has no importers either. Both of the pieces required to fix this were written and
neither was connected.

**Fix.** Declare the response model per route, reusing what exists:

```python
@router.get("", response_model=Envelope[list[FindingOut]])
```

This is the largest single improvement available to anyone consuming the API, including the
frontend's own generated types. It costs one argument per route and no new schemas for the
endpoints whose `Out` models already exist. The handlers returning assembled dictionaries
rather than a single model — `assets.py`, `dashboard.py`, the attack-path routes — need a
response model written first; those are the minority.

---

### Finding 3 — WeasyPrint and Celery `ping` block the event loop

**Severity:** High · **Area:** Performance
**Locations:** `apps/api/app/api/routes/reports.py:116`, `apps/api/app/api/routes/scans.py:223`

Two synchronous calls sit directly inside `async def` handlers. Neither stalls only its own
request — both stall every request the process is serving.

`reports.py:116` calls `render_pdf(report)`, which is WeasyPrint laying out a document. It is
CPU-bound and takes seconds on a technical report.

`scans.py:223` calls `celery_app.control.ping(timeout=1.0)`. That is synchronous kombu I/O
against the broker, and the timeout is the worst case it is allowed to hold the loop for.

The second is the more insidious of the two, because the endpoint exists to diagnose a broken
deployment — precisely the situation in which the broker is unreachable and the call takes its
full second, on every poll, while the scans page is the page everyone is looking at.

**Fix.** Both are one line:

```python
from starlette.concurrency import run_in_threadpool

content = await run_in_threadpool(render_pdf, report)
replies = await run_in_threadpool(lambda: celery_app.control.ping(timeout=1.0))
```

---

### Finding 4 — CSV export does not neutralise spreadsheet formulas

**Severity:** Medium · **Area:** Security (CWE-1236, formula injection)
**Location:** `apps/api/app/compliance/export.py:115`

`to_csv` writes rows through `csv.writer` with RFC 4180 quoting and no cell neutralisation.
RFC 4180 quoting protects the file's structure; it does not stop a spreadsheet from treating a
leading `=`, `+`, `-` or `@` as a formula.

The `inconclusive_reasons` column carries customer-controlled text. The chain is:

1. `apps/api/app/rules/azure/storage/public_access.py:128` and eight other rule modules build
   `message=f"{resource.name} is publicly accessible: ..."`.
2. `apps/api/app/services/scan/coverage.py:45` stores that message as
   `ScanEvaluationGap.reason`.
3. `apps/api/app/services/compliance.py:272` reads it back.
4. `export.py` writes it into the cell.

`resource.name` is whatever the customer named the resource in Azure. An Azure resource named
`=cmd|'/c calc'!A1` becomes a live formula in the spreadsheet an audit is run from — and the
reader opening that file is an auditor, who is exactly the person least able to judge that a
cell in a security vendor's export should not be executing.

The other customer-derived columns are lower risk but on the same path: `control_title` and
`rules` are CloudGuard-authored today, and nothing in the type system keeps them that way.

**Fix.** Prefix any cell whose first character is `=`, `+`, `-`, `@`, tab or carriage return
with a single quote, in `to_csv` rather than at each call site, so a column added later is
covered by construction. Note in the docstring that the guard is about the reader's
spreadsheet, not about the file's syntax — otherwise it looks redundant beside the quoting and
will eventually be removed as such.

---

### Finding 5 — `GET /cloud-connections/{id}` writes and calls Azure, and is polled in background tabs

**Severity:** Medium · **Area:** HTTP semantics / resource consumption
**Locations:** `apps/api/app/api/routes/cloud_connections.py:306`,
`apps/web/src/pages/ConnectionSetup.tsx:68`

The handler calls `service.try_auto_validate(session, connection)` — a probe against Azure
followed by a database write — inside a GET. GET is defined as safe: a client, a proxy, a
crawler or a retry may issue one freely, and nothing in the method's contract warns that it
mutates state or spends a third party's quota.

The comment at the call site explains why the auto-validation is there, and the reasoning is
sound: the wizard polls, and a silent failure means "not deployed yet". The problem is the
method it was put on, not the behaviour.

The client makes it concrete. `ConnectionSetup.tsx:68` polls every five seconds with
`refetchIntervalInBackground: true`, so a tab left open behind another window keeps driving
Azure calls and database writes indefinitely, with nobody looking at the result. The route's
only ceiling is the shared 300/minute.

**Fix.** The endpoint this should be is already written — `POST /{connection_id}/recheck`
(`cloud_connections.py:358`) is described in `API.md` as a probe rather than a read, for
exactly this reason. Have the GET read the stored row and have the wizard poll the POST, or
keep the auto-validation and gate it on elapsed time since `rbac_verified_at` so a poll every
five seconds does not mean a provider call every five seconds. Either way, stop
`refetchIntervalInBackground` on a route that costs a provider round trip.

---

### Finding 6 — OpenAPI declares no security scheme

**Severity:** Medium · **Area:** Clarity / developer experience
**Location:** `apps/api/app/main.py:72`; `docs/api/openapi.json`

`components.securitySchemes` is empty, there is no top-level `security`, and no operation
declares one. Seventy-seven of the seventy-nine operations require a bearer token; the
specification says none of them do.

The consequences are ordinary and annoying: a client generated from this spec sends no
`Authorization` header and every call 401s; the Swagger playground shipped by
`scripts/generate_openapi.py` has no Authorize button, so the interactive documentation cannot
be used interactively; and `X-Organization-Id` — the header that selects which tenant a
request acts in, documented at `app/core/deps.py:94` — appears nowhere at all, so a
multi-organization consumer cannot discover it from the spec.

**Fix.** Declare an `HTTPBearer` scheme and apply it globally, exempting the routes listed in
`OPEN_PATHS` / `OPEN_PREFIXES` / `OPEN_SUFFIXES` (`app/core/middleware.py:165`) — that list is
already the authoritative statement of what answers without a token, and is already
cross-checked against the live route table by `tests/unit/test_middleware.py`. Add
`X-Organization-Id` as an optional header parameter, either on the `get_tenant` dependency so
it documents itself, or as a global parameter.

---

### Finding 7 — The RLS transaction is held open across provider HTTP calls

**Severity:** Medium · **Area:** Performance / availability
**Locations:** `apps/api/app/core/db.py:149`, callers in
`apps/api/app/api/routes/cloud_connections.py:306`, `:342`, `:358`, `:470`

`rls_session` wraps the whole request in `session.begin()`. That is the right shape for the
tenancy guarantee — `SET LOCAL ROLE` and the JWT claims are transaction-scoped, which is what
stops them leaking to the next checkout of a pooled connection, and `db.py` explains this well.

It also means any handler that makes an outbound call makes it with a pooled connection
checked out and a transaction open. Four do: `get_connection` (auto-validation), `rediscover`,
`recheck_access`, and `check_revoked`. Each is an Azure round trip, and Azure is neither fast
nor reliably fast.

The pool is `pool_size=10, max_overflow=5` (`db.py:47`). Fifteen concurrent connection-setup
polls against a slow Azure exhaust it, and the endpoints that starve are every other endpoint
in the product — a dashboard that has nothing to do with Azure stops loading because a setup
wizard is waiting on a directory listing.

**Fix.** Commit and release before the provider call, then open a second short transaction to
record the result. The tenancy guarantee is per-transaction and survives the split; what does
not survive is treating the read-then-probe-then-write as atomic, which it already is not,
since the probe is not transactional.

---

### Finding 8 — No error responses documented on any operation

**Severity:** Medium · **Area:** Clarity / developer experience
**Location:** `docs/api/openapi.json`; every route module

Zero of seventy-nine operations declare a 401, 403, 404, 409, 413, 429, 502 or 503. The only
non-2xx in the whole specification is the 422 FastAPI adds.

This is a waste of unusually good work. `app/core/errors.py` defines a taxonomy with stable
codes — `ORGANIZATION_NOT_FOUND`, `SNAPSHOT_UNAVAILABLE`, `CLOUD_CONNECTION_ERROR`,
`NOT_CONFIGURED` — precisely so a client can branch on the code rather than on the prose. A
client reading the specification cannot discover that any of them exist, so it branches on the
prose, and the prose is the thing that is free to change.

**Fix.** Give the router a default `responses={...}` covering 401, 403, 429 and the envelope's
error shape, and add the per-route ones where they carry meaning: 409 on `POST /scans` (a scan
is already running), 409 on `/replay` (the source scan has not finished), 404 on every
`{id}` route, 503 on `GET /reports/{kind}?format=pdf` (WeasyPrint's native libraries are
missing). Model the error body once as a schema and reference it, so the codes are enumerated
in one place a client can read.

---

### Finding 9 — Rate limiting is keyed on address only, and does not tier by cost

**Severity:** Medium · **Area:** Security / resource consumption
**Location:** `apps/api/app/core/middleware.py:262`

The limiter keys on `client_address(scope)`. The address derivation itself is careful — it
counts trusted proxy hops from the right rather than taking the first `X-Forwarded-For` entry,
which is the mistake this would otherwise be. Two gaps remain above it.

**The identity is never used.** By the time a request reaches a handler, `tenant.user.id` and
`tenant.organization_id` are known and verified. The limiter runs before that and so can only
use the address, which means an organization behind one NAT shares one bucket, and one caller
across several addresses gets several.

**Every route shares one ceiling.** `POST /scans` (queues work against a customer's cloud),
`GET /reports/{kind}?format=pdf` (seconds of CPU, per Finding 3), `POST /{id}/discover` and
`POST /{id}/recheck` (provider round trips) are all limited at the same 300/minute as a
dashboard poll. The expensive routes are a small, enumerable set.

Failing open on a Redis outage is documented at `middleware.py:217` and is the right call —
but it does mean this ceiling is the only limit, and it is one number for everything.

**Fix.** Add a second limiter as a dependency, after authentication, keyed on
`(organization_id, route)` with per-route ceilings for the handful of expensive routes. It
does not replace the middleware — that one has to run before authentication to be any use
against an unauthenticated flood — it sits behind it.

---

### Finding 10 — `get_tenant` issues a membership query on every request

**Severity:** Low-Medium · **Area:** Performance
**Location:** `apps/api/app/core/deps.py:94`

Every authenticated request joins `organization_member` to `organization`, ordered, to resolve
which tenant the caller is acting in. The result changes when somebody joins or leaves an
organization, which is rare, and it is recomputed on every call to every endpoint, which is
constant.

The design is right — `organization_id` as the output of authentication rather than an input
to it is the property the whole tenancy model rests on, and `deps.py` says so. Only the
caching is missing.

**Fix.** Cache the resolved memberships per user for a short TTL — the token's remaining
lifetime is a natural bound — and invalidate on the membership writes, which all pass through
`app/services/organizations.py`. RLS re-checks the boundary on every statement regardless, so
a stale cache cannot widen access; it can only briefly show a stale role, which the role-change
path can invalidate directly.

---

### Finding 11 — `GET /dashboard` and `GET /assets` are expensive and polled

**Severity:** Low-Medium · **Area:** Performance
**Locations:** `apps/api/app/services/dashboard.py`, `apps/api/app/api/routes/assets.py:150`,
`apps/web/src/pages/Dashboard.tsx:75`

`build_dashboard` issues roughly 25 sequential database round trips. `Dashboard.tsx:75` polls
it every 20 seconds, per open tab. The trips are sequential because they share one session and
SQLAlchemy's asyncio session is not concurrency-safe, so parallelising them means more
sessions, which means more pooled connections — see Finding 7 for why that pool is already
the constraint.

`GET /assets` issues seven: a total count, an unchecked count, three facet `GROUP BY`s over
the whole filtered set, the page itself, and a graph load. The facets are computed on every
request including every page-turn, where by construction they cannot have changed — the
comment at `assets.py:160` explains correctly why they must be computed over the filtered set
rather than the page, and that reasoning does not require recomputing them per page.

**Fix.** For assets, make the facets opt-in (`?facets=true`) and have the client request them
on the first page only. For the dashboard, the cheaper win is Finding 12: the payload changes
only when a scan completes, and most of those 25 queries are answering a question whose answer
has not moved since the last poll.

---

### Finding 12 — No conditional GET on pollable reads

**Severity:** Low · **Area:** Performance
**Locations:** `apps/api/app/api/routes/dashboard.py`, `findings.py`, `scans.py`

Nothing in the API emits an `ETag` and nothing reads `If-None-Match`. The only cache headers
present are two `no-store`/`no-cache` (`cloud_connections.py:33`, `scans.py:307`), both
correct and both about suppressing caching rather than enabling it.

The dashboard is polled every 20 seconds and its content changes when a scan completes, which
is minutes or hours apart. Every poll in between transfers a full body to produce a screen
identical to the one already on it.

**Fix.** Derive a weak ETag from the newest `completed_at` among the organization's scans plus
the query parameters, and answer 304 when it matches. That is a single cheap query replacing
twenty-five, and it needs no invalidation logic because the timestamp *is* the version.

---

### Finding 13 — `meta.total` means two different things

**Severity:** Low · **Area:** Consistency
**Locations:** `apps/api/app/api/routes/notifications.py:35`, `findings.py:143`,
`scans.py:201`, `cloud_connections.py:298`

`API.md` section 2 fixes the envelope, and `meta` is where pagination lives. Three different
conventions are in use:

- `findings` and `assets` set `total` to the full filtered count — the number a client needs
  to render "showing 100 of 4,312" and to know whether to fetch another page.
- `notifications.py:35` sets `total` to `len(rows)`, the page length. Same key, different
  meaning, and the value is indistinguishable from a small result set.
- `list_scans` and `list_connections` accept a `limit` and return no pagination metadata at
  all, so a client cannot tell a complete list from a truncated one.

**Fix.** Fix `notifications` to report the real count or rename the key to `returned`, and give
every paginated list the same three keys. This pairs naturally with Finding 1 — both are the
list endpoints not sharing a contract they could share — and with Finding 2, where a typed
`Envelope[T]` is the place to put a typed `meta` for paginated responses.

---

### Finding 14 — Request models accept unknown fields silently

**Severity:** Low · **Area:** Robustness
**Location:** `apps/api/app/schemas/`

No request model sets `model_config = ConfigDict(extra="forbid")`. Pydantic's default is to
ignore unrecognised fields, so a client that sends `{"scan_interval_hrs": 6}` to
`PATCH /cloud-connections/{id}/schedule` receives a 200 and a response body showing the
schedule unchanged, with nothing anywhere indicating that the request was misspelled.

This matters most on the PATCH endpoints, where a partial update is legitimately allowed to
omit everything, so "field absent" and "field misspelled" are indistinguishable by design
unless the model rejects the unknown key.

**Fix.** `extra="forbid"` on the request models — `OrganizationUpdate`, `ScheduleUpdate`,
`ScopeSelection`, `ChangeEventsUpdate`, `RemediationUpdate`, `ContextDeclarationIn`,
`CloudConnectionCreate`, `ScanCreate`, the risk status requests. It is a breaking change for
any client currently sending extra keys, which is why it belongs in `v1` now rather than after
there are consumers outside this repository.

---

### Finding 15 — No `servers` block and no stable `operationId`

**Severity:** Low · **Area:** Clarity / developer experience
**Location:** `apps/api/app/main.py:72`; `docs/api/openapi.json`

The specification has no `servers` entry, so a reader cannot tell from the document where the
API is, and the generated playground can only call whatever origin serves it.

Operation ids are FastAPI's defaults, derived from the Python function name plus the path —
`recheck_access_api_v1_cloud_connections__connection_id__recheck_post`. Two consequences:
generated client methods carry that name, and renaming a handler silently renames a method on
every generated client. The `--check` mode in `scripts/generate_openapi.py` would catch the
diff, which is good, but it reports it as a documentation drift rather than as a client break.

**Fix.** Add a `servers` entry built from `settings.api_url`, and set explicit `operation_id`
values on the routes. Both are small; the second is worth doing before anything outside this
repository generates a client.

---

## 3. What was examined and held

Recorded so a later reader knows these were looked at rather than skipped.

**The envelope.** `{"data": ..., "error": null, "meta": {}}` is applied uniformly across all
seventy-nine operations, including from the two raw-ASGI middlewares that refuse requests
before a route is reached (`middleware.py:_refuse`), which is where this kind of consistency
usually breaks. A 413 and a 429 parse exactly like a 200.

**The error taxonomy.** `app/core/errors.py` carries stable codes, correct status mappings, and
a `__str__` override with a real justification — the scan pipeline stores `str(exc)` as
user-facing text, and `HTTPException`'s default rendering would put a status code in it.
`_describable` handles the Pydantic `ctx`-containing-an-exception case, which is a 500 that
most codebases discover in production.

**Unhandled errors inside CORS.** `UnhandledErrorMiddleware` exists because a bare `Exception`
handler becomes `ServerErrorMiddleware`, outside CORS, and the browser then reports a network
failure instead of a 500. The reasoning is documented at the class and the middleware order in
`main.py` is annotated with why it reads backwards. This is correct and unusually well
explained.

**Method semantics.** Sound apart from Finding 5. `PUT /cloud-accounts/{id}/context` replaces
and `PATCH` endpoints merge, and `API.md` explains why the context declaration is a PUT. Action
endpoints (`/rescan`, `/replay`, `/cancel`, `/recheck`) are POSTs, which is the right answer
for operations that are neither safe nor idempotent. `202 Accepted` is used for the three
routes that queue work.

**Route ordering.** Literal paths are declared before parameterised ones in every module where
it matters, each with a comment saying why — `/scans/worker-status`,
`/compliance/{id}/export`, the `cloud-connections` literals.

**Bulk operation bounds.** `BulkRiskStatusRequest.risk_ids` is `min_length=1, max_length=100`
with a comment explaining the per-item write cost. This is the bound Finding 1 is about the
absence of, applied correctly.

**Tenancy.** `X-Organization-Id` is treated as a preference and honoured only when a membership
row backs it, with RLS re-checking independently. Own organizations sort before the demo so the
fallback cannot land a member of both in the sample estate.

**Input validation on identifiers.** The attack-path routes bound their string parameters
(`min_length`, `max_length`) and the enum parameters are typed as enums, so an unknown value is
a 422 rather than a query that silently matches nothing.

**Webhook handling.** `events.py` verifies an HMAC-signed token, answers identically for
malformed, expired and wrong-connection tokens so connection ids cannot be enumerated, and
refuses SNS confirmation URLs whose host the provider does not vouch for. The decision to
answer 200 for events it deliberately drops is explained and correct.

**Report rendering.** Jinja autoescaping is on with a comment explaining that every string in a
report comes from a customer's cloud. The PDF path fetches nothing external. The blocking
problem in Finding 3 is about where it runs, not what it produces.

---

## 4. Suggested order

1. **Finding 1** — bound the page parameters. Removes reachable 500s; the model already exists.
2. **Finding 3** — two calls into a thread pool. Removes event-loop stalls.
3. **Finding 4** — neutralise CSV cells. Contained, and the reader is an auditor.
4. **Findings 2, 6, 8** — response models, security scheme, error responses. One pass over the
   routers; the largest improvement for anyone consuming the API.
5. **Finding 5** — move the probe off the GET, and stop the background polling with it.
6. **Finding 7** — release the connection across provider calls.
7. **Findings 9–15** — hardening and consistency, in whatever order suits the work in flight.

Findings 13 and 14 are breaking changes for existing clients and are cheapest to make now,
while the only consumer is `apps/web`.
