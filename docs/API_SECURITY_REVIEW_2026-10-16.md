# API & Security Best-Practices Review — CloudGuard

**Date:** 16 October 2026 **Scope:** `apps/api/app/` (FastAPI setup, middleware stack,
authentication, RBAC, PostgreSQL RLS, outbound SSRF controls, rate limiting, and all route modules
under `app/api/routes/`) and `apps/web/src/lib/` (API client, auth/tenant storage, and TanStack
Query cache lifecycle) on branch `refactor/provider-adapter`. **Method:** Static security and API
design review against the OWASP API Security Top 10 (2023), OWASP Top 10 (2021), and
`docs/API_GUIDELINES.md`. **Companion reviews:**
[`ARCHITECTURE_DEEPENING_REVIEW_2026-10-16.html`](ARCHITECTURE_DEEPENING_REVIEW_2026-10-16.html),
[`SECURITY_REVIEW_2026-09-20.md`](SECURITY_REVIEW_2026-09-20.md),
[`API_REVIEW_2026-09-20.md`](API_REVIEW_2026-09-20.md).

---

## 1. Executive Summary & Verified Security Controls

All major findings from the September 2026 API and security reviews (`SECURITY_REVIEW_2026-09-20.md`
and `API_REVIEW_2026-09-20.md`) were re-verified against the current codebase and remain intact:

- **JWT & OIDC Authentication (`apps/api/app/core/security.py`)**:
  - `verify_access_token` (`security.py:220-315`) enforces algorithm pinning (`ES256`/`RS256` when
    `supabase_jwks_url` is configured, or `HS256` in local development), rejects `alg: none` and
    algorithm confusion, and validates `aud`, `iss`, `exp`, and `sub` claims.
  - `CurrentUser` (`security.py:46-70`) carries `aal` (`aal1`/`aal2`) and `guest` (`is_anonymous`)
    directly from verified JWT claims.
  - `Settings._validate_production_secrets` (`config.py:84-154`) refuses startup outside
    `local`/`test` if default secrets, `auth_dev_bypass`, missing
    `supabase_issuer`/`supabase_jwks_url`, or missing `fernet_key` are present.
- **Tenant Isolation, RBAC, MFA & PostgreSQL RLS (`apps/api/app/core/deps.py`,
  `apps/api/app/db/session.py`)**:
  - `get_tenant_context` (`deps.py:94-162`) resolves organization membership from the database,
    validates `X-Organization-Id` against real membership (raising `404 NotFound` on non-membership
    to prevent cross-tenant enumeration), enforces `organization.require_mfa` (`aal2` check), and
    blocks anonymous guest sessions on mutating methods (`POST`, `PUT`, `PATCH`, `DELETE`) when real
    cloud accounts exist.
  - `get_db_session` (`deps.py:64-81`) and `rls_session` (`db/session.py:51-82`) execute
    `SET LOCAL role = 'authenticated'` and populate `request.jwt.claims` on every transaction so
    PostgreSQL Row-Level Security (RLS) acts as a second, database-enforced tenant boundary.
  - Explicit role hierarchy (`Viewer` $\le$ `Editor` $\le$ `Approver` $\le$ `Admin`) is enforced via
    `require_role` (`deps.py:204-214`).
- **Outbound SSRF & DNS-Rebinding Protection (`apps/api/app/core/outbound.py`)**:
  - Customer-supplied webhook URLs are validated by `check_webhook_url` (`outbound.py:72-108`) and
    connected via `PinnedResolverBackend` (`outbound.py:126-157`) with `follow_redirects=False` and
    `trust_env=False`, preventing DNS rebinding, private IP/IMDS (`169.254.169.254`) access,
    redirect chains, and ambient proxy variable leakage.
- **Transport, Headers, Request Size & Rate Limiting (`apps/api/app/main.py`,
  `apps/api/app/core/rate_limit.py`)**:
  - `BodySizeLimitMiddleware` (`main.py:73-109`) enforces a streaming 2 MiB ceiling on request
    bodies regardless of whether `Content-Length` is omitted or spoofed.
  - `SecurityHeadersMiddleware` (`main.py:112-133`) sets
    `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`,
    `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`,
    `Cross-Origin-Resource-Policy: same-origin`, `Permissions-Policy`, and
    `Strict-Transport-Security`.
  - Dual-layer sliding-window rate limiting: per-IP in `RateLimitMiddleware`
    (`rate_limit.py:130-185`, trusting `X-Forwarded-For` only when `trust_proxy_headers=True`) and
    per-authenticated-user in `limit_user` (`rate_limit.py:223-250`) and `Costly` (`deps.py:227`,
    `20/min`).
  - OpenAPI/Swagger/ReDoc endpoints are disabled outside `local`/`dev` (`openapi_url=None` in
    `main.py:244-253`).

---

## 2. Findings Fixed on 16 October 2026

| #   | Finding                                                                                                                                                                         | OWASP API | Area                          | Status    |
| --- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- | ----------------------------- | --------- |
| 1   | `GET /scans/worker-status` blocked the asyncio event loop for 1.0s and lacked `Costly` rate limiting                                                                            | API4:2023 | DoS / Concurrency             | **Fixed** |
| 2   | `GET /scans/{scan_id}/events` SSE stream omitted `email` and `guest` in `rls_session` JWT claims                                                                                | API1/API5 | RLS Consistency               | **Fixed** |
| 3   | Compliance CSV export did not neutralize spreadsheet formula triggers (`=`, `+`, `-`, `@`, `\t`, `\r`) and `_attachment` raised `500 UnicodeEncodeError` on non-ASCII org names | API8:2023 | Injection / Robustness        | **Fixed** |
| 4   | Outbound `httpx.AsyncClient` calls in AWS SNS handshake and GitHub integration did not set `follow_redirects=False, trust_env=False`                                            | API7:2023 | SSRF / Egress                 | **Fixed** |
| 5   | String filter and `ILIKE` search query parameters on `/findings`, `/assets`, and `/risks` had no `max_length` bounds                                                            | API4:2023 | Input Validation              | **Fixed** |
| 6   | Frontend `fetchDocument` omitted `MFA_REQUIRED` event dispatch, and `QueryClient` did not auto-clear cache on 401 sign-out or tenant switch                                     | API2/API1 | Client Auth & Cache Isolation | **Fixed** |

### 2.1 Event-Loop Blocking & Rate Limiting on `GET /api/v1/scans/worker-status`

- **Location:** `apps/api/app/api/routes/scans.py:51-68`
- **Problem:** `worker_status` called `celery_app.control.ping(timeout=1.0)` synchronously on the
  main asyncio event loop and was not gated by `Costly`. When no Celery worker answered, each
  request stalled the entire FastAPI event loop for 1 second.
- **Fix Applied:** Added `dependencies=[Costly]` (`20/min` per user) and wrapped the broker ping in
  `await asyncio.to_thread(celery_app.control.ping, timeout=1.0)`.

### 2.2 Complete RLS JWT Claims in SSE `scan_events`

- **Location:** `apps/api/app/api/routes/scans.py:316-320`
- **Problem:** `scan_events` opened `rls_session(user.id)` without `user.email` or
  `guest=user.guest`, diverging from `get_db_session` (`deps.py:72`).
- **Fix Applied:** Updated `scan_events` to call
  `rls_session(user.id, user.email, guest=user.guest)`.

### 2.3 CSV Formula Injection & RFC 6266 `Content-Disposition` in Compliance Export

- **Locations:** `apps/api/app/compliance/export.py:194-212`,
  `apps/api/app/api/routes/compliance.py:61-100`
- **Problem:**
  1. `to_csv()` in `app/compliance/export.py` did not prefix cells starting with `=`, `+`, `-`, `@`,
     `\t`, or `\r` with a leading apostrophe `'`, unlike `app/compliance/archive.py:54`. Provider
     error text in `inconclusive_reasons` could therefore execute as a formula when opened in Excel.
  2. `_attachment()` in `app/api/routes/compliance.py` placed `export_filename(organization, ...)`
     directly into `Content-Disposition`. Non-ASCII letters in an organization name (e.g. `"Łódź"`)
     caused Starlette's Latin-1 header encoding to fail with `500 UnicodeEncodeError`.
  3. `GET /api/v1/compliance/{framework_id}/export` lacked `dependencies=[Costly]`.
- **Fix Applied:**
  - Added `_FORMULA_TRIGGERS` and `_cell()` escaping in `app/compliance/export.py:to_csv`.
  - Updated `_attachment()` in `app/api/routes/compliance.py` to emit both an ASCII fallback
    `filename` and RFC 6266 `filename*=UTF-8''...`.
  - Added `dependencies=[Costly]` to `export_framework`.
  - Added unit tests in `apps/api/tests/unit/test_compliance_export.py:208-229`.

### 2.4 Explicit Outbound `httpx.AsyncClient` Hardening

- **Locations:** `apps/api/app/api/routes/events.py:254-263`,
  `apps/api/app/integrations/github.py:84-163`
- **Problem:** `httpx.AsyncClient` instances in `events.py:_handshake` and `integrations/github.py`
  (`_request`, `user_token`) did not pass `follow_redirects=False, trust_env=False`.
- **Fix Applied:** Explicitly configured `follow_redirects=False, trust_env=False` on all three
  `httpx.AsyncClient` call sites.

### 2.5 Query Parameter `max_length` Bounds on List & Search Endpoints

- **Locations:** `apps/api/app/api/routes/findings.py:60-66`,
  `apps/api/app/api/routes/assets.py:34-39`, `apps/api/app/api/routes/risks.py:57`
- **Problem:** Query string parameters (`search`, `rule_id`, `environment`, `resource_type`,
  `subscription_id`, `resource_group`, `region`) accepted arbitrary-length strings before running
  SQL `ILIKE` queries.
- **Fix Applied:** Bounded all string filter parameters with
  `Annotated[str | None, Query(max_length=...)] = None` (`256` for `search`, `128` for
  environment/resource/subscription/group, `64` for `rule_id` and `region`).

### 2.6 Frontend `MFA_REQUIRED` Handling on Document Downloads & Automatic Query Cache Isolation

- **Locations:** `apps/web/src/lib/api.ts:235-236`, `apps/web/src/lib/queryClient.ts:50-71`
- **Problem:**
  1. `fetchDocument` in `api.ts` did not dispatch `SECOND_FACTOR_REQUIRED_EVENT` when a
     report/archive download returned `403 MFA_REQUIRED`.
  2. `createQueryClient` did not subscribe to `auth` state changes, leaving cached queries in memory
     if a `401` cleared the token or if `organizationId` changed outside `OrganizationSwitcher`.
- **Fix Applied:**
  - Dispatched `SECOND_FACTOR_REQUIRED_EVENT` in `fetchDocument` on `error.code === "MFA_REQUIRED"`.
  - Subscribed `createQueryClient` to `subscribeToAuth` so `client.clear()` runs whenever
    `auth.token` is cleared or `auth.organizationId` changes.
  - Added unit tests in `apps/web/src/lib/__tests__/api.test.ts:180-206` and
    `apps/web/src/lib/__tests__/queryClient.test.ts:34-57`.

---

## 3. Backlog — Items to Work On Later

The following items require deeper architectural changes or external infrastructure coordination and
are tracked here for future sessions:

### Priority 1 — Security & Cryptographic Hardening

1. **Verify AWS SNS X.509 Message Signatures on `POST /api/v1/events/aws`**
   - **Location:** `apps/api/app/api/routes/events.py:168-251`
   - **Current state:** `aws_events` authenticates the URL via the per-account HMAC query token
     (`verify_event_token(account_id, token)`) and validates the `SubscribeURL` hostname
     (`sns.<region>.amazonaws.com`), which already blocks unauthenticated spoofing. However, it does
     not verify the AWS SNS message's `Signature` / `SigningCertURL` X.509 signature.
   - **Next step:** Validate the SNS message signature against the AWS regional SNS signing
     certificate (ensuring `SigningCertURL` matches
     `https://sns.<region>.amazonaws.com/SimpleNotificationService-*.pem`) as defense-in-depth in
     case a webhook token is ever leaked in logs.

2. **Consolidate Security & Crypto Primitives into `app/core/security/` (`SecurityBoundary`)**
   - **Locations:** `apps/api/app/core/security.py`, `apps/api/app/core/crypto.py`,
     `apps/api/app/core/state.py`, `apps/api/app/core/outbound.py`,
     `apps/api/app/api/routes/events.py:92-121`
   - **Current state:** Token verification (`security.py`), Fernet encryption (`crypto.py`), HMAC
     state tokens (`state.py`), route-local HMAC event tokens (`events.py:92-121`), and SSRF socket
     pinning (`outbound.py`) are spread across 5 files; `events.py` implements its own ad-hoc HMAC
     signing using `jwt_secret_key` instead of `core/state.py`.
   - **Next step:** Unify HMAC token signing with explicit domain-separation prefixes (`purpose`)
     and constant-time comparison inside `app/core/security/`, and expose a single
     `SecurityBoundary` facade (see Candidate 03 in
     [`ARCHITECTURE_DEEPENING_REVIEW_2026-10-16.html`](ARCHITECTURE_DEEPENING_REVIEW_2026-10-16.html)).

3. **Move Browser Session Tokens from `localStorage` to `HttpOnly` Cookies or Short-Lived In-Memory
   Access Tokens**
   - **Location:** `apps/web/src/lib/api.ts:66-100`
   - **Current state:** Access tokens are persisted in `localStorage` (`cloudguard.token`). While
     CSP and strict output escaping mitigate XSS, any script execution in the origin can read
     `localStorage`.
   - **Next step:** Keep the short-lived access token in JavaScript memory only and rely on
     Supabase's refresh flow or an `HttpOnly; Secure; SameSite=Lax` cookie proxy when moving to
     production multi-tab session management.

---

### Priority 2 — Rate Limiting, Resilience & Scalability

1. **Redis-Backed Distributed Rate Limiting for Multi-Worker Production**
   - **Location:** `apps/api/app/core/rate_limit.py:42-119`
   - **Current state:** `_Window` stores sliding-window timestamps in process memory
     (`dict[str, deque[float]]`). With multiple Uvicorn workers or replicas, a client's effective
     allowance is multiplied by the number of workers, and each worker independently tracks up to
     `50,000` keys.
   - **Next step:** Add a Redis-backed sliding-window implementation (using the existing
     `settings.redis_url` connection with a Lua script / `ZREMRANGEBYSCORE` + `ZADD` + `ZCARD`) with
     automatic fallback to the in-memory `_Window` when Redis is unavailable or in unit tests.

2. **Dedicated Lightweight Rate Limit on `GET /api/v1/health/ready`**
   - **Location:** `apps/api/app/api/routes/health.py:21-29`, `apps/api/app/core/rate_limit.py:28`
   - **Current state:** `/api/v1/health/ready` is exempt from `RateLimitMiddleware` (`EXEMPT_PATHS`)
     and executes `SELECT 1` against PostgreSQL on every call.
   - **Next step:** Either cache the readiness probe result for `1–2 seconds` in memory
     (`monotonic()` TTL) so a burst of unauthenticated requests can never open more than 1 DB
     connection per second, or restrict `/api/v1/health/ready` to internal ingress / apply a
     generous per-IP bucket.

3. **Release DB Transactions Before Long Outbound Provider Calls**
   - **Locations:** `apps/api/app/services/cloud_connections.py`,
     `apps/api/app/api/routes/cloud_accounts.py`, `apps/api/app/api/routes/remediation.py`
   - **Current state:** Several endpoints hold an open `DbSession` (with `SET LOCAL` RLS transaction
     state) while making outbound HTTP calls to Azure ARM / Microsoft Graph / AWS STS / GitHub API.
     Under slow provider responses, PgBouncer/SQLAlchemy pool connections remain checked out for the
     duration of the network round-trip.
   - **Next step:** Split long-running provider interactions into a three-phase pattern: (1) read
     connection config & commit/close DB transaction, (2) perform outbound provider I/O outside the
     DB session, (3) persist results in a fresh short-lived transaction.

---

### Priority 3 — API Contract, Pagination & Performance

1. **Keyset (Cursor) Pagination & Single-Query `COUNT(*) OVER()` on High-Volume List Endpoints**
   - **Locations:** `apps/api/app/services/findings.py`, `apps/api/app/services/assets.py`,
     `apps/api/app/services/changes.py`
   - **Current state:** List endpoints run separate `SELECT count(*)` and `OFFSET/LIMIT` queries
     (and `findings` runs 3 separate count/facet queries per page load). Deep `offset` values
     degrade linearly in PostgreSQL.
   - **Next step:** Bound `offset` (e.g., `le=10_000`) or introduce an opaque `cursor` parameter for
     keyset pagination, and consolidate total/confidence counts into a single CTE pass (see
     Candidate 04 in
     [`ARCHITECTURE_DEEPENING_REVIEW_2026-10-16.html`](ARCHITECTURE_DEEPENING_REVIEW_2026-10-16.html)).

2. **Automated OpenAPI $\rightarrow$ TypeScript Schema Generation (`openapi-typescript`)**
   - **Locations:** `docs/api/openapi.json`, `apps/web/src/types/api.ts`
   - **Current state:** Backend Pydantic `*Out` schemas and frontend `apps/web/src/types/api.ts`
     interfaces are maintained by hand and can drift silently.
   - **Next step:** Wire a CI check and `npm run generate:types` script that exports FastAPI's
     OpenAPI schema to `docs/api/openapi.json` and generates `apps/web/src/types/openapi.d.ts` (see
     Candidate 07 in
     [`ARCHITECTURE_DEEPENING_REVIEW_2026-10-16.html`](ARCHITECTURE_DEEPENING_REVIEW_2026-10-16.html)).
