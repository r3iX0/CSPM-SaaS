# Security Review — CloudGuard API setup

**Date:** 20 September 2026
**Scope:** `apps/api` (application setup: configuration, authentication, tenancy, middleware,
error handling, every route module), `apps/web` auth and header configuration, `database/`
RLS migrations, `infrastructure/` (Docker, CI, Vercel) at commit `f7de6b0` (branch
`develop-eh`).
**Method:** Static review against the OWASP API Security Top 10 (2023) and the OWASP Top 10
(2021), following the audit recorded in `SECURITY_AUDIT_2026-09.md`. No live traffic was sent;
no deployed environment was touched.
**Assessed by:** Claude Opus 5, at the request of the repository owner.

---

## 1. Summary

The six findings of the September audit were re-checked against the code and all six are
fixed, not merely described as fixed. What follows is new: eight items, none of them a
remotely exploitable authentication or tenancy defect, and two of which matter because they
silently undo work that audit already did.

The first is a transaction boundary. The consent nonce introduced by that audit is cleared in
memory and committed several provider calls later, so any failure in between rolls the clear
back and leaves the link redeemable — the exact property the nonce exists to remove. The unit
test that asserts otherwise uses an in-memory session fake and cannot observe a rollback.

The second is a configuration split. The security response headers added for finding 4 of
that audit live in `apps/web/vercel.json`; the repository root also carries a `vercel.json`,
it has no `headers` block, and `DEPLOYMENT.md` tells the operator either Root Directory works.
A deployment from the repository root therefore ships the frontend with no CSP, no HSTS and
no framing protection, and nothing fails to announce it.

The rest are hardening: a rate-limit bucket chosen by an unverified header, an unauthenticated
health endpoint exempt from limiting that opens a database connection per call, a container
image running as root with its build toolchain still in it, unquoted substitution into
copy-paste shell commands, and two informational notes.

Multi-tenant isolation, JWT verification, signed-state handling, SSRF and XSS were each
re-examined and each held. Section 4 records what was checked.

| # | Finding | OWASP API | CWE | Severity |
|---|---------|-----------|-----|----------|
| 1 | Consent nonce is not spent when the callback fails after the guard | API2 | CWE-384 | Medium |
| 2 | Root `vercel.json` carries no security headers | API8 | CWE-693 | Medium |
| 3 | Rate-limit bucket is chosen by an unverified `Authorization` header | API4 | CWE-807 | Low-Medium |
| 4 | `/health/ready` is unauthenticated, rate-limit exempt, and opens a connection | API4 | CWE-770 | Low |
| 5 | API image runs as root and retains its build toolchain | API8 | CWE-250 | Low |
| 6 | Fix commands substitute cloud-supplied names without shell quoting | API8 | CWE-78 | Low |
| 7 | SNS confirmation host parsed by string operations; no message signature check | API7 | — | Informational |
| 8 | Access token in `localStorage`; `/health` echoes the environment name | API8 | — | Informational |

---

## 2. Findings

### Finding 1 — The consent nonce is not spent when the callback fails after the guard

**Severity:** Medium · **OWASP API2** Broken Authentication · **CWE-384** Session Fixation (replay)
**Location:** `apps/api/app/services/cloud_connections.py:353` (clear) and `:392` (commit)

`record_consent` verifies the nonce, clears it on the connection row, and only then performs
the work that follows: the tenant-rebind check at `:356`, and the provider calls at `:376-389`
(`ensure_principal`, `grant_problem`, `missing_grants`). The commit is at `:392`.

Every one of those can raise. The rebind check raises `ValidationFailed` by design; the
provider calls reach Entra over the network and can fail for any of the usual reasons. The
caller is `consent_callback`, which wraps the whole thing in `async with service_session()`
and returns a redirect from its `except` block — so the session closes without committing and
PostgreSQL discards the cleared nonce along with everything else in the transaction.

The result is that a consent link survives the callback it was already redeemed against,
until its 30-minute signature expires. The docstring at `:350` states the opposite
intent —

> Spent, whatever happens next. A link that has been followed once is not a link any more, and
> clearing it before the provider calls below means a failure there cannot leave it redeemable.

— and that is the behaviour worth having; it is the transaction boundary that does not deliver
it. The affected window is narrow (the link must already have been issued, and the attacker
must hold it), but it is precisely the replay the nonce was added to close.

`tests/unit/test_consent_binding.py:144` asserts `row.consent_nonce is None` after a refused
rebind and passes, because `_Session` (`:41-58`) is a fake with a `commit()` that sets a
boolean and no rollback of any kind. The test is measuring the in-memory assignment, not the
durable outcome.

**Recommendation.** Spend the nonce in its own committed transaction before any work that can
fail — clear, commit, then proceed — and assert the durable outcome in
`tests/integration/`, where a rollback is observable.

---

### Finding 2 — The repository-root `vercel.json` carries no security headers

**Severity:** Medium · **OWASP API8** Security Misconfiguration · **CWE-693** Protection Mechanism Failure
**Location:** `/vercel.json`, against `apps/web/vercel.json` and `docs/DEPLOYMENT.md:321-323`

`apps/web/vercel.json` defines the frontend's `Content-Security-Policy`,
`Strict-Transport-Security`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`,
`Permissions-Policy` and `Cross-Origin-Opener-Policy`. This is the remediation recorded for
finding 4 of the September audit.

The repository root carries a second `vercel.json` with `installCommand`, `buildCommand`,
`outputDirectory` and `rewrites`, and no `headers` block at all. Vercel reads whichever file
matches the project's Root Directory, and `DEPLOYMENT.md` says so explicitly:

> **Root Directory**: `apps/web` is the cleanest choice, but the repo now carries a
> `vercel.json` at both the root and in `apps/web`, so the build works either way.

The build does work either way. The headers do not. A project configured with an empty Root
Directory — which is what the API and the Railway instructions in the same document ask for,
and therefore the value an operator is most likely to have in mind — deploys a frontend with
no CSP and no HSTS, and the only symptom is the absence of something.

**Recommendation.** Copy the `headers` block into the root `vercel.json` so both paths carry
it, and keep the two in step. Naming one Root Directory in `DEPLOYMENT.md` is the alternative
and is weaker: it fixes the instruction rather than the artifact.

---

### Finding 3 — The rate-limit bucket is chosen by an unverified header

**Severity:** Low-Medium · **OWASP API4** Unrestricted Resource Consumption · **CWE-807** Reliance on Untrusted Input
**Location:** `apps/api/app/core/middleware.py:200`

```python
authenticated = bool(headers.get("authorization"))
limit = self.authenticated_limit if authenticated else self.anonymous_limit
```

The header's presence is the whole test; nothing verifies the token, and the middleware runs
long before anything does. The two ceilings are 300 and 60 requests per minute, so any caller
that attaches `Authorization: Bearer x` to a request receives five times the allowance.

The endpoints this matters for are exactly the three the anonymous ceiling was written for —
the change-event webhook, the ARM template and the consent callback — each of which performs
HMAC verification and a database read or write on every call, and none of which looks at the
`Authorization` header at all.

The cost is bounded (a factor of five on a limit that is deliberately generous, and the limit
is per client address), which is why this is not higher. It is still a control whose stated
reasoning — "the unauthenticated surface is the webhook, the ARM template and the consent
callback" — does not hold against a caller who reads the code.

**Recommendation.** Decide the bucket from the path for the routes that are unauthenticated by
design, or resolve the bucket after verification and key the authenticated one on the token's
`sub` rather than on the address.

---

### Finding 4 — `/health/ready` is unauthenticated, exempt from limiting, and opens a connection

**Severity:** Low · **OWASP API4** Unrestricted Resource Consumption · **CWE-770** Allocation Without Limits
**Location:** `apps/api/app/core/middleware.py:179,195`; `apps/api/app/main.py` (`ready`)

`RateLimitMiddleware` exempts every path under `/health`, for the good reason that the
platform's probe runs on a schedule the limit would otherwise throttle. `GET /health/ready`
calls `ping()`, which opens a connection on the app engine — a pool of 10 with 5 overflow.

The September audit named this endpoint in its finding 5 table ("Opens a database
connection"), and the remediation made it exempt rather than limited, so the item is carried
rather than closed. Unauthenticated, unlimited, one connection checkout per request, against a
pool the request path shares.

**Recommendation.** Exempt `/health` alone and let `/health/ready` be limited, or cache the
readiness answer for a few seconds so repeated calls do not each reach PostgreSQL. Either
keeps the platform probe working.

---

### Finding 5 — The API image runs as root and retains its build toolchain

**Severity:** Low · **OWASP API8** Security Misconfiguration · **CWE-250** Execution With Unnecessary Privileges
**Location:** `infrastructure/docker/api.Dockerfile`

No `USER` instruction, so uvicorn and the Celery worker run as uid 0. `build-essential` and
`curl` are installed in the same layer as WeasyPrint's runtime libraries and are never
removed, and the build is single-stage, so a compiler toolchain ships in the deployed image.

Neither is exploitable on its own. Both are the difference between a container escape being
one step harder or one step easier, in a product whose whole subject is that distinction.

**Recommendation.** Add a non-root system user and `USER` before `CMD`; either split the build
into stages or drop `build-essential` and `curl` after `pip install`. Neither change affects
the runtime.

---

### Finding 6 — Fix commands substitute cloud-supplied names without quoting

**Severity:** Low · **OWASP API8** Security Misconfiguration · **CWE-78** OS Command Injection (downstream)
**Location:** `apps/web/src/lib/remediationFill.ts:35-68`

`placeholderValues` takes the resource's name, region, subscription id and resource group —
all of them strings that came back from the customer's own cloud — and `fillPlaceholders`
substitutes them into the rule's CLI string with a plain `String.replace`. The result is
displayed for the user to copy into a shell.

CloudGuard never executes it, and the resource-name charsets Azure enforces make a useful
payload hard to construct. But the value crossing that boundary is provider-controlled text,
the destination is a shell, and the amount of quoting applied is none.

**Recommendation.** Wrap each substituted value in single quotes and escape any embedded
quote, so a name can only ever be an argument.

---

### Finding 7 — SNS confirmation URL parsing and message signatures

**Severity:** Informational · **OWASP API7** SSRF
**Location:** `apps/api/app/connectors/aws/change_events.py:96-109`

The allowlist itself is right and the fetch is not redirect-following, so this is not a
finding against behaviour. Two observations:

The host is extracted with `removeprefix` and two `split` calls rather than with a URL parser.
Userinfo, port and fragment forms all fail the `fullmatch` today, so the check holds — but it
holds because the regex is strict, not because the parse is correct, and a later relaxation of
the regex would be evaluated against a hand-rolled parse.

Separately, no SNS message signature (`SigningCertURL` / `Signature`) is verified. The
connection token is the only thing standing behind a delivery. AWS has never been run live
(CLAUDE.md), so this belongs on the `AWS_INTEGRATION.md` §1 checklist rather than in the
backlog.

---

### Finding 8 — Two accepted properties, recorded

**Severity:** Informational

The Supabase access token is kept in `localStorage` (`apps/web/src/lib/api.ts:59`), so any XSS
in the frontend reads it. This is the ordinary SPA trade-off and the CSP is the control that
stands behind it; it is recorded because it is a decision, not an oversight.

`GET /health` returns `app_env` to an unauthenticated caller. One word about the deployment,
and unlikely to matter, but it is disclosure.

---

## 3. Areas examined that held

Re-checked at this commit rather than taken from the earlier audit.

**Authentication.** `core/security.py` reads the header's `alg`, refuses anything outside
`ES256/RS256/HS256` including `none`, resolves a key appropriate to that algorithm, and then
pins `jwt.decode(algorithms=[...])` to that one algorithm. Audience is checked; `sub` and
`exp` are required. No fallback path produces a user on failure.

**Multi-tenancy.** Every table declared in `apps/api/app/models` has row-level security
enabled with both a member arm (`app.is_member(organization_id)`) and a worker arm
(`app.current_org() = organization_id`). This was verified table by table against the
migrations, including the tables created after the earlier audit — `asset_change_events` and
`finding_events` via `_secure()` in `0018_temporal_model`, the three notification tables via
`0025` and `0030`. `organization_id` is derived from a membership lookup in `core/deps.py`;
`X-Organization-Id` is honoured only when a membership row backs it. `rls_session` sets the
claims and role with `SET LOCAL`, so they die with the transaction rather than leaking to the
next checkout of a pooled connection.

**Route inventory.** Enumerated from the live FastAPI app: five routes resolve without an
authentication dependency, and they are the four documented as necessarily unauthenticated
(`/health`, `/health/ready`, the ARM template, the consent callback, the change-event webhook)
plus `GET /api/v1/cloud-accounts/azure/permissions`, which returns a static list of the
permissions CloudGuard will ask for. Every other route carries `Tenant`, and every mutating
one calls `require_role` or `require_write`, both of which refuse the demo organization by
flag as well as by role.

**Signed state.** `core/signing.py` stamps a `purpose` on signing and demands it on
verification, as keyword arguments with no default, so a token issued for the webhook cannot
be presented to the callback. The MAC comparison is `hmac.compare_digest`; signature is
checked before the payload is decoded, and age after.

**Injection.** No dynamic SQL. The `text()` call sites in `core/db.py` are literal strings with
bound parameters. No `eval`, `exec`, `subprocess` or `shell=True` in the application package.

**XSS and report rendering.** Jinja autoescaping with `default_for_string=True`; the three
`| safe` filters take the inline stylesheet and SVG built from integers bounded to 0-100.
WeasyPrint fetches nothing — the stylesheet is inline — so a resource name cannot cause an
outbound request. The API's own CSP (`default-src 'none'`) applies to the HTML report it
serves.

**Error handling.** `UnhandledErrorMiddleware` sits inside CORS so a 500 is readable by the
browser, logs the traceback server-side, and returns a sentence carrying no exception detail.
The validation handler stringifies exception objects in `ctx` so a 422 cannot itself raise.

**Supply chain.** `pip-audit --strict` and `npm audit --audit-level=high` run as their own CI
job; `.github/dependabot.yml` covers pip, npm, GitHub Actions and Docker. The 18 advisories
passed to `--ignore-vuln` match the four packages documented in `SECURITY_AUDIT_2026-09.md`
§6 exactly (starlette 7, cryptography 7, weasyprint 3, pytest 1) — the list has not drifted
into a dumping ground. PyJWT is at 2.13.0 and python-multipart at 0.0.31, as that remediation
states.

**Configuration.** `Settings.raise_if_misconfigured` fails the boot on a missing or
localhost-valued variable, and `app_env` defaults to `production` so a forgotten value fails
closed. CI refuses a real password in `infrastructure/supabase/roles.sql`.

---

## 4. Remediation

All eight were addressed on branch `develop-eh` immediately following this review. The
reasoning is recorded in `docs/DECISIONS.md` §126.

**Finding 1 — the nonce.** Verifying, clearing and committing the nonce moved into
`_spend_consent_nonce`, which runs before the tenant-rebind check and before any directory
call, so the spend survives whatever fails afterwards. The guard stays in front of that
commit: a wrong nonce still writes nothing, or anyone able to reach the callback could burn a
link they had never seen. The session fake in `tests/unit/test_consent_binding.py` now records
the row's state at each commit rather than only at the end — an assignment that is rolled back
is not a spend — and `tests/integration/test_consent_nonce.py` asks the same question of a
real transaction: after the callback has failed, what does a fresh session see in the column?

**Finding 2 — the headers.** The root `vercel.json` carries the same `headers` block as
`apps/web/vercel.json`, so the deployment is identical whichever Root Directory the Vercel
project uses. `infrastructure/ci/check-deployment-headers.mjs` compares the two and fails the
build if either drops a header or they stop matching; it runs as a step in CI's `web` job and
can be run directly with `node`.

**Finding 3 — the bucket.** `OPEN_PATHS`, `OPEN_PREFIXES` and `OPEN_SUFFIXES` in
`app/core/middleware.py` name the routes served without a token, and a request to one of them
is counted as anonymous however it is dressed. The list is literal because the middleware is
constructed before the router is mounted, so `tests/unit/test_middleware.py` cross-checks it
against the live application's route table: a new route that skips authentication fails there
rather than quietly inheriting the larger ceiling.

**Finding 4 — the exemption.** `exempt_prefixes` became `exempt_paths`, matched exactly, so
`/health/ready` is limited like anything else while Railway's probe on `/health` is not. Paths
are normalised first, so a trailing slash is not a second path.

**Finding 5 — the image.** A system user (`uid 10001`) owns the process, and the tree stays
root-owned and read-only to it, so a foothold cannot overwrite the code it is running.
`build-essential` is installed, used and purged inside the dependency layer; `curl` is gone.

**Finding 6 — the quoting.** `fillPlaceholders` substitutes a value bare only when it is
unambiguously one shell word, single-quotes it when it is not, and leaves the placeholder in
place when the rule already put it inside quotes — where quoting would nest quotes and produce
a command that is wrong rather than dangerous. Tests cover a name carrying a semicolon, a name
carrying a single quote, and the quoted-JSON position.

**Finding 7 — the URL.** `confirmation_url` parses with `urlsplit` and refuses userinfo, a
port, a non-`https` scheme or a host outside the SNS pattern, so a credentialed form is
refused as what it is rather than by happening to miss a strict regex. Message-signature
verification cannot be written against an event nobody has received, so it is item 19 on
`docs/AWS_INTEGRATION.md` §1's checklist.

**Finding 8 — the two accepted properties.** `/health` no longer names the environment. The
token stays in `localStorage`: moving it would mean cookie-backed sessions, which Supabase's
browser client does not issue here, and the CSP is the control that stands behind it. Recorded
as a decision rather than silently left.

---

## 5. Disposition

| # | Finding | Status |
|---|---------|--------|
| 1 | Consent nonce not spent when the callback fails after the guard | Fixed |
| 2 | Root `vercel.json` carries no security headers | Fixed |
| 3 | Rate-limit bucket chosen by an unverified header | Fixed |
| 4 | `/health/ready` unauthenticated, exempt, opens a connection | Fixed |
| 5 | API image runs as root with its build toolchain | Fixed |
| 6 | Fix commands substitute cloud names without quoting | Fixed |
| 7 | SNS URL parsing hardened; signature verification carried to `AWS_INTEGRATION.md` §1 item 19 | Fixed / carried |
| 8 | `/health` no longer names the environment; `localStorage` accepted | Fixed / accepted |

Tests were added or updated with the fixes: `tests/unit/test_middleware.py` covers the bucket
decision, the exact-match exemption and the route-table cross-check;
`tests/unit/test_consent_binding.py` and `tests/integration/test_consent_nonce.py` cover the
durable spend; `tests/unit/test_aws_change_events.py` covers the credentialed and ported URL
forms; and `src/lib/__tests__/remediationFill.test.ts` covers the quoting.

**What was verified where.** The API's 1,881 unit tests, `ruff` and `mypy` pass locally, as do
the frontend's 494 vitest tests, its typecheck and the header check. The integration tests —
including the new one — need a live PostgreSQL and were not run here: this machine has the
`libpq` client tools and no server, and no container runtime. They run in CI. The Docker
image was likewise not built locally for the same reason, so finding 5's change is reviewed
rather than executed.
