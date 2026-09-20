# Security Audit — CloudGuard API and Web

**Date:** 20 September 2026
**Scope:** `apps/api`, `apps/web`, `database/`, `infrastructure/` at commit `f245f1c` (branch `develop-eh`)
**Method:** Static review against the OWASP Top 10 (2021). No live traffic was sent; no deployed environment was touched.
**Assessed by:** Claude Opus 5, at the request of the repository owner.

---

## 1. Summary

Six findings, three of which are the same flow and must be fixed together. The three are an
authorization gap in the Azure admin-consent callback: it is an unauthenticated,
state-changing endpoint whose only guard — the HMAC-signed `state` — is handed to every
member of the organization on an ordinary read, carries no `purpose` discriminator, and is
accompanied by a tenant identifier that is written to the database without being verified.

The remaining three are hardening gaps rather than exploitable defects: no security response
headers, no inbound rate limiting, and no dependency or static-analysis scanning in CI.

Nothing was found in the categories where this class of application most often fails.
Injection, multi-tenant isolation, cryptographic handling, SSRF and XSS were each examined
and each held. Section 4 records what was checked and why it passed, because a finding list
without that context reads as a verdict on the whole codebase rather than on six specific
things.

| # | Finding | OWASP | CWE | Severity |
|---|---------|-------|-----|----------|
| 1 | Consent callback mutates state with no authentication or role check | A01 | CWE-862 | High |
| 2 | `tenant` query parameter is written to the database unverified | A01 | CWE-807 | High |
| 3 | Consent state carries no `purpose`; callback checks none | A01 | CWE-345 | Medium |
| 4 | No security response headers on API or frontend | A05 | CWE-693 | Medium |
| 5 | No inbound rate limiting and no request body size cap | A04 | CWE-770 | Medium |
| 6 | No dependency scanning in CI; 31 advisories in the pinned set | A06 | CWE-1104 | High |

---

## 2. Findings

### Finding 1 — Consent callback mutates connection state with no authentication and no role check

**Severity:** High · **OWASP:** A01 Broken Access Control · **CWE-862** Missing Authorization
**Location:** `apps/api/app/api/routes/cloud_connections.py:223` (`consent_callback`)

`GET /api/v1/cloud-connections/azure/consent/callback` is unauthenticated, and necessarily
so: the caller is a customer's browser mid-redirect from Microsoft, carrying no CloudGuard
session. The only thing standing in for authorization is the HMAC-signed `state` parameter.

That state is not a secret held by the person who may act. `get_connection`
(`cloud_connections.py:291`) depends on `Tenant` alone — any role, including `VIEWER` — and
`_serialize` regenerates a fresh consent URL on every single read:

```python
if connection.consent_status != ConsentStatus.GRANTED:
    fresh, problem = service.grant_start_url(connection)
    consent_url = consent_url or fresh
```

So a `VIEWER`, who is refused every write by `require_write()` and every privileged action by
`require_role(Role.OWNER, Role.ADMIN)`, reads the connection, lifts `state` from the JSON, and
calls the callback directly. The callback reaches `record_consent`
(`apps/api/app/services/cloud_connections.py:282`) on a `service_session()` — the owner
connection, which bypasses RLS entirely — and writes `consent_status = GRANTED`,
`consented_at`, `tenant_id`, `service_principal_object_id` and `missing_permissions`.

**Impact.** A read-only member performs an action reserved for owners and administrators.
Separately, anyone who obtains the URL within its 30-minute window — browser history, a
`Referer` header, a screenshot, a pasted support ticket — can do the same without any
CloudGuard account at all.

**Recommendation.** Mint the consent URL only for roles permitted to complete onboarding, and
make the state single-use so that a link which has already been redeemed cannot be redeemed
again.

---

### Finding 2 — The `tenant` query parameter is trusted and written to the database

**Severity:** High · **OWASP:** A01 Broken Access Control · **CWE-807** Reliance on Untrusted Inputs in a Security Decision
**Location:** `apps/api/app/api/routes/cloud_connections.py:264`, `apps/api/app/services/cloud_connections.py:282`

The callback passes the raw `tenant` query parameter into `record_consent`:

```python
async with service_session() as session:
    await service.record_consent(session, connection_id, tenant)
```

`tenant` is unsigned and unverified. It is not part of the HMAC-protected `state`, and no
token issued by Microsoft is exchanged or validated at any point in this flow — the Entra
admin-consent endpoint redirects back with `tenant` and `admin_consent` as plain query
parameters, and both are taken at face value.

`record_consent` states the opposite as an invariant in its own docstring:

> `tenant_id` arrives from the provider, not from the customer, and this is the whole
> tenant-binding guarantee: when it came from a request body, any user could name an
> organization somebody else had already consented for and validate against their environment.

As implemented, `tenant_id` arrives from whoever constructs the URL. The write is
unconditional apart from emptiness:

```python
connection.tenant_id = tenant_id or connection.tenant_id
```

so any non-empty value replaces an existing binding.

**Impact.** An attacker holding a `state` (see Finding 1 for how easily one is obtained) can
point a victim organization's connection at an Entra directory under their own control.
Everything downstream then addresses that directory: `ensure_principal`, `grant_problem`,
`missing_grants`, and every subsequent collection run through `TokenProvider(tenant_id)`.
The result is a security product reporting on an estate that is not the customer's, under the
customer's own organization.

**Recommendation.** Treat the first successful consent as the binding event and refuse to
re-bind afterwards. Do not silently overwrite a tenant that has already been established.

---

### Finding 3 — Consent state carries no `purpose`, and the callback checks none

**Severity:** Medium · **OWASP:** A01 Broken Access Control · **CWE-345** Insufficient Verification of Data Authenticity
**Location:** `apps/api/app/connectors/azure/onboarding.py:109`, `apps/api/app/api/routes/cloud_connections.py:246`

Three separate round trips are authenticated by tokens minted from one secret through
`app/core/signing.py`. The module documents exactly what keeps them apart:

> `purpose` is not enforced here on purpose. Every caller checks its own, and it must: the
> tokens are signed with one secret, so a template token and a webhook token differ *only* by
> that field, and a caller that verified the signature and skipped the purpose would accept
> the other one.

Two of the three callers honour that. The ARM template endpoint checks
`payload.get("purpose") != "template"`; the change-event webhook checks
`payload.get("purpose") != "event_grid"`. The consent flow does neither: `start_url` mints
`{cloud_connection_id, organization_id, issued_at}` with no `purpose` at all, and the callback
calls bare `verify_state(state)`.

Both other token kinds carry `cloud_connection_id` and `issued_at` and therefore satisfy the
consent callback's parsing and its 30-minute freshness check.

**Impact.** A freshly minted Event Grid webhook token — a value customers are instructed to
paste into `az` commands, so one that lands in shell history, CI configuration and
infrastructure repositories — is a working credential for the consent callback. So is a
template token. The separation the signing module describes as load-bearing is absent on the
one endpoint that writes the tenant binding.

**Recommendation.** Mint the consent state with an explicit purpose and require it on verify,
matching the other two callers.

---

### Finding 4 — No security response headers on API or frontend

**Severity:** Medium · **OWASP:** A05 Security Misconfiguration · **CWE-693** Protection Mechanism Failure
**Location:** `apps/api/app/main.py`, `apps/web/vercel.json`

`main.py` installs `UnhandledErrorMiddleware` and `CORSMiddleware` and nothing else.
`vercel.json` declares `framework`, `buildCommand`, `outputDirectory` and a SPA rewrite, with
no `headers` block. Neither surface sends `Content-Security-Policy`,
`Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options` or `Referrer-Policy`.

This matters more than the usual checklist entry because the API serves HTML built from
customer data. `GET /api/v1/reports/{kind}?format=html` (`app/api/routes/reports.py:112`)
returns a `text/html` document rendered from resource names, tag values and provider error
text collected out of the customer's cloud. Jinja autoescaping is enabled and correctly
configured, so this is not a cross-site scripting vulnerability today — but it is a
same-origin HTML surface with no `nosniff`, no CSP and no framing policy behind it.

**Recommendation.** Send a conservative header set from the API, and configure the equivalent
for the static frontend at the CDN.

---

### Finding 5 — No inbound rate limiting and no request body size cap

**Severity:** Medium · **OWASP:** A04 Insecure Design · **CWE-770** Allocation of Resources Without Limits
**Location:** `apps/api/app/main.py`

Nothing limits the rate or size of inbound requests. `RequestLimiter` in
`app/connectors/azure/client.py` is an *outbound* concurrency control for calls CloudGuard
makes to Azure, and is unrelated.

Four endpoints are reachable with no authentication and each performs real work:

| Endpoint | Work performed |
|---|---|
| `POST /api/v1/events/{provider}/{connection_id}` | Parses a JSON body of unbounded size |
| `GET /api/v1/cloud-connections/{id}/template` | HMAC verification, database read |
| `GET /api/v1/cloud-connections/azure/consent/callback` | HMAC verification, database write |
| `GET /health/ready` | Opens a database connection |

Authenticated endpoints include `GET /api/v1/reports/{kind}`, which renders a PDF through
WeasyPrint on every request.

**Recommendation.** Apply a shared-state rate limit — Redis is already a dependency, and a
per-process counter is wrong across multiple Railway instances — and reject oversized bodies
before they are buffered.

---

### Finding 6 — No dependency scanning in CI, and 31 known advisories in the pinned set

**Severity:** High · **OWASP:** A06 Vulnerable and Outdated Components · **CWE-1104** Use of Unmaintained Third Party Components
**Location:** `.github/workflows/ci.yml`, `apps/api/pyproject.toml`

CI runs lint, type checks and tests. There is no `pip-audit`, no `npm audit`, no Dependabot
configuration and no code scanning. Python dependencies are pinned exactly — which is correct
— and every pin dates from around December 2024, so nothing prompts a review when an advisory
lands.

This was opened as a process gap and did not stay one. Running `pip-audit` against the pinned
set returned **31 known advisories across six packages**, the most serious being **seven
against PyJWT 2.10.1** — the library that verifies every authentication token this API
accepts. A finding about missing scanning is ordinarily Low. A finding that the scanning was
missing *and* that the library holding up authentication is five releases behind its
advisories is not.

| Package | Pinned | Advisories | Note |
|---|---|---|---|
| pyjwt | 2.10.1 | 7 | Verifies every request's token |
| python-multipart | 0.0.20 | 6 | Request parsing |
| starlette | 0.41.3 | 7 | Transitive; capped by FastAPI 0.115 |
| cryptography | 45.0.7 | 7 | Transitive; capped by msal 1.31 |
| weasyprint | 63.1 | 3 | PDF rendering |
| pytest | 8.3.4 | 1 | Test-only |

**Recommendation.** Add a dependency audit job that fails the build, enable automated
dependency updates, and upgrade. The two direct dependencies with their own pins can move
immediately; the rest need a major-version upgrade run against the test suite.

---

## 3. Remediation

All six were addressed on branch `develop-eh` immediately following this audit. Findings 1–3
are one flow and were fixed as one change; 4–6 are independent.

**Findings 1, 2 and 3 — the consent flow.** `purpose` moved from each caller's discretion
into `core/signing.py`, where `sign_state` stamps it and `verify_state` demands it, both as
keyword arguments with no default — a new round trip cannot be added without naming one, and
the callback that forgot to check cannot forget again. The consent link now carries a nonce
whose counterpart is stored on the connection row (`0039_consent_nonce`), so it is redeemable
once rather than replayable until expiry; it is reissued identically while live, so polling
the wizard does not invalidate a link the customer has already sent to their administrator.
The link is minted only for a caller who passes the owner/admin check, so reading a connection
no longer hands a read-only member a credential. And a connection that already names a tenant
is never repointed at a different one — the returning `tenant` parameter is accepted as a
first binding only.

**Finding 4 — headers.** `app/core/middleware.py` adds `SecurityHeadersMiddleware`, installed
outermost so it stamps CORS preflights and anything raised further in. The frontend's
equivalent is in `apps/web/vercel.json`, deliberately a different and looser policy: an
application needs `script-src 'self'`, and Tailwind and React both write inline styles.

**Finding 5 — limits.** `RequestSizeLimitMiddleware` checks `Content-Length` *and* counts
bytes as they arrive, because the first is a claim and a chunked request carries none.
`RateLimitMiddleware` counts in Redis rather than per process — the API runs as more than one
instance — with a smaller ceiling for requests carrying no `Authorization` header. Which
client a request is counted against is decided by `trusted_proxy_hops` rather than by
believing the caller's own `X-Forwarded-For`.

**Finding 6 — dependencies.** A `pip-audit --strict` and `npm audit` job, plus
`.github/dependabot.yml`. PyJWT moved to 2.13.0, python-multipart to 0.0.31 and jinja2 to
3.1.6, which clears 14 of the 31 advisories including all seven against the token library. The
remaining 18 are listed explicitly in the audit step's `--ignore-vuln` arguments as a triage
backlog rather than silently excluded — see section 6.

The order the middleware is installed in is load-bearing and `main.py` documents it. The
reasoning behind the consent changes is recorded in `docs/DECISIONS.md` §124, and behind the
middleware in §125.

---

## 4. Areas examined that held

Recorded deliberately. Six findings against a codebase of this size is a narrow result, and
that is only meaningful alongside what was checked and passed.

**A03 Injection.** No dynamic SQL anywhere. Four `text()` call sites exist and all four are
literal strings; every other query is SQLAlchemy Core or ORM with bound parameters. No `eval`,
`exec`, `pickle`, `subprocess`, `os.system` or `shell=True` in the application package.

**A01 Multi-tenant isolation.** All twenty-nine model tables have row-level security enabled,
each with both a member arm (`app.is_member(organization_id)`) and a worker arm
(`app.current_org() = organization_id`). The `evidence` table inherits its policies through
the `scan_collection_results` rename in migration 0010. Every route handler scopes on
`tenant.organization_id`. The `X-Organization-Id` header is resolved against a membership
lookup before it is honoured, and PostgreSQL re-checks the same thing independently.

**A02 Cryptographic failures.** State verification uses `hmac.compare_digest`. AWS external
ids are `secrets.token_urlsafe(24)`. JWT verification pins `algorithms` to the single
algorithm declared in the header and only after resolving a key appropriate to it; `none` and
the wider symmetric family are refused outright rather than falling through to a weaker check.

**A10 SSRF.** One code path makes an outbound request triggered by an inbound payload — the
SNS subscription confirmation. The URL is host-allowlisted at
`app/connectors/aws/change_events.py:96` against `^sns\.[a-z0-9-]+\.amazonaws\.com(\.cn)?$`.
Userinfo (`@`), port and fragment tricks all fail the `fullmatch`, and httpx does not follow
redirects by default.

**A03 Cross-site scripting.** Jinja autoescaping is enabled with `default_for_string=True`.
The three `| safe` filters in report templates apply to the stylesheet and to SVG built from
bounded integers, none of which is customer-controlled. The single
`dangerouslySetInnerHTML` in the frontend is vendored shadcn `chart.tsx` operating on
developer-defined configuration. `portalUrl` prefixes a literal `https://portal.azure.com/`
origin, so a `javascript:` scheme cannot be introduced through a resource identifier.

**Open redirect.** The consent callback builds every redirect from `settings.app_url`, never
from client input.

**SQL privilege escalation.** All five `SECURITY DEFINER` functions pin
`search_path = public, pg_temp`.

**Error handling and secrets.** `UnhandledErrorMiddleware` logs the traceback server-side and
returns a sentence carrying no exception detail. No credential is passed to a log call. No
secret material is committed; `infrastructure/supabase/roles.sql` retains its placeholder
password and CI enforces that.

---

## 5. Disposition

| # | Finding | Status |
|---|---------|--------|
| 1 | Consent callback mutates state with no authentication or role check | Fixed |
| 2 | `tenant` query parameter written unverified | Fixed |
| 3 | Consent state carries no `purpose` | Fixed |
| 4 | No security response headers | Fixed |
| 5 | No rate limiting or body size cap | Fixed |
| 6 | No dependency scanning in CI | Fixed; 18 advisories remain, section 6 |

Tests were added or updated with the fixes: `tests/unit/test_consent_binding.py` covers the
nonce and the tenant binding, `tests/unit/test_middleware.py` covers all three middlewares
including the fail-open path and the forwarded-address decision, and
`tests/unit/test_consent_callback_redirect.py` gained the token-confusion case.

## 6. Carried forward

Four upgrades remain, each crossing a major version and each needing a run against the test
suite before it ships. They are named individually in the CI audit step's `--ignore-vuln`
list, so the job still fails on any advisory that is not one of them — the list is what a new
advisory is measured against, and it should only ever get shorter.

| Package | From | Blocked by | Advisories |
|---|---|---|---|
| starlette | 0.41.3 | FastAPI 0.115 pins `starlette <0.42` | 7 |
| cryptography | 45.0.7 | msal 1.31 caps it | 7 |
| weasyprint | 63.1 | 63 → 70 changes rendering; report tests assert on output | 3 |
| pytest | 8.3.4 | 8 → 9, test-only | 1 |

Two smaller items, neither a finding:

**The frontend CSP's `connect-src` is `https: wss:`** rather than naming origins. The API and
Supabase URLs are per-deployment environment variables, and a static header naming the wrong
one is a frontend that cannot reach its backend. Narrowing it per environment is worth doing
and is a configuration change rather than a code change.

**A read-only member opening a connection's setup step** now sees the "consent cannot be
started" alert, because the link is no longer minted for them. That is correct behaviour and
an imprecise message; the wizard is not a page a viewer has business in either way.
