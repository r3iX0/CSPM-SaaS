# CloudGuard — Testing Framework Review (September 2026)

**Date:** 20 September 2026
**Scope:** The test framework itself — `apps/api/tests`, `apps/web/src/**/__tests__`, `apps/api/pyproject.toml`, `apps/web/vite.config.ts`, `apps/web/src/test/setup.ts`, `.github/workflows/ci.yml`, `docs/TESTING.md` — at commit `f5f5993` (`develop-eh`).
**Companion documents:** [`docs/TESTING.md`](TESTING.md) (the strategy this reviews), [`docs/ARCHITECTURE_REVIEW_2026-09-20.md`](ARCHITECTURE_REVIEW_2026-09-20.md), [`docs/SECURITY_REVIEW_2026-09-20.md`](SECURITY_REVIEW_2026-09-20.md).

This is a review of the testing *apparatus*, not of the product's correctness. Nothing here is a bug report against a feature; every item is about what the suite can and cannot catch, how fast it says it, and whether its own documentation is true.

---

## 1. Executive Summary

The suite is fast, deterministic, and unusually well commented. It contains a set of architecture fitness tests that are rarer and more valuable than the coverage number suggests. The gaps are not in the tests people wrote — they are in the framework around them: the default command does not work, coverage is never measured, and the one seam that spans the two applications (the API response contract) is checked by nothing.

Measured on this commit, on a developer machine:

| Suite | Result | Wall clock | Notes |
| --- | --- | --- | --- |
| `apps/api` unit (`pytest tests/unit`) | 1881 passed, 1 skipped | **3.8s** | 78% line coverage over `app/`, unit lane only |
| `apps/api` integration (`pytest -m integration`) | 326 collected | not runnable locally | requires live PostgreSQL; no compose file exists |
| `apps/web` (`vitest run`) | 494 passed, 58 files | **7.4s** | no coverage provider installed |

Health signals that came back clean: no focused tests (`.only`, `fdescribe`), no skipped web tests, no assertion-free tests (checked by parsing every `it()` body), and no `.skip` left behind. Query style in web tests leans on roles (248 `ByRole` against 413 `ByText`), which is the right direction.

The three findings that matter most:

1. **`pytest -q` fails without a database** — 110 failures and 529 errors — while `CLAUDE.md` and `docs/TESTING.md` §6 both state it is the unit lane and needs no database.
2. **Coverage is never measured.** `pytest-cov` is a pinned dev dependency that is never invoked; `apps/web` has no coverage provider at all. The 78% above is a number nobody on the team has seen.
3. **Nothing tests the API↔web contract.** CI validates `docs/api/openapi.json` against the code and stops there. The frontend's 74 hand-written types and roughly 40 files of inline response fixtures can drift from the schema indefinitely while every test stays green.

---

## 2. What Is Already Strong

These should survive every refactor below, and the first three are the pattern worth extending.

- **Architecture fitness tests.** `tests/unit/test_provider_seam.py` (nothing neutral imports a provider package), `test_scan_writer.py` (every commit in the scan package goes through `ScanWriter.commit`), `test_evidence_keys.py` (every key a rule depends on is one some task actually produces, in both directions), `test_request_transaction.py` (a service does not commit a transaction it may not own), `test_transaction_ownership.py`. These encode the invariants in `CLAUDE.md` and `docs/DECISIONS.md` as executable checks rather than prose.
- **`tests/unit/test_remediation_spec.py` and the CIS §4 block in `test_aws_rules.py:1206`.** The remediation text a customer is told to run is evaluated against the check that produced the finding, so the CLI command and the rule logic are one claim rather than two that can drift. This is the strongest test in the repository.
- **Registry-driven parametrisation.** `SECTION_FOUR = [rule for rule in RULE_REGISTRY if isinstance(rule, _MonitoredEventRule)]` with `ids=lambda r: r.rule_id` means rule sixteen is covered the day it is added, and each rule reports as its own test id. Where parametrisation is used, it is used correctly.
- **`apps/web/src/test/setup.ts` promotes React's keyless-list warning to a test failure.** A warning class that would otherwise scroll past in a green run now fails the test that produced it.
- **Environment discipline in `tests/conftest.py`.** `APP_ENV` and `SUPABASE_JWT_SECRET` are set with `setdefault` before any app import, so CI's own values still win.
- **CI proves the constrained paths.** `DATABASE_URL` uses `cloudguard_app` and `DATABASE_WORKER_URL` is set explicitly, both with comments explaining that leaving them unset would make the RLS tests pass while proving nothing.
- **Drift gates already exist** for the Graph permission manifest, `docs/api/openapi.json`, `docs/RULE_CATALOG.md`, the `roles.sql` placeholder password, and the duplicated `vercel.json` headers. The pattern is established; §4.1 below asks for one more gate of the same shape.

---

## 3. P0 — The Harness Misreports Itself

### 3.1 The default test command fails without a database

`[tool.pytest.ini_options]` sets `testpaths = ["tests"]` and nothing deselects the `integration` marker, so a bare run collects all eight integration modules. Observed on this commit with no PostgreSQL running:

```
110 failed, 1893 passed, 2 skipped, 207 warnings, 529 errors in 14.52s
```

Both documents that tell a developer what to run are wrong about this:

- `CLAUDE.md`: `pytest -q  # all tests`
- `docs/TESTING.md` §6: `pytest -q  # unit; no database needed`

The first command a new contributor runs produces 639 red lines that mean nothing about their change.

**Fix.** Make the marker the lane boundary, and make CI state both lanes explicitly:

```toml
# apps/api/pyproject.toml — [tool.pytest.ini_options]
addopts = "-m 'not integration' --strict-markers --strict-config -ra"
xfail_strict = true
```

```yaml
# .github/workflows/ci.yml
- name: Test (unit)
  run: pytest -q
- name: Test (integration)
  run: pytest -q -m integration
```

A worthwhile alternative, additive rather than instead: a session-scoped autouse fixture in `tests/integration/conftest.py` that attempts one connection and calls `pytest.skip` for the whole package when it fails. That turns "639 errors" into "326 skipped" for anyone who runs the wrong command anyway.

Then correct the two documentation lines, and delete the file counts in `docs/TESTING.md` (see §6.4).

### 3.2 Markers are not strict

Without `--strict-markers`, a typo such as `@pytest.mark.integraton` is a no-op that only warns. The test then runs in the unit lane, against no database, and fails for a reason unrelated to its subject. Covered by the `addopts` above; called out separately because it is the cheapest correctness win in this document.

### 3.3 Coverage is never measured or enforced

`pytest-cov==6.0.0` is pinned in `[project.optional-dependencies].dev` and appears in no command, script, or workflow step. `apps/web` has no `@vitest/coverage-v8` dependency, so `vitest --coverage` cannot run at all.

Because the two lanes cover different halves of the codebase, a unit-only measurement is actively misleading. From the unit lane alone:

| Module | Unit-lane coverage |
| --- | --- |
| `app/services/scan/pipeline.py` | 19% |
| `app/services/dashboard.py` | 22% |
| `app/services/scan/assets.py` | 22% |
| `app/services/compliance.py` | 29% |
| `app/api/routes/*` | 26–40% |
| **Total** | **78%** |

Those services are exercised by `tests/integration/test_scan_pipeline.py`; the number is low because the measurement is partial, not because the code is untested. Any floor set against the unit lane alone would either be meaningless or would force unit tests that duplicate integration coverage.

**Fix.** Measure both lanes into one report and put a floor on the combined figure:

```bash
pytest -q --cov=app --cov-report=
pytest -q -m integration --cov=app --cov-append --cov-report=term --cov-fail-under=85
```

For `apps/web`, add `@vitest/coverage-v8` and declare thresholds in `vite.config.ts` under `test.coverage`. Set the initial floors to the measured value minus a point or two, so the gate ratchets rather than blocks the change that introduces it.

---

## 4. P1 — Drift Risk

### 4.1 Nothing checks the API↔web contract

`apps/web/src/lib/types.ts` is 1288 lines and declares 74 types that mirror the API's Pydantic schemas by hand. Separately, each web test writes its own response literal — `src/pages/__tests__/findings.test.tsx:11-29` builds a `finding()` object with fifteen fields, and roughly forty other test files do the equivalent for their own endpoints.

The consequence of a field rename on the API side, today:

1. `python scripts/generate_openapi.py --check` fails in CI. Good — that gate works.
2. The author regenerates `docs/api/openapi.json`. CI goes green.
3. `src/lib/types.ts` and forty files of fixtures still describe the old shape. Every web test passes. TypeScript is satisfied, because the fixtures were written to match the hand-written types, and both are now wrong together.

`docs/TESTING.md` §5 already records this honestly: "a contract drift between the API envelope and the client's types is caught by TypeScript and by `docs/API.md` being right, not by a test."

**Fix, in the shape of the gate that already exists.** Generate the types from the schema and check them in CI:

1. Add `openapi-typescript` as a dev dependency; generate `apps/web/src/lib/api-types.d.ts` from `docs/api/openapi.json`.
2. Add a CI step that regenerates and diffs, failing with the same `::error file=` treatment the OpenAPI and rule-catalog gates use.
3. Replace the hand-written response types in `src/lib/types.ts` with aliases onto `components["schemas"][...]`. Keep the hand-written ones that describe *client* concepts (view state, filter shapes) — those are not the API's to define.
4. Add `apps/web/src/test/factories.ts`: one typed factory per response shape, `makeFinding(overrides?: Partial<Finding>): Finding`, returning the generated type. Migrate the inline literals to it.

After that, a renamed schema field is a compile error in every affected test at once, which is the only way forty fixture literals stay honest.

### 4.2 Test doubles are untyped and duplicated

`[tool.mypy]` sets `exclude = "^(database/|tests/)"`, so nothing type-checks the test tree. Inside it, 32 hand-rolled doubles stand in for real interfaces, and the same double is redeclared per file:

- `class FakeTokens` — **12 files** (`test_azure_identity_access.py`, `test_resource_graph.py`, `test_azure_collection_plan.py`, `test_request_limiter.py`, `test_azure_client_errors.py`, `test_directory_scope.py`, `test_graph_grant_check.py`, `test_role_drift.py`, `test_dormant_accounts.py`, `test_evidence_keys.py`, `test_azure_v7_rules.py`, `test_azure_probe_reporting.py`)
- `class FakeSession` — **11 files**
- Plus `FakeGraph`, `FakeClient`, `FakeResult`, `FakeEngine` variants

A double that is neither typed nor shared can silently stop resembling the thing it replaces: the real `AsyncSession` or token provider grows a parameter, the fake does not, and the test keeps passing against an interface that no longer exists.

**Fix.** One `tests/doubles/` package, each double typed against the Protocol the application already defines (or a new one where it does not), and type-checked:

```toml
# apps/api/pyproject.toml
[tool.mypy]
exclude = "^database/"

[[tool.mypy.overrides]]
module = "tests.*"
disallow_untyped_defs = false
```

CI then runs `mypy app tests`. The relaxed `disallow_untyped_defs` keeps the migration from becoming a rewrite of 36,000 lines of tests while still catching a double whose signature no longer matches its subject.

### 4.3 `respx` is pinned and never used

`respx==0.22.0` appears in `pyproject.toml:43` and nowhere else in the tree. Either remove it, or spend it where HTTP-level mocking would raise the weakest coverage in the codebase — see §4.4.

### 4.4 The least-verified code is also the least-tested

`CLAUDE.md` is explicit that AWS "has never been run against a live AWS account" and that every string under `app/connectors/aws/` is unverified until `docs/AWS_INTEGRATION.md` §1's checklist passes. The tests do not compensate for that:

| Module | Unit-lane coverage |
| --- | --- |
| `app/connectors/aws/client.py` | 38% |
| `app/connectors/aws/collector.py` | 45% |
| `app/connectors/aws/connector.py` | 47% |
| `app/connectors/aws/auth.py` | 66% |
| `app/connectors/aws/onboarding.py` | 64% |

The normalizer (93%), plan (71%), change events (95%) and the 46 rules are well covered — the gap is precisely the wire layer, which is the part a fixture-only strategy cannot reach and the part with no Azure equivalent to borrow confidence from (SigV4, three protocols, per-region reads).

**Fix.** `botocore.stub.Stubber` tests for `client.py` and `collector.py`: paginated responses, a region that returns `AccessDenied`, a partial read that must become an UNKNOWN verdict rather than a PASS, and the region-scoped reading versus per-key verdict rule from `docs/DECISIONS.md` §69. This is the cheapest assurance available before the first live account, and it is a prerequisite for trusting the checklist run when it happens.

### 4.5 One rule of 98 has no test

Checked by evaluating `RULE_REGISTRY` rather than by grep: `AWS-NET-003` / `AwsPublicDatabasePortRule` (`app/rules/aws/network/exposure.py:242`) is referenced by no test, by rule id or by class name. Its siblings `AWS-NET-001` and `AWS-NET-002` share the `_OpenPortRule` base and are tested, so the base logic is exercised — the port set specific to NET-003 is not.

(An earlier pass flagged eleven CIS §4 monitoring rules as untested. They are covered, parametrised through `SECTION_FOUR`; their class names simply never appear as literals. The registry-driven pattern is correct and is what §2 recommends extending.)

**Fix.** Make the guarantee structural rather than a one-line patch. A parametrised meta-test over `RULE_REGISTRY` asserting that every rule reaches both a FAIL and a PASS verdict on some context, so rule 99 cannot land untested. `docs/TESTING.md` §1 already describes this convention (`FAIL` / `PASS` / `NOT_APPLICABLE` per rule); nothing currently enforces it.

### 4.6 The fixture strategy in the documentation is not the one in the tree

`docs/TESTING.md` §1 presents `tests/fixtures/{secure,vulnerable,unknown}/` as how rules are tested. Those directories hold 8, 10 and 5 files against 98 registered rules; most rule tests build their context inline (`context_from(...)`, `make_context(...)`) instead.

Inline construction is arguably the better choice — it keeps the input next to the assertion — but the document should say which one is the convention, because "add a fixture file" and "build a context in the test" are different instructions for the next rule author.

---

## 5. P2 — Speed

The unit lane at 3.8s and the web suite at 7.4s need no attention. Everything below is about the integration lane, which is the entire cost of CI and could not be measured on this machine (see §6.1).

### 5.1 178 full pipeline runs in one file

`tests/integration/test_scan_pipeline.py` is 5030 lines and 168 tests, and calls `run_scan` / `run_replay` / `run_connection_scan` 178 times. Each call creates an organization, connects an account, and drives a complete scan through the orchestrator loop to `COMPLETED`.

`TestFirstScan` (line 386) is the pattern: four tests, each one re-running the whole pipeline from a fresh organization, then asserting on four different parts of what is effectively the same scan — the capture rows, the discovered assets, the findings' evidence, the finding titles.

**Fix.** A class-scoped fixture that runs the pipeline once and yields `(org_id, account_id, scan_id)`, with the tests asserting read-only against it. Where a test mutates state (remediation then rescan, retention pruning, abandonment) it keeps its own run. This is the single largest available reduction in CI wall clock, and it needs no new tooling.

### 5.2 Connection pools are disposed after every test

`tests/integration/conftest.py::_reset_connection_pools` is autouse and calls `dispose_engines()` after each test. Its docstring explains why: pytest-asyncio gives each test its own event loop, and a pooled asyncpg connection created under one loop fails under the next. So every integration test pays fresh connection handshakes for every engine.

**Fix.** Remove the cause rather than the symptom — `asyncio_default_fixture_loop_scope = "session"` in `[tool.pytest.ini_options]`, pools kept for the session, `dispose_engines()` once at session teardown. This interacts with §5.1 and should be done alongside it, since both change how state is shared between tests in a class.

### 5.3 No parallelism

`pytest-xdist` is not installed. The unit lane does not need it. The integration lane will still be database-bound after §5.1 and §5.2, and its data is organization-scoped, so `--dist loadfile` is plausible — but only once the autouse pool dispose is gone, and it likely needs a per-worker database or schema. Sequenced last on purpose.

### 5.4 CI wastes runner time

`.github/workflows/ci.yml`:

- No `concurrency` block, so a superseded push keeps its predecessor running to completion.
- No `timeout-minutes` on any job. A hung test holds a runner for the GitHub default of six hours.
- The `api` job provisions PostgreSQL, Redis, WeasyPrint's native libraries, and runs migrations before it gets to `ruff check .`. A PR with a lint error pays the full setup before hearing about it.
- No JUnit XML and no coverage artifact, so a failure is readable only by scrolling the raw log.

**Fix.**

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```

Add `timeout-minutes` to every job. Split `api` into a fast job (ruff, mypy, unit — no services, no native libraries, no migrations) and a slow one (migrations, drift gates, integration). Upload `--junitxml` and the coverage report as artifacts.

---

## 6. P3 — Missing Layers

### 6.1 No local path to the integration lane, and no E2E

There is no compose file anywhere in the repository — `infrastructure/docker/` contains only `api.Dockerfile`. The 326 integration tests are therefore CI-only; they could not be run for this review. `docs/TESTING.md` §6 suggests `pytest --collect-only tests/integration` as the local substitute, which catches import errors and nothing else.

**Fix, first:** `infrastructure/docker/compose.test.yml` with `postgres:16-alpine`, `redis:7-alpine`, and `infrastructure/ci/postgres-roles.sql` applied on init, so local matches CI exactly. This is a prerequisite for anyone doing §5.1.

**Fix, second:** `docs/TESTING.md` §5 is right that E2E was specified and never written, and right that recorded fixtures beat a live tenant per commit. What is left uncovered is the browser half: the sign-in redirect and the `onAuthStateChange`-after-`getSession` race that `src/lib/api.ts` documents, the connect wizard, the scan wizard's SSE stream and its polling fallback, and the PDF download. A five-test Playwright smoke against the built SPA, on `main` and nightly rather than on the PR path, covers the journey no unit test reaches. The demo organization (`organizations.is_demo`, `docs/DECISIONS.md` §99) is the natural fixture for it.

### 6.2 No accessibility assertions

The UI's design decisions are substantially accessibility decisions — the graph canvas as one tab stop with arrow keys inside (`docs/DECISIONS.md` §101), reduced motion answered once by `<MotionConfig reducedMotion="user">`, keyboard navigation through lists. None of it is asserted beyond the incidental coverage of role-based queries.

**Fix.** `vitest-axe` on six or so page tests. It runs in-process, adds roughly a second, and catches the regressions (contrast tokens, unlabelled controls, heading order) that role queries pass over.

### 6.3 No load test on the orchestrator or the event stream

`GET /scans/{id}/events` re-reads through a fresh `rls_session` on every tick (`docs/DECISIONS.md` §88). Nothing tests N concurrent streams against the connection pool size, and nothing tests the orchestrator under several workers competing for the same leases beyond the single-process lease tests. A k6 scenario on the nightly lane would put a number on both.

### 6.4 `docs/TESTING.md` is stale

§5 says "37 vitest files"; §6 says "43 files". The actual count is 58. §6 also carries the `pytest -q` claim corrected in §3.1.

**Fix.** Correct the command, and delete the counts rather than gate them. A number in prose that changes on every PR is a drift gate nobody asked for; the drifts worth gating (OpenAPI, rule catalog, permission manifest) already are.

### 6.5 CI has no SAST and no secret scanning

The `audit` job runs `pip-audit --strict` and `npm audit --audit-level=high`. Both are dependency-advisory tools. For a security product there is no static analysis of first-party code and no secret scanning beyond the single `grep` that protects `roles.sql`'s placeholder password.

**Fix.** Add semgrep (or bandit) and gitleaks to the `audit` job. Separately: the `--ignore-vuln` list is 19 entries, each a real triage decision documented in `docs/SECURITY_AUDIT_2026-09.md` §6, with no expiry. Give each entry a date and fail the job when one ages past a threshold, or the backlog becomes permanent by default.

### 6.6 No mutation testing

The rule engine is deterministic pure functions over fixture input — no network, no database, no LLM — which is the ideal mutation-testing target. `mutmut` scoped to `app/rules/` and `app/risk/`, on the nightly lane, would demonstrate that the fixtures discriminate between a correct rule and a subtly wrong one rather than merely executing it. Given that UNKNOWN must never be treated as PASS, the mutants that flip a verdict default are exactly the ones worth knowing about.

### 6.7 No flake or order-dependence detection

`pytest-randomly` is not installed, so test order is stable and order dependence is invisible. The integration lane shares one database and `cleanup_orgs` is opt-in rather than autouse, which makes leftover rows between tests plausible. Adding random ordering to the nightly lane (not the PR lane, where a reproducible order is worth more) would surface it.

### 6.8 Web test hygiene is per-file where it should be global

`vite.config.ts`'s `test` block sets `environment`, `globals`, `setupFiles` and `testTimeout`, but none of `restoreMocks`, `clearMocks`, `unstubGlobals` or `unstubEnvs`. Consequences observed:

- 13 test files stub globals; each hand-writes `vi.unstubAllGlobals()` in `afterEach`. `src/lib/__tests__/api.test.ts` stubs `fetch` and never unstubs it — contained today only because Vitest isolates per file.
- `localStorage` is cleared in 6 files of 58, although `auth` (`cloudguard.token`, `cloudguard.org`), the theme store, and the sidebar collapse state all write to it. Within a file, state carries between tests.

**Fix.** `restoreMocks: true, clearMocks: true, unstubGlobals: true, unstubEnvs: true` in the config, and `localStorage.clear(); sessionStorage.clear();` in a global `afterEach` in `src/test/setup.ts`. The whole class of leak disappears and 13 files get shorter.

### 6.9 No test-specific lint rules

`eslint.config.js` covers `js.configs.recommended`, `tseslint.configs.recommended`, `react-hooks` and `react-refresh`. There is no `eslint-plugin-testing-library` and no `eslint-plugin-vitest`, so nothing catches a missing `await` on a `findBy*` query, an unnecessary `act`, a `waitFor` with multiple assertions, or the 67 `fireEvent.` calls in places where `userEvent` is the more faithful simulation (76 uses already prefer it).

### 6.10 Warning filters are blanket

`filterwarnings = ["ignore::DeprecationWarning"]` hides every upstream deprecation — SQLAlchemy 2.x, Pydantic, and the `pytest` 8→9 move already on the audit backlog. The suite emits 29 warnings in the unit lane and 207 across both; nobody reads them because they are pre-declared as noise.

**Fix.** `filterwarnings = ["error", "ignore:<specific message>:DeprecationWarning:<module>", ...]`. Each ignore then documents a known upstream issue instead of a policy of not looking.

---

## 7. Implementation Order

Sequenced by dependency and by ratio of value to effort, not by section number.

| # | Item | Sections | Why here |
| --- | --- | --- | --- |
| 1 | `addopts` with marker lane + strict markers; correct `CLAUDE.md` and `docs/TESTING.md` | 3.1, 3.2, 6.4 | Fixes a false statement every new contributor hits first. Minutes of work. |
| 2 | `compose.test.yml` for local PostgreSQL + Redis + roles | 6.1 | Unblocks the integration lane locally; prerequisite for item 3. |
| 3 | Class-scoped pipeline fixtures; session-scoped event loop; drop the autouse pool dispose | 5.1, 5.2 | Largest CI wall-clock reduction available. Needs item 2 to verify. |
| 4 | Coverage over both lanes with a ratcheting floor; web coverage provider | 3.3 | Makes every later item measurable. |
| 5 | Generated OpenAPI types + CI check; typed web factories | 4.1 | Closes the one seam nothing tests. Largest correctness gain. |
| 6 | `tests/doubles/`; mypy over `tests`; remove or use `respx` | 4.2, 4.3 | Stops 23 duplicated doubles from drifting from their subjects. |
| 7 | CI: concurrency cancel, job timeouts, fast/slow split, JUnit + coverage artifacts | 5.4 | Independent of the above; pure infrastructure. |
| 8 | AWS wire-layer tests with `botocore.stub.Stubber`; registry fitness meta-test covering `AWS-NET-003` | 4.4, 4.5 | Should land before the first live AWS account, per `docs/AWS_INTEGRATION.md` §1. |
| 9 | `vitest-axe` on page tests; test lint plugins; global mock/storage cleanup | 6.2, 6.8, 6.9 | Cheap, in-process, no new lane. |
| 10 | Nightly lane: Playwright smoke, `mutmut` on rules and risk, semgrep + gitleaks, k6 on SSE, random ordering | 6.1, 6.3, 6.5, 6.6, 6.7 | Everything that should not sit on the PR path. |
| 11 | `pytest-xdist` on the integration lane | 5.3 | Only worthwhile after items 2, 3 and 4. |
| 12 | Document the real rule-fixture convention; tighten `filterwarnings` | 4.6, 6.10 | Cleanup; no behavioural dependency. |

---

## 8. Decisions This Review Does Not Make

Three items above change something `docs/DECISIONS.md` would normally record, and are flagged rather than assumed:

- **Generated API types** (§4.1) introduce a build step and a generated file into `apps/web`. The alternative — keeping the types hand-written and adding a test that asserts the fixtures against `docs/api/openapi.json` at runtime — preserves the current shape at the cost of a weaker guarantee.
- **E2E and Playwright** (§6.1) would reverse the deliberate absence recorded in `docs/TESTING.md` §5. The recommendation is narrower than the draft that was abandoned: five tests, nightly, against the demo organization, no live Azure tenant.
- **Type-checking the test tree** (§4.2) changes what `mypy` means in this repository. The relaxed override keeps it from becoming a rewrite, but it is still a policy change rather than a fix.
