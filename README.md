# Cleave

Azure-first cloud security posture management (CSPM).

Cleave connects to a customer's cloud read-only, discovers what is there, evaluates it against
deterministic security rules, scores the results as business risks rather than raw alerts, shows
how an attacker could chain them, tells the user how to fix the ones that matter — and then
**verifies the fix itself** on the next scan.

The product was called CloudGuard until the redesign ([`DECISIONS.md` §144](docs/DECISIONS.md)).
Names that exist in a customer's cloud or directory, and identifiers in the code, keep CloudGuard
(§147). The specification this is built from lives in [`docs/`](docs/); start with
[`docs/PRODUCT_SPEC.md`](docs/PRODUCT_SPEC.md).

## What it does

- **Scans** Azure through REST and MSAL, storing each provider response verbatim so a new rule can
  be run against an old capture.
- **Evaluates** the estate with deterministic rules, one engine, per provider
  ([`docs/RULE_CATALOG.md`](docs/RULE_CATALOG.md), generated from the registry).
- **Scores** findings into risks by severity, asset criticality, data sensitivity and public
  exposure ([`docs/RISK_ENGINE.md`](docs/RISK_ENGINE.md)).
- **Draws attack paths**: the routes from the internet or a directory role to an asset, which link
  closes the most routes, and a plan of cuts simulated as a whole.
- **Maps compliance** evidence to frameworks, including the controls nothing checks.
- **Shows the fix** as a CLI command, and for Terraform as a diff against the customer's own file
  ([`docs/FIX_AS_CODE.md`](docs/FIX_AS_CODE.md)).
- **Reports and notifies**: PDF reports, webhooks, an append-only audit log, and invitations for
  colleagues.

## AWS is built and is not offered yet

An AWS connector, its permission manifest, its onboarding flow, change-triggered scanning and fifty
AWS rules exist behind the same seam Azure sits behind
([`docs/AWS_INTEGRATION.md`](docs/AWS_INTEGRATION.md)). CIS AWS 3.0 is catalogued at 44 of its 56
controls. **None of it has been run against a live AWS account.** Every IAM action name, response
shape and CloudFormation string is written from AWS's published reference, so the wizard shows AWS
greyed out with the reason until the nineteen-item checklist in `AWS_INTEGRATION.md` §1 has passed
and `AWS_ENABLED=true` is set.

That is why the line above still says Azure-first. It will stop saying so when somebody has scanned
an AWS account with it, and not before.

---

## Running it

Cleave is cloud-only. There is no local run mode, no `docker-compose.yml`, and no localhost
defaults anywhere in the configuration — the API refuses to start unless it has a complete
deployment environment.

| Layer | Platform |
|---|---|
| PostgreSQL + Auth | Supabase |
| API + Celery worker + Redis | Railway |
| Frontend | Vercel |

Full walkthrough: **[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)**. Both Railway and Vercel build
directly from this repository and redeploy on every push to `main`.

### Seeing the product loop before a cloud is registered

Scanning a real environment needs an Entra app registration
([`docs/AZURE_INTEGRATION.md`](docs/AZURE_INTEGRATION.md) §2), or an AWS principal
([`docs/AWS_INTEGRATION.md`](docs/AWS_INTEGRATION.md) §2). Until then, the demo seed runs the
**real** pipeline — real normalizer, real rules, real risk engine — against a recorded snapshot.
From the API service's shell on Railway, with `APP_ENV=staging`:

```bash
python /srv/database/seed/demo_environment.py --email you@example.com
python /srv/database/seed/demo_environment.py --email you@example.com --provider aws
python /srv/database/seed/demo_environment.py --shared
```

The first two attach a private demo organization to your account. `--shared` builds, or rebuilds,
the one read-only demo organization any signed-in user can join as a viewer (§99).

The AWS recording matters more than a demo usually would: it is the only way to watch that half of
the product work end to end, because none of it has been run against a live account. It exercises
the normalizer, the AWS rules, the risk engine and the findings lifecycle. What it cannot prove is
whether the payloads it replays are the payloads AWS actually sends — that is what §1's checklist
is for.

Sign in first so Supabase has created your account; the demo organization attaches to it. Then run
it again with `--fix` to watch findings auto-resolve and the security score move. Nobody clicks
"resolved" — that is the point.

---

## Developing

Running the product needs the cloud; changing it does not. From a fresh clone:

```bash
tools/dev/setup.sh               # dev dependencies for both apps, and the git hooks
pre-commit run --all-files       # every standard, as CI's `repo` job runs it
```

`setup.sh` needs Node 22 or later and Python 3.12 (or `uv`, which fetches it).

| App | Check | Command, from `apps/api` or `apps/web` |
|---|---|---|
| API | lint, format, types | `ruff check .`, `ruff format .`, `mypy app` |
| API | tests | `pytest -q` |
| Web | lint, format, types | `npm run lint`, `npm run format`, `npm run typecheck` |
| Web | tests, build | `npm test`, `npm run build` |

The API tests that carry `@pytest.mark.integration` need PostgreSQL 16 and Redis 7, plus
`DATABASE_URL` (the RLS-constrained `cloudguard_app` role, never the owner), `DATABASE_OWNER_URL`,
`REDIS_URL`, `SUPABASE_JWT_SECRET` and `APP_ENV=test`. CI provisions them as service containers
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)), and that run is the supported one.

Rule tests run against fixture JSON in `apps/api/tests/fixtures/` — no database, no network, no
Azure. There is deliberately no mock connector in the application; test plumbing that replays
recorded Azure responses lives only in the test suite and the demo seed.

Every standard is a check that fails, not advice, and nothing is committed with `--no-verify`.
Where each one lives and how to ask for an exception is in
[`docs/STANDARDS.md`](docs/STANDARDS.md); the guidelines behind them are
[Python](docs/PYTHON_GUIDELINES.md), [TypeScript](docs/TYPESCRIPT_GUIDELINES.md),
[API](docs/API_GUIDELINES.md) and [Markdown](docs/MARKDOWN_GUIDELINES.md). A decision that changes
how the system works is recorded in [`docs/DECISIONS.md`](docs/DECISIONS.md) first.

---

## Layout

```text
apps/api/app/
├── core/          config, RLS-scoped sessions, auth, errors, enums, vocabulary
├── domain/        cloud-neutral resource model the rules operate on
├── connectors/    base contract, onboarding seam, azure/ and aws/
├── rules/         base contract, registry, engine, azure/<category>/, aws/<category>/
├── risk/          scoring config and scorer
├── graph/         the asset graph: attack paths, access, severance, identity
├── compliance/    framework catalogue (data), crosswalk and per-control coverage
├── remediation/   how to fix, and the Terraform edits behind a diff
├── reports/       PDF rendering
├── services/      scan orchestrator and pipeline, findings, dashboard, connections, audit
├── schemas/       response models behind the API envelope
├── models/        SQLAlchemy tables
├── api/routes/    HTTP surface
└── workers/       Celery app, the scan step tasks, and the periodic sweeps

apps/web/src/      React, TypeScript, Tailwind 4 and shadcn/ui primitives
database/          migrations (with RLS policies) and the demo seed
infrastructure/    Dockerfile, Railway, Supabase, Azure app registration, CI helpers
tools/             dev scripts (setup, hook runners) and Terraform-schema tooling
docs/              the specification, the decisions, the guidelines, the generated API reference
```

---

## The parts worth understanding

**Tenant isolation is enforced twice, independently.** The API derives `organization_id` from the
authenticated user's membership and never from the request. Separately, PostgreSQL enforces the
same boundary through Row-Level Security — and the API connects as `cloudguard_app`, a role that
owns no tables and therefore cannot bypass a policy. See
[`docs/DECISIONS.md`](docs/DECISIONS.md#1-rls-is-enforced-against-a-non-owner-role).

**UNKNOWN is never PASS.** A rule that could not read its data returns UNKNOWN. That never becomes
a finding — there is nothing to report — but it is recorded in `scan_evaluation_gaps` and surfaced
as a coverage figure. A storage API timeout must never read as "no storage problems".

**Findings and risks are separate.** "RDP is open" is a fact about a config. "An internet-reachable
production jump box accepts RDP from anywhere" is a risk. The same misconfiguration scores
differently on a dev box than on a production database, and the finding detail page shows the
arithmetic.

**Remediation is verified by the scanner, not asserted by a human.** There is no "mark as fixed"
button anywhere in the product, and the API refuses to set a finding to RESOLVED by hand.

**A fix is written into the customer's Terraform only by changing a value already there.** The
diff is built from a file the customer uploads, patches a resource it can identify exactly, and
declines — with the reason — rather than guess at an interpolated name. Nothing is applied for
them (§190).

**Attack paths are computed, not drawn by hand.** One graph holds assets, identities and the links
between them. What each link holds up is worked out exactly for every link at once, so the lines,
the ranked choke points and the what-if are one analysis, and a plan of cuts is simulated whole on
the server rather than summed from the lines' numbers, since two cuts can close what neither
closes alone (§122, §141).

**A connection is a tenant, and subscriptions are discovered beneath it.** The customer picks a
scope and never types a GUID — not the tenant id, not a subscription id. Entra reports which
directory consented, and that report is the only thing that ever writes `tenant_id`, which is what
binds a connection to a directory rather than to a claim. Subscriptions are then found by asking
Azure, so one created next month gets scanned instead of quietly missed.

**The read access grant is generated, not described.** After consent the product knows its own
service principal's object id in the customer's tenant, so it hands them a Cloud Shell script,
Bicep, or Terraform with every parameter already filled in. Customers who want more than Azure's
`Reader` can take the custom role instead: exactly the read operations the collector performs, no
`*/action` entries at all, generated from the connector so a test fails if the two ever disagree.

**A scan is durable steps, not one long task.** Planning, one collection per subscription plus one
for the tenant directory, then a single analysis — each recorded, claimed under a lease, and
retried on its own. A redeploy costs the step in flight rather than the scan, one unreadable
subscription does not take the other forty-nine with it, and every write a running step makes is
fenced on the claim it was made under, so a worker that stalled past its lease cannot settle a step
another worker has taken over. See [`docs/DECISIONS.md`](docs/DECISIONS.md).

**Compliance is evidence, never a verdict.** The `/compliance` view maps rules to framework
controls — including the controls nothing checks, so coverage cannot read 100% by omission. A
framework about one cloud is shown only to organizations that use it (§74). A control whose rules
returned UNKNOWN is _inconclusive_, not passing, and the headline figure counts conclusions rather
than passes. "78% GDPR compliant" is a sentence this product must never produce. Each control also
carries the provider readings its verdict rests on — which listing, when it was taken, under what
permission, whether the bytes are still stored — for the controls that _passed_ as much as the ones
that failed, and the whole assessment exports as CSV or JSON.

**The API never handles a password or a customer credential.** Sign-in is Supabase Auth —
Microsoft (Entra ID), email and password, or a magic link. Whichever route someone takes, a
password goes from their browser straight to Supabase and the API only ever verifies the JWT that
comes back. Azure access is separately a multi-tenant Entra app plus admin consent, so there is no
per-customer cloud secret to store or leak.
