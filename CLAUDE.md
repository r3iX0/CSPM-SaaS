# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this
repository.

## Project

CloudGuard — an Azure-first CSPM (Cloud Security Posture Management) SaaS. Modular monolith API +
Celery worker backend, React SPA frontend.

AWS is implemented behind the same connector seam — connector, IAM manifest, onboarding, change
events, fifty rules, CIS AWS 3.0 (44 of 56 catalogued controls) — and **has never been run against a
live AWS account**. It is reachable through the API and gated out of the UI by `AWS_ENABLED` until
`docs/AWS_INTEGRATION.md` §1's checklist passes. Treat every string in `app/connectors/aws/` as
unverified until then.

## Commands

### Whole repository

```bash
tools/dev/setup.sh               # once per clone: dev deps for both apps + git hooks
pre-commit run --all-files       # every standard, as CI's `repo` job runs it
```

Standards are the checks in `.pre-commit-config.yaml` (DECISIONS.md §191, `docs/STANDARDS.md`): Ruff
and mypy for Python, ESLint and Prettier for the web app, plus hygiene and gitleaks. Never commit
with `--no-verify`; CI runs the same hooks.

### Backend (apps/api)

```bash
pip install -e ".[dev]"          # install with dev deps
uvicorn app.main:app --reload    # dev server
ruff check .                     # lint
ruff format .                    # format
mypy app                         # type check
pytest -q                        # all tests
pytest -q -k "test_name"         # single test
alembic upgrade head             # run migrations
```

Requires PostgreSQL 16, Redis 7, and env vars: `DATABASE_URL`, `DATABASE_OWNER_URL`, `REDIS_URL`,
`SUPABASE_JWT_SECRET`, `APP_ENV=test`.

`DATABASE_URL` must use the RLS-constrained `cloudguard_app` role, not the owner.
`DATABASE_OWNER_URL` is the owner connection for migrations only.

### Frontend (apps/web)

```bash
npm ci                           # install (strict lockfile)
npm run dev                      # vite dev server (port 5173)
npm run build                    # tsc -b && vite build
npm run typecheck                # tsc --noEmit
npm run lint                     # eslint
npm run format                   # prettier
npm test                         # vitest run
```

## Architecture

**Monorepo**: `apps/api` (Python/FastAPI), `apps/web` (React/Vite/TypeScript), `database/` (Alembic
migrations + RLS policies), `infrastructure/` (Docker, Railway, Supabase, CI), `docs/` (specs).

**Request flow**: React → FastAPI (Supabase JWT auth) → Supabase PostgreSQL (with RLS) → Celery
worker (Redis) → Azure APIs (MSAL).

**Scanner pipeline** (`app/services/scan/`): Collect raw Azure JSON → store snapshot → normalize to
`CloudResource` → evaluate rules → score risk → persist findings. Raw JSON is stored verbatim for
later re-evaluation against new rules. `pipeline.py` drives the steps, `analyze.py` orders the
stages, and each stage is its own module taking one `AnalyzeContext` (DECISIONS.md §108).

**Scan execution** (`app/services/orchestrator.py`): a scan is durable `scan_steps` — PLAN, one
COLLECT per subscription plus one for the tenant directory, then ANALYZE once all have settled —
claimed under a lease and routed to the `collect`/`analyze` queues. Every write a running step makes
is fenced on the attempt it was claimed under: a step commits only through `ScanWriter.commit`
(`app/services/scan/writer.py`), which checks the step row `FOR SHARE` inside the transaction and
rolls back if the step was taken. Never call `session.commit()` in the scan package; append-only
rows (events, coverage, citations, edges, links) go through `writer.add` and are sent in bulk
(§108).

**One engine** (DECISIONS.md §168): Prowler ran beside the native rules as a second engine, behind
`ASSESS_ENABLED`, and is removed. The six frameworks it brought (CIS Azure 6.0, CIS AWS 7.0, AWS
FSBP, NIS2, HIPAA, ATT&CK) are data in `app/compliance/data/frameworks.json`, and `crosswalk.json`
beside it adds controls to a rule for frameworks the rule does not map itself — a rule's own
`compliance_mappings` always win (`app/compliance/crosswalk.py`). Both are hand-edited now. What
Prowler checked that no native rule does is `docs/NATIVE_COVERAGE_BACKLOG.md`: close an entry by
writing a native rule (and delete the entry), never by bringing a second engine back without a
DECISIONS entry first.

**Multi-tenancy**: Dual-enforced. App layer derives `organization_id` from JWT. PostgreSQL RLS
policies enforce row-level isolation via the `cloudguard_app` role.

**Rule engine** (`app/rules/`): `SecurityRule` ABC. Rules are deterministic — no network, no
database, no LLM calls inside evaluation. Results: PASS, FAIL, UNKNOWN, NOT_APPLICABLE. UNKNOWN is
never treated as PASS. Rules are per provider over neutral `ResourceType`s: an S3 bucket and an
Azure storage account are both `STORAGE_ACCOUNT`, so `matches()` compares the provider too. Never
write one rule that branches on provider — `remediation` is snapshot-copied onto findings, and `aws
s3api` is not a variant of `az storage account update` (DECISIONS.md §74).

**Graph** (`app/graph/`): `model.py` walks it; `facts.py` reads a hop's evidence — the role, the
network, the kind of identity — back off the two assets rather than storing it on the edge (§121);
`severance.py` answers what every link holds up exactly, in one forward pass per entry point, and
the ranked choke points, the what-if and the number on a drawn line are all that one analysis
(§122); `patterns.py` collapses routes that differ at one end only (§123); `access.py` walks a role
edge only as far as the role controls — the connector evaluates each role definition's actions into
neutral `AccessKind`s per resource type (`connectors/azure/access.py`), so Reader over a
subscription reaches nothing in it — and answers who holds access to an asset and what an identity
holds (§125); `identity.py` makes each identity one node when the graph is built — copies merged, a
connector's stand-in (`stub`) folded into the directory's record by `identity_id`, and a group's
recorded members drawn as `MEMBER_OF` edges — because the directory and each subscription are
normalized separately (§126); it also derives the directory's reach, `CAN_ACT_AS` (an application's
owners, its own credential, and application administrators, to its service principal) and
`CAN_TAKE_OVER` (Global Administrator and the roles that can become one, to every subscription)
(§128).

**Risk engine** (`app/risk/`): Scores findings by rule severity × asset criticality × data
sensitivity × public exposure.

**Cloud connectors** (`app/connectors/`): `CloudConnector` ABC with Azure and AWS implementations.
Azure uses REST + MSAL directly (not azure-mgmt-* SDKs) to store verbatim JSON; AWS uses
`aiobotocore`, because AWS is three wire protocols under SigV4 rather than one uniform REST surface
— the principle is unchanged, store what the provider said (DECISIONS.md §72).

**Onboarding** (`app/connectors/onboarding.py`): `ProviderOnboarding` ABC — how a customer grants
access, and how CloudGuard proves they did. `services/cloud_connections.py` holds the neutral half
and nothing provider-shaped; `tests/unit/test_provider_seam.py` fails the build on a provider import
from anywhere neutral.

**Regions**: AWS reads per region, so a _reading_ is scoped by evidence key **and** region while a
_verdict_ stays per key — a key is trustworthy only if every region's reading of it was
(DECISIONS.md §69). Never put a region into an `EvidenceKey`.

**Auth**: Supabase Auth on frontend, JWT verification on backend (ES256/RS256/HS256). Azure
integration uses a separate multi-tenant Entra app with admin consent.

**Findings lifecycle**: Auto-resolve when a later scan shows PASS on a prior FAIL.

**Scan wizard**: `ScanWizardProvider` is mounted in `Shell`, so a scan is started and followed from
any page and the header's `ScanIndicator` reopens it. It is a lazy-loaded `Dialog` of four steps
(Environment, Review, Scan, Result), the one view of any scan — a history row opens it rather than
drawing its own progress — with the scan it is open on in the URL (`?scan=`) (DECISIONS.md §154).
`ScanPipeline` only draws; `useLiveScan` reads the scan. The live view animates only what `GET
/scans/{id}/detail` reports — no timer-driven progress, no sub-phases the API does not expose
(DECISIONS.md §87). ANALYZE's sub-phases come from `scan_steps.phase`, written fenced on the
attempt; `GET /scans/{id}/events` pushes the same detail payload over SSE, re-reading through a
fresh `rls_session` each tick, and the browser falls back to polling whenever the stream is not live
(§88).

**Shell**: `Shell.tsx` runs on shadcn's `Sidebar` primitive. The collapse state is controlled from
the shell and stored in `localStorage` — the vendored `sidebar.tsx` has upstream's cookie write
removed, because CloudGuard sets no cookies (DECISIONS.md §84) — and its `SidebarInset` is a `div`,
so the shell's own `<main>` is the page's only one (§155).

## Code Style

- **Python**: follow
  `docs/PYTHON_GUIDELINES.md` (PEP 8, Google and Hitchhiker's condensed, with where this codebase
  departs; `.claude/rules/python.md`
  loads it for any
  `.py` work). Ruff (line-length 100, py312, rules E/F/W/I/N/UP/B/C4/SIM/RUF). MyPy strict with
  `disallow_untyped_defs`.
  B008 ignored (FastAPI
  `Depends()`). N818 ignored (domain errors named `NotFound`/`PermissionDenied`).
- **TypeScript**: follow `docs/TYPESCRIPT_GUIDELINES.md` (Google's guide condensed, with where
  this codebase departs; `.claude/rules/typescript.md` loads it for web code). Strict mode, path
  alias `@/` → `./src/`. React 18 SPA on Vite — not Next.js, no SSR, no server components; the
  build is static and Vercel serves it. React Router for routing, TanStack Query for server
  state.
- **UI**: Tailwind 4 is the styling layer (CSS-first: the theme is `@theme inline` in
  `apps/web/src/index.css`, there is no `tailwind.config.js`), with severity/status color tokens
  defined there — use the tokens, not raw hex. Font sizes are the nine steps of the type scale there
  (`text-caption`, `text-body`, `text-page`…), never `text-[Npx]`; a string in
  `i18n/en.ts` is one line (at most 90 characters) unless its key ends `Explain` and it is read
  through `InfoTip`, and `i18n/overBudget.ts` only shrinks (DECISIONS.md §166). The primitives are
  written in v4 syntax and v3 silently dropped it (DECISIONS.md §35), so do not downgrade.
  Primitives are shadcn/ui components vendored as source under
  `src/components/ui/`, built on `@base-ui/react` and installed through the shadcn CLI
  (`components.json` is checked in, style `base-nova`);
  `src/components/ui.tsx` is gone (DECISIONS.md §24 supersedes §12). Add new primitives with the
  CLI, or hand-write one in the same style — they are source, not a runtime black box, and are
  edited and reviewed like any other file. The severity scale stays deliberately separate from
  shadcn's chrome tokens: `destructive`
  means "this button deletes something",
  `critical` means "an attacker can reach your data", so `SeverityBadge` and
  `StatusPill` (in `src/components/security/`) are not shadcn's
  `Badge`. A control drawn outside the primitives with a focus halo takes `focus-ring` (or
  `focus-ring-inset`) beside it, the solid line the halo alone lacks; a route is named in
  `lib/pageTitle.ts`,
  and a detail page names itself with `usePageTitle`; a one-key shortcut asks `singleKeyShortcut`,
  so it can be turned off (DECISIONS.md §155); an unavailable
  `Button` stays focusable as `aria-disabled` (a raw
  `<button>` does the same by hand), and a list whose filters change speaks the count line it draws
  through `LiveStatus`
  (§165). A navigation styled as a button is a `Link` carrying
  `buttonVariants({ variant, size })`, never `Button render={<Link/>}` (DECISIONS.md §31);
  `buttonVariants` merges through
  `cn`, so a link and a button of one variant get the same classes (§135). Charts: Recharts (v3)
  inside shadcn's `ChartContainer`/`ChartTooltip`
  for anything with axes or series; hand-written SVG for one-off visuals like
  `ScoreRing` and `Donut`, whose segments name their share in a `<title>` (§149). `chart.tsx` emits
  a per-chart `--color-<key>` from its `ChartConfig` and defines no palette of its own — the ramp in
  `index.css` and the severity scale stay authoritative (DECISIONS.md §84). Graph canvases: React
  Flow (`@xyflow/react`),
  `base.css` only and coloured from the tokens, laid out by hop count rather than a force
  simulation, lazy-loaded, nothing draggable; on every canvas a click selects, the rest fades around
  what is selected (`kept`
  in
  `flowChrome.ts`), and pointing previews the same fading while nothing is selected; the canvas is
  one tab stop with arrow keys inside — the asset neighbourhood view, whose panel says what is
  selected and where a double click or Enter re-centres (`?around=`
  in the URL) (DECISIONS.md §101, §134), and the estate map on Assets, which draws subscriptions,
  groups and assets as boxes opened one lens at a time, with only the reach that crosses them
  (§111), laid out by longest reach so an arrow runs back only where reach loops and a long arrow
  passes through a slot kept for it (§134); it is one frame — canvas plus a side panel of contents
  and links — where a click selects and Enter or a double click opens (§133), and it is for
  exploring connections only: a selected box lists what reaches it and what it reaches, and where
  attack paths run through it, links to them on the attack-path page, narrowed to it (§138). The map
  replaced the hierarchy view, and its contents list is what the tree was (§112). The attack-path
  page draws every route as one graph
  (`RouteMapCanvas`, laid out by hop from the outside in), each line weighted by how many routes
  close if it is cut, with the cut simulated in place (§123), no label printed over another — a pair
  of lines between one pair of boxes speaks once (`pairSpeakers`)
  and
  `placeLabels` leaves out what would collide, most important first (§143), in one frame with a side
  panel that lists the routes and reads a traced one (§137) and, in its Simulate tab, answers for a
  plan of up to ten cuts made together — from
  `POST /attack-paths/simulate`, never summed from the lines' numbers, since two cuts can close what
  neither closes alone — with the plan in the URL (`cut`)
  (§141); a traced route is read in the panel by
  `RouteNavigator` — its stops always shown with where each place is entered (a link to the estate
  map), its links walked with up and down, the one being read saying what cutting it closes (the
  earliest cut and the link closing the most both marked) with "Add to the plan" beside it, and the
  routes before and after it in the list's order a left or right away; there is no step bar over the
  drawing, and a press on the traced route's own line or box reads that hop rather than planning it
  (§142). The list is ordered and narrowed by `listRoutes`
  (`routeOrder.ts`), searched by any asset on a route and sorted four ways, and pointing at a row
  previews its route on the drawing; a group's row carries its shape, the worst it reaches and its
  tracked and closed counts, with what a group is behind a question mark (§143). What is traced, the
  hop, the box picked, the place narrowed to, the search and the sort are in the URL (`trace`,
  `hop`, `through`, `scope`, `group`, `q`, `sort`) (§138, §142);
  `AttackPathRoute` stays the straight line one route is read as — on a finding, a risk, and in the
  PDF. Every graph canvas carries a `GraphLegend`
  above it, built from the shared
  `MARKS`, with how to read it behind a question mark and an entry only while its mark can be drawn
  (§136). The dashboard's region map is hand-drawn SVG too — a dot grid from `lib/geo/worldDots.ts`
  (generated by
  `scripts/build-world-dots.mjs`; edit the script, not the file) with coordinates in
  `lib/geo/regions.ts`,
  never from the API and never guessed for an unknown code; no map library (§113). Motion:
  `motion` (framer) for what React cannot express in CSS — route exits, list arrivals, rows sliding
  to their new places (`listLayout`,
  `MotionTableRow`) and indicators sliding between options (`layoutId`) — as
  `m.*` elements under `<LazyMotion strict>`, whose engine (`lib/motionFeatures.ts`,
  `domMax`) loads after the first paint (§149, §179), with timings from `src/lib/motion.ts`, moving
  only when a value it shows changed (`useValueChange`, `layoutSpring`,
  `drawPath`, §167), and reduced motion answered once by
  `<MotionConfig reducedMotion="user">` in `main.tsx`; keyframes in
  `index.css` for the rest. The one movement across pages is the browser's View Transitions API: a
  link into the graph (`GraphLink`,
  which loads its graph ahead, §139) grows what it was clicked from
  (`data-graph-source`) into the next page's frame (`data-graph-frame`) through
  `lib/viewTransition.ts`. It runs only where the API exists and the reader has not asked for less
  motion, never waits more than 300ms for the frame, and `PageTransition`
  holds its key across that one navigation (§140). Icons:
  `lucide-react` only, and any icon that means something comes from `src/lib/icons.ts` — resource
  types, factors, facts, change kinds — rather than being imported ad hoc, so one thing never gets
  two shapes; `SeverityBadge` and `StatusPill` deliberately carry no icon (DECISIONS.md §86);
  `ProviderMark` is the one hand-drawn exception, because Lucide has no brand logos. Do not
  introduce a second UI, chart, graph, or animation kit (Tremor, MUI, Chakra, Cytoscape) — Tremor in
  particular ships its own Tailwind token layer that would collide with the severity tokens; a swap
  needs an entry in `docs/DECISIONS.md`
  first.
- **Markdown**: follow `docs/MARKDOWN_GUIDELINES.md` (Google, Microsoft and IBM condensed;
  `.claude/rules/markdown.md` loads it for any `.md` work); markdownlint-cli2 holds the mechanical
  part (`.markdownlint-cli2.jsonc`).
- **Tests**: pytest with `asyncio_mode = "auto"`.
  `@pytest.mark.integration` for tests requiring live PostgreSQL. Frontend uses vitest +
  testing-library; every test's last rendered state is run through axe and a violation fails it, and
  ESLint runs `jsx-a11y`
  strict (DECISIONS.md §155).

## Deployment

- **API**: Railway (Docker, `infrastructure/docker/api.Dockerfile`). Start: `alembic upgrade head &&
  uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}`.
- **Frontend**: Vercel (auto-deploy from `apps/web`).
- **Database**: Supabase PostgreSQL. RLS role setup in `infrastructure/supabase/roles.sql`.
- CI checks that `infrastructure/supabase/roles.sql` retains the placeholder password — never commit
  a real credential there.

## Key Design Decisions (docs/DECISIONS.md)

- REST over Azure SDKs: raw JSON stored for re-evaluation
- Relationship edges indexed both ways at RuleContext construction
- No mock connector in production code; fixture-based unit tests instead
- API design (resources, status codes, errors, paging, security, the new-endpoint checklist):
  `docs/API_GUIDELINES.md`, loaded for API work by `.claude/rules/api.md`
- API response envelope: `{ "data": ..., "error": null, "meta": {} }`; a route returns
  `Envelope[Data, Meta]` built from models -- or, where a service's dict has other readers,
  validated from it against `ClosedModel`s, which refuse undeclared keys -- and documents
  `ErrorEnvelope` through `responses=`; every router is converted, and
  `tests/unit/test_typed_responses.py` walks every route, naming the few that answer with a file, a
  stream or a provider's protocol (§157)
- A step is fenced to the worker that claimed it; one advisory lock per scan target (§65)
- Nothing a request triggers blocks the loop or idles on a pooled connection: signing keys are
  fetched async at most once per 30s, reports render in a thread after the session is closed, and a
  refused enqueue is recorded in a fresh `rls_session` -- never a second commit on the request's
  (§158)
- Graph work runs in a thread through `graph_service.off_loop`, never on the loop and never with a
  session; the fair-use rate limit counts verified users, with a smaller allowance on routes marked
  `dependencies=[Costly]`; every request carries a server-minted `X-Request-ID`, read in service
  code through `core/request_context.py` (§161)
- Colleagues join by invitation: a single-use token stored only as its hash, carried in the link's
  fragment, accepted through `app.accept_invitation` only by the address on the caller's verified
  token (read from the claims `rls_session` now carries); only an owner makes or unmakes an owner,
  and the last owner stays (§162)
- The audit trail is append-only in the database and has one writer, `services/audit.record`, which
  stamps the caller's address and request id; every change a person makes is recorded, and owners
  and admins read it at `GET /audit-log` (§163)
- A request to a URL a customer typed goes only through `core/outbound.post_json` -- HTTPS on 443,
  every resolved address public, the connection pinned to the checked IP with the name kept for TLS,
  no redirects; webhook deliveries are owed once per endpoint and notification, claimed under a
  lease and sent outside any transaction (§164)
- The frontend catches its own failures: error boundaries, request timeouts, 401 signs out (§66)
- A reading is scoped by region; a verdict is not (§69)
- Two neutral scope columns plus `provider_ref`; the rename to `provider_directory_id` is deferred
  because `RawSnapshot` writes the old names into stored captures (§70)
- Onboarding sits behind `ProviderOnboarding`; the seam test has no exceptions left (§71)
- AWS's external id is generated server-side, is never client-supplied, and a role is never assumed
  without one (§73)
- Compliance frameworks about one cloud are shown only to organizations that use it (§74)
- Identifiers keep Azure's vocabulary; sentences do not — `app/core/vocabulary.py` and
  `src/lib/vocabulary.ts` (§78)
- A hop names its evidence, derived from the assets rather than stored on the edge (§121)
- What each link holds up is exact and computed for every link at once (§122)
- The attack-path page draws every route, and says a repeated route once (§123)
- A delete that takes a risk's findings (connection delete, scan purge) deletes the risks it leaves
  with no member; never resolves them (§124)
- A role edge reaches only what the role's evaluated actions control; an unread role or a data
  action under an ABAC condition is not claimed, and a role stored before evaluation walks as it
  always did (§125)
- One identity is one node: joined at graph build on `identity_id`, never in a capture; a group's
  members are recorded on it and `MEMBER_OF` is derived, never stored (§126)
- Removing a role assignment is one cut: an escalation line beside a role line is keyed as the role
  line (`AssetGraph.removal_key`); routes break ties in the remediation queue rather than raising a
  finding's score, which would count a route twice (§127)
- A Graph permission that is a directory role by another name (`RoleManagement.ReadWrite.Directory`,
  `AppRoleAssignment.ReadWrite.All`, `Application.ReadWrite.All`) is a directory power, matched on
  Graph's own catalogue, never on recalled ids; non-user principals holding a power get a directory
  record that the graph merges with the subscription's stand-in (§129)
- A role that could be activated under PIM is recorded apart from roles held (`eligible_roles`,
  `eligible_directory_powers`), drawn as `ELIGIBLE_FOR`, never walked, and listed on the Access tab;
  the scanner role is v8 for it; deny assignments are deliberately not read (§130)
- The directory's say over the estate is derived at graph build: `CAN_TAKE_OVER` is its own
  relationship so severance never folds a directory role into an Azure assignment; rebuilding from
  `links()` uses `derive=False` (§128)
- One shared demo organization (`organizations.is_demo`): joined as VIEWER through a SECURITY
  DEFINER function, visitors see only their own membership, and every write is refused there by flag
  as well as role (§99)
- A plan of cuts is simulated whole on the server; each cut is weighed against the rest
  (`needed_for`), and what to add next is ranked over the estate with the plan made (§141)
- A signed token names its purpose and the signer checks it; a consent link carries a nonce spent
  once, under a row lock, before any provider call; the API's own messages say Cleave, while names
  that exist in a customer's cloud or directory keep CloudGuard (§147)
- Role v9 reads six more types -- AKS, Container Registry, Cosmos DB, MySQL, Databricks, AI Search
  -- each through its own ARM listing and evidence key, modelled as neutral types with exposure from
  their own settings; a cluster runs as its control-plane and kubelet identities; Reader still
  reaches nothing, so a registry pull is not claimed (§169)
- Fourteen rules judge the v9 types (AKS, ACR, Cosmos DB, Databricks, AI Search); an absent setting
  fails only where the service documents the unsafe default, and is UNKNOWN otherwise; no policy is
  generated until their aliases are verified (§170)
- Five more rules (private endpoints, Databricks CMK, public function apps, Linux SSH passwords); a
  site's access restrictions now lower its exposure; HTTP on 80/443 stays unflagged by design (§171)
- Role v10 reads MySQL's TLS parameters; the tenant authorization policy is read under the
  Policy.Read.All already consented; nine tenant and MySQL rules, and `mfa_protected_apps` records
  which apps an all-users MFA policy covers (§172)
- The authentication methods policy and Group.Unified are read under consent already held; Tier 1 of
  the backlog is closed (§173)
- A single-setting check is a `PropertySpec` (`app/rules/property.py`) built into a rule by
  `property_rule`; state what absence means per spec, and declare the safe value where it is one
  value (§174)
- Server parameters are read by name (`get_postgresql_parameter`, `get_mysql_parameter`) under
  configuration reads already held; `PropertySpec.applies_when` limits a check to matching
  resources; Tier 2 needing no new permission is done (§175)
- Role v11 adds twenty-one reads and closes Tier 2: forty-eight rules over Defender settings,
  activity-log alerts, networks and flow logs, vault keys and secrets (management-plane attributes
  only, never a value), SQL defences, file shares, backup, just-in-time access and disks, which are
  now `ResourceType.DISK` assets; two checks moved to Tier 3 (§176)
- Six checks misfiled as "never to be ported" read configuration after all, and are ported: the AKS
  Defender profile, Defender CSPM, and four Cognito user pool settings under AWS policy v5
  (`ResourceType.USER_POOL`); Tier 3 is ported but for seven -- role v12 reads backup policies and
  scale sets (`BACKUP_VAULT`, `SCALE_SET`), availability checks are LOW with exploitability 0, and
  runtime versions are judged against a dated end-of-support table as of each capture's collection
  time; a `PropertySpec` whose `applies_when` field is unstated is UNKNOWN, and evidence failures
  are checked before it (§177)
- One rule engine: the Prowler second engine (§150, §151) and its Reader prompt (§153) are removed
  -- its frameworks kept as data, its uncovered checks a backlog, its findings, tables and database
  role dropped by migration 0047; an Azure grant is still read with `$filter=atScope()` (§168)
- A scan runs only the rules of the clouds it read (`RuleContext.providers`, from its accounts and
  directory, never its resources); compliance weighs only the rules of connected clouds (§184)
- A request body refuses a field it does not know (`RequestModel`); a `201` and a `202` carry
  `Location` and a `202` `Retry-After` (`app/api/links.py`); counted responses carry `X-RateLimit-*`
  and everything under `/api/` is `private, no-store`; `/health/ready` is a `503` naming the
  dependency; the OpenAPI document declares `bearerAuth` and short operation ids. Routes hold no
  queries (`tests/unit/test_thin_routes.py`): services flush, and the route commits the request's
  transaction because the RLS claims live in it (§194)
- A reading the tenant's licence rules out (sign-in activity, PIM eligibility) is
  `TaskOutcome.UNAVAILABLE`, raised as `ReadingUnavailable`: untrustworthy like FAILED, so its
  checks stay UNKNOWN, but counted, drawn and explained apart and never blamed on the role (§196)
- The scan wizard is a dialog and the one view of any scan, finished or running; the scan is in the
  URL (`?scan=`) (§154)
- A fix is read and worked in a sheet on the remediation page, keyed by finding so an untracked one
  opens too (`?fix=`); the finding page says the fix in brief and links there (§202)
- Tracking a fix is offered on the finding's fix card, in the fix sheet's header and under the
  queue for the worst untracked findings, through one `useTrack` (§205)
- Coverage by domain shows one framework at a time (`?domains=`), each section a row drawn by
  status with its counts, linking to the framework page narrowed to it (`?section=`) (§206)
- Settings is one page per topic under `/settings/*` (General, Members, Risk context,
  Integrations, Activity, Preferences); a form holds edits until Save and asks before they are
  left (`LeaveGuard`), an instant control answers in a toast; risk context is a table read from
  `GET /context-declarations`, edited in a sheet (`?account=`) and settable across many
  subscriptions, each a whole statement of its own (§207)
- The queue draws a rule's tasks as one row, and its fix as one sheet (`?rule=`) with the commands as
  one script over every asset; no batch endpoint and no group rescan -- marking done verifies (§203)
- Every observable control of CIS Azure 6.0, NIS2, ATT&CK, HIPAA, GDPR, NIST CSF and PCI DSS is
  answered by a rule; CIS Azure 2.0 leaves exactly twelve no API exposes
  (`tests/unit/test_compliance_closure.py`). Role v13 reads application and VPN gateways, locks and
  PostgreSQL firewall rules; consent adds `Policy.Read.DeviceConfiguration` and
  `AccessReview.Read.All`; HTTP(S) exposure, client certificates and a lock role are asked at LOW
  after all (§204)
- The Azure demo replays `tests/fixtures/azure_raw/snapshot_demo.json`, generated by
  `build_snapshot_demo.py` as a superset of `snapshot_mixed.json` — edit the script, not the JSON
  (§102)
