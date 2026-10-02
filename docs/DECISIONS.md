# CloudGuard — Implementation Decisions

Where the build made a choice the specification did not fully determine, or
deviated from it, the reasoning is recorded here. Companion to the spec, not a
replacement for it.

---

## 1. RLS is enforced against a non-owner role

**Spec:** "Tenant isolation enforced by PostgreSQL RLS, independent of app
logic" (requirement 4).

PostgreSQL exempts a table's owner from its own RLS policies unless
`FORCE ROW LEVEL SECURITY` is set. If the API connected as the owner — the
default for most FastAPI/SQLAlchemy setups — every policy in the schema would be
silently inert, and requirement 4 would be decorative.

So there are two database roles:

| Role | Used by | RLS |
|---|---|---|
| `cloudguard` (owner) | migrations, Celery worker | exempt |
| `cloudguard_app` | every API request | **enforced** |

Each request opens a transaction that sets `request.jwt.claims` and switches to
the `authenticated` role — precisely what Supabase's PostgREST does — so one set
of policies works unchanged against local PostgreSQL and a real Supabase
project. `app/core/db.py::rls_session`.

`FORCE ROW LEVEL SECURITY` is deliberately **not** set: the membership lookup
inside a policy runs through a `SECURITY DEFINER` function, and forcing RLS on
the owner would make that function re-enter the policy it is evaluating and
recurse. Not owning the tables is what makes the isolation real; forcing it is
not.

Two tests assert the premise itself rather than only its consequences:
`test_application_role_is_not_the_table_owner` and
`test_application_role_cannot_bypass_rls`.

## 2. Organization creation goes through a SECURITY DEFINER function

Creating an organization is a bootstrap problem: the creator is not yet a
member, so no membership-based INSERT policy can authorize it. Widening the
membership policy enough to allow it would also let any user insert themselves
into any organization.

`app.create_organization()` creates the organization and the creator's OWNER
membership in one transaction. The `organizations` table has no INSERT policy at
all, and `organization_members` accepts inserts only from an existing
OWNER/ADMIN. Covered by `test_cannot_add_self_to_another_organization`.

## 3. Azure is reached over REST with MSAL, not the `azure-mgmt-*` SDKs

**Spec:** the original build spec named "Azure SDK for Python" in
`ARCHITECTURE.md` §1. That table now records the REST decision instead, so this
entry is the reason it changed rather than a live disagreement.

Requirement 9 says every scan stores a snapshot, and the value of that snapshot
is that it holds the provider's _own_ JSON, so a scan can be re-evaluated later
against improved rules. Going through SDK model objects would mean deserializing
Azure's JSON into Python objects and then serializing it back out again — losing
fidelity for no gain. The management SDKs are also synchronous, which fits
poorly with an async collector.

Authentication still uses **MSAL**, Microsoft's own library, which is what
actually matters: the multi-tenant client-credentials flow against each
customer's tenant is not something to hand-roll. `httpx` makes the ARM and Graph
calls. `app/connectors/azure/client.py`.

## 4. Relationship edges are stored once, indexed both ways

`resource_relationships` stores an edge in its natural direction (an NSG
_protects_ a VM). Both endpoints need to query it, though: AZ-NET-001 asks an
NSG what it is attached to, AZ-CMP-001 asks a VM what guards it. Rather than
writing each edge twice, `RuleContext` derives the reverse index at
construction. `get_related` / `get_related_inverse`.

## 5. UNKNOWN is distinguished from absent at the normalizer, not the rule

A rule can only report UNKNOWN honestly if the normalizer preserved the
difference between "we read this and it was empty" and "we never read this".
The normalizer therefore emits `None` where a call failed and `[]` where it
succeeded and found nothing — and omits `mfa_methods` entirely for users whose
authentication methods were never queried.

`test_unqueried_user_has_no_mfa_key_at_all` and
`test_empty_diagnostics_list_is_not_none` pin this down, because it is the kind
of distinction that erodes silently.

## 6. A rule that raises is UNKNOWN, never PASS

`RuleEngine._safe_evaluate` catches exceptions from rule code and converts them
to UNKNOWN. A crashing rule must degrade coverage, not report a clean
environment. This is the one broad `except` in the evaluation path and it is
load-bearing.

## 7. Asset context defaults to UNKNOWN, not LOW

The risk formula needs asset criticality, data sensitivity and exposure. Most
real environments are partially tagged. The normalizer infers what it can from
tags and naming conventions, then falls back to `UNKNOWN` — which the risk
engine scores at 3.5, just below HIGH.

Defaulting to LOW would quietly discount every untagged production asset, which
is exactly the population most likely to be untagged.

## 8. `Findings` are keyed on (organization, rule, resource)

A re-detection updates the existing row rather than inserting a new one, so
`first_detected_at` means what it says and a finding keeps its identity across
scans. A finding that was RESOLVED and is detected again is reopened rather than
duplicated — a regression is not a historical record.
`test_findings_are_not_duplicated_across_scans`,
`test_a_regression_reopens_a_resolved_finding`.

## 9. Enum columns are varchar with a coercing type decorator

Columns are `varchar` rather than native PostgreSQL enums so adding a value is a
code change rather than a migration that takes a lock. That alone would return
plain strings on read, making `FindingStatus.is_open` fail at runtime on exactly
the paths that matter. `StrEnumType` (`app/models/base.py`) stores the value and
returns the enum.

## 10. Rescanning a finding runs a full scan

`POST /findings/{id}/rescan` queues a complete scan rather than re-running the
single rule. Fixing one thing frequently changes another — closing a public port
may reroute traffic, disabling public network access may orphan a dependency —
and a narrow re-check could report a fix that a wider view would contradict.

## 11. Authentication is Supabase only

Production authentication is Supabase Auth. The browser signs in one of four
ways — Microsoft (Entra ID), email and password, a magic link, or a password
reset — and sends the resulting JWT to this API, which only ever _verifies_ it
(`app/core/security.py`). The API cannot tell the routes apart and does not need
to: it checks the signature and reads the user id.

Microsoft is offered first because this is an Azure-first product; the account
someone signs in with is usually the same directory account that later grants
admin consent. That sign-in grants CloudGuard no access to Azure _resources_ —
scanning access is the separate consent flow in `AZURE_INTEGRATION.md`.

Passwords are Supabase's to hold. One typed into `SignInPage` is posted directly
to Supabase's auth API over TLS; it never reaches this API, is never logged
here, and there is no column for it in this schema. What remains true without
qualification is that CloudGuard has no token-minting code — the test suite
signs its own tokens rather than the product shipping a code path that hands out
credentials. See #13 for why the earlier development-only variant was deleted
rather than gated.

## 12. shadcn/ui components are hand-written — **superseded by §24**

**Spec:** shadcn/ui (`ARCHITECTURE.md` §1).

shadcn/ui is a copy-in component collection installed via an interactive CLI,
not a dependency. The handful of primitives this prototype needs — badge, card,
button, field, empty state — are written directly in `src/components/ui.tsx` in
the same style (Tailwind + `clsx` + `tailwind-merge`). Running the CLI later to
add richer components remains possible.

## 13. Cloud-only: no local development mode

**Spec:** `ARCHITECTURE.md` §1 listed Docker Compose for local development.

CloudGuard now targets exactly one environment — Supabase, Railway, Vercel —
and cannot be run anywhere else. `docker-compose.yml` and `.env.example` are
gone, there are no localhost defaults in `Settings`, and the API validates its
entire environment at import and refuses to start if anything is missing.

Three things follow, and the third is the point:

- **The dev sign-in route is deleted**, not disabled. It minted a valid token
  for any email address with no password. Gating it behind an environment check
  meant one wrong variable turned it back on in a deployment — as nearly
  happened when Railway's "suggested variables" pre-filled `APP_ENV=development`
  from `.env.example`. Code that cannot be reached by accident is code that is
  not there. `app/core/security.py` now only verifies tokens; the test suite
  signs its own.
- **`APP_ENV` defaults to `production`** and no longer accepts `development`.
  A forgotten variable fails closed rather than silently relaxing every check.
  `test` is the only exemption and exists for CI.
- **Database engines are built lazily.** Removing the localhost defaults meant
  `create_async_engine("")` ran at import and broke test collection. Importing a
  module should not open a connection pool anyway, so `get_app_engine()` /
  `get_owner_engine()` construct on first use.

The cost is real and worth stating: there is no way to run CloudGuard offline,
and the 45 integration tests need the PostgreSQL that CI provisions. The
tradeoff is that a whole class of "worked locally, insecure in production" bug
is now unrepresentable — which for a security product is the right side to
err on.

## 14. Resource Graph reads inventory; ARM reads everything a rule judges

**Spec:** `AZURE_INTEGRATION.md` collected inventory with the ARM resource
listing, one paged call per subscription.

Inventory is the one collection task that asks for every provider's resources
at once, and it is the one that scales worst as a tenant grows. Azure Resource
Graph answers it in a single KQL query per subscription, and — the part that
decides it — states `totalRecords` for the query, so a short read is caught by
comparing two numbers the service supplied. ARM paging could only ever infer
completeness from whether the page cap was reached, which is a guess about the
tail of a list nobody saw.

The split is deliberate and narrow:

- **Resource Graph collects inventory only.** Its rows are a projection of
  ARM's own state and can be minutes stale — fine for "what exists here",
  wrong for the configuration a rule passes or fails on. Every listing a rule
  reads stays on ARM, where the snapshot keeps the provider's JSON verbatim
  (§3), so replay is unaffected.
- **`ResourceGraphClient` is a separate class,** not more methods on
  `ArmClient`. Same host and same retry behaviour; different paging
  (`$skipToken` rather than `nextLink`), different quota (per principal rather
  than per subscription), different error surface. One class would put two
  paging models behind one name and leave a reader unable to tell which one a
  call is subject to.
- **The projection excludes `properties`.** Inventory answers what exists;
  carrying configuration here would hold a second, staler copy of data no rule
  reads in every snapshot.

**Cost:** the custom role gains `Microsoft.ResourceGraph/resources/read` and
`ROLE_VERSION` moves to `v2`. The action string was verified against the
published RBAC operations reference on 2026-08-30 — it is real, and described
as "Submits a query on resources within specified subscriptions, management
groups or tenant scope", so the template deploys. Whether Resource Graph
actually _checks_ it is not established: the service documents its requirement
as read access to the resources being queried, and its only documented 403 is a
subscription list the caller cannot read. Granting it is the cheaper side of
that uncertainty, and the connection probe (§14, validation) will settle it —
a `v1` connection whose Resource Graph probe succeeds proves the action
redundant, and the role can then be narrowed. Connections deployed on `v1` lose inventory —
and only inventory — until the customer redeploys, which the role-drift
machinery already tells them to do. Falling back to the ARM listing when the
query is denied would hide that, and leave the customer on a role that will not
serve the next thing built on Resource Graph either.

## 15. Concurrency is capped over requests, not over tasks

**Spec:** none. The plan capped fan-out per task (`DETAIL_CONCURRENCY`) and the
executor ran a whole wave at once.

Those two limits multiply, and nothing owned the product. A wave of nine tasks
with eight detail calls apiece is seventy-odd requests against one
subscription, and the number moves every time a task joins the plan. Azure
answers that with 429s, which the retry path turns into wall-clock time and,
past the retry budget, into recorded gaps: a scan that collects _less_ because
it asked for more at once.

`RequestLimiter` caps what Azure actually meters. One limiter per scan is
shared by every client the plan builds, a permit covers a single HTTP attempt,
and it is released before any `Retry-After` sleep — a throttled call must not
hold a slot while it is deliberately not using the network. The per-task limits
stay as fairness between tasks inside a wave; this is the protection for the
subscription.

It also makes the cost visible: `azure.collection_finished` now carries the
request count, the peak in flight and the time spent queued behind the ceiling,
because a scan that never waits and one that waits a minute are otherwise
indistinguishable — and only the second is evidence the number wants changing.

## 16. A scan's collection plan is derived; carrying evidence forward is opt-in per key

**Spec:** `ARCHITECTURE_REVIEW.md` §7 and §12 item 10 — "the evidence planner:
rule-set union minus fresh evidence".

Two halves, and only the first came out the way the review assumed.

**Derived, not written down.** What a scan collects is now the union of every
enabled rule's `requires_evidence` plus the connector's `baseline_evidence`,
and the provider's plan is filtered through it. Three Azure keys are named by
no rule — inventory, role assignments, role definitions — and they are the
reason the baseline exists rather than an oversight to be tidied away: the
first is what the customer's asset list is made of, and the other two are what
the graph's identity edges are built from. A rule-derived plan without a
declared baseline would have dropped all three while every check carried on
passing.

Today the union equals the plan exactly, so nothing is dropped and no request
is saved. What the derivation buys is that the equality is now checked: a
listing whose last reader was deleted fails a test instead of being collected
at the customer's expense for ever, and a rule added with a new dependency
starts being collected for.

**Reuse is off unless a key earns it.** Evidence has carried provenance and a
content hash since migration 0010, so a complete reading from an earlier scan
can stand in for a new one. Almost none of it should. The strongest claim this
product makes is "verified fixed", and it survives exactly as long as nothing
verifies a fix against evidence collected before the fix: a customer who
corrects a storage account and asks CloudGuard to check must be answered from
the storage account as it is now, or the word means nothing.

So `EvidenceKey.reuse_window` defaults to `None` — read it again — and a window
is granted per key, by the provider that produces it, only where a stale reading
cannot change a verdict. Being expensive to collect or slow to change are
reasons to _want_ a window; they are not reasons one is safe. Exactly one Azure
key qualifies today: `role_definitions`, the catalogue of what each role
permits, several hundred near-static rows per subscription that no rule reads.
Role assignments are deliberately excluded on the same reasoning inverted —
they change constantly and every privilege path is drawn from them. A test
fails the build if any key some rule reads is ever given a window.

A carried reading is recorded COMPLETE, because that is what it was: age is not
incompleteness, and degrading it to PARTIAL would tell every rule reading it to
return UNKNOWN. Its evidence row keeps the _original_ `collected_at`, so the
next scan's freshness question is asked about the read rather than about the
last scan that reused it — otherwise one reading renews itself for ever.

## 17. Asset context is its own module, and a customer declaration is a floor

**Spec:** `ARCHITECTURE_REVIEW.md` §12 item 11 — "a context engine as its own
module, out of the normalizer, with every fact carrying source and confidence.
Add customer-declared context."

Context — how critical an asset is, how sensitive its data, which environment it
belongs to — is the multiplier that turns a finding into a risk. It lived in
three helper functions inside the Azure normalizer, which was wrong in two ways.
None of it is Azure-specific, so a second connector would have written its own
slightly different copy of the tag vocabulary and the production/development
word lists. And there was nowhere for the customer to disagree: normalization is
a pure function of a capture, and a declaration is not in the capture.

`app/context/` now holds inference and resolution separately. `infer()` stays
pure and runs in the normalizer's path; `resolve()` applies declarations in the
pipeline, where the database is — read at _evaluation_ time rather than frozen
into the capture, so marking a subscription production changes how its findings
rank today, including on a replay of an older reading.

**Every value carries its source.** `ContextSource` runs NONE → INFERRED →
TYPE_FLOOR → PROVIDER_TAG → INHERITED → CUSTOMER, and confidence is a property
_of_ the source rather than a column beside it, so the two cannot drift apart —
there is no reading of "a naming guess, confidence 0.95" worth being able to
express. `GET /assets/{id}` returns the pair, because the value alone cannot be
argued with: "CRITICAL" invites the question "says who", and the answer used to
exist nowhere.

**A declaration is a floor, not an override.** "This subscription is production"
is a statement about everything in it, so nothing inside it scores below what
was declared — but an asset carrying its own `criticality=critical` tag is the
more specific of the two facts, and lowering it to the subscription's level
would discard the better one. So the higher value wins and the declaration wins
ties. The consequence is the property that makes this safe to hand a customer:
nothing declared can make an asset look _safer_ than the capture already showed,
so the worst a mistaken declaration does is over-rank something.

Environment is the exception to the floor, because a name has no maximum: a
person naming it beats a substring match on a resource name every time. That is
the case the feature exists for — the customer whose production runs in a
subscription called `sandbox-eu`.

**Declarations are a table, not columns on `cloud_accounts`.** A discovered
subscription records what Azure said and discovery runs again; a declaration
records what a person said, and mixing the two into one row would make them
untellable apart. The table also carries who declared it and why, because "who
says this is production" is a question people ask of the label rather than of
the audit log. The worker's RLS arm grants SELECT only: a background job that
could write a declaration would be CloudGuard putting words in the customer's
mouth.

**Not done, deliberately.** Per-resource declarations are the obvious next ask
and are a later migration rather than a nullable column nothing writes. And a
declaration does not rescore stored findings on the spot — a risk score is what
a scan concluded, and rewriting one from an API call would leave findings
carrying numbers no observation ever produced.

## 18. A claimed fix is verified on a backoff, and not-verified has three answers

**Spec:** `ARCHITECTURE_REVIEW.md` §12 item 12 — "a verification engine:
expected-state records, targeted plans, backoff for eventual consistency, and
`INSUFFICIENT_EVIDENCE` as an outcome distinct from `STILL_FAILING`".

Marking a task done recorded a timestamp and told the customer to run a scan.
If they did, and if that scan happened to produce a PASS on the same rule and
asset, the finding resolved. Every part of that is a coincidence: nothing
recorded what CloudGuard was expecting to see, nothing looked again on its own,
and every way of _not_ being verified came out as the same silence — the finding
stayed open and the customer was told nothing.

`remediation_verifications` holds the expectation, written when the claim is
made: this rule, on this asset, should now PASS. Every scan that reaches a
verdict on that pair settles it or spends one attempt — every scan, not only one
started to verify something, because a nightly scan that passes the rule a
customer fixed this morning has answered their question and making them wait for
a scan with the right label on it would be ceremony.

**The backoff is about the cloud, not about load.** Azure applies a change to
its control plane before every read path agrees about it, so a check run a
minute after the work reads the old state and is right to — the environment
genuinely still said that when it was asked. Four attempts over roughly five
hours (5m, 15m, 1h, 4h), then an answer. It stops rather than retrying
indefinitely because an answer is the product: a verification that never settles
is the same silence this table was built to remove, dressed up as diligence.

**Three outcomes, because "not verified" is three different pieces of news.**
STILL_FAILING is CloudGuard looking and disagreeing. INSUFFICIENT_EVIDENCE is
CloudGuard failing to look — its own problem to explain, not the customer's to
fix. That is exactly the FAIL/UNKNOWN line the rule algebra already draws,
carried up to the one screen where somebody is told whether their work counted.
Telling a customer who has done the work that their fix failed, when the
evidence never arrived, is the same overclaim as a PASS nobody earned, pointed
at the person instead of the environment. A verification that once saw a
definite FAIL settles as STILL_FAILING even if later attempts went blind: having
seen the check fail is the stronger and truer statement.

**A scan settles only what it read.** Spending an attempt on a subscription the
scan never opened would burn the customer's answer on a reading that never
looked at their fix. A pending verification the scan reached no verdict on
_does_ count as an attempt, recorded as UNKNOWN — the scan covered the scope and
said nothing about that asset, usually because the asset is no longer there, and
without that a verification whose asset vanished would stay pending for ever
with the scheduler starting scans to settle it.

**Not done:** targeted collection. A verification scan could collect only the
evidence its rule needs — the planner (§16) is the seam for it — but a scan
narrowed that way must also evaluate only what it collected fresh, or it would
re-assert stale verdicts about every rule it did not look at. That is a rule
about what a narrowed scan may conclude, not a planning decision, and it is the
next thing here rather than part of this.

## 19. Privilege escalation is read from role definitions, never from role names

**Spec:** `ARCHITECTURE_REVIEW.md` §12 item 15 — the second correlation
template, which "needs edges the graph does not yet have".

The edge is `CAN_GRANT_ROLES`, drawn beside `GRANTS_ROLE` rather than instead of
it: they are different claims about the same pair of nodes, one saying what a
principal may do today and the other that the ceiling is whatever it decides to
give itself.

Whether to draw it is decided by the role _definition_, and that is the entire
difficulty of this feature. **Owner and Contributor both carry
`actions: ["*"]`.** The only thing separating them is that Contributor excludes
`Microsoft.Authorization/*/Write` in its `notActions`. A check that matched role
names, or that read `actions` without honouring the exclusions, would report
every Contributor assignment in existence as a privilege escalation path — one
false alarm per subscription, on the feature whose whole value is that it finds
the thing no rule can. Reading the definition also catches what a name list
never could: a tenant's own custom role granting exactly that one action, which
is precisely the case worth finding.

Matching is segment-wise and case-insensitive, because ARM patterns are
(`Microsoft.Authorization/*`, `*/read`) and Azure's own definitions mix `/Write`
and `/write` freely.

**A chain ends at the scope, not at the identity.** The scope is the size of the
answer — naming the subscription an identity could take over is what turns an
alarm into something someone can act on. And a chain requires an entry point: a
directory administrator who can hand out roles is over-privileged, not a chain,
and reporting one would invent the half of the story that makes it urgent.

**Unmonitored critical assets stay unbuilt, with a reason.** The third template
the review lists is one finding (missing diagnostic settings) on one asset whose
criticality the finding formula already multiplies by. A scenario for it would
be a second opinion on a single finding rather than several findings seen as one
thing — the same double-count §16 avoids by keeping scenario risks out of the
security score. It earns a template when it spans several assets; as one rule on
one asset, the risk score already says it.

The fixture changed with this: `snapshot_mixed.json` described a role called
Contributor carrying Owner's permissions, which was never a real Azure role. It
now carries the real exclusions, so the fixture proves the distinction rather
than sidestepping it.

## 20. History is a feed of transitions, never a log of having looked

**Spec:** `ARCHITECTURE_REVIEW.md` §2.10 and §12 item 18 — the temporal model.

Three tables, and one rule that shapes all of them: a scan that finds nothing
different writes nothing. The alternative -- a row per scan per asset -- is
easier to write and produces a feed whose signal falls as the customer scans
more often, which is backwards.

**Asset changes are five things, not everything.** An asset appearing or
disappearing, and a change to exposure, sensitivity or criticality -- the three
values the risk engine multiplies a finding by. Diffing whole provider payloads
would be a change feed nobody can read, and the drift that matters is already a
finding.

**Disappearance is a transition, so it needed a column.**
`cloud_resources.absent_since` is set when a scan that covered an asset's scope
does not find it, and cleared when it returns. Derived from `last_seen_at`
instead, an absence would need a scan cadence nobody records, and would
re-report itself on every scan for ever. The row is never deleted: a finding
about the asset is still history worth keeping, and something that vanishes for
a week and comes back is one asset with two events rather than two assets.

**A finding's timeline sits beside the audit log, not instead of it.** They
answer different questions for different readers: the audit log is "what has
anybody in this organization done", for a security reviewer; the timeline is
"what happened to this finding", for whoever is looking at it. Only the second
can be complete, because only it holds the transitions a _scan_ made, which no
person did -- and that distinction is the point, since a scan observing a check
pass is verification while a person moving a status is a decision.

**A superseded replay writes no history at all.** It re-evaluates an old capture
and makes no observation, so it records neither changes nor events, exactly as
it records no risk history and resolves no findings.

## 21. Remediation is declared once and the artifacts are generated from it

**Spec:** `ARCHITECTURE_REVIEW.md` §12 item 20 — "`expected_state` and
`verification_spec` beside the human text, with IaC and Policy snippets
generated from the same declaration that generates the RBAC artifact".

The prose stays. `SecurityRule.remediation` is what somebody reads at two in the
morning and it is snapshot-copied onto every finding, so an old finding keeps
the guidance it was raised with. What is new is the half a machine can act on.

**One setting has three names, so the declaration carries three.** The
normalized field the rule reads, the ARM alias a policy matches on, and the
Terraform argument that sets it — and often three values too: ARM says
`publicNetworkAccess: "Disabled"` where the provider says
`public_network_access_enabled = false`. Emitting the ARM spelling into HCL
would produce a line that does not mean what it says.

**The test runs in both directions**, exactly as the RBAC ones do. An asset
built from a rule's own declaration must make that rule PASS; one violating it
must make it FAIL. Without the second half the declaration is documentation, and
documentation drifts — a rule whose check moved on while its remediation stayed
put tells a customer to change something that no longer closes the finding.

**A policy is generated only where it can enforce the whole rule.** One covering
half of it would pass an asset that still fails, and a customer who deployed it
would believe the class was closed. Where no policy can exist — a directory
setting, a condition over a child collection — the API says so rather than
emitting a definition that deploys and checks nothing, which is the same
discipline `rbac.py` records for permission strings nobody verified: an alias
that looks plausible and is not real fails the customer's deployment outright.

**`also_accepts` exists because floors are not equalities.** A rule accepting
TLS 1.2 or higher, expressed as a policy pinned to 1.2, refuses an account
configured better than asked. That is a change-control incident rather than a
bug report, so the accepted set is declared rather than discovered after
deployment.

The generator negates the expected state, because a policy matches what it
refuses. Doing that by hand per rule is how one ends up denying every compliant
resource, which is why it is computed in one place.

**The vocabulary is three comparisons, and stops there.** `EQUALS` for a
setting, `NONE_MATCHING` and `NOT_EMPTY` for the collections most rules actually
judge. That covers eight of the ten rules; anything beyond it stays undeclared
rather than half-declared, because a remediation that describes most of a check
is worse than one that describes none — the customer satisfies what they were
shown and the finding stays open. A collection expectation carries a witness,
which is both the clearest way to say what is being looked for and what lets a
test build the asset a rule must fail.

**An empty expectation has to say why.** Two rules genuinely have none: one
judges a ratio across the directory, the other a relationship between a machine
and the security groups governing it. But an empty declaration is also what a
rule looks like when nobody could be bothered, and those must not be
indistinguishable — so a test requires an empty one to carry a reason and
something the customer can still run.

## 22. The customer wires up change events, because CloudGuard cannot

**Spec:** `ARCHITECTURE_REVIEW.md` §12 item 19 — "change-triggered scans via
Azure Event Grid".

The whole design falls out of one refusal. Creating an Event Grid subscription
is a **write** in the customer's tenant. CloudGuard holds no write permission
anywhere, that is the strongest security claim it makes, and it is not one to
spend on saving a customer a copy-paste. So CloudGuard generates the command —
one per subscription, because that is how Event Grid is scoped — and the
customer runs it, exactly as they deploy the scanner role.

**The webhook is reachable by anyone**, so the signed token is the whole guard.
It is the same HMAC scheme the ARM template endpoint uses and is separated from
it by `purpose` alone, which is why the webhook checks that field rather than
treating a valid signature as proof of intent. Every rejection returns the same
400 whether the token is malformed, expired, or signed for another connection:
distinguishing them would let a caller enumerate connection ids.

**It answers 200 to what it drops.** Event Grid retries a non-2xx for hours, and
redelivering an event CloudGuard has already decided it cannot act on is load
with no possible outcome. The validation handshake is answered before any
database work and for a connection that need not exist yet, because that
exchange happens at the moment the customer is watching their `az eventgrid`
command.

**Three things stand between an event and a scan**, and without them the feature
is a denial of service against the customer's own API limits, paid for by them.
Events outside the resource providers a rule reads are dropped. A burst marks
the connection and the scan waits for quiet, so one deployment is one reading
rather than forty. And a connection is not scanned for a change more often than
a floor, so an afternoon of deployments is not an afternoon of scans — the same
storm arriving more slowly.

**The webhook only records.** Event Grid times the response; starting a scan
behind it would put a queue, a database write and a provider call between Azure
and its acknowledgement. The sweep that acts on a settled burst is a beat task,
using the same advisory lock and in-flight check every other scan trigger uses.

Turning the feature off closes the webhook immediately, before the customer has
deleted anything in Azure — their subscription keeps delivering to an endpoint
that now refuses it. That is the right way round: a switch that appears to stop
something and does not is worse than one that leaves a tidy-up to do.

## 23. The provider seam is tested, not asserted

**Spec:** `MULTI_CLOUD.md` §8, and the claim in `ARCHITECTURE.md` §6 that
everything above `CloudConnector` is provider-neutral.

That claim was false in three places, and each was invisible to every test of
behaviour because with one provider they all give the right answer:

- the scan pipeline imported Azure's evidence-key enum to ask which keys a
  permission category holds, so a second connector's categories would have
  degraded no rules at all;
- the permissions endpoint returned Azure's grants for every provider, so the
  first AWS customer would have been told CloudGuard wanted Entra admin consent;
- the change-event service hard-coded ARM operation names and the `az` command.

All three now ask the connector or the registry. `get_connector_class` answers
the questions that are properties of a _provider_ rather than of a connection to
one, so nothing needs credentials to ask what permissions a cloud wants.
`get_change_feed` does the same for change events, which arrive before any
connection has been resolved.

**`sign_state` moved to `app/core/signing.py`.** Nothing in it was ever Azure —
it signs a dictionary — and it lived under `connectors/azure/auth.py` only
because that is where the consent round trip needed it first. Three unrelated
flows now use it, and the next provider's onboarding would have imported Azure's
package to get a HMAC.

**One exception is scheduled rather than accidental.**
`services/cloud_connections.py` still imports Azure's auth, client and RBAC
modules, and `MULTI_CLOUD.md` §8 step 5 deliberately puts that split _after_ a
second connector exists: it is a refactor whose right shape is knowable from two
examples and guessable from one. It is named in the test, so it stays one known
exception rather than becoming a habit — a new leak appears in the failure
message beside it.

**The test looks at imports, not text.** A docstring naming Azure is fine and
unavoidable; an import is what makes neutral code depend on one cloud, and what
a second connector would have to break.

## 24. shadcn/ui is now the primitive foundation (supersedes §12)

**Spec:** none. A frontend brief asked for shadcn/ui as the component
foundation, and §12 required a written decision before that swap — this is it.

§12's reasoning was that a handful of badges, cards and buttons did not justify
a runtime primitive dependency, and for those it was right. What it did not
survive is the second half of the product: a findings table with filters, a
remediation panel with tabs, an organization switcher, a mobile navigation
drawer, a command palette. Every one of those is a focus trap, an escape
handler and a set of ARIA relationships, and hand-writing them is how a security
product ends up with a dialog that keyboard users cannot leave.

So the primitives are now `@base-ui/react` through shadcn's registry, vendored
as source under `src/components/ui/`. Base UI rather than Radix because it is
what the current CLI installs by default; the distinction §12 drew — source, not
a runtime black box — still holds, and these files are editable and reviewed
like any other.

**The severity scale stays separate, and that is the load-bearing part.**
shadcn's tokens are chrome — `primary`, `destructive`, `muted`. CloudGuard's are
meaning: `destructive` says "this button deletes something" and `critical` says
"an attacker can reach your data", and a design system that collapsed the two
would eventually paint a cancel button and a public storage account the same
colour. `tailwind.config.js` therefore carries both layers, and
`SeverityBadge` is deliberately _not_ shadcn's `Badge`.

UNKNOWN keeps its dashed border and gains an icon. Colour alone would hide the
product's most important distinction — "we could not look" versus "we looked and
it was fine" — from a reader who cannot separate the hues.

**The compatibility seam is gone.** `components/ui.tsx` was written to let ~20
call sites keep passing `title`/`subtitle`/`action` to a card while the
primitives underneath changed. Every one of them has since moved to the composed
API, so the file was deleted rather than left as a second way to build the same
card. `StatusPill` moved out first: it is security vocabulary, not chrome --
RESOLVED means _a scan observed the fix_ -- and it now sits in
`components/security/` beside `SeverityBadge`, which is where a reader would
look for it.

**One thing the CLI got wrong, worth recording.** `init` writes Tailwind v4 CSS
(`@theme inline`, `@import "shadcn/tailwind.css"`) and leaves a v3
`tailwind.config.js` untouched, so every `bg-background` referred to a class
that did not exist and the build failed outright. The v3 bridge in
`tailwind.config.js` is hand-written, and maps `var(--x)` directly rather than
through `hsl()` — the variables hold complete oklch colours, and the usual v3
`hsl(var(--x))` recipe would silently render every one of them black.

## 25. The theme is applied before React exists, and "system" is a real choice

**Spec:** none. The dark palette had been defined since §24 — every neutral
token and a re-lit severity scale under `.dark` — with nothing in the product
able to put that class on the document.

Three decisions worth recording.

**Three states, not a switch.** `light`, `dark` and `system` are stored as
given, because "system" is a standing instruction rather than a synonym for
whichever theme the machine happened to prefer at the moment of choosing. A
laptop that goes dark in the evening takes CloudGuard with it, and a boolean
could only ever record one day's answer. The store subscribes to
`prefers-color-scheme` and follows it only while the choice is `system` — an
explicit choice is not a default for the OS to overrule.

**The class is set by an inline script in `index.html`, before the bundle
loads.** React cannot do this: by the time it mounts the browser has painted a
white page, and correcting it afterwards is a flash of white in a dark room —
which for a console people sit in front of at 2am during an incident is worse
than having no dark mode. That script is the one place in the frontend that
duplicates a constant (`cloudguard-theme`, and the `dark` class), so
`lib/__tests__/theme.test.ts` reads the real `index.html` and fails if the two
copies ever drift.

**`next-themes` is gone.** It arrived as a dependency of the vendored `sonner`
component, which nothing mounts. Two theme stores writing one class to one
element is how a toast ends up light on a dark page, so `sonner.tsx` reads
`lib/theme.ts` like everything else and the dependency was removed.

The severity scale is re-lit rather than reused across the two surfaces, for
the reason §24 gives: a light severity background on a dark page glows, and a
glowing badge reads as more urgent than the one beside it — a ranking the rules
never made.

**A React 18 bug this surfaced.** `Button` came from the registry without
`forwardRef`, which is correct for React 19 where a ref is an ordinary prop.
This app is on React 18, so every Base UI trigger rendering a Button
(`render={<Button />}`) handed a ref to a plain function component: React warned,
and the element the popup anchors to was never captured. `Button` now forwards
its ref, which fixes the existing `Sheet` trigger as well as the new menu.

## 26. The command palette searches what can actually be searched

**Spec:** none. `cmdk` was installed with the shadcn primitives and nothing
used it.

The palette (`components/layout/CommandPalette.tsx`, Cmd/Ctrl-K) jumps to any
page, any asset by name, and any rule. Three decisions are worth recording
because each one is a limit rather than a feature.

**Findings are not searched from the palette, and it says so.** At the time it
was built `GET /findings` had no text search; §27 has since added one, and the
palette could now use it. It still does not, because the rows it would return
are the same rows the findings page ranks and filters properly -- the palette
is for jumping to a _thing_, and a finding is reached through its rule
(`/findings?rule_id=`) or its asset. What the palette must never do is the
option that was rejected outright: filtering the loaded page in the browser,
which would search a hundred findings out of thousands and report "nothing
matches" for the rest. The empty state names what was searched rather than
implying everything was.

**One authority over what matched.** `shouldFilter={false}`: assets are matched
by the API (`name ILIKE %search%`) and everything else by the same substring
rule in this file. Leaving cmdk's fuzzy scoring on top would let it re-rank and
sometimes drop rows the server had already decided matched.

**No mutations in it.** No "run a scan" entry, though it would be easy: every
row is one keystroke from being triggered by whatever happens to be
highlighted, and a scan reads a customer's entire environment. Actions with a
cost stay behind a button somebody meant to press.

Pages come from `NAV_GROUPS`, the same source the sidebar renders, so the two
cannot drift; a test asserts every navigable page appears.

## 27. Searching and ordering belong to the database once a list paginates

**Spec:** none. Two pages had the same silent bug and it was worth naming
rather than just fixing.

`GET /findings` and `GET /risks` both paginate and both report a `total`. The
findings and risks pages asked for neither `limit` nor `offset`, took the API's
default hundred rows, and rendered them as the whole set -- so a tenant with
four hundred findings saw a hundred with nothing on screen saying so.

That alone is a display bug. What made it a correctness one is what the pages
then did with those rows: the findings page searched and sorted them **in the
browser**. Search over one page of an estate answers "no findings match" for
data that was never in the browser to match against, and a client-side "worst
first" puts the CRITICAL on page four below the LOW on page one. In a product
whose entire claim is _we tell you what matters_, both are wrong answers rather
than missing features.

So `search` and `sort` moved into the endpoints (`docs/API.md`), the pages
paginate against the real `total`, and a filter change resets to page one
because page four of the old result describes nothing in the new one. An
unrecognised `sort` is a 422 rather than a silent fallback: quietly ordering a
list differently than asked is the same class of lie in a smaller font.

`sort=severity` is a SQL `CASE` over the severity ranking rather than a column
sort, because alphabetically CRITICAL comes before HIGH but LOW comes before
MEDIUM -- an ordering that looks plausible enough on screen to be believed.

The risks page also gained the filters it had never had (level, status, kind,
and a search), all of them server-side. UNKNOWN is offered as a risk level
because the engine genuinely assigns it, and leaving it out of the filter would
hide precisely the risks CloudGuard could not score. Findings and routes stay in
one ranking by default, per §14: a route outranking the findings inside it is
only visible where they are listed together.

## 28. Connect and Scans are split by what each part fetches

**Spec:** none. `Connect.tsx` was 749 lines and `Scans.tsx` 593.

Length alone would not have justified the change. What did is that both files
mixed several independent request lifetimes, and reading either one made it
genuinely hard to see which request fired when: the scan list polls every two
seconds while anything is in flight, a running scan's card polls a second
endpoint every three, and the panels underneath -- stages, what was collected,
how many findings a delete would purge -- each fetch only when opened. Those are
four different answers to "when does this run", and they were interleaved down
one file.

So the split follows the fetching rather than the layout. `components/scans/`
now holds `ScanCard` (the two live polls), `ScanDetailPanel` and
`CollectionPanel` (open-only), and `DeleteScanConfirm` (which reads the purge
count). `components/connections/` holds `ConnectionCard` (polls until the
connection can actually be scanned), `ScheduleControl` and `RemoveConfirm`. Each
page is now a list, a control and the states around them: 125 and 105 lines.

`IN_FLIGHT` lives in its own module because both the page and the card decide
things from it, and a constant exported beside a component switches off fast
refresh for that file.

**Two behavioural notes from the move.** The schedule dropdown is now a Base UI
`Select`, whose options live in a portal that is not mounted while the control
is closed -- so the trigger renders its label from the value rather than
delegating, or an interval the list does not offer would show as a bare number.
And the connection's status ticks gained icons: three signals distinguished only
by green-versus-grey are three signals a colour-blind reader cannot tell apart.

`@testing-library/user-event` is now a dev dependency. The Base UI listbox is
built out of pointer events and `fireEvent.click` never reaches an option, so
the schedule tests were asserting against a control they could not actually
operate.

---

## 29. The remediation queue joins the finding in the browser

**Spec:** none. `UI.md` section 3 describes the queue; nothing said what a row
had to contain.

`GET /remediation` returns the task and nothing of the finding behind it -- no
title, no rule, no asset -- so every row said the same three things: a priority
badge, a status, and a link reading "View finding". Everything on the card was
about the record and nothing was about the problem, and a person deciding what
to work on next had to open each one to find out what it was.

The finding is therefore fetched per task in the browser, under the same
`["finding", id]` cache key its own page uses, so opening a row from the queue
costs no request at all. That is a round trip per task rather than a join, which
is the right trade at this size: the queue is bounded by work a human created,
and the alternative -- widening the endpoint's response -- is a change to a
stable API for a display concern. It stops being the right trade if the queue
ever grows into the hundreds, and at that point the serializer should carry a
finding summary.

`RemediationOut` is otherwise unchanged, and the API note the endpoint returns
when work is marked done is now shown rather than discarded: marking a task done
never closes a finding, and the sentence saying CloudGuard will look again is
the whole reason that is not a broken promise.

## 30. Actions that do not navigate say so in a toast

**Spec:** none.

Three actions on the finding page and one in the remediation queue changed a
record without moving the reader anywhere, and two of them said nothing at all
-- marking a finding in progress and accepting a risk both wrote to the audit
log and left an unchanged screen. `sonner` was already vendored as
`components/ui/sonner.tsx` and never mounted.

Toasts are used for exactly this: the outcome of an action that has no page of
its own. What stays inline is anything a reader must be able to re-read later --
a failed report generation, an expired session, the verified-fixed banner --
because a message that disappears after four seconds is not where a security
product puts a fact somebody may need to act on.

---

## 31. A navigation styled as a button is a link, not a button

**Spec:** none.

Fourteen places dressed a route change as a button by handing Base UI's
`Button` a `render={<Link />}`. Base UI warned on every one of them, and the
warning was right for a reason that matters: it renders with `nativeButton`
true, which asserts native button semantics over an element that has none.

The tempting central fix -- defaulting `nativeButton` to false whenever a
`render` is passed -- is wrong, and the tests caught it. Base UI then gives the
element `role="button"`, so an anchor announces itself as a button to a screen
reader and loses what a link is actually for: middle-click, ctrl-click, "open
in new tab", and the status bar showing where it goes.

So these render a real `Link` wearing the button's classes --
`className={buttonVariants({ variant, size })}`, wrapped in `cn()` when there
is anything to merge -- which is shadcn's own recipe for this case. `Button` is
kept for things that act rather than navigate. The rule is worth stating because
the wrong version reads as more idiomatic: _if it changes the URL it is a
`Link`, whatever it looks like._

---

## 32. A report can leave things out, but not the terms it is read on

**Spec:** `UI.md` section 3 described two fixed documents. A frontend brief
asked for period, scope and section options.

**Sections and a window, yes.** `GET /reports/{kind}` now takes `days` (the
activity window: verified fixes, completed work, and how much of the trend line
is drawn) and `sections` (a comma-separated subset of top risks, attack paths,
compliance, remediation, findings). Two of those sections are new content
rather than new switches: the report can now carry the shortest attack paths
with the link worth cutting, and remediation progress with work _claimed_ and
fixes _proved_ side by side and never summed.

Three rules hold the shape:

- **The posture block and the evidence caveats are not optional.** Coverage,
  staleness and collection failures are the terms every number in the document
  is read on. A report that could drop "12% of checks reached no verdict" would
  let somebody produce a cleaner-looking PDF by unticking a box, which is the
  same transformation — "we could not look" into "we looked and it was fine" —
  that this product refuses everywhere else.
- **What was left out is printed on the cover.** Once a PDF has been forwarded
  twice, an omission somebody chose looks exactly like an absence of evidence,
  and only one of those is true.
- **An absent `sections` means all of them; an empty one means none.** The two
  are distinguished rather than collapsed, because collapsing them would make
  the emptiest request produce the fullest document. An unknown section name is
  a 422 rather than a silent omission.

**The window does not touch the posture, and that is deliberate.** A score, the
open findings and the severity split are a reading of _now_. Giving them a date
range would invite "our score over the last quarter", which no scan can answer
and which this product does not measure. What the window legitimately bounds is
activity — fixes verified, work completed — and the trend, which is cut to the
window rather than resampled: every point is a reading that happened.

**Scope is not offered, and the reason is not effort.** A per-subscription
report would have to recompute the score, the coverage ratio and the freshness
for that scope; anything less produces a document whose headline is estate-wide
and whose list is one subscription, which is the most quietly misleading report
this product could print. It stays out until the posture itself can be scoped.

---

## 33. A finding says what it is part of, from its own endpoint

**Spec:** `UI.md` section 3 listed what a finding detail must answer. Nothing
there said whether the finding was one fault or one link in a route.

The graph has been able to answer this since attack paths were built, and the
finding page could not ask: `ResourceSummary` carries the database id and the
routes are keyed by provider resource id, so the browser had nothing to match
on. The gap was real rather than cosmetic — the findings list ranks problems
one at a time, and a medium misconfiguration on a host standing between the
internet and customer data is not a medium problem.

`GET /findings/{id}/attack-paths` answers it. Three choices in that shape:

- **Its own endpoint, not a field on the finding.** It costs a graph build, and
  the page that answers "what is wrong" must not wait on one. The panel is
  fetched after the page renders; a finding with no asset never asks at all.
- **Membership is asked of the whole route.** A misconfiguration on the jump
  box at the start and one on the storage account at the end are the same
  problem seen from two ends. The response says which by way of `asset_role`
  (`ENTRY`/`STEP`/`TARGET`), because that is what decides the action.
- **An empty answer is not an all-clear, and does not read as one.** What counts
  as sensitive is declared per subscription, so an estate that has classified
  nothing yields no routes. The panel says that in as many words rather than
  printing a reassuring dash.

`serialize_path` moved from the attack-paths route into `services/graph.py`,
because two endpoints now render the same object and a second copy of that
serializer is how two screens start disagreeing about one route.

---

## 34. The asset hierarchy is counted server-side, or it is a lie

**Spec:** `UI.md` section 3 described a filterable inventory. A frontend brief
asked for the subscription → resource group → resource tree.

The page already grouped by resource group, in the browser, over the fifty rows
it had. That is fine as a visual aid to one page and wrong as a hierarchy: a
resource group whose assets straddled two pages appeared twice, each time
holding a fraction of its findings — and the number a reader takes away from a
tree is exactly the count it puts beside a group's name.

So `GET /assets/hierarchy` aggregates over the whole estate in one query and
returns it whole. The tree it feeds is a summary, not a page of rows; the list
keeps paging, and the two are offered as two readings of one inventory rather
than as one replacing the other. Expanding a group asks `/assets` for that
group, so no level of the tree is ever assembled out of something it only
partly has.

**The resource group is read, not stored.** An ARM id spells out its own
subscription and resource group, so the fifth segment _is_ the group —
`split_part(provider_resource_id, '/', 5)`, positional because ARM treats
`/resourcegroups/` and `/resourceGroups/` as the same path, and guarded by an
`ILIKE '/subscriptions/%'` so a directory principal's id is never sliced into
an invented group. The backend derives containment the same way when it builds
the asset graph, so the tree and the graph agree by construction.

**A directory asset is not an asset with an unknown subscription.** Users and
service principals belong to the tenant, which outlives every subscription
under it, so they are a named scope of their own. For the same reason, assets
sitting directly in a subscription are labelled as that rather than as
"Ungrouped", which would read as somebody's tagging oversight instead of as
where they actually are.

---

## 35. Tailwind v4, because the primitives were already written in it

**Spec:** none. §24 adopted shadcn/ui through the CLI and recorded that the CLI
wrote v4 CSS against a v3 config, patched at the time with a hand-written
bridge in `tailwind.config.js`.

The bridge was not enough, and the way it failed is the point: **v3 does not
error on v4 syntax, it emits nothing.** Four constructs in the vendored
components compiled to empty:

- `p-(--card-spacing)`, `w-(--anchor-width)`, `origin-(--transform-origin)` —
  the parenthesis shorthand. Cards lost every scrap of internal padding;
  popovers, selects and tooltips lost their anchor sizing.
- `[--card-spacing:--spacing(4)]` — emitted the literal `var(--spacing(4))`,
  which is not a value, so the variable was never set either.
- `in-data-[...]`, `@container/...` — dropped variants.
- `ring-foreground/10` — an opacity modifier against an oklch `var()` colour,
  which v3 cannot compute. **This is the one that was visible from across the
  room.** The class was dropped while the `ring-1` beside it survived, so every
  card, dropdown and tooltip fell back to Tailwind's default ring colour —
  blue — and the whole dark theme was outlined in it.

So the app is on v4, which is what the components were written for. The theme
moved into `src/index.css` as `@theme inline` and `tailwind.config.js` is
deleted; `@custom-variant dark (&:is(.dark *))` keeps the class-based theme
§25 requires, and `* { @apply border-border outline-ring/50 }` now resolves,
which is the recipe §24 had to work around.

**The severity scale keeps its own layer, unchanged.** `--color-critical` and
friends are declared beside the semantic tokens and mapped from the same
`--sev-*` variables, for the reason §24 gave: `destructive` says a button
deletes something and `critical` says an attacker can reach your data.

Autoprefixer is gone — v4 prefixes and inlines `@import` itself.

## 36. A provider's failure is stated once, not once per key it cost

**Spec:** none.

Azure reports collection failures per evidence key, so a single missing admin
consent arrives as three entries carrying the same nine-hundred-character
sentence about ungranted Graph scopes. The dashboard printed the joined string
verbatim, and the coverage card — the place a customer goes to find out what
CloudGuard could not see — became a wall of the same paragraph repeated.

Identical causes are now stated once with the keys they cost named beside them,
and the message is clipped with the rest one click away. Clipped rather than
summarised: this is the text an administrator will paste into a search box, and
a paraphrase of an Azure error is not an Azure error. The splitting is
defensive about the provider's own punctuation — a part that does not look like
`key: message` is joined back onto the one before it, because a message cut in
half on its own semicolon is worse than a long one.

---

## 37. The overview is an argument, not a grid of cards

**Spec:** `UI.md` §1 named the parts of the executive dashboard. It did not say
what order they go in, and order is most of what a dashboard is.

The page now reads top to bottom as one argument, each step the precondition for
the next: where the posture stands and which way it moves; what that number is
made of; how much of the estate the opinion was formed from; what to deal with
and what those faults form _together_; whether any of it is being fixed; what
moved while you were away.

Four choices in that shape are load-bearing:

- **Coverage is third, not last.** A score computed over half an environment is
  a different claim from the same number over all of it. Placed after the risk
  list, the caveat arrives once the reader has already acted.
- **UNKNOWN is in the severity strip**, at the end and labelled "no verdict".
  It is not a fifth severity and never a pass, but a reader tallying what is
  wrong has to see what could not be answered in the same glance rather than
  further down the page.
- **A ranked risk carries the terms it was ranked by.** The list is the
  product's whole argument and used to ask the reader to take it on trust; the
  three context levels are already columns on the risk row, so a rank now reads
  as a reason.
- **Inventory counts are not headline figures.** Assets and resource counts are
  true and answer a different question; every pixel one takes is a pixel not
  spent on what is wrong. They remain on the pages that are about them.

**Three requests, deliberately.** `/dashboard` is a set of database aggregates
and answers quickly. Attack paths cost a graph build and changes are a windowed
feed, so folding them in would make the numbers everybody came for wait on the
two panels nobody scrolls to first. Both fail quietly — a dashboard that cannot
draw its last panel is still a dashboard.

**Two small backend additions, both aggregation only.** `coverage.categories`
(one grouped read of the evidence table) says _which_ part of the estate could
not be read, because "identity is unreadable" and "storage is unreadable" call
for different people to fix them. `top_risks[]` gained `kind` and the three
context levels, which were already loaded on the row.

**What was left out for lack of data, rather than invented.** "12 fixed this
week, 3 reopened", per-risk effort and impact estimates, and a recommended-next-
actions list ranked by effort all need numbers the API does not expose today.
The remediation panel therefore reports only what is measured: the verified-fix
rate, verified fixes in the last thirty days, and what is still open — and every
one of those counts an observation rather than somebody's claim to have fixed
something.

`SecurityScore` and `CoverageIndicator` were deleted rather than left beside
their replacements. Two components that render the same fact are how two screens
start disagreeing about it.

---

## 38. Every chart has to earn its form

**Spec:** none. A request for "prettier, with charts" — which is a request to
_show_ more, and the way that goes wrong is showing it in shapes that flatter
the data.

Five forms, each chosen by the question rather than by variety:

- **Rings only for a whole divided in two or three.** Coverage — reached a
  verdict versus did not — and finding status. A ring encodes one share well
  and comparison badly, so nothing ranked is ever drawn as one.
- **Severity is a single stacked bar**, not a five-slice pie: lengths on one
  line are compared exactly, angles around a circle are not, and it costs 8px
  of height rather than a panel.
- **Risk bands and framework coverage are bars from a common baseline**, which
  is the form a ranking asks for. Both are plain elements — a list of widths
  does not need a charting runtime, a canvas and a resize observer.
- **The posture trend is an area on a fixed 0–100 axis**, with the score bands
  painted behind it at 8% so the height _means_ something without the line
  changing colour as the data does. Every reading is dotted, because the points
  are the moments CloudGuard actually looked and a smooth line between them
  invites belief in measurements that were never taken.
- **The estate treemap is the one place area is the right encoding.** A tree
  names the parts and a table ranks them; neither answers "is my problem
  concentrated or spread out", which decides whether a customer sends one team
  or six. Tint is a _rate_ — findings per asset — so a large group is not darker
  merely for being large.

**Sparklines carry the series the payload already had and nothing rendered.**
`history[].findings_by_severity` and `attack_path_count` were in every dashboard
response and shown nowhere; they are now the line under each severity count and
beside the attack-path panel. "One critical" and "one critical, and there were
none last week" are the same number and a different Monday.

**No dual axes anywhere.** Route counts and a 0–100 score share no scale; two
y-axes in one frame let any two shapes be made to look correlated, so the second
series is a sparkline of its own instead.

**Status colours stay reserved.** Severity is a status palette, not a
categorical one: it is never spent on "series 4", and every chart that uses it
also prints the label, so nothing is carried by hue alone.

**Motion is a statement about honesty, not polish.** Numbers count up on mount
and when the value actually changes — never on a poll that returned the same
figure, which would make an untouched page twitch three times a minute. Charts
animate once on mount and not on update. Lists stagger by 30ms and cap at eight
rows, past which it reads as a slow page rather than as arrival.
`prefers-reduced-motion` is honoured globally in `index.css` and again per
component, and it degrades to the _finished_ state rather than a slower one.

**One backend addition:** `remediation_activity`, eight weeks of findings
raised, verified fixed, and reopened, read from the transition log. Reopenings
are counted separately and never netted against fixes — a fix that did not hold
happened, and subtracting it would hide the pattern the panel exists to show.

**A chunking trap worth recording.** `DonutLegend` lives in its own module away
from `Donut`. Imported from beside the ring, it dragged Recharts into the
dashboard's own chunk — 15kB became 206kB — and quietly undid the lazy loading
the charts were written for.

---

## 39. A select's trigger renders its own label, everywhere

**Spec:** none. Reported from a screenshot: the changes window read `30`
instead of "Last 30 days".

§28 recorded this once, for the schedule dropdown, and fixed it there: Base UI
keeps a select's options in a portal that is **not mounted while the control is
closed**, so `<SelectValue />` has no item to read a label from and falls back
to the raw value. What that entry did not do was generalise, and every other
filter in the product carried the same bug — severity reading `CRITICAL`, group-
by reading `resource_type`, the report window reading `90`. The machine's word
for the thing, shown to the person.

So the pattern is a component now. `SelectField` takes one list of options and
feeds both the trigger and the menu, which closes the second half of the same
problem: a label that was written twice and updated once. Every select in the
product — sixteen of them across nine files — goes through it, and
`components/ui/select.tsx` is imported by nothing else.

**The worst instance was not a filter.** The scans page picks which
subscription to read, keyed by the account's row id, so closed it displayed a
UUID: an identifier the customer has never seen, cannot recognise and cannot
act on. `ScheduleControl`, which §28 had already fixed by hand, moved onto the
same component rather than staying a second implementation of it.

Three details worth keeping: `id` is forwarded so a `FieldLabel`'s `htmlFor`
still lands on the trigger; an unrecognised value falls back to printing itself
— a stored filter from an older build should look odd rather than make the
control look broken; and `fallbackLabel` overrides that where the value is an
identifier rather than a word, so an unknown subscription reads "Unknown
subscription" and an interval the list does not offer keeps its own "18 h".

---

## 40. The risks list shows live risks, and the schedule moved to the scans page

**Spec:** none. Three bugs from screenshots, and two of them had the same
shape — a screen showing something the product itself does not believe.

**The risks page listed every risk row ever raised.** A risk outlives the
finding it was scored from: the finding closes, a later scan supersedes it, and
the row stays. Unfiltered, that rendered four identical "Storage account allows
public access" cards, all marked Open, on an estate the dashboard was
simultaneously reporting two open findings for. The two screens disagreed
because only one was applying the product's own definition of live — a finding
risk counts while its finding is open, a scenario counts until the route
closes — so `GET /risks` now applies it by default. Asking for a status by name
still reaches the rest, which is how a resolved risk is looked up rather than
lost.

**The rule is _settled_, not _strict_, and the difference matters.** A risk is
hidden when its findings say it is over, never merely because they fail to say
it is current: a risk linked to no finding at all stays listed. The link table
is the only thing that could vouch for such a row, so its absence is not
evidence the risk has been dealt with — and hiding it would trade four
duplicates for an empty page, which is the worse failure for a security
product. The first version of this filter was strict, and an integration test
that inserts a risk without links caught it.

**Tabs rendered as a vertical strip beside their own panel.** The registry's
classes matched `data-horizontal`, a bare attribute Base UI never writes: it
writes `data-orientation="horizontal"`. So `data-horizontal:flex-col` compiled
to a rule nothing matched, the root stayed a flex row, and the remediation
panel's Steps/CLI tabs stacked into a narrow column. Same family as §35 —
syntax that is silently inert rather than loudly wrong.

**A select whose value is the empty string had no label.** `SelectField` treated
empty as "nothing selected" and fell through to the placeholder, but the
schedule control's "Manual scanning only" _is_ the empty value, so that control
rendered blank — which reads as broken rather than as switched off. Options are
consulted first now, empty string included.

**The schedule is a row inside one panel, not a card inside a card.** Moved as
it was, `ScheduleControl` kept its own border and heading inside the new
panel's border and heading, so one setting rendered as two nested boxes both
titled "Automatic scanning". The control now draws only the control; the panel
around it says what it is, once.

**Automatic scanning moved from the connection card to the scans page**, at the
customer's request and for a reason worth recording: the connections page
answers "can CloudGuard see my cloud", a setup question asked once, while the
scans page answers "when was this last read, and when will it be read next" —
and a schedule is the second half of that sentence. A history of runs with no
visible cadence makes the gaps between them look like something that happened
rather than something that was chosen. The connection card keeps a line saying
where the setting went and what it is currently set to: somebody who configured
it there once should be told it moved, not left to conclude it was dropped.

---

## 41. The remediation queue is reachable from the finding

`POST /remediation` shipped with the API and no screen ever called it. The
queue's own empty state told the reader to "assign a finding from its detail
page", and the detail page had no control that did so — the queue could
therefore only ever be empty, and the one screen that ranks work by impact
against effort was unreachable from every screen that produces work.

The control sits under the recommended fix rather than in the row that holds
"Rescan to verify". Tracking work is a statement about who is going to do the
thing written above it; the verify row is where a person asks for proof, and the
two must not blur into one strip where a button recording intent looks like a
button producing evidence. The caption under it says the finding stays open
until a scan observes the fix, because assigning does move the finding to
`IN_PROGRESS` server-side and that status is the closest thing in the product to
a person marking a security problem solved.

Whether a finding is already tracked is read from `GET /remediation` under the
key the queue page itself uses, rather than by widening the finding detail
response. The detail endpoint is on the hot path of the page the product is
really about, and a join added there to decide the label on one button is a cost
paid by every reader who never presses it. Sharing the cache key also means
opening the queue afterwards costs no request. The API refuses a second open
task per finding, so a button offered unconditionally would be one that
sometimes only produced an error: once a task exists the control is replaced by
what is true — that the work is queued, and where.

A cancelled task does not count as tracking. The work was called off, and the
finding can be picked up again. A verified or accepted finding is offered
nothing at all: one has no work left in it and the other is a recorded decision
not to do the work.

---

## 42. Setup is a wizard at its own URL, and the step is derived, not remembered

Connecting Azure leaves this application twice: to Microsoft for admin consent,
and to Azure Portal for the reader role. Each trip returns through a full page
load, so a dialog over the connections list could not survive either one, and a
step number held in React state is gone before the customer comes back. The
wizard therefore lives at `/connections/new` and `/connections/:id/setup`, and
which step it shows is computed from the connection itself
(`lib/connectionStage.ts`): consent is recorded by the callback, read access by
the probe that runs on every read of the connection. That is the only answer
still correct after the tab is closed, or after the consent link is opened by an
administrator on a different machine.

The consent callback now redirects into that URL rather than to the connections
list, on failure as well as on success — the signed state comes back on a denial
too, so a failure knows which connection it belongs to and can be shown against
the step that produced it, beside the button that starts consent again. Only a
state that cannot be verified at all has nothing to return to, and that is the
one case that still lands on the list.

The steps moved out of `ConnectionCard` entirely. A card that carried a consent
button, a deploy button, a discovery retry and a scope list was the largest
component in the product and the first screen a customer ever used, and it read
as four things to do at once when three of them were not yet possible. The card
now states what a half-finished connection is waiting for and links to the step
it stopped on. What genuinely outlives setup — the subscription scope list, and
the discovery retry, since a subscription created next month appears on the next
read — is shared between the card and the wizard as one component rather than
copied.

Handing the consent link to someone else is a first-class branch of the consent
step, not advice in a paragraph. Admin consent needs a Global Administrator and
the person evaluating CloudGuard usually is not one; the step offers the link
together with a sentence explaining what is being approved, because a bare URL
pasted into a chat window is exactly the request an administrator should refuse.
For the same reason every waiting step offers "Finish later" alongside "Cancel
setup": both grants are somebody else's to give, and a flow that can only be
completed or abandoned makes a customer sit on a spinner waiting for a colleague
who is in a meeting.

A stalled deployment names its three causes — propagation, wrong scope, and
Contributor rather than Owner — with the scope one worded for the scope this
connection actually covers. Changing scope is offered there as discard and start
again, because the scope is what both the consent state and the role assignment
were bound to; there is no edit that would leave either of them meaning what
they meant.

---

## 43. The connections page is a table of rows, and each row answers the same four questions

Four connections as four stacked cards answered "how is this one connection
doing" four times, and never answered the question the page is actually opened
for: is every environment being read, and how recently. That is a comparison, so
the shape is a row — connection, status, subscriptions, last read — with
everything needed to _act_ behind a disclosure rather than in front of it.

Column labels sit above the rows, but this is not a `<table>`. Every row opens
into a two-column panel, which a table cell cannot hold without colspan
gymnastics or a nested grid inside a cell; on narrow screens the labels are
hidden and each row stacks carrying its own.

The status column does not print the enum. `ACTIVE` is true of a connection with
every subscription unticked, and `PENDING` is true both of one waiting on an
administrator and of one whose deployment failed an hour ago — so `statusSummary`
answers "is CloudGuard reading this environment" in words, with a second line
saying what to do when the answer is no. Last read is derived from the
subscriptions rather than fetched, including ones now out of scope: the question
is when this environment was last looked at, and one excluded yesterday was
still looked at last week. It is rendered as elapsed time, because an absolute
timestamp asks the reader to subtract against a clock they cannot see.

A closed row costs nothing. The list endpoint already carries subscriptions, so
the per-connection request runs only while a row is open — and the polling that
used to justify itself on this page (a card left open was what noticed a
finished deployment) moved with setup into the wizard. `change_events_enabled`
and `last_change_event_at` are serialized onto the connection for the same
reason: the cadence line needs both halves of the answer, and fetching the
second half from the change-events endpoint would be one request per row to
render one line.

Each subscription row carries its own history — first seen, new since last read,
excluded by you and when. `scope_changed_at` (migration 0021) is stamped only
when the flag actually flips, so a screen re-sending rows it displayed cannot
move the date on subscriptions nobody touched. Without it the product could say
_that_ a subscription was excluded and never _when_, which is the difference
between a decision somebody made in August and an environment that has been
silently unscanned for as long as anyone can remember. Long estates collapse
behind a count rather than pushing the panels beside them off the screen.

"Scan now" on a row posts one scan naming any scannable subscription beneath the
connection, because a scan is already connection-scoped server-side: the worker
resolves the subscriptions when it runs, so one discovered between queueing and
running is still read.

The empty state states the read-only claim and then proves it: "Read what
CloudGuard will do" fetches `/cloud-accounts/azure/permissions` and lists the
directory permissions, the Azure role and the writes performed. A hardcoded list
would be a second copy of the claim, free to drift from the one Microsoft's
consent screen actually shows. Its four-step preview is the wizard's own
`SETUP_STEPS`, in the same words, so the list cannot drift from the flow it
previews.

---

## 44. The graph holds present assets, and a rule may group its findings into one risk

Two separate corrections to the same habit of counting rows instead of problems.

**`load_graph` reads assets that are still there.** An asset a scan looked for
and did not find keeps its row — `absent_since` is set rather than the row
deleted, so its findings stay history and so an asset that vanishes for a week
and returns is one asset rather than two. The loader was reading every row the
organization had, so `/attack-paths`, the asset detail page and the PDF report
served routes through resources that no longer existed, while the scanner's own
graph, built from one scan's normalized state, never contained them. Two views
of one tenant disagreeing, with the wrong one facing the customer. Edges are
already dropped when either endpoint is missing from the node set, so filtering
the nodes is the whole fix.

Still unfiltered, deliberately: a subscription the customer excludes stops being
scanned, so its assets never become absent and stay in the graph indefinitely.
That wants scope on the query and is a change to what "the organization's graph"
means, not a bug in this one.

**A rule may declare that its findings are one risk.** `AZ-ID-001` fails once
per privileged account without a second factor, and each of those is separately
fixed and separately verified, so the _findings_ stay per resource. As forty
risks it was forty rows saying one sentence, and forty Critical deductions —
which pins the org security score at zero over a single Conditional Access
policy that was never written. The remediation the rule itself prints is one
policy covering every privileged role at once.

So `SecurityRule.risk_grouping` declares it, as a `RiskGrouping` carrying the
singular and plural sentences. Declared rather than inferred from the count:
whether repeated failures are one problem or many is a judgement about the
rule's subject. Two storage accounts left public are two mistakes; two
administrators without MFA are one policy nobody wrote.

The group is **scored as its worst member**, exactly as a scenario is — it
cannot be less serious than the worst thing in it, and must not be more serious
either. Its breakdown is that member's, so "why is this 84?" still names
components measured on a real asset rather than an average of forty. What the
group adds is the count, and the count is in the title.

Identity across scans reuses `scenario_key` (`group:<rule_id>`), the column that
already answers "what identifies a risk that is not identified by a single
finding" — so no migration, and the existing unique index on (organization, key)
covers it. Per-finding risks from before a rule grouped are **deleted** when
absorbed, which is the opposite of what happens to a closed route and for the
opposite reason: nothing ended. The same accounts still fail the same check, and
a resolved duplicate would show a customer a fixed MFA risk beside an open one
for the same people. The findings keep every event they ever had.

Two counting rules follow. A group closes only when nothing in it is still open,
or the first administrator to register an authenticator app would close a risk
covering thirty-nine who had not. And the band queries behind the security score
count `distinct` risks, because the junction fans a risk out across its members
— counting join rows would reinstate the forty deductions the grouping exists to
collapse. `open_finding_count` is now taken from the findings, having been the
width of that band query, which was the same number only while every risk had
exactly one member.

---

## 45. The security score decays instead of subtracting

`max(0, 100 - Σ deductions)` was strict, which was right, and clamped, which was
not. Five open Criticals scored 0. Twenty scored 0. So did the same estate after
seven of them had been fixed and verified. The number stopped moving exactly
where a customer needs it to move most — through the months of a remediation
programme — and `score_delta` on the dashboard, computed from it, reported that
nothing had happened. On the product whose north-star metric is verified risk
reduction, the headline number was structurally incapable of showing it.

The same deduction total now drives `round(100 × exp(-Σd / k))`. Every fix moves
the score; the curve is steepest across the first few Criticals, where the
strictness has to live; and 0 is where a catastrophic estate lands rather than
where an ordinarily bad one starts. One Critical leaves 77, five leave 28,
twelve leave 5, thirty leave 0.

**Fitted to an anchor, not to a rate.** `k` is solved for from
`score_anchor_criticals` and `score_anchor_value` — two Criticals leave 60, the
sentence already in `RISK_ENGINE.md` §3 and already asserted in the tests. The
calibration is therefore the thing configured, and it survives somebody retuning
what a Critical costs, rather than silently parting company with the doc.

Two consequences worth stating because neither is obvious:

- Fitting to the anchor **normalizes** the deductions, so their absolute size is
  absorbed and only their ratios to a Critical decide anything. Doubling every
  deduction changes no score at all — which matters because "make everything
  cost more" is the obvious way to attempt a stricter score. The levers are the
  ratios, and the anchor.
- The integer rounding does flatten the curve eventually, around twenty open
  Criticals. That is a real limit and an acceptable one: the score is read
  rather than computed with, and by then it has said what it has to say. Below
  that, every Critical closed is visible.

The band thresholds the UI colours by (`scoreColor`: 85 / 60 / 40) are unchanged
and still land where they should — two Criticals is amber at 60, five is red at
28, where it used to be red at 0 alongside every other broken estate.

---

## 46. The security score charges for context CloudGuard established, not context it guessed at

`RISK_ENGINE.md` §3 has always said coverage is reported beside the score and
not folded into it. Half of that was true. A check that reaches no verdict
raises no finding, so evidence coverage genuinely never reached the number. But
§1 scores an UNKNOWN criticality, sensitivity or exposure at 3.5 — just under
High — and that band drove the deduction. An estate nobody had labelled was
therefore told its posture was worse, on the strength of what CloudGuard could
not work out rather than anything about the customer's risk, on the same
dashboard that promises the opposite.

The cautious 3.5 is not the mistake and has not changed. It is what stops the
cheapest route to a good score being to tag nothing, and an unclassified
production database must never sort below a labelled dev box. The mistake was
using one number for two jobs.

So the scorer produces both. `risk_score` / `risk_level` rank, cautiously, and
still drive the risks list, the top-risks panel and the band distribution.
`known_score` / `known_risk_level` take every UNKNOWN input at the LOW floor —
not zero, because an asset is at least a low-criticality asset — and the org
Security Score deducts on those. For a fully classified asset the two are
identical, so nothing changes for a customer who has done the labelling.

Recomputed rather than discounted: the weights are not uniform, so which
component was unknown changes how much it mattered, and a blanket multiplier
would get that wrong in both directions.

`known_risk_level` is NULL on scenario risks, and NULL means "not computed"
rather than "no risk" — a route is a statement about wiring rather than about an
asset's context, and it never reaches the org score because the findings it
groups already do. The band queries coalesce to `risk_level`, which also leaves
rows written before migration 0022 scoring exactly as they did rather than
being silently re-banded.

**The consequence is a visible one, and it is the point.** Untagged estates
score higher than they did, immediately, without anyone fixing anything. What
replaces the deduction is a sentence the customer can act on: `coverage.context`
counts the open risks sitting on unclassified assets, shown on the dashboard
beside the evidence-coverage ring and printed on the cover of every PDF, with a
link to the subscription context declarations in Settings. Silently deducting
told them nothing and gave them nothing to do.

---

## 47. Exploitability is required, and it is a ceiling rather than a constant

Two defects in one tag, and both of them are shapes this codebase refuses
everywhere else.

**It defaulted to 0.** `exploitability: int = 0` on `SecurityRule` meant a rule
whose author never thought about the question silently asserted the
misconfiguration was unexploitable — an absence reading as safe, which is the
same overclaim as a PASS nobody earned and the exact thing the UNKNOWN/PASS
distinction exists to prevent. It is now declared without a default, like
`severity`: a rule that omits it raises `AttributeError` at import rather than
quietly scoring 0.

**It was flat across instances.** An NSG rule allowing RDP from the whole
internet scored 5 whether it guarded a production jump box or nothing at all —
on the engine whose entire premise is that the same misconfiguration means
different things in different places. The distinction was already computed:
`_attachment_evidence` records whether the group protects anything, AZ-CMP-001's
own description contrasts itself with "an unattached NSG rule", and the note on
`ResourceRelationship` says an unattached NSG allowing RDP is noise. It reached
the evidence and never reached the score.

So `RuleResult` now carries an optional `exploitability`, and the class value
becomes the **worst** instance of that misconfiguration rather than every
instance of it. Three rules step down where they can already tell:

- an NSG rule protecting nothing → 1. Nobody can connect to a machine it does
  not guard, so what is left is a latent mistake, real and worth fixing before
  something is attached to it.
- a storage account open to every network but with anonymous blob access off →
  3. A key or a SAS token is still required, which is an attacker who already
  has a credential rather than one with a browser.
- a database whose only over-broad firewall rule is Azure's `0.0.0.0-0.0.0.0`
  shortcut → 3. Every Azure tenant is a serious and usually unintended gap, and
  it is not the open internet.

**Down only.** `effective_exploitability` clamps to `0..tag`, so a rule can
never claim an instance is worse than its own tuned value. That number is the
starting value `RULE_ENGINE.md` §5 says to tune against real environments; a
rule able to raise it per finding would be retuning itself in the dark, one
finding at a time. A mistaken override can therefore only understate — the
direction that costs a customer nothing the severity has not already told them.

The starting values themselves are unchanged. Retuning them wants the real
environments the doc asks for, and this change is about the mechanism.

The scale is now written down (`RULE_ENGINE.md` §5) in terms of what the
attacker must already have, from "nothing, anonymous, today" at 5 to "weakens
detection rather than enabling anything" at 1. Eleven magic integers with no
stated basis could not be reviewed; 4 versus 5 is now a question with an answer.

`_upsert_risk` reads the exploitability from the scored inputs rather than from
the rule, so the number shown on the detail page is the number the arithmetic
used.

---

## 48. Compensating controls lower a finding's score and never close it

Every path CloudGuard scored was scored as though nothing in the environment
defended it. An administrator with no registered second factor ranked identically
in a tenant where security defaults challenge every sign-in and in one where
nothing does — which is the same flattening the risk engine exists to refuse,
pointed at defences instead of at assets.

A `Control` (`app/rules/controls.py`) is one observed defence and what it leaves
an attacker needing. A rule returns them on its `RuleResult`, and
`effective_exploitability` takes the minimum of the class tag, any instance
step-down and every control — so several compose to the strongest without any of
them knowing the others exist, and none can ever raise a finding.

Three rules, and each is the product refusing a temptation the category is full
of:

**A control never turns FAIL into PASS.** A policy demanding a second factor of
an account that has never registered one locks that account out of its own
tenant at the first challenge — a real operational problem, not a fixed one —
and the policy can be disabled, rescoped or have that account excluded in a
change nobody reviews. Reporting a pass would be CloudGuard vouching for a state
of affairs it is not observing.

**Only prevention counts.** Detection is not compensation. Defender watching a
storage account changes whether somebody finds out, not what an attacker must
have to get in, and the exploitability scale is written in terms of the second
(§47). A control that only shortens time-to-discovery belongs in a report.

**The control must be observed.** Every one is built from the same capture the
finding came from, and one CloudGuard could not fully read is simply absent.
Absence of evidence lowers nothing.

Implemented for AZ-ID-001 from two Graph readings, both under permissions
already in `REQUIRED_GRAPH_PERMISSIONS` and already consented by every connected
tenant — so this costs nobody a second trip to a Global Administrator.
Security defaults are unconditional. Conditional Access is only accepted when
every part of it resolves: enabled rather than report-only; granting MFA
unambiguously, so `MFA or compliantDevice` under `OR` is discarded because a
stolen password still works on an enrolled machine; covering all applications,
since CloudGuard cannot know which one an attacker would use; and with every
group it names read back, because an unread exclusion group could be the one
holding the account being judged. That last case is why the collector reads the
members of exactly the groups a policy mentions — essentially every real tenant
excludes a break-glass group, and without resolving it the feature would be
theatre.

Role template ids are matched through the tenant's own `directoryRoles` rather
than a table of GUIDs written from memory, for the reason `rbac.py` records
about ARM action strings: a wrong identifier is indistinguishable from a right
one by inspection.

Controls are **not** normalized into `resources`. A Conditional Access policy is
not a thing anybody secures, has no exposure and no data sensitivity, and would
inflate every inventory count with rows a customer never asked to own. They ride
on `NormalizedState.controls` and reach rules through `RuleContext.controls`.

The pipeline writes them onto the finding's evidence under
`compensating_controls`, and the detail page renders them above the raw evidence
under "What is standing in the way" — because a score arrived at through a rule
nobody can see is the kind a customer stops trusting. The copy is deliberately
not reassuring.

**Just-in-time VM access is the obvious next one and is deliberately absent.**
It would need `Microsoft.Security/locations/jitNetworkAccessPolicies/read` in
the scanner role, and `rbac.py` requires every action string to be verified with
`az provider operation show` before it ships — an unverified one fails the
customer's entire role deployment atomically, which is exactly how
`autoProvisioningSettings/read` was caught. It would also cost every existing
customer a role redeploy and a `ROLE_VERSION` bump. It goes in when the string
has been checked against a real tenant.

---

## 49. Choke points: the one change, verified rather than counted

The attack-path list ranks routes shortest-first, which is the right order for
reading them and the wrong one for acting. Fifty routes are fifty things to
read. "Remove this one role assignment and thirty-seven of them close" is one
thing to do — and it is frequently not the fix any single route would have
suggested, because each route's own `cheapest_break` is at its start while the
link they all share sits in the middle.

`AssetGraph.choke_points()` is two passes, and the second one is the whole
point. Counting how many routes a link sits on takes a single walk and
**overstates**: a link on twenty routes closes only the ones with no way round.
So the leading candidates by containment are then checked by removing the link
and re-running the entire traversal, comparing which (entry, target) pairs are
still reachable. That is the only way to distinguish a route that is gone from
one that has merely been made longer.

Verified in order of containment, and only until no unchecked link could make
the list, because each check is a full re-traversal. Containment is an upper
bound on severance, so once `limit` links are kept, one sitting on fewer routes
than the weakest of them cannot displace it. A link that closes nothing does not
count towards `limit` — see §100 for why a fixed number of checks was wrong.

Both numbers are reported. `severs` is what closes and `on_routes` is what it
sits on, and where they differ the UI says so — a customer told four routes
close who then sees two remain stops believing the next number too. The severed
routes are named as well as counted: a count is a claim, and those are its
working.

`CONTAINS` is never a candidate. A storage account has to live somewhere, so
offering "stop the resource group containing it" is a recommendation nobody can
take — the same reason `Path.cheapest_break` skips it.

Attack paths only, not escalation chains. They answer a different question, and
one count spanning both would make "routes" mean two things in a single
sentence.

Its own endpoint and its own query, fetched only once the page has routes to be
about. It costs a re-traversal per candidate, and the list is read far more often
than the question is asked.

**Not wired into the remediation queue.** A choke point is a change to make and
frequently corresponds to no finding at all — the shared role assignment may be
perfectly ordinary in isolation. Turning one into a queue item would mean
minting work with no finding behind it, which is a decision about what the queue
_is_, not a detail of this analysis.

---

## 50. Every colour is lit for the surface it sits on

The theme had two blocks, light and dark, and the dark one was not a re-lighting
of the light one so much as a partial copy of it. Measuring every pair found
three things wrong, and they are the same mistake in three places: a colour
chosen against one background and then used against another.

**The chart ramp was one greyscale in both blocks.** `--chart-1` through `-5`
ran 0.87 → 0.269 in lightness, which is a ramp built to sit on white. On the
light page the top of it measured 1.48:1 and was invisible; on the dark page the
bottom measured 1.31:1 and was invisible. Each mode now runs from its own
surface outward, every step clearing 3:1 against both the page and the card,
because a chart lives inside a card.

**`bg-ok text-white` measured 1.95:1 in dark.** `--sev-ok` is a light green
there, as it has to be, and white on it is unreadable. The fix is
`text-background` rather than a new token: it is white in light mode and near
black in dark, it was already the idiom two lines away in the same component,
and it cannot drift from the surface because it _is_ the surface.

**Two statuses were written in Tailwind palette classes.** `bg-stone-50` and
`bg-white` in `format.ts` do not flip with the theme, so on a dark page the
"not covered" cell — the quietest status in the product — rendered as the
brightest block on the screen. They are separated by fill and a dashed border
now, not by a hardcoded grey.

The chrome moved as little as possible around those: `--muted-foreground` from
4.73:1 to 5.51:1 (it is every secondary line in the product, and it sat close
enough to the AA line that antialiasing decided it), `--ring` from 2.59:1 to
4.28:1 (the focus indicator is `focus-visible:border-ring` at full opacity, so
that value is what WCAG 1.4.11 measures — the `/50` ring beside it is a halo),
and the two severities under 5:1 on their own tint nudged just past it with
their hues untouched.

One thing was removed rather than adjusted: `--sidebar-primary` in dark was
shadcn's default indigo, the only saturated hue in the chrome of either theme.
An accent that appears in one mode and not the other reads as a bug, and in this
product a colour that means nothing sits badly beside a scale where every colour
means something.

**The rule this leaves.** A colour is not correct or incorrect on its own, only
against a surface — so a token defined in one block is not done until it has
been measured in the other, and a component that names a palette colour has
opted out of the theme rather than styled itself.

---

## 51. Retention keeps the present, whatever the window says

Two things grew without bound and neither had ever been pruned: the raw captures
in `cloud_snapshots`, and the content-addressed payloads in `evidence_blobs`.
Both are the largest rows in the schema and both are kept for real reasons — a
capture is what lets a scan be re-evaluated against improved rules, a payload is
what a citation points at — and neither reason survives indefinitely.

**The newest capture of each scope is never pruned, whatever the window says.**
It is what an _applied_ replay reads: replaying the newest snapshots may resolve
findings, while every older one is `evaluation_only` and may not. Pruning it
raises nothing — it turns "did the fix work" into an advisory answer, months
later, on the path the north-star metric runs through. So it is excluded by
construction rather than by choosing a window long enough that it probably will
not happen.

Two scopes, not one. A subscription's resources and the tenant directory read
through a connection are different things, and a tenant-wide replay restores the
directory beside each subscription — pruned out from under it, the identity
rules read nothing while the subscription rules carry on, which is a replay that
half worked.

**Payloads are measured from `last_seen_at`, not `first_stored_at`,** which is
the whole reason that column exists. An estate that has not changed in six
months stores one copy and touches it on every scan; measuring from first
storage would delete the payload behind every current reading, which is
deduplication working against itself.

**And pruning a payload invalidates nothing that cited it.** `finding_evidence`
copies the hash rather than holding a foreign key, so a finding raised last year
still says truthfully what was read, when, and under which permission — the API
reports the payload as unavailable rather than offering a link that fails. That
was designed in §50's neighbourhood before there was anything to prune; this is
the entry that makes use of it.

Evidence _rows_ are deliberately not pruned. They are one row per key per
subscription per scan against a payload that is the listing itself, and deleting
the record of what was read to save the size of the record of what was read is
the wrong trade — it is also the trade that makes an old finding unanswerable.

Windows are settings (`snapshot_retention_days` 30, `evidence_retention_days`
90) with defaults rather than required values: a missing one costs disk, not
correctness, which is not the kind of misconfiguration the rest of `config.py`
refuses to boot on.

---

## 52. The asset graph is cached against its data, not against a clock

Six callers build the graph and four are request handlers — the attack-path
list, choke points, blast radius, and a finding's routes. Every one read the
whole tenant, every present asset and every edge, and somebody clicking between
those screens paid for it each time. On the one page where a tenant large enough
to have interesting paths is also large enough to be slow.

**Cached on the version of the data rather than on a TTL.** A time-based cache
would make these pages briefly wrong after every scan, and briefly wrong here
means telling somebody an attacker can still reach their data through a route
they closed this morning. §"the graph holds present assets" already established
that a stale path is not a weaker claim than a real one, it is a false one — a
TTL would reintroduce exactly that, on a timer.

The version is four aggregates: the newest `cloud_resources.updated_at`, the
newest `resource_relationships.created_at`, and a count of each. The counts are
not redundant. A scan that only _removed_ something moves no timestamp — the
rows that remain were not touched, and the one that went is not there to carry
a time — so without the asset count the graph would go on serving routes
through something no longer in the estate, and without the edge count it would
go on serving a route whose link the last scan pruned (§120).

Keyed on the data rather than on "the newest scan", though a scan is the only
thing that rewrites assets today. Keying on the scan would be an inference about
which processes write, and the day something else does — a context declaration
applied in place, a manual edit — the cache goes stale silently.

Bounded at eight tenants, LRU. This is a read cache in a process that serves
every customer, and holding a graph per tenant for the life of the process
trades a latency problem for a memory one whose size is a function of how many
customers happened to open one page.

The scan pipeline does not read it: `_correlate_paths` builds from the
normalized state in hand, so it can neither be served a stale graph nor leave
one behind.

---

## 53. The capture is stored twice, and the gate on stopping

`cloud_snapshots.data` holds a whole capture per scan. The per-key payloads in
`evidence_blobs` hold the same bytes, split by reading and content-addressed.
The difference is that the second is deduplicated and the first is not: a daily
scan of an estate that has not changed writes one payload set and a **fresh full
capture every night**, for as long as retention keeps it.

That is worth fixing by making `cloud_snapshots` a manifest — the keys and
hashes of its readings — and rebuilding the capture from blobs on replay. It is
not worth doing on an assumption, which is why `test_evidence_store.py` has
carried the precondition since evidence was per-key: _replay reads
`cloud_snapshots` and must keep doing so until reconstruction holds against real
scans._

So the gate ships before the change. `TestCaptureReconstruction` asserts, on a
real pipeline run, that the stored readings rebuild the capture exactly, and
that a second scan of an unchanged estate adds no payloads while adding a whole
capture.

**The case a careless flip gets wrong,** and the reason a unit test was not
enough: a task can produce more than one payload key. `authentication_methods`
has no task of its own — the directory's role-map task reads it — so a
reconstruction keyed by task rather than merged by payload drops it, and the MFA
rule then finds nothing to judge while reporting no error at all.

**Two lifetimes to reconcile before flipping.** Captures are pruned at 30 days
and payloads at 90, and the two are independent today because neither depends on
the other. A manifest makes captures depend on payloads, so `prune_blobs` would
have to refuse any hash a retained manifest still names — otherwise retention
would quietly destroy a capture that is inside its own window.

---

## 54. The capture is a manifest, and retention is now interlocked with it

§53 named the waste and shipped the gate. `TestCaptureReconstruction` passed
against real scans, so the flip: `cloud_snapshots` stores everything the capture
recorded _except_ the payloads, plus the content hash of each reading. The
payloads live once in `evidence_blobs`, shared by every scan that read identical
bytes.

`data` is kept and made nullable rather than dropped. Captures written before
this carry their payloads inline and must go on being replayable, so the read
path takes whichever it finds — and dropping a column holding the only copy of
anything is not a migration anybody should be able to run by accident.

**A missing blob is refused, not skipped.** `SnapshotUnavailable` rather than a
partial rebuild: half a capture replays as an estate missing whatever the other
half held, and that replay may resolve findings. A resolution reached by
omission is the same overclaim as a PASS nobody earned, arrived at from a
direction the rule engine cannot see.

**The dependency this created, and the interlock that answers it.** A capture
used to be self-contained. It now points at blobs, so a blob can be the only
copy of part of a capture that is well inside its own window — and the two have
different windows (30 days and 90). `prune_blobs` therefore keeps any hash a
surviving manifest still names, whatever its age says. Without it, retention
would delete nothing visibly and fail months later, at the one moment somebody
replays a capture to check whether a fix held.

Two things the tests had to be corrected about while building this, both the
same mistake in different clothes: a fake matched `payload_hashes` in SQL text,
where it is a bound parameter of the `->` operator and never appears; and a fake
`DELETE` reported no rowcount, so every prune looked like a no-op regardless of
what it named. Each made a test pass by proving the opposite of its name.

**And the column default that made all of this fail in CI.**
`cloud_snapshots.data` was created in 0001 as `jsonb NOT NULL DEFAULT
'{}'::jsonb`. 0027 stopped writing the column and dropped its NOT NULL — and
left the default. So every capture written after the flip came back holding an
empty object rather than NULL, and `_rebuild_capture`, which chose between the
inline and manifest forms by asking whether `data` was NULL, took the inline
branch and rebuilt an estate with nothing in it.

Nothing failed where the mistake was. Collection succeeded, the capture was
stored, the payloads were stored, the manifest was correct — and then every
scan died in ANALYZE with `KeyError: 'provider'` on a capture that was
perfectly good. Sixty integration tests failed, all of them downstream of the
one question asked the wrong way round.

The fix is 0029 and a changed question. The default goes, and the rows already
written that way are set back to NULL — guarded on `manifest IS NOT NULL`,
which names exactly the captures written since 0027 and cannot touch a pre-0027
capture that genuinely held an empty object. And `_rebuild_capture` now decides
the form from the _manifest_, because the manifest is the thing that is present
in one form and absent in the other. A column with a default cannot answer "did
anybody write this", and the general lesson is that a nullable column is only a
reliable "unset" signal once its default is gone too.

**A failed listing that returned nothing used to cost no verdict at all.**
A rule reports UNKNOWN from inside `evaluate`, and `evaluate` runs once per
matching resource. So a rule whose evidence failed to collect had nothing to
iterate over and produced nothing: no verdict, no gap row, and a coverage ratio
computed over the rules that happened to have something to look at. Failing to
look cost less than looking and finding a problem — the same overclaim as a
PASS nobody earned, arrived at through silence rather than through a wrong
answer.

It survived this long because a fixture hid it. The recorded snapshot carried
its storage listing even when the test marked storage as failed, so the rules
had resources to iterate and degraded correctly. A real run has no such
listing, and neither does a capture rebuilt from a manifest, which is why §54
surfaced it.

`RuleEngine._run_per_resource` now records one UNKNOWN when a rule matched
nothing _and_ its declared `requires_evidence` names a listing that failed. The
two conditions together are the whole point: no resources plus no error is a
customer who has none of them, which is NOT_APPLICABLE and correctly excluded
from the coverage ratio; no resources plus a failed listing is nobody having
looked. The gap carries no `resource_id`, because there is no asset to
attribute it to — that absence _is_ the finding about the scan.

**A request must not commit the transaction it was handed.**
`rls_session` wraps a whole request in `session.begin()` and declares who is
asking with `SET LOCAL ROLE authenticated` and `request.jwt.claims`. Both are
transaction-scoped — which is what stops them leaking to the next checkout of a
pooled connection, and equally means a commit inside a request tears down the
settings every RLS policy reads. `commit_unless_externally_managed` exists for
exactly this, and is a no-op under a session that owns its transaction.

`set_change_events` called `session.commit()` directly, the only one of eleven
writes in that file that did. Turning change detection _off_ worked, because
nothing ran afterwards. Turning it _on_ did not: the route goes on to build the
Event Grid wiring commands, which reads the connection's subscriptions, and
that read ran as the bare `cloudguard_app` role with no claims.

The guard is now a test over `app/services/`, not over the one function that
had it, with per-function exemptions for the code that opens its own session —
per function rather than per module, because `scans.py` holds both the worker's
reaper and endpoints a request reaches, and exempting the file would exempt
those too.

**And the failure was invisible from the browser, which is the worse half.**
The API registered handlers for `AppError`, `HTTPException` and
`RequestValidationError`, and nothing else. Anything unanticipated escaped to
Starlette's `ServerErrorMiddleware`, which sits _outside_ `CORSMiddleware`, so
its 500 carried no `Access-Control-Allow-Origin` and the browser refused to
read it. `fetch` then rejected with `TypeError: Failed to fetch` — what a
browser says when a request never arrived at all. So a server-side bug was
indistinguishable from the API being unreachable, and the connections page
reported a network failure for a request that had arrived, run, and raised.

Registering a handler for bare `Exception` does not fix this: Starlette
special-cases that one and hands it to the same outermost layer.
`UnhandledErrorMiddleware` sits inside CORS instead — `main.py` adds it first,
and `add_middleware` inserts at the front, so the last one added is outermost.
The response carries the envelope and a sentence; the stack trace goes to the
log, because rendering one into a browser is a disclosure and this is a
security product.

---

## 56. Rules are bounded by collectors, not by ambition

The catalogue went from 10 rules to 17, and what decided _which_ seven is worth
recording, because the obvious approach produces a worse product.

A CSPM is expected to check key vault configuration, database auditing, disk
encryption, activity logs, credential expiry, vulnerabilities and backups.
CloudGuard collects none of those. A rule for each would have been quick to
write and would have answered UNKNOWN for every customer for ever — a catalogue
that looks complete and says nothing, which is the same overclaim as a PASS
nobody earned wearing different clothes. So the rule set is bounded by the 16
evidence keys that exist, and grows when a collector does.

**The RBAC family needed no new collection, and that is why it went first.**
Role assignments were already read for the graph. What was missing was smaller
and stranger: the normalizer recorded a role's _name_ only on principals it
minted, never on directory users, on the stated grounds that a traversal reads
the edges anyway. True of a traversal, false of a rule — an edge says a
principal reaches a scope and cannot say as what. "This named person holds Owner
over your subscription" was therefore a fact CloudGuard collected, drew a line
for, and could not state. Three rules fell out of fixing that one line.

`AZ-IAM-003` reads the role _definition's permissions_ rather than its name,
because Owner and Contributor both carry `actions: ["*"]` and only Contributor
excludes the assignment write. A name-based check would flag every Contributor
on nearly every subscription in existence, which is how a whole feature gets
switched off.

**Three guard tests caught omissions in this work, and each was fixed in the
code rather than in the test.** `ROLE_DEFINITIONS` carried a seven-day reuse
window justified by "no rule reads them"; `AZ-IAM-003` made that false, so a
customer editing a custom role to remove escalation and rescanning would have
been answered from last week's catalogue — `_REUSE_WINDOWS` is now empty. Every
rule must carry a machine-readable remediation, and the RBAC rules legitimately
have no expected state, so they take the documented empty form that owes a
reason and a command. And `applies_when` could only express metadata, so
`AZ-DB-002` — whose expectation is about a database _holding sensitive data_ —
was handed a synthetic asset it declined to judge, and its round-trip test
passed by never running. It now accepts the classification fields the normalizer
computes.

**Scoping is a design decision, not a filter.** `AZ-DB-002` returns
NOT_APPLICABLE below HIGH sensitivity, and a shared-key-access rule was written
and then not shipped: shared key is on by default, so it would have fired on
essentially every storage account in existence. A rule that fires everywhere
teaches people to stop reading, and the cost lands on the finding next to it.

---

## 57. The scanner role reads a vault's configuration and none of its contents

Key vault was the largest gap in the catalogue and the first one closed by
adding collection rather than by writing rules against evidence that already
existed. It is worth recording as a shape, because every remaining gap —
database auditing, disk encryption, activity logs — is the same shape.

**One action, and precisely one.** `Microsoft.KeyVault/vaults/read` is the
management plane: whether the vault can be purged, whether it answers the
public internet, which authorization model it uses. It grants nothing over the
keys, secrets and certificates inside, which live behind
`Microsoft.KeyVault/vaults/secrets/read` and a separate permission model that
CloudGuard does not request and should never request. A product that can tell a
customer their vault is destroyable _without being able to read a single secret
in it_ is making a stronger claim than one that can do both, and a test asserts
the role holds no other `Microsoft.KeyVault/` action so that stays true.

**The role is versioned, so the cost lands as a prompt rather than a 403.**
`ROLE_HISTORY` gains a `v3` entry written out literally beside v1 and v2 — never
by reference, for the reason recorded in that file. A customer still on v2 keeps
every other category and loses only the vault checks, which then report UNKNOWN;
`categories_behind("v2")` is exactly `{SECRETS}`, and a test says so, because an
upgrade that quietly cost them an unrelated category would be worse than the gap
it closed.

**Absent and false are different answers, and Azure means different things by
them.** `enableSoftDelete` comes back as a value; `enablePurgeProtection` is
omitted when it has never been set. So AZ-KV-001 reads a missing purge
protection as off and a missing soft delete as missing — reversed, the rule
would either report nothing for the overwhelming majority of vaults that
genuinely lack purge protection, or report a gap CloudGuard invented.

**Sensitivity comes from the context engine, not from the normalizer.** A vault
holds the credentials to everything else, so an untagged one is not an
unclassified asset. That is expressed by adding `KEY_VAULT` to
`DATA_HOLDING_TYPES`, which carries the `TYPE_FLOOR` source with it — a first
attempt overrode criticality inside the normalizer instead, which would have
produced a HIGH nobody could trace to a reason.

**And check whether the gap costs a permission before assuming it does.** The
subscription activity log looked like the next role bump and was not. A
subscription is a scope diagnostic settings apply to like any other, so
`Microsoft.Insights/diagnosticSettings/read` — granted since v1 — already
reaches it, and the collector simply asks about one more id. AZ-LOG-002 is
therefore live for every existing customer with no redeploy, which is worth more
than the two vault rules that need one.

The two logging rules divide cleanly and must keep doing so. AZ-LOG-001 asks
whether a resource records what happens _to_ it; AZ-LOG-002 asks whether the
subscription records _who did it_, across every resource including the ones that
no longer exist. A test asserts AZ-LOG-002 applies to subscriptions and nothing
else — if both claimed the same asset, one problem would be raised twice with
two different fixes.

---

## 58. v4 grants one action, because two of the three candidates were not worth one

The plan going into v4 was SQL auditing, transparent data encryption and
managed disk encryption, batched into a single redeploy prompt rather than
three. Two of the three did not survive being looked at.

**Transparent data encryption has been on by default since 2017**, and
**managed disks are always encrypted at rest and cannot be turned off**. Checks
for either would have cost a permission, a per-database fan-out, and a place in
the catalogue, to report PASS for very nearly every customer. That is how a rule
set grows in size and shrinks in signal — the failure mode ROADMAP.md warns
about, arrived at through diligence rather than laziness.

**SQL auditing is the opposite and is the whole of v4.** It is off by default on
every Azure SQL server, so it is a setting most customers have never turned on
rather than one they turned off. It costs one call per server, folded into the
task that already lists them, and it pairs with AZ-DB-001: a publicly reachable
database with no audit trail is the worst combination this catalogue can
describe, and the auditing finding carries `public_network_access` in its
evidence so the two read together.

**The rule declares no expected state, and that is the honest form.**
`Comparison` offers three checks and says in its own docstring that anything
they cannot express stays undeclared rather than half-declared. AZ-DB-003 checks
two things about one nested setting — auditing is on, and it writes somewhere —
which none of the three express. A declaration saying only "state is Enabled"
would have a customer satisfy exactly what they were shown, still be auditing to
nowhere, and watch the finding stay open. So the spec is the empty form, with
the reason in `notes` and the commands still handed over.

**Two failure modes, reported apart.** Off is a switch; on-with-no-destination
is the setting people believe they have. The fix differs, so the finding says
which it found.

**And the UNKNOWN names the role.** A customer still on v3 gets a 403 on this
one call while the server listing and firewall rules succeed, so every SQL
server they own reports UNKNOWN. The message says the deployed role may predate
the permission, because an unexplained UNKNOWN on every database is worse than
the gap it describes.

---

## 59. The access panel stopped calling a stale role verified

`role_upgrade_available` has been on the connection payload since role versions
existed, computed correctly, and read by nothing. So bumping the role to ship a
check — twice in a week, v3 for key vaults and v4 for SQL auditing — left every
existing customer collecting UNKNOWN across whole categories while the access
panel printed their role in the same green as a current one, next to the word
"verified".

That is the failure `role_upgrade_available`'s own docstring says the mechanism
exists to prevent, reached anyway because the last step was never taken. A
backend that knows and a screen that does not is indistinguishable from a
backend that does not know.

**Three states, not two.** The role is now green when current, red when never
granted, and amber when behind. Behind is not a failure — most checks are
running on it — and painting it red would send somebody to fix an outage they do
not have.

**Named, not counted.** "Two categories are degraded" is a notification;
"Databases, Key vaults" is a decision. The categories come from
`degraded_categories`, the same function the scanner uses to explain its own
gaps, so the screen and the scan cannot disagree about which checks are
affected. The customer-facing labels live in the frontend — `secrets` is what
the permission model calls a key vault, and "Key vault" is what the customer
went looking for.

**The panel states the invariant where it is felt.** The affected checks report
"not known" rather than passing, and the alert says so: a customer who assumed
silence meant a pass would draw exactly the wrong conclusion, and this is the
one screen where that assumption is most tempting.

**The redeploy link is the setup wizard's link.** Redeploying is deploying again
— the template carries the current role definition — so a second route would be
inventing one, and it is omitted entirely when there is no template URL to point
at, because a dead button is worse than none.

**And the seam test earned its keep.** The first attempt imported
`rbac.ROLE_VERSION` straight into the route to report which version to redeploy
toward. The route layer is provider-neutral and a role version is not, so it now
asks `required_role_version`, which returns `None` for a provider with no such
notion.

**The collection panel was not the liar; the SQL task was.** The panel reports
each reading's outcome, and the SQL reading came back COMPLETE while every
auditing verdict was UNKNOWN. That task makes three calls -- the servers, then
each server's firewall rules and auditing settings -- and a per-server failure
was recorded on the server for the rules to degrade on and nowhere else. So the
one screen whose job is saying what was and was not read said everything was.
A role predating v4 produces exactly this: a 403 on every auditing call while
the listing and firewall rules succeed. `_arm_task` now accepts a `TaskData`
from a call that knows something about its own completeness the wrapper cannot
see, and reports both reasons when a truncated listing and a half-read server
apply at once.

**And the invariant was stated for PARTIAL and nowhere else.** A scan where
storage failed outright showed a badge, a count, and no word about what it cost
-- leaving "could not read" free to be read as "nothing to report", which is the
one inference this product exists to prevent. Two sentences rather than one
covering both, because the reasons differ: an incomplete listing cannot support
a pass, and an absent one supports nothing at all.

`degraded_categories` on the collection payload is deliberately still not
rendered. It rolls up the same per-reading outcomes the list underneath already
shows one by one, and a summary that repeats the thing below it adds a place for
the two to disagree rather than a fact.

**And making that PARTIAL truthful exposed the next layer of the same
mistake.** A rule degrades on the evidence _keys_ it declares, and the SQL
listing was one key covering three calls -- the servers, their firewall rules,
and their auditing settings. So the moment a refused auditing read correctly
made the reading PARTIAL, it also took AZ-DB-001's verdict, over a call that
rule never reads. That is the gap CloudGuard invents rather than finds, and it
is precisely what `requires_evidence` was introduced to stop when rules named
whole categories instead of keys. The same error, one layer down: a key naming
three calls is a category wearing a key's name.

Auditing is now its own key and its own dependent task, keyed per server the
way diagnostics is. AZ-DB-001 declares `SQL_SERVERS`; AZ-DB-003 declares both,
because without the listing there are no servers to judge and without the
auditing read there is no posture to judge them on. A role predating v4 now
costs exactly one rule its verdict, and the reading's detail names the role as
the likely cause rather than leaving a v3 customer with an unexplained partial
on every scan.

The general form, worth stating because there will be a next one: **an evidence
key is the unit a rule depends on, so two calls belong under one key only when
no rule could depend on one without the other.** Separately deniable means
separately keyed.

**`RESOURCES` was checked for the same defect and does not have it — it has a
different one.** No rule declares the inventory, so a failed Resource Graph
query costs no check its verdict; every rule reads its own service listing
instead. Two tests now hold that, and hold the pair to it: the key stays in
`baseline_evidence`, because a plan derived from the rule set would otherwise
stop collecting it silently.

What was wrong was the justification. `BASELINE_EVIDENCE` claimed the customer's
asset list was made of the inventory, and it is not — every asset CloudGuard
shows comes from the per-service listings, normalized into `cloud_resources`.
The Resource Graph payload is stored verbatim in every snapshot and read by
nothing, anywhere. Both docstrings also said "these three" for a set of five,
the two control readings having been added without updating the count.

So the honest statement got written down — and then built. The inventory is the
one reading that covers resource types no rule has been written for, and the
asset list now says so.

**Resources no service listing produced become assets carrying
`ResourceType.UNKNOWN`.** That type is the load-bearing part: no rule's
`applies_to` names it, so nothing judges them and none can become a PASS nobody
earned. They are counted, listed, and reported as unchecked — which is a fact
about CloudGuard's limits rather than about the customer's estate, and the one
thing a customer cannot work out for themselves.

**Nothing is counted twice.** The inventory covers the same storage accounts the
storage listing already produced, in far less detail, so it is filtered against
the assets already normalized — including against itself, since a repeated
Resource Graph row would otherwise be a repeated asset. Two rows for one asset
would be an inventory that miscounts and a graph holding the same thing twice.

**The real Azure type travels with them.** A list row reading "Unknown" would be
a worse answer than the omission it replaced: the point of showing these is that
the customer can see _what_ is unchecked, not merely how many. `azure_type` is
null for a modelled asset, whose cloud-neutral label is the better one.

**Exposure stays UNKNOWN rather than LOW.** Resource Graph's projection excludes
`properties` deliberately, so there is no configuration here to establish
exposure from, and LOW would be reassurance CloudGuard did not earn.

**The count is phrased as a limit, not a percentage.** "35 with no checks yet"
rather than "74% coverage": a percentage invites the reader to feel good about a
high one, and the useful question is which resources are unexamined.

---

## 60. A control says why it is inconclusive, not only that it is

The compliance page already distinguished the five verdicts properly — labels,
dashed styling for INCONCLUSIVE so a control CloudGuard could not evaluate never
looks like one it cleared, and NOT_COVERED quieter still. That part was right and
stays.

What it could not answer was the question INCONCLUSIVE raises and the other four
do not. FAILING points at findings. PASSING needs nothing. NOT_COVERED is a fact
about CloudGuard with no action behind it. NOT_ASSESSED resolves itself on the
next scan. "Three rules could not be evaluated" points nowhere — and the
sentence that answers it has been sitting in `scan_evaluation_gaps` since
UNKNOWN became a recorded outcome, written by the rule that gave up, and never
read by this view.

It matters more than it did. Since the scanner role started gaining permissions,
the answer is frequently "your deployed role predates the permission this
needs", which is a thing a customer can act on this afternoon — and the access
panel now says the same thing one screen over, so the two agree.

**Distinct per rule, and capped at three.** The ledger holds one row per
resource, so forty storage accounts that failed for one reason are one sentence.
A tuple rather than a single string because one rule can fail differently on
different resources — a listing that timed out and a configuration that never
arrived are two causes, and collapsing them would name the wrong one for half
the assets. Past the cap it is a scan-level question, and the collection panel
answers it in full.

**The explanation never softens the verdict.** Knowing why CloudGuard could not
look is not the same as having looked, and a test says so explicitly: an
explained UNKNOWN is still INCONCLUSIVE, and a failing rule still outranks it.
This is the one screen somebody might put in front of an auditor.

The page had no test at all before this. It has five now, including the one that
matters most: a control nothing checks and a control that could not tell must
never render the same.

**And one flaky test found on the way, fixed rather than tolerated.** The
finding detail page draws on three independent queries — the finding, its attack
paths, its provenance — which settle in whatever order they settle in. A test
awaited the first sentence and then read two more synchronously, which proves
nothing about the second and third, and lost the race whenever the machine was
busy. Every assertion awaits now.

Worth recording how it was nearly missed: the suite had been run as
`npx vitest run … | tail`, and a pipeline reports the exit code of its _last_
stage, so vitest's failure read as a pass. A verification command that cannot
fail is not a verification command.

**And a React key warning that had been scrolling past in green runs.** The
assets table renders each group as a heading row plus its assets, wrapped in a
`<>` fragment returned from a `.map()`. The rows inside were keyed all along,
which is what made it look fine — but the _wrapper_ is what sits in the list,
and the shorthand fragment cannot take a key. React answers a list child it
cannot identify by reusing the wrong DOM under a changed key: rows appearing
under the wrong heading after a regrouping, invisible to any test asserting on
first paint.

The instance is a one-line fix, `<Fragment key={groupName}>`. The interesting
part is that a test asserting on the console does **not** hold it: React
de-duplicates these per call site, so such a test catches the warning only if it
happens to run before every other test that renders the same component. Written
that way it passed with the fix reverted — which is worse than no test, because
it reports a guarantee it does not provide.

So the guard is in the shared test setup instead, and fails any test that
produces one. Narrow on purpose: failing every `console.error` would fail tests
deliberately exercising error paths, and the class worth catching here is
specific. Verified the honest way — with the fix reverted, the suite fails; with
it in place, it passes.

---

## 61. Three more frameworks, and no new scanning

NIST SP 800-53 Rev. 5, the SOC 2 Trust Services Criteria and PCI DSS v4.0.1 are
now catalogued. None of them cost a rule. That is the whole point of the mapping layer: a rule is
the
reusable unit, a framework is a set of references to it, and a seventh catalogue
is a data change rather than a scanning engine. A test asserts every rule maps
to all three, and that no rule was written _for_ any of them — a rule named after a
standard would be the same technical check duplicated per standard, which is the
failure the compliance layer exists to prevent.

**800-53 is a US Government work and could be quoted; SOC 2's criteria are
AICPA's and cannot.** Both are described in CloudGuard's own words anyway, so
the two pages read alike and the rule at the top of the catalogue holds without
exception. The identifiers are the durable part; `url` points at the
authoritative text.

**SOC 2 is the easiest page in this product to overreach on**, and the catalogue
is shaped to make that hard. Its criteria are mostly about whether an
organization _has_ a control and operates it — CC1 through CC5 are control
environment, communication, risk assessment, monitoring and control activities,
and a scanner reads none of them. Nine of twenty-seven criteria are technically
assessable and the rest are listed unassessable rather than omitted, so the page
reports honest partial coverage instead of implying a SOC 2 report is a
configuration problem. The scope note says in as many words that only a licensed
firm can issue the opinion.

A test asserts fewer than half of SOC 2's criteria are assessable, and the first
version of the catalogue failed it at exactly half — because the catalogue was
understating how organizational the standard is, not because the assertion was
wrong. Seven more of the organizational criteria were named. That is the right
direction to resolve that failure in: the honest ratio is a fact about SOC 2,
and a catalogue that flattered CloudGuard's reach would be the thing at fault.

**Both list controls no rule covers**, as every framework here does — 800-53
covers 16 of 24, SOC 2 8 of 27. The uncovered ones are the backlog and the
never: `RA-5` and `SI-2` want vulnerability data CloudGuard does not collect,
`CC6.8` wants anti-malware status, and `PE-3` wants somebody to walk into a
building.

**PCI DSS v4.0.1 followed, and it carries the caveat that matters most.** The
standard applies to the cardholder data environment, and CloudGuard does not
know which resources are in it — scope is a decision a QSA makes with the
merchant about segmentation and data flows, and every figure on that page is
computed over the whole subscription instead. A resource group holding no card
data is counted exactly like the one that does.

That caveat is more consequential than SOC 2's, because PCI is contractual
rather than advisory: a merchant assessed against it can lose the ability to
take payments, so a page implying it had assessed them would be doing harm
rather than merely overreaching. The scope note says so first, before anything
else, and a test asserts it.

PCI's uncovered controls also divide cleanly in a way worth keeping visible.
`9.1.1`, `11.4.1`, `12.1.1` and `12.10.1` — physical access, penetration
testing, policy, incident response — are marked unassessable because no scanner
reaches them. `5.2.1`, `6.3.3` and `11.3.1` — anti-malware, patching,
vulnerability scanning — stay _assessable_ and uncovered, because a scanner
could report them and this one does not collect the evidence. Backlog and never
are different answers and the catalogue distinguishes them.

**One bug I introduced and caught before it shipped.** The PCI scope note was
written with markdown emphasis around the scope caveat.
`ComplianceFramework.tsx` renders `{data.scope_note}` straight into JSX, so it
would have reached the customer as two literal asterisks — on the page that
most needs to be believed. A test now rejects markup in any framework's
customer-facing text, because the place a caveat most wants emphasis is exactly
where the next person will reach for it.

The frontend needed no change at all, which is the property worth noting: no
page branches on a framework id, so the compliance views rendered three new
catalogues the moment the API listed them.

---

## 62. Defender's findings are evidence, not verdicts to repeat

Six controls across four frameworks wanted the same thing — NIST `RA-5` and
`SI-2`, SOC 2 `CC6.8`, PCI `5.2.1`, `6.3.3` and `11.3.1` — and no ARM
configuration answers any of them. Whether a machine is patched, and whether an
agent is installed and healthy, are facts only the machine knows. Microsoft
Defender for Cloud is what knows the machine, so v5 of the scanner role reads
its assessments.

**The line worth holding is what a rule does with them.** Defender has already
reached a verdict on every asset it assesses. Mirroring those as CloudGuard
rules would turn two hundred assessments into two hundred findings, none of
which a customer could not already see in the Azure portal — a product that adds
a second inbox rather than a decision.

What CloudGuard has and Defender does not is the graph. So an assessment is read
as evidence: `AZ-VULN-001` fires only where Defender's vulnerability finding
meets CloudGuard's own knowledge that the machine answers the internet, and
returns NOT_APPLICABLE otherwise — explicitly, because Defender raises the
vulnerability on its own terms and there is nothing there CloudGuard knows that
Defender did not say better. The finding is the pairing, which neither says
alone.

**Severity stays Microsoft's, under Microsoft's name.** `provider_severity`
rather than mapped onto CloudGuard's scale: the two were tuned by different
people for different purposes, and quietly equating them would put somebody
else's judgement inside this product's risk formula.

**Only unhealthy assessments are kept.** A healthy one is Defender's verdict
rather than CloudGuard's evidence, and several hundred per subscription in every
snapshot would store a great deal to say nothing. `NotApplicable` is dropped for
a stronger reason: it frequently means the assessment could not run, and reading
it as a pass is the overclaim this engine refuses everywhere.

**And the absence is the case to get right.** A subscription with no Defender
plan returns no assessments. `security_assessments` is therefore absent on an
asset nothing assessed and an empty list on one Defender looked at and cleared —
None is UNKNOWN, `[]` is a PASS somebody earned. Reading the first as clean
would be an absence of evidence reported as evidence of absence, on the class of
finding a customer is most likely to believe.

**One catalogue correction fell out of it.** Mapping these rules gave NIST CSF
100% coverage, which `test_catalogue_lists_controls_no_rule_covers` refused —
correctly, and the fault was the catalogue rather than a mapping. CSF holds over
a hundred subcategories and this catalogue listed thirteen, all from Protect and
Detect, while its own scope note said Identify, Respond and Recover were out of
reach without naming any of them. Five are named now. The same correction as SOC
2's: a framework that reports full coverage is a catalogue understating the
framework.

---

## 63. The last two identity gaps cost a collector, not a consent

Application credential expiry and dormant privileged accounts are the two
categories `RULE_ENGINE.md` names as absent because the evidence is. Both were
assumed to be blocked behind a second Global Administrator consent — a per-tenant
ask heavier than anything CloudGuard has needed since onboarding, and worth
deciding deliberately. Checked rather than assumed, the ask is not there.

**The consent screen is already wider than the collector.**
`REQUIRED_GRAPH_PERMISSIONS` has carried `Application.Read.All` and
`AuditLog.Read.All` since the two-click redesign, alongside
`IdentityRiskyUser.Read.All`. No collector calls anything that needs any of the
three. So every tenant that has ever consented to this application granted them
at the moment they clicked, and the two gaps are collector work under permissions
already in hand — no redeploy, no re-consent, nothing to ask a customer for.

- Credential expiry reads `/applications` and `/servicePrincipals` for
  `passwordCredentials` and `keyCredentials`, which `Application.Read.All`
  covers.
- Dormancy needs no new object at all: role members are already collected. The
  missing field is `signInActivity` on `/users`, which Graph gates on
  `AuditLog.Read.All` _and_ `User.Read.All` — both granted.

A tenant that consented against an older registration would be the exception,
and needs no campaign to find: `missing_permissions` reads the granted
permissions out of the token's `roles` claim and names exactly what is absent,
per tenant, on every scan.

**The real gate on dormancy is a licence, and it is not consent's problem.**
`signInActivity` requires Microsoft Entra ID P1 or P2. A Free tenant with
complete consent still gets a 403, and the fix is a licence its administrator may
have decided against on purpose. That has to degrade as its own reason: this
scan could not read sign-in activity because the tenant is not licensed for it —
UNKNOWN with a sentence, like every other gap here. Reporting it as a permission
problem would send a Global Administrator to a consent screen that cannot fix it,
which is the failure `client.py`'s access-denied hints exist to prevent.

**Why the mistake was available to make is worth fixing too.** The ARM half of
the grant asserts this exact thing: `ROLE_ONLY_ACTIONS` derives every action the
role requests that no client call reaches, and a test asserts it empty, so a
permission on a customer's consent screen that nothing uses cannot survive a
build. The Graph half has no equivalent — which is how three unused permissions
sat there long enough for the collector's reach to be read off the code rather
than off the consent screen. The same derivation belongs on the Graph side, and
it turns green as these two collectors land rather than before.

---

## 64. Both collectors landed, and an expiry date is not a finding

§63 established that application credentials and dormant accounts were a
collector rather than a consent. Building them settled four things that were
not obvious from the outside.

**An expired credential is an outage, not an exposure.** The gap was named
"application credential expiry", and the obvious rule — this secret has expired,
or expires next week — is one CloudGuard should not ship. An expired secret
grants nobody anything; an application has stopped working, which the customer's
own alerting is better placed to notice than a security tool is. What an
attacker actually gets from an expiry date is its _remaining_ life: a secret
copied out of a pipeline log today keeps working until the day it was issued
for. So AZ-APP-001 asks how long a stolen credential would keep working, fails
above a year, and passes an expired one explicitly.

The registration is the asset rather than each credential. One application with
four long-lived secrets is one thing to fix, and four findings for it would be
the score charged four times for a single rotation.

Service principal credentials are deliberately not read. They exist, and reading
them means listing every service principal in the tenant — several hundred of
them Microsoft's — for the handful a customer created. That is the trade the
Conditional Access collector already made when it read back only the groups a
policy names: a directory dump for a few ids is worse than the narrower answer,
and what a customer rotates is the registration. AZ-APP-001's finding says so rather than claiming
to cover
every credential in the tenant.

**A licence is not a consent, and must not be reported as one.**
`signInActivity` needs Entra ID P1 or P2 on top of the grant every tenant
already has. A free-tier tenant with complete consent is refused it with a 403 —
the same status code a missing permission produces, from the same endpoint. The
collector reads Graph's own explanation and rewrites only that case, so the
tenant is told about a licence its administrator may have declined on purpose,
rather than being sent to a consent screen that cannot fix it. Everything else
keeps the existing behaviour of naming the permissions consent did not grant.

**An age has to be measured from the capture.** Days remaining on a credential
and days since a sign-in are the first evidence in this product that is a
duration rather than a value, and a duration computed against `now()` would make
a rule a function of when it was asked instead of what it read — so a replayed
snapshot would reach a different verdict from the same JSON, and "CloudGuard
verified the fix" would mean nothing. `RawSnapshot` carries `collected_at`, it
round-trips through `to_json`, and the normalizer measures every age from it.
The rules see plain numbers and stay pure.

**And the Graph side now asserts what ARM already did.** `ROLE_ONLY_ACTIONS`
has long derived every ARM action the scanner role requests that no collector
reaches, and a test keeps it empty. Graph had no equivalent, which is exactly
how three requested-and-unused permissions went unnoticed long enough for §63's
mistake to be available. `GRAPH_PERMISSION_USE` names the call behind each
permission and a test refuses any that is neither used nor reserved.

`IdentityRiskyUser.Read.All` is the one reserved entry. Trimming it would be the
tidier-looking move and the wrong one: §63's whole point is that a permission
already on the consent screen is one a future collector spends nothing to use,
and dropping it would sell that for a shorter list. Reserved with a reason keeps
it a decision rather than an oversight.

---

## 55. A payload is stored as compressed bytes, not as JSONB

§54 removed the copies. This removes the size of what is left.

`evidence_blobs.payload` was JSONB, which is the wrong representation for what
these rows hold. A payload is a provider listing — five hundred near-identical
objects repeating the same twenty key names, the same resource-group prefix on
every id, the same `"provisioningState": "Succeeded"` on every row — and JSONB
stores that as a parsed tree with the key names held per value. PostgreSQL's
TOAST compression only engages above a couple of kilobytes, and by then the
expensive representation has already been chosen. The column is now `bytea`
holding zlib-compressed bytes: roughly a tenth of the size on this input.

**Nothing was given up, because nothing used it.** A payload is read whole, by
hash, in `_rebuild_capture` and in the evidence planner, or not at all. There is
no query anywhere that reaches into one with a JSONB operator, and the rules
read the _normalized_ `CloudResource`, never the stored blob. So the JSONB
operators being lost were never load-bearing — which is the only thing that
makes this a size change rather than a capability change.

**The stored bytes are the hashed bytes.** `canonical()` is the one
serialization the content hash is ever taken over, and it is that exact byte
string that gets compressed and written. So a stored payload is checkable
against the hash it is filed under: inflate, hash, compare, which is what
`test_a_stored_payload_still_hashes_to_the_hash_it_is_filed_under` does against
real scans. A version that compressed a fresh `json.dumps` would round-trip to
an equal dict through a different byte string, and that check would become a
coin toss between a real corruption and a whitespace difference.

**zlib rather than zstd.** zstd would get perhaps a fifth off zlib's result on
this input, at the price of a native wheel in the API image, the worker image
and CI, for bytes already an order of magnitude down. The compression also runs
on the scan's hot path, so the level is 6 rather than 9: level 9 spends
noticeably longer for low single digits on JSON this repetitive.

**No backfill, and a CHECK instead.** Rewriting every historical payload is a
long write on the largest table in the schema, and retention retires those rows
on its own schedule anyway — so `payload` is kept, made nullable, and read as a
fallback, exactly as §54 kept `cloud_snapshots.data`. What 0028 does add is a
CHECK that a row holds one form or the other. Without it, a row that had lost
its bytes would read back as `{}`, and an empty payload is a real thing a
subscription with no storage accounts produces: "the bytes are gone" would be
indistinguishable from "there was nothing there", which is the same class of
error as UNKNOWN being read as PASS.

The downgrade inflates the compressed rows back into `payload` before dropping
the column, in Python and a page at a time. PostgreSQL ships no zlib inflate —
`pg_column_compression` reports how a value is TOASTed and nothing undoes an
application-level `zlib.compress` — so a SQL-only downgrade would have had to
discard every reading taken while compression was in use.

**And the write path stopped reading what it was about to skip.** `_store_blobs`
loaded whole `EvidenceBlob` rows to decide which payloads were already stored,
then set `last_seen_at` on them. On an unchanged estate — the case content
addressing exists for, and the common one — that read every payload it already
held back out of PostgreSQL, decompressed nothing, used none of it, and wrote a
timestamp. It now selects the hashes alone and touches them with one `UPDATE`,
guarded by `last_seen_at < observed_at` so a replay of a capture collected in
March cannot make its payloads look freshly read.

---

## 65. What holds a step, what stops two scans, and what a tenant may keep

Five production problems in the scanning path, all of them invisible in a
demo tenant and all of them certain in a large one. They are recorded together
because four of the five are the same mistake in different places: a mechanism
that was correct about the state it wrote and silent about who was entitled to
write it.

**A step is fenced by the attempt it was claimed under.** The lease made a
redeploy survivable: a step that stops renewing is returned to PENDING and run
again elsewhere. What it did not handle is the worker coming back. A process
paused past its lease -- a throttled container, a database stall, a long
garbage collection -- has not died, and it finished its collection minutes
later and marked the step SUCCEEDED while another worker was in the middle of
the same step. ANALYZE waits on collection _settling_, so the scan then
interpreted a subscription still being written and reported it as a complete
reading: the same overclaim as a PASS nobody earned, arriving through the
orchestrator instead of through a rule. Renewals and settles are now
conditional on the row still carrying the attempt the worker claimed, and a
worker that lost its step writes nothing. The renewal fence matters as much as
the settle: unfenced, the returning worker kept alive the lease of a step
somebody else was running, so the mechanism that reports a lost step was the
thing concealing that two workers held it.

**The lease is held by a clock, not by whatever the phase reports.** Renewal
used to happen inside collection's progress callback, which covered one of the
three step kinds. ANALYZE -- reconstructing every capture, evaluating every
rule, scoring every finding, the longest thing a scan does -- renewed nothing.
A tenant whose analysis ran past `ScanStep.LEASE_SECONDS` had its step reaped
mid-evaluation and restarted while the first was still writing, so the one case
where the reaper reliably fired was the case where nothing had gone wrong, and
it fired more reliably the larger the tenant. A background keeper now renews on
a fraction of the window for every kind of step, and a refused renewal stops the
work at the next opportunity rather than spending the customer's Azure quota on
a capture that will be discarded.

**One target, one lock.** Starting a scan takes a transaction-scoped advisory
lock and then checks whether one is already in flight. The lock was keyed on
whichever ids the caller happened to hold, and the callers do not agree: the API
and the rescan button pass a connection _and_ the subscription they resolved it
from, while the scheduler, the change trigger and the verification sweep pass
the connection alone. Those are two different locks over one connection, so a
customer pressing "Scan now" at the moment the scheduler started the same
connection got two scans writing findings for the same resources -- and the
unique index on (organization, rule, resource) turned the overlap into a scan
that failed with nothing a customer could read. The key is now the connection
wherever there is one, which is exactly the set the in-flight check treats as
overlapping.

**A lost message no longer strands a scan.** `unfinished_scan_ids` was written
as the safety net for an advance message the broker never delivered, and nothing
called it. A PENDING step holds no lease to expire, and the scan reaper
deliberately skips a scan with a live step -- so such a scan sat at whatever
percentage it had reached, permanently, with its connection answering "a scan is
already running". The reaper now nudges every scan with work outstanding, which
is a no-op on the normal path where a step enqueues its own successor.

**A step carries its own time limits, and a worker reserves one at a time.**
The general Celery ceiling bounds the short tasks, where anything past a minute
is a fault. A step is not that: one evaluation of an entire tenant legitimately
runs for half an hour, and cutting it at the general limit turned a large tenant
into a killed worker that the reaper retried at the same size -- three attempts,
three kills, and a failure whose only cause was the number of subscriptions the
customer owned. Prefetch drops to one for the same reason: a reserved message is
invisible to every other worker, so the default of four left three tenant-sized
steps idle inside one process while the queue looked empty to the rest of the
pool.

**Retention is a count as well as a window.** Days alone is a policy about time,
and storage is not spent in time. A customer scanning every half hour writes 48
captures a day per subscription and 1,440 inside a 30-day window; a customer
scanning weekly writes 4. Both are inside the same stated retention and their
tables are two orders of magnitude apart, which is how one tenant enabling
change-triggered scanning becomes the reason a shared database fills up. A
per-scope ceiling caps the series, ranked in PostgreSQL by the same
(created_at, id) order the replay path uses -- and the newest capture of a scope
is exempt from the ceiling exactly as it is from the window, because it is what
an applied replay reads.

**Evidence records which scan read the provider.** A reading inside its reuse
window is carried into the next scan, which writes a row of its own under its
own id holding the original's `collected_at`. The age survived; the authorship
did not. `finding_evidence.source_scan_id` exists precisely to say that the
collecting scan is not necessarily the scan that raised the finding, and it was
copied from `evidence.scan_id`, which could only ever name the latter -- so a
customer following a citation back to the reading it rests on was handed a scan
that made no such call. `evidence.source_scan_id` (migration 0031) carries the
collecting scan, NULL meaning this row is the reading, and a carried row's
source is followed rather than restarted so the trail stays one hop long however
many scans have reused it.

**And one performance change with no correctness argument behind it.**
Rebuilding a capture fetched its own stored readings, so an analysis of a
fifty-subscription tenant opened with fifty queries against the largest table in
the schema before a single rule ran. The readings are content-addressed and the
captures share them; they are now fetched once and handed down.

## 66. The frontend's own production failures

Four of them, all invisible in development and none of them a bug in any
feature. Development serves every module from a running dev server, never
redeploys under an open tab, and talks to an API on localhost that either
answers or refuses immediately -- so the conditions below only exist once the
thing is deployed.

**Nothing caught a thrown error, so the page went white.** React unmounts the
whole tree when a render throws and nothing catches it: no message, no way back,
and nothing on screen for a customer to describe to support. For a product whose
job is telling somebody whether their cloud is secure, a blank page is the worst
available answer. There is now a boundary at the root and a second one around
the router's outlet, so a page that throws leaves the reader with the navigation
they arrived by rather than an empty document.

**The most common cause of that blank page was not a bug at all.** Every page is
a dynamic import, and a deploy replaces the hashed files a tab already open was
going to fetch. Somebody who leaves CloudGuard open, gets a release, then clicks
Findings asks for a chunk that no longer exists; the import rejects, and the
`Suspense` boundary above it has nothing to catch it. That is not an error to
report -- it is a page that needs the new build -- so the boundary recognises
the shape of it and reloads once, guarded in session storage. Once, because a
reload that hits the same error again loops for ever, which is a worse blank
page than the one it replaced.

**A hanging request never resolved.** `fetch` has no timeout and neither does
TanStack Query, so a host that accepts the connection and then says nothing --
a container mid-redeploy, a captive portal, a mobile connection that dropped --
left the query in `isLoading` for as long as the tab stayed open. Requests are
now bounded (30s, and 120s for a report, which is rendered on demand and
legitimately slow), and a rejected fetch is reported as an unreachable API
rather than as the browser's own "Failed to fetch", which reads to a customer as
a bug in CloudGuard.

**An expired session read as a broken product.** Only the dashboard noticed a
401, and it noticed by rendering an error where its charts go. Everywhere else
every panel on the page failed with its own message, none of them said "signed
out", and nothing offered the action that fixes it. A 401 now clears the token,
which puts the router back in charge and sends the reader to sign in. A 403 is
deliberately not this: a viewer refused a write is signed in and should stay
signed in, and answering "you may not do that" with "prove who you are" would
land them back at the same refusal.

And one smaller thing found on the way: the query client retried every failure
once, including the ones the server has already answered definitively. Retrying
is now limited to the failures where nobody actually answered -- a 5xx, a
timeout, a dropped connection.

## 67. A control cites its readings, and the whole assessment leaves as a file

The compliance view walked the chain the product claims -- reading, rule,
control, framework -- in one direction only, and stopped one link short at each
end.

**At the evidence end it could only explain failure.** A finding cites the
readings behind it (`finding_evidence`), so "how do you know this is wrong" had
an answer. A _passing_ control has no findings, so it had no citations at all:
CloudGuard painted a green row and offered nothing to check it against, on the
one screen somebody might put in front of an auditor. The question an auditor
actually asks first is the other one -- how do you know this control is met --
and the answer was "because no rule complained", which is an assertion, not
evidence.

So a control now carries the provider readings its verdict rests on, taken from
the rules' own declared evidence keys and the latest scan's `evidence` rows:
which listing, when the provider was read, across how many scopes, under which
permission, and whether the payload is still stored. Three choices inside that
are load-bearing:

- **The oldest read and the worst outcome, never an average.** A control is
  only as current and as complete as the least of the things it rests on.
  Averaging would let forty-nine freshly read subscriptions hide the one nobody
  could read, which is the same overclaim as a PASS nobody earned, arriving
  through arithmetic.
- **A key nothing read is listed, not omitted.** It reports no outcome rather
  than a failure -- the provider did not refuse, nothing asked -- and it is the
  case that matters most, because it is precisely how a control ends up green
  on nothing.
- **Retention is reported, not assumed.** The blob store is asked which hashes
  still exist rather than inferring it from the hash being present. A citation
  whose bytes have aged out is still a true statement about what was read, and
  saying so beats offering a link that fails.

The evidence keys come from the `rules` read-mirror rather than the Python
registry (migration 0032 adds `requires_evidence` beside `compliance_mappings`),
for the reason that table exists at all: a rule deleted from the registry keeps
its row, disabled, so the controls it used to answer for do not silently become
uncovered.

**At the other end it could not leave the browser.** An audit is run from a
spreadsheet, and a GRC platform ingests JSON; a screen is neither.
`GET /compliance/{id}/export?format=csv|json` is the assessment as a document --
every control, its verdict, the rules behind it and the readings behind those,
including the controls that passed. It answers with a file rather than the
`{data, error, meta}` envelope, as reports do, because the caller is saving
bytes to disk and an envelope would make every consumer unwrap a shape that
means nothing there.

Two details of the CSV are decisions rather than formatting. **Every row repeats
the framework, its version and when the assessment was read**, which is
redundant on screen and is the only thing that survives what actually happens to
an export: fifteen rows copied into a larger sheet, where a row that no longer
says which reading it came from is a compliance claim with no date on it. And
**booleans are written as yes/no**: a spreadsheet coerces TRUE/FALSE into its
own boolean type and then formats it in the reader's locale, so a German auditor
opens the file and finds WAHR.

Nothing here issues a score. The export says what was checked, what was found,
and what it was found from -- the same position `coverage_ratio` takes on the
screen, carried into the one artefact that outlives it.

## 68. Thirteen more rules, and the ten that were already the same finding

A catalogue of 25 checks grew to 38. The interesting part is not the thirteen
that were written; it is the twelve that were asked for and are not here, and
why each is missing.

**Ten of them already ship under a different id.** A public storage account is
AZ-STO-001, which covers anonymous blob access _and_ an unrestricted network
default; a vault that can be purged is AZ-KV-001; an Any/Any inbound rule is
AZ-NET-003; a person or workload with subscription-wide control is AZ-IAM-001
and AZ-IAM-002; an identity that can hand out roles is AZ-IAM-003; a database
firewall admitting the whole internet is AZ-DB-001. Adding the requested ids
beside them would raise two findings for one misconfiguration, ask a customer
to close the same door twice, and deduct from the security score twice for
closing it once. The split was offered and declined deliberately: renaming
those rules into finer ids would orphan every finding raised under the old ones,
and the history is worth more than the taxonomy.

**Two more were near-duplicates found while building.** A subscription-level
Contributor is what AZ-IAM-001 already reports -- its ``FULL_CONTROL_ROLES`` is
Owner, Contributor and User Access Administrator, not Owner alone -- and a
managed identity with excessive privilege is AZ-IAM-002, which covers every
workload identity rather than only service principals.

**What is genuinely new falls into four groups.**

_The tenant, rather than anything in it._ AZ-ID-005 asks whether anything
enforces multi-factor authentication at all, and AZ-ID-006 whether legacy
authentication is blocked. Both are aggregate rules reading Conditional Access
and security defaults -- data CloudGuard already collected to _lower_ findings'
scores as compensating controls, and had never read in the other direction. The
second is the one that matters most in practice: IMAP, POP, SMTP AUTH and
Exchange ActiveSync cannot present a second factor, so they bypass every policy
demanding one, and a tenant can enforce MFA everywhere and still accept a
password on those endpoints.

_The accounts nobody calls an administrator._ AZ-ID-004 asks for a second
factor on ordinary accounts, and is careful to decline the privileged ones,
which AZ-ID-001 already reports at Critical. AZ-ID-011 and AZ-ID-012 are the two
states a privileged account can be in that a role review does not show: a guest
whose password and second factor belong to another tenant's administrator, and a
disabled account whose privilege survived being disabled -- offboarding that
stopped halfway, one checkbox from being an administrator again.

_Privilege the subscription cannot see._ AZ-IAM-008 reports full control granted
at a management group or the tenant root, which every subscription beneath it
inherits, including the ones created next year. AZ-IAM-010 reads the tenant's
own role definitions: a custom role granting ``*``, or the right to write role
assignments, is Owner under a name a privilege review does not recognise -- and
``notActions`` is read the way ARM reads it, so a Contributor-shaped custom role
is not reported as dangerous. AZ-IAM-005 is the count rather than the holders:
no single Owner is the one too many, so it cannot be asked per identity.

_Exposure and evidence._ AZ-NET-005 and AZ-NET-008 give SQL and SMB rules of
their own, and both ports leave AZ-NET-003's catch-all list in the same change,
following the convention RDP, SSH and WinRM already set -- a port in both places
would be that double-reporting again. AZ-NET-015 reports a public address on a
machine the estate says is sensitive or business-critical, and declines to judge
one nothing has classified: AZ-CMP-001 already reports what the internet can
reach, and this is a statement about the data behind it. AZ-LOG-004 asks
AZ-LOG-001's question of the two security-relevant types it does not cover --
key vaults and machines -- with the applies-to sets deliberately disjoint and a
test holding them that way.

**AZ-DB-006 is a reversal, and is marked as one.** `RULE_ENGINE.md` recorded a
decision against a transparent-data-encryption check: it costs an ARM
permission and a per-database fan-out to report PASS for very nearly everyone,
since TDE has defaulted to on since 2017. That reasoning still holds on its own
terms. What changed is §67: a control's passes now carry the readings behind
them, so a pass on an encryption control is the evidence an auditor asks for by
name rather than a row nobody reads. The role goes to `v6` for it, which means
every existing connection reports "redeploy the role" until they do -- the
prompt is honest, the checks that need the new actions report UNKNOWN in the
meantime, and no other category is affected.

Two smaller things fell out of the work. `Microsoft.Sql/servers/databases/read`
and its transparent-data-encryption sibling are the first actions whose task
fans out two levels deep -- servers, then databases -- which is why the reading
is keyed separately: a role that cannot make those calls loses exactly that
check rather than the reachability rule beside it. And the ARM action matcher
moved from the normalizer into `rbac.py`, where the vocabulary it interprets
already lives, because three callers now need the same reading of a wildcard.

## 69. A reading is scoped by region; a verdict is not

The first thing AWS breaks is not a name. Azure's ARM lists a subscription's
resources globally, so one evidence key meant one reading, and every layer of
the collector took that for granted: the executor indexed tasks by key, the
coverage report indexed results by key, and `evidence` was unique on
`(scan_id, cloud_account_id, evidence_key)`. AWS reads almost everything per
region. An account with seventeen enabled regions produces seventeen readings
of `security_groups`, which the executor would have called a duplicate task and
the database would have refused.

The temptation is to put the region into the key — `security_groups_eu_west_1`
— and it is wrong for a reason that is not aesthetic. `EvidenceKey` is what a
rule declares in `requires_evidence`, and a rule has no business knowing which
regions a customer has enabled. A rule asking for the security groups is asking
about the estate.

So the two are separated. A **reading** is identified by key and region; a
**verdict** is reached per key.

- `CollectionTask` and `TaskResult` carry an optional `region`, and a
  `scoped_key` of `security_groups@eu-west-1`. `None` — every Azure task —
  leaves the scoped key equal to the bare one, so nothing about a
  single-region-free provider changed.
- `CoverageReport` files results and payloads under the scoped key, so
  seventeen readings are seventeen rows rather than one overwritten sixteen
  times.
- `key_is_trustworthy` aggregates back: a key is trustworthy only if **every**
  region's reading of it was. Not any. Sixteen good regions and one denied is a
  partial view of the estate, and "nothing is open" is not a conclusion a
  partial view supports — the same position `PARTIAL` already takes on a
  listing truncated at the page cap.
- `key_problems()` therefore reports one gap per key and names the regions
  inside the reason. Per region would hand the rule engine a key it has never
  heard of; without the region a customer would be told their security groups
  failed and left to check seventeen of them.

Dependencies follow the same split. `depends_on` names bare keys, and a key
becomes available only once every one of its regional tasks has been scheduled
— counted down rather than marked on the first, or a dependent task would fan
out from one region's results and report the rest as absent.

### What the capture holds

A regional key's payload is a list of blocks:

```json
{"security_groups": [{"region": "eu-west-1", "items": [ ... ]}, ...]}
```

The provider's own JSON is untouched inside `items`, which is what keeps the
capture verbatim and replayable. The region sits beside it rather than being
recovered later from an identifier, because several AWS services return ARNs
with an empty region field and a normalizer would have to guess.

`coverage` entries now state `key` and `region` explicitly instead of leaving
them to be parsed back out of the entry name. A record that has to be recovered
by splitting a string is a record that is a function of how the string happens
to be spelled.

### Two smaller things this forced

**A wave is now bounded.** Concurrency was unlimited because a wave was eleven
ARM listings. A regional fan-out puts one listing per region in a wave, and a
customer with seventeen regions would open a hundred and fifty concurrent calls
— a shape designed to be throttled, since AWS throttles per region per service.
`CollectionRun` takes `max_concurrency`; a provider that asks for nothing keeps
exactly the behaviour it had.

**A regional key cannot be carried forward.** `CollectionPlan.carried` is keyed
by evidence, and one entry cannot hold seventeen readings without silently
keeping whichever was written last. Reuse is opt-in per key through
`reuse_window`, which defaults to never, so a provider gets this right by
leaving it alone.

### The migration

`evidence` gains `region`, and the unique constraint is rebuilt over
`(scan_id, cloud_account_id, evidence_key, region)` with `NULLS NOT DISTINCT`.
Both nullable columns there mean "this reading is not scoped that way" — a
directory reading belongs to no subscription, a global listing to no region —
and two readings that are both unscoped are the same reading. Under Postgres's
default the NULLs would be distinct from each other and the constraint would
stop protecting the rows it exists for. Migration 0033 removes any duplicate
first rather than failing on a customer's database; it is expected to match
nothing, because the only rows the old constraint could not separate are
directory readings and a scan takes one directory capture.

Nothing above the connector changed. The rule engine, `RuleContext`, the risk
scorer and every rule still degrade one `EvidenceKey` at a time and have not
learned that regions exist.

## 70. Two neutral columns, one provider blob, and a rename not done

`MULTI_CLOUD.md` §3 proposed renaming `tenant_id` and `subscription_id` to
`provider_directory_id` and `provider_account_id`, plus a `provider_ref JSONB`
for what is genuinely provider-shaped. Half of that is now built and half of it
is deliberately not.

**The blob is built.** `cloud_connections` and `cloud_accounts` each gain
`provider_ref`. AWS needs two things Azure has no equivalent of — the scanner
role's ARN, and the external id its trust policy must require — and neither is
read by anything neutral. That is the line: `tenant_id` and `scope_id` are
columns because the scanner, the scheduler and the UI read them; nothing outside
one provider's own onboarding module ever looks inside `provider_ref`.

It holds no customer secret and must not start to. The external id is a name the
customer's trust policy pins against, not a credential to their cloud.
`cloud_account.py` has claimed since v0.1 that CloudGuard stores nothing that
could leak access to a customer's environment, and a JSONB column labelled
"provider-shaped" is the obvious place for that to quietly stop being true.

**The rename is not.** `RawSnapshot.to_json` writes `tenant_id` and
`subscription_id` into every stored capture. Renaming the columns without the
payload keys would leave two vocabularies for one pair of facts; renaming both
would make every capture already taken unreplayable, which is the one thing the
raw snapshot exists to prevent. The rename is worth doing against a migration
of the stored snapshots, and it is not worth doing inside the change that adds
the second provider — the same ordering `MULTI_CLOUD.md` §8 already argues for,
now with a specific reason rather than a general one.

The columns are neutral enough to carry AWS meanwhile: an organization id and an
account id, in the two columns whose names happen to be Azure's.

**`ConnectionScope` gained AWS's three levels** rather than growing a second
enum. Every cloud has the same shape — a trust boundary, a grouping inside it,
and the unit a scan reads — so it is one question with three answers per
provider:

```text
Azure   TENANT_ROOT     MANAGEMENT_GROUP      SUBSCRIPTION
AWS     ORGANIZATION    ORGANIZATIONAL_UNIT   ACCOUNT
```

Named per provider rather than abstracted to "root / group / unit". Whoever
reads one of these rows is usually a support engineer matching it against a
portal, and the portal says "organizational unit". An abstract name would be
accurate and would leave them translating.

**AWS has one grant, recorded in two columns.** `consent_status` and
`rbac_verified_at` exist because Azure's two grants fail independently — admin
consent for Graph, and the ARM role — and a customer very often completes the
first and forgets the second. AWS has one cross-account role, and one successful
`sts:AssumeRole` proves everything there is to prove, so that single call sets
both. The alternative was leaving `consent_status` permanently PENDING for a
working connection, which would make `is_verified` false for a connection that
verifies. Its docstring no longer says "both grants": that was true while Azure
was the only provider, and is exactly the kind of sentence that stops being true
without anyone noticing.

## 71. Onboarding moves behind the seam, and the seam has no exceptions left

Scanning was provider-neutral from v0.1 and onboarding never was.
`services/cloud_connections.py` imported Azure's token provider, its ARM and
Graph clients and its role definitions at six call sites, and
`tests/unit/test_provider_seam.py` listed it as `SCHEDULED_EXCEPTIONS` — a leak
by schedule rather than by accident, because `MULTI_CLOUD.md` §8 step 5 put the
split after a second connector and gave the reason: a refactor whose right shape
is knowable from two examples and guessable from one.

AWS is the second example. `ProviderOnboarding`
(`app/connectors/onboarding.py`) is what the two turned out to have in common,
and it is a shape rather than a set of operations:

1. the customer names a scope and a connection is created;
2. CloudGuard hands them something to deploy, **generated from the declared
   permission set** rather than hand-maintained;
3. CloudGuard proves the grant by _using_ it, never by being told it exists;
4. the accounts beneath the scope are discovered rather than typed in.

What differs is how many grants there are. Azure has two that fail
independently — Entra admin consent for Graph, and an ARM role — with a service
principal to resolve between them. AWS has one cross-account role and nothing to
consent to.

**The steps a provider does not have return "nothing to do" rather than being
special-cased by the caller.** `start_url` answers `(None, None)`,
`ensure_principal` answers `ready=True`, `grant_problem` answers `None`. This is
the load-bearing part: a caller that branched on provider would be the thing
this split exists to remove, and a connection with no consent step must not sit
forever waiting for one.

### What stayed neutral

The service kept everything that is the same in every cloud and is most of its
length: creating and listing connections, the polling loop and its patience
window, writing discovered accounts and disabling the ones that vanished, the
scan schedule, the change-event debounce, the scope choices, the audit entries.
`_auto_discover` is the clearest split — the provider answers _what exists_, and
the neutral half decides what that means for rows already held.

### Two things this changed on purpose

**`CloudConnection.scope_path` is not a model property any more.** It rendered
an ARM management-group path for whatever it was handed, so an AWS connection
would have carried a plausible-looking Azure scope on every API response — a
wrong answer that reads as a right one. It is `ProviderOnboarding.scope_path`
now, reached through `cloud_connections.scope_path`.

**An unimplemented provider raises rather than answering "current".**
`role_upgrade_available` used to return False for any cloud that was not Azure.
That was correct while the question was "is the Azure role behind" and stopped
being correct the moment the question was routed by provider: False would say a
grant nobody has written is up to date. `get_onboarding` refuses, exactly as
`get_connector_class` does.

### The names

`role_version` stayed as a column and stopped being the word in code.
`grant_version`, `grant_upgrade_available`, `refresh_grant_version`,
`render_artifact`, `deployment_url` — the same mechanism, named for what every
cloud has rather than for what Azure calls it. The column keeps its name because
renaming it is a migration that buys nothing; the code does not, because the
code is what a reader uses to decide whether a concept is Azure-only.

One implementation detail is load-bearing and easy to undo by tidying:
`azure/onboarding.py` imports `app.connectors.azure.auth` as a **module** and
calls `auth.TokenProvider(...)`, rather than importing the name. The service it
came from imported inside each function, which read as an accident and was not:
every test of this path replaces `TokenProvider` with one that issues a prepared
token, and a name bound at import time would not see it.

`SCHEDULED_EXCEPTIONS` is now empty rather than deleted, so the next exception
has to be written down beside a reason instead of quietly appearing in the
allow-list above it.

## 72. The AWS connector, and an SDK where Azure has none

`MULTI_CLOUD.md` §8 step 2 is built: `app/connectors/aws/` sits behind the same
`CloudConnector` contract Azure does, and nothing above the seam changed to
accommodate it except the region dimension, which landed in the collection
executor (§69) rather than in the connector.

### aiobotocore, and why that is not a reversal

`DECISIONS.md` has said "REST over Azure SDKs" since v0.1, and the reason was
never a preference for HTTP: it was that the raw JSON had to be stored verbatim
so a scan could be re-evaluated later against better rules. Azure makes that
easy — ARM is one uniform paginated shape over one auth scheme.

AWS is not one shape. EC2 and IAM speak a query protocol answering XML, S3
speaks REST-XML, and everything else speaks JSON — three parsers, three
pagination idioms, and SigV4 underneath all of them. Hand-rolling that is a
large body of code whose failure mode is a subtly wrong canonical request, and
the property it would buy is one `aiobotocore` already gives: what it returns is
the provider's own response, parsed, and that is what the snapshot stores.

So the principle is unchanged and the implementation differs: **store what the
provider said, whatever it takes to obtain it.**

Two properties are kept from the Azure client because they are not the SDK's job
and the scan depends on them. Pagination is capped, and stopping at the cap is
recorded as PARTIAL rather than returning a shorter list — a list missing an
unknown number of entries cannot support "none of them are public". And a
refusal carries the operation that raised it, so `AccessDenied` on one listing
costs one evidence key.

`ResponseMetadata` is stripped from every response. It is a fact about the HTTP
round trip, changes on every call, and would make two identical readings hash
differently — defeating the evidence store's whole reason for being content
addressed.

### The plan's shape is a function of a call

This is the part with no Azure precedent. `ec2:DescribeRegions` is read _before_
the plan exists, because the plan emits one task per (listing × region) and
cannot be written without the answer.

The case that needed care is when that read fails. A key with **no reading at
all** raises no gap — so a rule sees no error, evaluates against an empty
payload, and returns PASS over an estate nobody looked at. That is the worst
outcome this product can produce. So when the region listing fails, the plan
still emits one task per regional key, region-less, each depending on the region
listing; the executor records them SKIPPED, the gap reaches the rules, and every
regional check reports UNKNOWN. `test_aws_plan.py` pins it, and the reason is
written there so the tasks are not removed as redundant.

An account reporting _zero_ enabled regions is treated the same way: an empty
region list is a failure to answer, not an answer.

### One grant, and where it is kept

Azure has two grants that fail independently; AWS has one cross-account role.
The role ARN and its **external id** live in `provider_ref` on the account row,
and every connector now takes `provider_ref` in its constructor — Azure accepts
it and ignores it, which is what lets the pipeline build a connector for any
provider without branching on which.

Per _account_ rather than per connection, because an organization-wide
connection assumes one role in each member account. The same stack is deployed
everywhere, so the ARNs differ only by account id and discovery can write them
without asking.

The external id is generated server-side, never accepted from a request body,
and `RoleAssumer` refuses to assume a role without one. An assume-role call with
no external id succeeds against a role whose trust policy does not require one,
which is exactly the misconfiguration CloudGuard must not participate in.

### What the policy grants, and how much of it is ours

`aws/iam.py` mirrors `azure/rbac.py`, with one difference that changes what a
mistake costs. ARM validates a role definition atomically, so a single wrong
action string fails the whole deployment and the customer sees "Deployment
Failed". **IAM accepts a policy naming an action that does not exist** and simply
grants nothing — the deployment succeeds, the customer sees green, and the read
fails mid-scan with `AccessDenied`. That is worse, not better.

So the bulk comes from AWS's own `SecurityAudit` and `ViewOnlyAccess` managed
policies, which cannot contain a typo of ours, and the inline policy holds only
what they do not. Every action in it is a read: no `s3:GetObject`, no
`kms:Decrypt`, no `secretsmanager:GetSecretValue`. CloudGuard can tell a
customer their bucket is public without being able to read a byte out of it, and
that claim is checkable from one tuple.

`iam:GenerateCredentialReport` is the one action that reads as a write and is
not. It creates nothing and changes no configuration; it asks IAM to compile a
report about state that already exists, and without it every credential-age
check reports UNKNOWN.

### Nothing here has been run against AWS

Every action string, response key and pagination shape comes from the published
reference. The modules say so in their docstrings, the action list carries
`# UNVERIFIED`, and `docs/AWS_INTEGRATION.md` §1 holds the checklist that turns
it from plausible into verified. Until that has been run, AWS is reachable
through the API and is not offered in the UI.

## 73. Onboarding AWS: one grant, three steps, and an id generated once

`ProviderOnboarding` (§71) was written against two clouds; this is the second
one filled in. The shape held — name a scope, deploy something generated from
the declared permission set, prove the grant by using it, discover what is
beneath — and every difference falls out of AWS having one grant where Azure has
two.

**No consent step, so nothing waits for one.** The polling loop refused to probe
until consent had reported the trust boundary, which is right for Azure and
would have left every AWS connection permanently PENDING. `has_separate_consent`
is the flag, and the point of it is that the caller does not branch on provider:
a cloud without a consent step says so, and the loop probes immediately because
the stack _is_ the grant.

**One probe sets both columns.** A successful `sts:AssumeRole` proves everything
there is to prove, so it writes `consent_status`, `consented_at` and
`rbac_verified_at` together. The organization id arrives from
`organizations:DescribeOrganization` on the same probe rather than from a
callback that does not exist — still from the provider, never typed, which is
the guarantee the Entra callback gives reached by a different route. An account
outside an organization answers with an error, and that is not a failure: a
standalone account is a boundary of one and names itself.

**Every scope names an account, including the widest.** Azure's tenant root
needs no id because consent reports the tenant; AWS has no call it can make
until it knows an account to assume a role in. That is `requires_scope_id`
rather than a comparison against `root_scope`, because the two clouds disagree
about the answer and only one of them can be the default.

### The external id

Generated in `initial_provider_ref`, before the row is written, and never
accepted from a request body. An id the customer chooses is an id an attacker
can choose.

`RoleAssumer` refuses to assume a role without one. That refusal is not
belt-and-braces: an assume-role call with no external id **succeeds** against a
role whose trust policy does not require one, so the only way to be sure
CloudGuard is not participating in that misconfiguration is to make the call
impossible to write.

It is shared across every account under one connection, and correctly — it
identifies the relationship, not the account. The role ARNs differ only by
account id, because the same stack is deployed into each, so discovery writes
them rather than collecting them.

### Reading the deployed version

From the role's inline policy document, not from the stack's version tag. A tag
is a label and a label is not evidence — the same reason the Azure equivalent
resolves role definitions rather than trusting a name, and it gets the answer
right for the customer who attached a broader policy of their own instead of
deploying the stack.

### The gate

AWS is registered in both registries and reachable through the API. It is **not
offered in the UI** until `AWS_INTEGRATION.md` §1's ten-item checklist has been
run against a live account. Shipping the picker first would be the failure
`MULTI_CLOUD.md` §8 named: a large body of code claiming to scan a cloud nobody
had scanned, with the seam looking finished.

## 74. Thirteen AWS rules, and the two things they made the normalizer do

`MULTI_CLOUD.md` §6 said rules stay provider-specific over neutral resource
types, and the reason was never aesthetic: `remediation` is snapshot-copied onto
every finding, and `aws s3api put-public-access-block` is not a variant of
`az storage account update`. A shared rule would have to branch on provider to
produce the fix, which is the same mistake as branching on framework name.

Thirteen rules under `app/rules/aws/` — public bucket, bucket without default
encryption, SSH / RDP / database ports open to the world, RDS publicly
accessible, RDS unencrypted, IAM user without MFA, root access key, stale access
key, weak password policy, a region with no CloudTrail, EBS default encryption
off. Every one declares `provider = Provider.AWS`, so `matches` keeps it away
from an Azure storage account, and the engine narrows the context per provider
so the aggregate rules — which never call `matches` — cannot reach one either.

### The normalizer grew a rule-facing surface

The first draft had rules reading AWS's own payload keys —
`resource.get("PublicAccessBlock.PublicAccessBlockConfiguration")`. That worked
and was wrong in two ways at once. It is not what the Azure normalizer does
(rules there read `allow_blob_public_access`, not an ARM sub-document), and it
made `RemediationSpec` undeclarable: an expected state names _the field the rule
reads_, and a nested path is not a field a test can set.

So the normalizer emits flat fields beside the verbatim payload:
`public_access_blocked`, `policy_is_public`, `default_encryption_enabled`,
`open_ingress`, `publicly_accessible`, `storage_encrypted`, `mfa_active`,
`password_enabled`, `key_idle_days`. The raw shape stays for whoever reads the
capture back.

`open_ingress` earns its place three times over: five rules ask the same
question of the same nested structure, and a fifth copy of that parser is a
fifth chance to read `-1` as "no ports" rather than "all ports".

**`None` is load-bearing in every one of them.** It means the setting was not in
this capture, which is not "off" — and the rules turn it into UNKNOWN rather
than a PASS nobody earned.

### Ages come from the capture, never the clock

`key_idle_days` is computed by the normalizer against `snapshot.collected_at`,
the way Azure computes `days_since_sign_in`. A rule that read `now()` would
answer differently on replay, which would quietly make "verified fixed" a
statement about when somebody asked rather than about the environment.

IAM writes `N/A` for a key nobody has ever used. That falls back to the creation
date rather than being dropped: a key nobody has ever used is the strongest case
for removing it, not a missing value.

### Four rules declare no expected state, and say why

`RemediationSpec` on AWS carries `expected` and `cli` and no `arm_alias`, so
`enforceable` correctly answers False — Azure Policy cannot enforce an S3
setting. The AWS equivalents are an AWS Config rule or an SCP, and neither is
generated, because an unverified one would deploy and check nothing.

Four rules declare `expected=()` outright: the root access key, the password
policy, CloudTrail coverage and EBS defaults. Each is a statement about the
_account_ or about a set of regions rather than about an asset, so there is no
resource an expected state could be checked against. That is the existing escape
hatch and it comes with the existing price — an empty declaration owes a reason
and something a customer can still run, and a test enforces both.

The stale-key rule joins them for a different reason worth keeping distinct: its
expectation is a _threshold over a collection_ ("no active key unused for ninety
days"), which the three comparisons cannot express. Half-declaring it would let
a customer satisfy what they were shown and still have the finding open.

### Compliance is scoped by the clouds in use

CIS AWS Foundations 3.0 joins the catalogue as data, and `Framework` gains a
`provider`. An AWS-only tenant measured against CIS Azure would report near-zero
coverage for reasons that have nothing to do with its security posture — the
same class of misleading number the coverage ledger exists to prevent, pointed
the other way (`MULTI_CLOUD.md` §7).

Frameworks written about _organizations_ — ISO, GDPR, NIST, SOC 2, PCI — carry
no provider and are always shown. An organization with no connections yet sees
everything: there is nothing to scope by, and answering "what does this product
check?" with silence would be worse than showing a benchmark they may not need.

Scoped on _any_ connection rather than a verified one, so the AWS benchmark
appears while a customer is still setting AWS up. A framework at 0% because
nothing has been scanned yet is an honest zero.

### The guards that had to become provider-aware

Two existing tests were checking every rule against Azure's answer.
`test_every_rule_depends_on_evidence_something_collects` now looks up the
producing plan per provider, and a new sibling asserts a rule declares its _own_
provider's evidence — a key from the wrong cloud degrades on something that
never runs, and would never appear in that scan's gaps either.

## 75. The wizard learns there are two clouds, and one of them is not offered yet

The setup flow was written for Azure and read as Azure everywhere: four rail
rows, a consent step, "Deploy to Azure", "subscriptions". Most of it generalized
by naming things differently; three parts did not, and those are the ones worth
recording.

**The rail is a function of the provider, not a constant.** AWS has three steps
where Azure has four, because there is nothing to consent to. A rail with a
permanently grey "Grant consent" row would read as a flow stuck on something
nobody is going to do — so `setupSteps(provider)` returns the rows and
`connectionStage` never returns `"consent"` for a cloud without one.

**The external id is on the deploy panel, before the customer deploys.** They
are about to create a trust policy that requires it, and the single thing making
this integration safe is that the policy demands a value only they and
CloudGuard know. Somebody who cannot see it cannot check that the stack they ran
actually asks for it. It is shown as copyable text with a sentence saying it is
not a password: on its own it grants nothing, and it is useless to anyone
without a role that demands it.

**The access panel states one grant or two, from the provider.** A permanently
green "Consent: granted" row beside a single AWS grant would be describing a
step that never happened.

### The copy is an override, not a second copy

`t.setup.aws` holds the dozen sentences that differ and nothing else;
`setupCopy(t, provider)` spreads it over the shared block. Two full sets would
drift, and the half that drifted would be the half nobody was looking at.

The types needed one accommodation: `en.ts` is a const object, so every value
has a literal type and an intersection of `"Connect Azure"` and `"Connect AWS"`
is `never`. `AsStrings<T>` widens, which is what lets one component read a
sentence whose wording depends on the cloud.

### AWS is in the picker and cannot be chosen

`GET /cloud-connections/providers` answers what this deployment can connect,
and the wizard renders unavailable options **greyed out with the reason** rather
than hiding them. A picker that silently held an option back answers "does this
support AWS?" with nothing; one that shows it disabled with a sentence answers
it, and tells an operator what to do about it.

Two reasons it can be unavailable, and they are different in kind. No AWS
identity configured is an ordinary deployment gap. `AWS_ENABLED=false` — the
default — is the honest one: every IAM action name, response shape and template
string in the connector was written from AWS's published reference and has been
called by nothing. `docs/AWS_INTEGRATION.md` §1 holds the ten-item checklist,
and until it has been run against a real account, offering AWS would be a
product claiming to scan a cloud nobody has scanned.

That gate is deliberately separate from having credentials, because the two
failures need different people. One is an environment variable; the other is an
afternoon with a real AWS account.

### What reaches the browser

`provider_ref` is filtered through an allow-list on the way out, not passed
through. That column is where a provider-shaped field lands, and the next one
added should have to be named before a customer can see it. Both current
entries are things the customer needs in front of them — the role ARN to check
what they deployed, the external id to check their own trust policy requires
it — and neither is a credential.

## 76. Change-triggered scanning on AWS, and the handshake that fetches

Change events were deliberately out of the first AWS slice (§72). They are in
now, and one difference from Azure turned out to have a security consequence
rather than a cosmetic one.

**The path is EventBridge → SNS → HTTPS.** EventBridge cannot post to an
arbitrary HTTPS endpoint on its own; doing it directly needs an API destination,
which needs the customer to create a connection holding a credential, then a
destination, then a rule — three resources and a secret of ours in their
account. An SNS topic with an HTTPS subscription is one more command than Azure
needs and stores nothing of ours. The topic is theirs, in their account, and
CloudGuard holds no permission over it — the same trade as the Event Grid
subscription: CloudGuard generates the commands and the customer runs them,
because creating any of it is a _write_.

### The handshake is an SSRF if you let it be

Event Grid confirms a subscription by asking for a code echoed in the response
body. **SNS confirms by handing over a URL and activating when it is fetched.**
That is an outbound request triggered by an inbound payload, from an endpoint
anybody holding the connection's token can reach — so the host is not taken on
trust. `confirmation_url` returns the URL only when it matches
`sns.<region>.amazonaws.com` (or `.com.cn`), and `None` for everything else;
`None` is refused rather than fetched.

The check lives in the _feed_, not in the endpoint, because the cloud that knows
what its own hosts look like is the one that should be saying. `test_aws_change_events.py`
pins the four ways this gets written wrongly: a suffix test passes
`…amazonaws.com.evil.test`, a substring test passes `evil.test/sns.…amazonaws.com`,
and anything splitting on the wrong character passes
`https://sns.…amazonaws.com@evil.test/`.

The contract gained `confirmation_url` for this. Azure answers `None` — it
echoes instead — so the endpoint serves both without learning which cloud does
which.

### One route, and the URL customers already have

`/events/azure/{id}` became `/events/{provider}/{id}`. The provider is a path
segment rather than a lookup, which means every Event Grid subscription already
wired to the old URL keeps working unchanged — the literal `azure` still
matches. An unknown provider, or one with no feed, is a 404 rather than a
dropped event: that is not a delivery CloudGuard decided against, it is a URL
nothing should be posting to.

### What is filtered, and where

Both feeds filter twice, and for the same reason. The endpoint drops what it
cannot use anyway; a filter the _provider_ applies is traffic that never leaves
the customer's account. AWS's rule pattern names the nine event sources rules
actually read, and the endpoint additionally drops reads (`Get`, `List`,
`Describe`…) and failed calls — a scan started because somebody listed their
buckets is a scan nothing asked for, and a call that failed left the environment
as it was.

A malformed `Message` is dropped rather than raised. The endpoint answers 200 to
everything it decides not to act on, and an exception would turn that into hours
of SNS redelivering the same unparseable payload.

## 77. Nothing is collected and unjudged, and the graph edge that stopped short

The first AWS slice left eleven evidence keys collected and read by no rule, and
nineteen of thirty-one CIS AWS controls with nothing behind them. Both are now
closed as far as they honestly can be: **thirty AWS rules, no key collected and
unjudged unless it is declared baseline, and 28 of 31 controls covered.**

The three that remain are named rather than quietly absent. 1.17 (a support role
exists) was called organizational here and marked `technically_assessable=False`
— **that was wrong, and §81 corrects it**. 4.1 and 4.3
are CloudWatch metric filters with alarms attached, which needs a collection this
connector does not have and a match against CIS's exact filter patterns — a
check that got the pattern slightly wrong would report a control satisfied that
is not, which is worse than reporting it uncovered.

### The distinction that decides whether an unjudged key is a bug

`BASELINE_EVIDENCE` is the answer, and it is not a loophole. VPCs, subnets,
network interfaces, elastic IPs, IAM roles, instance profiles and the account
list are collected because the _product_ is built from them — the inventory, the
graph — not because a rule judges them. Everything else that was unjudged now
has a rule, and `test_aws_evidence.py` holds the line: every key is produced by
something, and the ones no rule reads are declared.

### The graph edge that stopped one hop short

An EC2 instance names its **instance profile**; the profile names the **role**.
The first pass drew `HAS_IDENTITY` to the profile ARN, which is not a resource
CloudGuard holds — so the hop from a compromised workload to everything it may
do ended nowhere. `iam:ListInstanceProfiles` is collected for exactly this, and
the edge is resolved through it.

Deriving the role ARN from the profile's name would have worked most of the
time, which is the worst available property: the graph would have claimed a path
to a role that does not exist. An unresolvable profile draws no edge.

### Two collection calls that read like writes and are not

`iam:GenerateCredentialReport` was the first (§72). `config:DescribeConfigurationRecorderStatus`
is folded into the recorder task rather than given its own key — unusually for
this connector, which normally splits anything separately deniable. It is not
separately deniable here: both calls come from the same managed policy and are
refused together, and **a recorder that exists and is stopped is the finding**,
which needs both halves to see. Creating a recorder is two commands; starting it
is the third, and it is the one people miss.

### Where a naive check gets the wrong answer

Four cases were worth the tests they carry.

- **A network ACL's default entry is a deny-all on `0.0.0.0/0`.** Read without
  checking `RuleAction`, every correctly-written ACL in AWS reports as open.
  Egress entries are not ingress, either.
- **A multi-region CloudTrail trail is returned by every region it covers.**
  That is what makes coverage answerable (AWS-LOG-001) and what would make every
  other trail rule count one trail seventeen times. `_unique_trails` keys by ARN.
- **IAM accepts `*` and `*:*` and means the same thing.** A check that knew one
  spelling would pass the other. A statement carrying a `Condition` is not the
  unbounded grant this rule is about.
- **A flow log or an analyzer in a non-ACTIVE state records nothing.** Reading
  existence rather than status would pass an account logging nothing.

And one where the honest answer is UNKNOWN: the CloudTrail bucket is very often
in a _different_ account — a dedicated log archive is the shape AWS recommends —
and CloudGuard cannot read a bucket it was not granted. "We could not look" is
not "logging is off".

### Two rules that decline rather than raise

An AWS-managed KMS key rotates on AWS's schedule and the setting cannot be
changed, so AWS-SEC-001 returns NOT_APPLICABLE for one rather than a finding
nobody can close. AWS-LOG-002 does the same when the account has no trail at all:
that is AWS-LOG-001's finding, and raising both would charge the security score
twice for one problem written two ways.

### The policy goes to v2

Eleven new actions, so every existing connection reports "redeploy the stack"
until they do — the prompt is honest, the checks that need the new actions report
UNKNOWN meanwhile, and no other category is affected. `V1_ACTIONS` is written out
rather than sliced off v2: what an older stack grants is a fact about that stack,
and deriving it from today's list would make it change every time today's list
does.

## 78. The columns say "subscription" and the sentences do not

`DECISIONS.md` §70 kept `tenant_id` and `subscription_id` under Azure's names,
because `RawSnapshot.to_json` writes them into every stored capture and renaming
them would make each one unreplayable. That decision was about _identifiers_, and
it quietly became a decision about _sentences_ too — which it was never meant to
be.

The result was a product that told an AWS customer "this subscription is no
longer connected to CloudGuard", showed "3 of 5 subscriptions" against their
organization, and offered a button reading **Connect Azure** on the page where
they were about to connect AWS. Each is small. Together they are a CSPM that has
not noticed which cloud it is looking at, which is not a small thing for a
product whose whole claim is that it looked.

So the split is now explicit: **identifiers stay Azure-flavoured, sentences do
not.** `app/core/vocabulary.py` and `src/lib/vocabulary.ts` are the two places
that know the difference.

### Nouns, not sentences

Both hold `account` / `accounts` / `boundary` / `directory` / `artifact` /
`console` and nothing longer. A sentence per provider would be two sentences to
keep in step, and the half nobody was looking at would drift — the same reason
`t.setup.aws` is an override rather than a second copy of the setup block.

An unknown provider gets Azure's words rather than an exception. This is a
sentence, not a security decision: a missing noun should read slightly wrong
rather than break the page somebody is trying to read.

### Where it is applied, and where it is not

Applied to what a **customer** reads: the scanner's scope and collection errors,
`ScanStep.describe`, the scan's problem list (which becomes `error_message`), the
stalled-deployment message, the finding route's directory error, the connection
row, the account scope list, the scan detail panel.

Not applied to the log lines. `_log_step` keeps the neutral default, because a
log line is read by us and threading a provider through it would cost a query per
step to change a word nobody outside is reading.

Not applied to `t.setup`, either: that block is Azure's, and AWS overrides it
whole. Two of its strings still say "subscription" and are correct — they are the
Azure branch.

`DEPLOY_STALLED_DETAIL` stopped being a constant and became
`deploy_stalled_detail(connection)`. It names both the artefact and the console,
and it is shown at the moment a customer is most likely to be confused about
which step they are on — "the scanner role … in Azure Portal" is the wrong pair
of nouns for somebody who ran a CloudFormation stack.

### The scan scope now says which cloud it read

`ScanScope` gained `provider`. The field names around it keep Azure's vocabulary
because the columns do; this is the one field that lets the panel reading them
choose the right label rather than guess from the shape of an id.

### What is deliberately unchanged

Every API field name and every database column. `subscriptions`,
`subscription_id`, `subscription_count`, `tenant_id`. Renaming them is a
migration of stored captures plus a breaking change to the frontend, buys no
customer anything, and is the work §70 already argued should happen on its own
rather than inside the change that adds a second provider.

## 79. A recorded AWS estate, because there is no other way to watch it work

The demo seed replayed a recorded Azure snapshot through the real pipeline so
the product loop could be shown before anyone had a tenant. AWS needs that more,
not less: nothing in `app/connectors/aws/` has been run against a live account,
so a recording is the **only** way to see the second half of the product work end
to end.

`--provider aws` seeds an organization from
`tests/fixtures/aws_raw/snapshot_mixed.json`. The recording is in the shape the
collector produces — regional blocks, per-bucket readings keyed by name, the
credential report as parsed rows — and everything after it is real: the real
normalizer, thirty real rules, the real risk engine, the real findings
lifecycle.

**What it proves and what it does not** is worth being exact about. It proves
the regional blocks unwrap, the per-bucket readings join, the graph resolves its
capability hop through the instance profile, thirty rules reach a verdict, and
none of them reports UNKNOWN over evidence that arrived. It proves nothing about
whether the payloads it replays are the payloads AWS actually sends — which is
exactly what `AWS_INTEGRATION.md` §1 covers, and why the checklist still gates
the UI.

### The fixture is a test before it is a demo

`test_aws_demo_environment.py` pins the verdicts as a **set**, not a count: a
count tells you something changed, the set tells you what. It also asserts no
Azure rule touches the recording, and that the capture round-trips through
`to_json`/`from_json` to the same conclusions — if those disagreed about the
regional block shape, every replayed AWS scan would quietly reach different
verdicts from the scan that took the reading.

Sharing the fixture between the demo and the tests is deliberate in both
directions. A demo assembled from fabricated findings would prove nothing about
the code that produces them, and a fixture nobody looks at drifts from the
product it is supposed to describe.

### The estate is deliberately not catastrophic

The first draft failed 28 of 30 rules. That is a worse demonstration, not a
better one: the security score decays toward zero (`RISK_ENGINE.md` §3, §45
above), and a screen with no green on it says nothing about a
product whose whole point is telling the two apart.

Tuned to 14 failures against 21 passes, and the split is the realistic one — the
account-wide controls are in place, and what is wrong is wrong about particular
resources. That is what a competent team's estate looks like.

### `--fix` closes two, and the bucket needed both halves

The repaired replay closes the public bucket and the open SSH rule. The bucket
fix sets **both** the access block and the policy status, because the rule
refuses a bucket that blocks public ACLs and still carries a policy granting
`*` — two independent ways in. A fix satisfying half of it would leave the
finding open and make the demo look broken while the product was working
correctly, which is the kind of thing that gets a correct check deleted.

`ReplayConnector` takes its provider from the recording rather than from the
class, and asks the right connector's `keys_in` when turning a recorded category
error into per-key gaps. Getting that second one wrong would show a degraded
banner over rules that passed regardless — the contradiction the coverage ledger
exists to prevent.

## 80. CIS section 4, and the chain a setting cannot express

4.1 and 4.3 were left uncovered in §77 with a stated reason: they need a
collection the connector did not have, _and_ a match against CIS's exact filter
patterns, and a check that got the pattern slightly wrong would report a control
satisfied that is not. Both halves are now addressed, and the second one is
addressed by not pretending.

### The question is a chain, not a setting

"Is anybody told when this happens" has six hops:

```text
trail → CloudWatch log group → metric filter → metric → alarm → alarm action
```

Every one of them can be missing on its own, and a missing hop anywhere means
nobody is told. This is why the check is worth writing carefully rather than at
all: **the most common state is half-done** — the filter exists, the metric is
published, and no alarm was ever created on it. A rule that looked only for the
filter would pass exactly that account, which is worse than not having the rule,
because it would be a confident wrong answer about whether anyone is watching.

So `MonitoringCheck` carries _where_ the chain stops rather than a boolean.
"No filter" and "a filter with no alarm" are the same verdict and different
afternoons, and the message says which.

Two hops needed care beyond existence. An **alarm with no action** changes a
colour on a dashboard nobody is looking at, so it is counted as silent rather
than as an alarm. And an alarm can only watch a metric in its **own region**, so
the metric key includes the region — a filter in eu-west-1 and an alarm in
us-east-1 are two things that never meet, and pairing them would report a chain
that does not exist.

### The pattern match is necessary and not sufficient, and says so

CIS specifies exact filter patterns. Requiring the literal string would fail
every team that wrote an equivalent one; evaluating CloudWatch's filter-pattern
language properly means implementing somebody else's expression grammar, and
implementing it _nearly_ right is worse than not implementing it — a pattern that
parses differently to how AWS parses it produces a confident wrong answer, which
is the failure this codebase refuses everywhere.

So the test is that the pattern names every ingredient the event is about:
`$.errorCode` plus both refusal codes for 4.1, `$.userIdentity.type` plus `Root`
for 4.3. Each ingredient is a set of alternatives, which is what lets
`AccessDenied` and `AccessDenied*` both count without accepting a pattern
mentioning neither.

**And the matched pattern goes into the finding's evidence, verbatim.** That is
the part that makes the compromise honest rather than merely convenient: a
reader is shown what was matched and can judge it, instead of being asked to
trust this rule's opinion of a language it does not parse. The `notes` on the
remediation declaration say the same thing to the customer.

### Two rules rather than one

They walk the same chain and are not the same check: a pattern matching refused
API calls says nothing about root usage. `_MonitoredEventRule` holds the walk;
each rule declares its ingredients and its sentence.

Both return NOT_APPLICABLE when the account has no trail at all. That is
AWS-LOG-001's finding, and raising all three would charge the security score
three times for one problem written three ways — the same reasoning AWS-LOG-002
already followed.

### Where this leaves the benchmark

**30 of 31 CIS AWS controls covered** at the time this was written. The one
remaining was 1.17, "a support role exists to manage incidents with AWS Support",
described here as organizational — **§81 corrects that, and corrects the
catalogue it was counted against**.

The policy goes to **v3** for `logs:DescribeMetricFilters` and
`cloudwatch:DescribeAlarms`. Both are very likely already inside `SecurityAudit`,
which carries `logs:Describe*` and `cloudwatch:Describe*`; they are granted
anyway, in the direction `rbac.py` already prefers — a redundant read action
costs a redeploy prompt, and a missing one costs two checks whose cause is one
denied call several minutes into a scan.

## 81. 1.17 was not organizational, and the catalogue was flattering itself

Two corrections, and the second is the one that mattered.

### The control

§77 and §80 said CIS AWS 1.17 — "a support role exists to manage incidents with
AWS Support" — was organizational and marked `technically_assessable=False`. That
was an assumption from the control's wording, and it was wrong. **CIS's own audit
procedure for it is a single API call:**

```bash
aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess
```

The policy ARN is AWS's own and identical in every account, which is what makes
this one call rather than a walk over every principal's attachments. AWS-IAM-009
asks exactly that question, and the flag on the catalogue entry is now gone.

It is the first rule with `exploitability = 0`, and that is precise rather than
lazy: there is no attack here at all. The cost is paid _during_ an incident
rather than caused by one — an account under active abuse needs a case opened
with AWS, and without this policy attached to somebody the only way in is root,
which is slow, usually held by one person, and exactly the credential an incident
response should not be reaching for. It scores as nothing and is reported anyway,
because a product that only reported what scores would never mention it.

### The catalogue

Covering 1.17 took CIS AWS to 31 of 31, and
`test_catalogue_lists_controls_no_rule_covers` failed — correctly. Its reason is
in its own name: _"a catalogue of only what CloudGuard checks would report full
coverage forever."_

The catalogue was not complete; it was **the controls I had written rules for,
plus the handful I had written down as gaps.** Full coverage of that is not a
number worth printing, and the guard is what stopped it being printed.

So the catalogue grew to the shape it should have had: the whole of section 4
rather than the three controls referenced, the section 1 controls a scanner
genuinely cannot reach (contact details, security questions), and the section 2
and 5 entries this product does not check. **31 of 56**, and every one of the
twenty-five gaps is a real control somebody could ask about.

Thirteen of those gaps are section-4 metric filters, all the same shape as the
two now covered (§80). That makes them a backlog item rather than a limitation,
and the catalogue says so — which is a more useful thing for a customer to read
than a coverage bar at 100%.

**The lesson is the guard's, not mine.** A test asserting that every framework
has an uncovered control looks like an odd thing to write until the day a
catalogue quietly becomes a list of answers rather than a list of questions.

## 82. The other thirteen of section 4, written as declarations

§81 left thirteen CIS AWS controls uncovered and called them a backlog item
rather than a limitation, on the grounds that the two covered ones prove the
shape is reachable. This is that backlog item, closed. CIS AWS is now 44 of the
56 catalogued controls, and every one of section 4 is walked.

### Thirteen rules and no new evaluation

The chain was already written: trail → CloudWatch log group → metric filter →
metric → alarm → action, in `_MonitoredEventRule`. Each of the thirteen declares
what CIS's own filter pattern for that control names — `$.eventName` and
`StopLogging` for a trail being silenced, `kms.amazonaws.com` with both
`DisableKey` and `ScheduleKeyDeletion` for a key being destroyed — and nothing
else. No new collector, no new evidence key, no new walk.

The check stays what §80 made it: a **necessary condition**. CloudGuard does not
evaluate CloudWatch's filter-pattern language, because implementing somebody
else's expression grammar _nearly_ right produces a confident wrong answer. The
pattern that matched travels in the finding, so a reader judges it rather than
trusting this product's opinion of it.

### The remediation is generated, and that is the point

Thirteen copies of one paragraph drift. The day the alarm command gains an
argument, twelve of them keep the old one and a customer follows whichever they
were handed. So the prose and the `RemediationSpec` are both built from one
filter-name-and-pattern pair per rule, by `_monitoring_remediation` and
`_monitoring_spec` — the same reasoning as the IAM manifest being generated from
the declared permission set rather than hand-maintained (§72).

`test_the_filter_the_remediation_prints_satisfies_the_check` closes the loop:
for every rule in this family, the pattern printed in the remediation satisfies
that rule's own check. It is the discipline `test_remediation_spec.py` applies to
rules that can state an expected value, applied to the ones that cannot — a
customer who runs exactly what the finding told them to run passes.

The second test is the one that earns its place over time.
`test_no_rule_here_is_satisfied_by_another_one_s_filter` runs the full matrix:
fifteen patterns against fifteen rules, and only the diagonal passes. Fifteen
rules sharing one evaluation is a saving right up until two of them accept the
same filter, at which point an account is told something is watched that nothing
watches. Both tests read the family off `RULE_REGISTRY`, so a sixteenth rule is
covered on the day it is added rather than the day somebody remembers.

### Severities, and the one that is deliberately LOW

Two are HIGH because they are the ones that hide or destroy: a trail being
stopped (4.5) blinds every other alarm in the section, and a customer key being
scheduled for deletion (4.7) is the destructive path that needs no data access at
all. Organizations changes (4.15) are HIGH for a different reason — everything
CloudGuard checks in a member account is checked on the assumption that the
organization above it still constrains that account, and `LeaveOrganization`
ends that assumption without changing anything inside the account.

Console sign-in failures (4.6) are LOW, and stating why is more useful than the
number: a password policy and enforced MFA are preventive, CloudGuard checks
both separately, and this is only detective. It is still reported, because a
spray that eventually succeeds produces a _successful_ sign-in nothing else
distinguishes from a Monday morning.

All thirteen keep the family's exploitability of 1. None of them is exploitable;
each weakens detection.

### The recorded estate grew filters rather than findings

The obvious way to land thirteen aggregate rules is to let the recorded estate
(§79) fail all thirteen. That would have been dishonest twice over: an account
that has written no metric filters at all is not the account this recording
describes — it has a trail, a log group and a CIS filter already — and
`test_most_of_the_estate_passes` exists precisely to stop the demo becoming a
wall of red that shows none of the product's ability to tell good from bad.

So the fixture gained eleven filters and their alarms, and deliberately not
thirteen. It has no filter for a key being scheduled for deletion and none for
Organizations, which is what a real account looks like after somebody worked
through a benchmark and stopped at the services they use daily. Two new findings,
eleven new passes.

### What this does not change

Nothing here has been near a live AWS account. These rules read
`log_metric_filters` and `cloudwatch_alarms` as `normalizer.py` produces them,
and whether those payloads are the payloads AWS actually sends is still
`AWS_INTEGRATION.md` §1's question — checks 16 and 17 in particular, which are
about exactly the ARN shape and the `metricTransformations` spelling this family
joins on.

## 83. The dashboard's two list panels are Cards, and the feed is a timeline

Every dashboard panel drew its own chrome — a `<section>` with a hand-written
`rounded-xl bg-card ring-1 ring-foreground/10` and its own header padding —
which is the `Card` primitive's job (§24) copied nine times. `PriorityRisks` and
`RecentChanges` are the first two to move: both now use `Card` / `CardHeader` /
`CardTitle` / `CardDescription` / `CardAction` / `CardContent`, with
`role="region"` carrying the labelling the `<section>` used to, and
`--card-spacing` set to 5 so their padding still lines up with the seven
neighbours that have not moved yet. Those seven are a follow-on, not a
different decision: the two panels here changed because their _content_ was
being restyled, and converting the rest is a mechanical edit with no visual
consequence.

### A risk row leads with severity, not with an ordinal

The rank was rendered as a small grey `1 2 3` in its own column. The list is
already in rank order, so the column spent a column restating the reading
direction. It is replaced by a severity-tinted mark that takes its colours from
`levelStyle` — the same map `SeverityBadge` reads, so a row's tile and its badge
can never disagree about what CRITICAL looks like — and its _shape_ from what
the row is: a route mark for a scenario, a shield for everything else.

The badge moved to the trailing cluster beside the score, where the eye lands
after the title rather than before it. Nothing was dropped: the score, the
scenario marker, and the exposure/sensitivity/criticality terms that explain the
ranking all still render, the last of these now each with their own icon rather
than three identical radar glyphs.

### The change feed is drawn as the sequence it is

`RecentChanges` was five flat rows with a date pinned to the right edge. It is
now a three-column timeline — date gutter, spine, entry — because the question
it answers is temporal: whether a week's movement was one bad afternoon or a
steady drift is visible in the spacing of the marks and invisible in a right-
aligned column of dates.

The spine stops at the first and last mark rather than running to the edges of
the list, which would imply rows that are not there. The mark keeps both its
colour and its shape (`TrendingUp` for a regression, `Plus` for an arrival,
`Minus` for neutral), so the §66-adjacent honesty rule survives the restyle: an
attribute that moved into UNKNOWN is a loss of knowledge, renders neutral, and
is still distinguishable from an improvement without relying on hue.

## 84. A motion runtime, the sidebar primitive, and charts on shadcn's wrapper

Three UI decisions taken together, because each one is a thing the project had
declined before and the reasons it declined them have changed.

### The frontend now has a motion library

`motion` (framer-motion's current package name) is a dependency. The rule it
breaks is the useful kind of rule — no runtime for something CSS already does —
and it is broken for the one case CSS genuinely cannot do in a React SPA:
_exit_. A route that unmounts has no frames left to animate in, so a page swap
either cuts hard or the outgoing tree has to be kept alive by something that
knows it is leaving. That is `AnimatePresence`, and it is why `PageTransition`
exists.

What did **not** move: `index.css` still owns the two chart keyframes and the
`prefers-reduced-motion` block, and `useCountUp` is still hand-written, because
a number counting to its value is arithmetic rather than animation and the
existing one already guarantees it lands exactly on the value. The list staggers
on the findings and assets tables are still CSS — a `<tr>` cannot be wrapped in
a `<div>`, and the rise is the whole effect.

Reduced motion is answered in one place per layer and nowhere else:
`<MotionConfig reducedMotion="user">` in `main.tsx` for the runtime, the media
query in `index.css` for everything else. Both degrade to _the end state,
immediately_ — reduced motion means arriving, not crawling. Nothing below either
of them checks the preference itself.

The timings live in `lib/motion.ts` as `DURATION` and two easings, not as
numbers typed into components. Motion in this product is a claim that something
arrived or changed, and six panels each picking their own duration would make
six different claims about one event.

**Entry animation is never gated on a "first render" flag.** A motion element
runs `initial` when it mounts and never again, so a keyed row that survives a
refetch does not replay. Keep the keys stable and the animation stays honest:
the dashboard polls every twenty seconds, and a table that re-staggered on every
poll would teach the reader that movement means nothing.

### The shell runs on `@shadcn/sidebar`

`Shell.tsx` hand-rolled a fixed rail, a collapse button, a `Sheet` for mobile
and the padding that kept the two in step. All of that is the primitive's, so it
is the primitive's now — `SidebarProvider` / `Sidebar collapsible="icon"` /
`SidebarInset` / `SidebarRail`, with `SidebarMenuButton` carrying the collapsed
tooltip that used to be wired by hand.

Two edits to the vendored source were needed and both are deliberate:

- **The cookie is gone.** Upstream writes `sidebar_state` on every toggle. That
  would be the only cookie CloudGuard sets, and a security product that plants
  one to remember a rail width has to explain it in a privacy notice. The
  provider is controlled from `Shell` instead, and the preference stays in
  `localStorage` under the same `cloudguard.sidebar.collapsed` key it has always
  used — so nobody's remembered rail is lost.
- **`useIsMobile` reads its media query up front.** Upstream starts at
  `undefined` and fills the answer in from an effect, which renders one frame of
  "not mobile" on every phone and trips this project's lint rule against setting
  state in an effect.

`SidebarTrigger` names itself "Toggle Sidebar" in both states, which is a
control a screen-reader user cannot tell the state of. `NavToggle` wraps it to
say which way it will go and to carry `aria-expanded`, keeping the accessible
names the shell already had. (Where it sits changed in §85.)

Which row is current is `useMatch` per row rather than `NavLink`'s render prop:
the primitive wants the answer as a prop, because the anchor itself carries the
button styling and the focus ring, so nothing may sit between them. Non-exact
rows stay lit on their detail screens — a reader on `/findings/<id>` has not
left Findings.

### Charts sit inside `ChartContainer`

`ActivityBars`, `Donut`, `EstateTreemap` and `ScoreTrend` each hand-built a
Recharts `<Tooltip>` with an inline `contentStyle`, because Recharts paints that
element inline and it does not inherit the surface — unset, it stays white on a
dark page. Four copies of the same six declarations. They now use
`ChartContainer` / `ChartTooltip` / `ChartTooltipContent` / `ChartLegendContent`,
and the tooltip is a themed element like every other popover in the product.

**The tuned ramps stay authoritative.** `chart.tsx` defines no `--chart-*`
tokens of its own; it emits a `--color-<key>` per series, scoped to one chart
id, from the `ChartConfig` it is given. So the contrast-measured neutral ramp in
`index.css` and the severity scale are still the only definitions of those
colours, and `ActivityBars` still maps its three series to `--sev-medium`,
`--sev-ok` and `--sev-critical` — those are statuses, not categories.

This upgraded Recharts 2.15 → 3.8, which `chart.tsx` is written against. The
cost was the four hand-written tooltip formatters, whose v2 signatures no longer
typecheck; they were the code being deleted anyway.

### The rest of the pass

- **Destructive confirmations are `AlertDialog`.** `RemoveConfirm` and
  `DeleteScanConfirm` announce themselves as `alertdialog` and cannot be
  dismissed by a click on the backdrop. A stray click outside an ordinary dialog
  is a harmless miss; on these two it was the same gesture that deletes an
  environment or purges findings. `DeleteScanConfirm` also stopped being a red
  panel wedged under the scan card it was about to delete.
- **One pager, and it can jump.** Four pages had copied the same
  Previous / "3 / 9" / Next. `common/Pager.tsx` draws real page numbers with
  first, last, and a window either side, so reaching the end of a four-hundred-
  row findings list is one click rather than eight round trips. `StepPager` is
  the variant for the changes feed, which is windowed by date and has no total —
  inventing one would be a claim the API never made.
- **Severity is a `ToggleGroup`, not a select.** _Superseded by §85: severity
  is a `SelectField` again._ Four values plus "all", never changing, the filter
  the findings and risks pages are actually worked through — laid out, the
  current filter is visible without opening anything. Deselecting the active
  item keeps it: an empty severity filter is not a filter anybody wants.
- **Change detection is a `Switch`.** A pill reading "Listening for changes"
  beside a button reading "Turn on change detection" stated the same fact twice.
  The switch is labelled with what the setting is _for_ rather than what it
  currently is, because that is the half that does not change when it moves.
- **Compliance controls collapse, except the ones that matter.** CIS Azure is
  fifty-six controls; rendering every rule and reading of all of them buried the
  dozen that are wrong under the forty that are not. Failing and inconclusive
  controls arrive expanded, passing and not-covered collapsed — and the verdict
  is always in the trigger, never inside the panel. What a control says is not
  something a reader should have to expand to find out.
- **Finding titles preview on hover.** The column truncates, which is right for
  a table and wrong for the reader opening six rows to find the one they meant.

### One test-suite change, and it is not about this work

`findByText` waits one second by default — a figure that describes how long a
_component_ takes to settle. These tests mount whole pages inside jsdom, in
parallel across every core, and under that load a page rendering in 200ms alone
takes several seconds. The failure was always the same shape: a `findByText`
timing out on text the page does render, in a test that passes on its own. It
predates this work; one suite carries a comment about losing "about one run in
three". `asyncUtilTimeout` is now five seconds and `testTimeout` twenty, which
is a slow suite instead of a slow machine reported as a broken product.

## 85. The collapse control sits at the foot of the sidebar, and every filter is a select

Two reversals of §84, both made after using the result on the deployed build.

### The sidebar toggle moved from the header to the sidebar footer

§84 left `NavToggle` at the left edge of the page header. That put the control
for the column in a different element from the column, and it moved: the header
starts where the sidebar ends, so narrowing the rail slid the button left by
the width the rail gave up, out from under the pointer that had just clicked it. A reader
toggling back had to go and find it.

On a desktop it is now the last item in `SidebarFooter`, beside the connection
status — a row when expanded, stacked and centred on the icon rail. It sits in
the column it collapses and stays under the pointer in both widths.
`SidebarRail` remains as the second, edge-drag way to do the same thing.

**On a phone it stays in the header.** Below the mobile breakpoint the sidebar
is a `Sheet` that is not rendered until opened, so a trigger inside it could
never open it. `NavToggle` takes a `placement` and renders only where it
belongs, decided from the provider's `isMobile` rather than hidden with a
breakpoint class: two copies in the DOM would give the page two buttons with
the same accessible name, one of them invisible.

### Severity and risk level are selects, like every other filter

§84 laid severity out as a `ToggleGroup` on the findings and risks pages. In
practice it was the only filter drawn that way. Next to the status and kind
selects on the same row it read as a different kind of control, it was twice as
wide as its neighbours — six segments on the risks page, where `UNKNOWN` is a
real level — and it pushed those neighbours into truncating their own labels
("Findings and rou…").

Both pages now use `SelectField`, with "All severities" / "All levels" as the
unfiltered label. The original argument for the toggle — that the active filter
must be readable without opening anything — is already met by `SelectField`,
whose trigger always names the chosen option rather than the raw value. The
kind select widened to fit its longest label for the same truncation reason.

`common/ToggleFilter.tsx` had no other users and is deleted. The vendored
`ui/toggle-group.tsx` primitive stays: it is shadcn source, and removing a
primitive because nothing uses it today would mean re-adding it through the CLI
the next time something does.

## 86. Icons carry meaning, and each meaning has one icon

The interface had icons in the sidebar, on the dashboard panels and in empty
states, and almost none where a reader actually scans: a storage account, a
virtual machine and a key vault rendered identically in every table; a status
pill was told apart from its neighbours by tone alone; and a severity badge had
a mark only when it was UNKNOWN. This pass adds shape everywhere a reader is
sorting things by kind or by state, and nowhere else.

### One registry, `lib/icons.ts`

Every icon that means something is defined once: resource types, the risk
factors, detail page facts, change kinds, risk kinds and the verification
verdicts. Components read from those maps rather
than importing a glyph of their own.

The failure this closes is the one colour already taught: two screens choosing
their own shape for one state teaches the reader that shapes mean nothing.
`VerificationPanel` and the scans page had already drifted — `CheckCircle2`
and `XCircle` in one, nothing in the other — and the finding page's risk
factors used a shield for "business-critical" while nothing else used a shield
for it at all. A new status or resource type is now a one-line change to a map,
and a missing entry falls back to a neutral shape (a box, a plain circle)
rather than to nothing.

Icons follow the shadcn rule and are passed as component objects, never as
string keys. Lucide is still the only icon set; `ProviderMark` is the one
exception, below.

### What each mark says

- **Resource types** — `ResourceTypeLabel` puts the type's icon in front of its
  name in the findings and assets tables, the asset tree, the blast radius, the
  command palette, the change feed and the asset and finding detail pages. The
  icon comes from the neutral type even where the label is the provider's own
  (`azure_type`), so an unmodelled resource still reads as a box.
- **Risk factors** — criticality, data sensitivity, internet exposure,
  exploitability and business impact have one icon each, used on the risk
  cards, the risk and finding detail pages, the asset page and the dashboard's
  priority risks.
- **Facts** — environment, region, first seen, last seen and resolved on the
  detail pages.
- **Change kinds** — the change feed puts the kind's icon beside its name. The
  round mark at the start of each row is still _direction_ (worse, better,
  neutral), because an exposure change can go either way; kind and direction
  are separate facts and get separate marks.
- **Page headers** — `PageHeader` takes the page's sidebar icon, so a screen and
  the entry that opened it are visibly the same place.

### Filters say which of them are filtering

`SelectField` gained two things. An option may carry an `icon`, shown in the
menu and in the trigger — used for resource types, change kinds and risk kinds.
And `idleValue` marks a select as a filter: while its value differs
from the unfiltered one, a dot sits in the trigger. On a row of four filters
that is the difference between seeing which ones are narrowing the list and
reading every label against a default you have to remember. The findings status
filter idles at OPEN rather than "all", because open is what the page shows
unasked.

### Provider marks are hand-drawn and monochrome

Lucide deliberately ships no brand logos, so `ProviderMark` draws two small
glyphs for Azure and AWS. They are simplified shapes that identify the provider,
not the vendors' official artwork, and they are drawn in `currentColor` rather
than in brand colours: two vendor palettes on the connections page would be the
only raw colour in the product, and exactly the kind of second token layer the
severity scale is protected from. Each is labelled with the provider's name,
since a mark alone is only recognisable to someone who already knows it. They
appear on connection rows, the provider picker in setup, and a scan's scope.
Swapping in official artwork later is a change to one file.

### Severity and status stay text

The first version of this pass also gave every severity badge, status pill,
compliance control pill and collection outcome its own shape, and put those
shapes in the severity and status filters. It was taken back out the same day.
Those badges sit several to a row — a risk card carries a severity, a status and
three factor levels in one line — and a glyph on each one made the densest rows
in the product busier without saying anything the word beside it did not. They
are text on a tone again, as they were before this section.

What that costs, and why it is acceptable: colour is still not the only signal,
because every badge carries its word. UNKNOWN is additionally set apart from LOW
by its dashed border (`levelStyle`), which the badge test now asserts in place of
the icon. The same-day version had also dropped the help mark UNKNOWN carried
before §86; that is not restored, because the dashed border and the word already
answer the question it answered.

`VerificationPanel` keeps its icons. It is one large callout, not a badge in a
row, and it had them before this pass.

### What was left alone

Buttons that already had icons kept them, and buttons without one did not get
one: an icon on "Cancel" or "Save" is decoration. Headings, cards and panels did
not get icons for the sake of it. The dashboard's recent-changes timeline keeps
its direction marks only; its rows are one truncated sentence, and a second
icon there would cost the asset name its room.

## 87. A scan is started and followed in a wizard that lives in the shell

_The sheet became a dialog, the result became its own step, and the scan cards'
own progress went — §154._

The scans page started a scan with a subscription select and a button, and
followed it as a row of chips under a card on that page only. Two things were
wrong with that, and neither was how it looked.

**It asked a question the API ignores.** `POST /scans` takes a subscription id,
but a scan is scoped to the subscription's whole connection — the worker
resolves the subscriptions beneath it. Choosing "Payments" from the select
scanned Payments and every other subscription in its tenant. The wizard's first
step chooses an _environment_ (a connection), and review lists what is in
scope with a link to change it on the connections page, rather than offering a
per-subscription choice the backend would not honour.

**It said nothing before reading.** The review step exists for the three things
a reader should know before CloudGuard reads their cloud: what will be read,
roughly how long that took last time (the last finished run of that connection,
labelled as such, or nothing when there is none), and which checks will come
back UNKNOWN because the deployed role cannot serve them
(`degraded_categories`). A scan whose inconclusive checks arrive as a surprise
reads as a broken scan.

### The live view shows only what the API reports

The run step polls `GET /scans/{id}/detail` every 2.5 seconds while the scan is
in flight and stops when it is not.

- **Plan, Collect, Analyze** are drawn as one track. A connector fills when the
  phase before it has finished, however it finished — a partial collection
  still hands over to analysis. The current phase breathes.
- **Collect is one lane per scope**, with a segmented bar above it: one segment
  per scope, coloured by that scope's state. Not a single percentage: one red
  segment in twelve is a gap in a report, and a percentage would average it
  away. Lanes re-sort (running, failed, pending, done) and glide to their new
  place, so on a tenant with forty subscriptions the one that matters stays in
  view. A failed lane carries its error inline, and a retried one says which
  attempt it is on.
- **Nothing moves on a timer.** There is no progress invented from elapsed
  time, and ANALYZE stays one node although normalise, evaluate and score would
  be nicer to watch: the durable pipeline reports it as one step, and drawing
  sub-phases it does not report would be animating work nobody measured. Those
  arrive when the backend exposes them.

Every animation uses the timings in `lib/motion.ts`, and reduced motion is
answered by the existing `<MotionConfig reducedMotion="user">` — the breathing
node and the running segment hold still, and lanes arrive in place.

### How it ends

When the scan leaves the in-flight states the pipeline is replaced in place by
a result card: resources, rules run and findings counting up, the change in
findings against the last finished scan of the same connection (left out, not
guessed, when there is none), the severity breakdown, and the first three
collection gaps. **A partial scan ends amber, never green** — data came back,
and it still cannot support a pass for what was not read. Findings, risks, the
dashboard and the scan list are invalidated once, on that transition, because
none of them poll on their own.

A refused start — `409`, a scan already running for this connection — is not
shown as an error. The wizard finds the running scan and follows it, which is
the only useful thing a reader could have done with the message.

### It lives in the shell, and closing it minimises it

`ScanWizardProvider` is mounted in `Shell`, above every page, because a scan
outlives the page it was started from. Closing the sheet does not cancel or
forget the scan; the header's `ScanIndicator` is now a button that reopens the
live view of the running scan from wherever the reader is, where it used to
navigate to the scans page. Each opening is a fresh session — the body is keyed
on it — so a wizard reopened after a finished scan starts at the first step
rather than inheriting the last one's choices and errors, without an effect
resetting state.

The provider and its hook share a file, like `i18n/index.tsx`, and the lint
override for fast refresh names it for the same reason.

### What did not change

The connection row's **Scan now** still starts a scan directly: it is already
scoped to one connection and sits beside that connection's own status, so a
three-step panel in front of it would be ceremony. Scan cards on the scans page
keep their own progress chips and details. Live counts during a run, ANALYZE
sub-phases, and a push channel instead of polling were the backend half of this
work; they are §88.

## 88. Analysis reports its phase, and a running scan is pushed rather than polled

§87's live view drew ANALYZE as one spinning node and refreshed every two and a
half seconds. Both were the honest minimum, and both left the longest, quietest
stretch of a scan — persisting assets, running every rule, reconciling
findings, scoring risk — looking the same from its first second to its last.

### ANALYZE writes where it is

`scan_steps.phase` (migration 0035) holds an `AnalyzePhase` — `NORMALIZE`,
`EVALUATE`, `SCORE` — written by the step as it passes the three seams
`_evaluate` already had, immediately before each `_set_status`. It is a
progress mark and nothing more: the step is still claimed, retried and settled
as one unit, and nothing reads `phase` to decide what runs. That is the line
between this and splitting ANALYZE into three steps, which would have been a
change to the durable pipeline's shape for the sake of a label.

Three rules keep it truthful.

- **It is fenced.** `orchestrator.set_phase` updates only where the step is
  RUNNING _at the attempt it was claimed under_, exactly as `renew` does. An
  interrupted analysis still executing on the old worker cannot write
  "scoring" over the attempt that restarted it.
- **A reclaim clears it.** `claim` sets `phase` to NULL, so a retried analysis
  starts from no phase rather than inheriting where the failed one stopped.
- **It is written on its own session, and never fails the step.** Two of the
  three seams fall inside the pipeline's open transaction; a progress mark must
  neither wait for that work nor roll back with it. `_PhaseReporter` opens a
  `scan_session` per mark and logs a write that fails. A missing label costs the
  screen one word; failing the analysis over it would cost the scan.

Replay shares `_evaluate` and passes nothing, so it reports to a no-op: it is
one task, with no step row to mark.

### Live counts are the ones already committed

No new counter was added. `resource_count` is committed when normalizing has
persisted the assets, and `rule_count` when the scan moves to scoring, because
`_set_status` commits at every seam. The wizard shows each once it is non-zero.
**Findings are deliberately not counted live**: they are reconciled as one
change — raised, reopened and resolved together — and a number climbing through
that would be a count of nothing in particular. The result card states it.

### `GET /scans/{id}/events` pushes the detail when it changes

A server-sent event stream whose payload is exactly `GET /scans/{id}/detail` —
both are built by one `_detail_payload` — sent only when it differs from the
last one, with a keep-alive comment every fifteen seconds, an `end` event when
the scan settles, `gone` when it is deleted or no longer visible, and `timeout`
after thirty minutes.

It is the same read, done on the server, and that was the choice. A Redis
channel the worker publishes to would deliver sooner, and would also make the
browser trust a message to agree with the rows — a second source of truth for a
scan's state, which §65's fencing exists to keep single. Here the database is
still the only thing that knows, the worker writes nothing new, and the stream
cannot tell the reader anything a poll would not. The cost is a tick every one
and a half seconds per open wizard, paid only while a scan is in flight.

The tenant boundary holds per read, not per connection. The scan is resolved on
the request's session first, so a scan the reader cannot see is a 404 before any
stream opens; every tick after that opens a fresh `rls_session` for the same
user. The request session is not held for the life of the stream.

The loop is `services/scan_events.stream_scan`, a pure async generator over an
injected loader, clock and sleep, so its rules — change-only, keep-alive, the
three endings, stopping when the reader disconnects — are unit tested without a
database or a server.

### The browser treats the stream as an optimisation

`useScanEvents` reads the stream with `fetch`, not `EventSource`, because the
bearer token lives in memory and `EventSource` cannot send an Authorization
header. Each `scan` event is written into the `["scan-detail", id]` query the
pipeline already renders. While the stream is live the query stops polling;
the moment it is not — a buffering proxy, a dropped network, the server's
ceiling — polling resumes. Nothing on screen depends on which of the two
delivered a state, and a deployment where streaming never works simply behaves
as §87 did.

## 89. Fourteen Azure checks, role v7, and a CIS catalogue that named the wrong controls

Azure is the cloud customers can connect, and it had fewer rules than AWS, which
nobody can. This closes that with one release in two tiers, and corrects the
compliance catalogue the rules report into.

### Two tiers, one version

Five checks judge evidence the scanner already read, so every existing
connection gets their verdicts on its next scan with nothing to redeploy:
public UDP (AZ-NET-009), cross-tenant blob replication (AZ-STO-004), SQL's
minimum TLS version (AZ-DB-007), a key vault still on access policies
(AZ-KV-003), and unmanaged VM disks (AZ-CMP-003).

Nine need reads the role did not grant, and those six reads are `v7`:
`Microsoft.Security/pricings/read`, `Microsoft.Storage/storageAccounts/blobServices/read`,
`Microsoft.Sql/servers/administrators/read`,
`Microsoft.DBforPostgreSQL/flexibleServers/configurations/read`,
`Microsoft.Web/sites/read` and `Microsoft.Web/sites/config/read`. Each string
was checked against Microsoft's published operations reference on 2026-09-17,
because the `rbac.py` module docstring records what one unverified string
costs: the whole role fails to deploy.

They are one version rather than several for v4's reason. Every version is a
redeploy prompt, and a customer who ignores one ignores the next. A v6
connection keeps every verdict it had; the nine report UNKNOWN naming the role,
and `degraded_categories` lists compute, database, posture and storage.

The role is now twenty-five reads. `test_the_role_is_small_enough_to_read`
capped it at twenty and was raised to thirty rather than removed -- the cap is
what makes the next addition a decision.

### The four fan-outs share one task shape

Three of the new reads sit beneath a listing the plan already took (SQL
servers, PostgreSQL servers, storage accounts) and one beneath a new listing
(App Service sites). Each is its own evidence key and its own dependent task,
for the reason SQL auditing is (see `AzureEvidence.SQL_AUDITING`): a role predating v7 answers the
listing and refuses the fan-out, and folded into one key that refusal would cost
the listing's rules their verdicts too. `_per_resource_task` writes the shape
once; a resource whose read fails is recorded against its own id, so one refusal
costs one resource.

The SQL Entra administrator is read per server rather than through
`$expand=administrators/activedirectory` on the server listing, which would be a
call fewer. Whether the expansion is authorized by `servers/read` alone is not
documented, and guessing wrong would turn a missing permission into a failed
listing of every SQL server -- AZ-DB-001's verdict included.

### App Service is its own resource type

`APP_SERVICE`, not `VIRTUAL_MACHINE`, because the platform owns the host and
every fix is a site setting. Web apps and function apps are both
`Microsoft.Web/sites` and share the five rules. A site's managed identity is
drawn as a `HAS_IDENTITY` edge exactly as a machine's is, so a taken web app now
appears as the first hop of an attack path.

### Absent is not always unknown, and each case says which

Most of the new fields read absent as UNKNOWN: a minimum TLS version the listing
did not carry, a blob service that never arrived. Two read absent as the
documented default, and the rule says so in its evidence:

- `allowCrossTenantReplication` is omitted on accounts created before
  15 December 2023 that never set it, and Microsoft documents that such an
  account permits cross-tenant policies. AZ-STO-004 fails it with
  `default_applied: true`.
- `enableRbacAuthorization` defaults to false in the API version read. AZ-KV-003
  fails a vault that does not say it is on, as AZ-KV-001 already does for purge
  protection.

And one empty answer is not a pass: a Defender plan listing that names none of
the plans CIS asks about is UNKNOWN, because Azure returns every plan for a
subscription it can price.

### Two checks declined

CIS 6.4, HTTP(S) reachable from the internet, was offered and not built.
AZ-NET-003 records why 80 and 443 are excluded from its own list -- a public web
server is a design rather than a defect -- and a rule firing on every one would
bury the findings that are defects. Encryption at host was not built for the
reason v4 dropped disk encryption: managed disks are encrypted regardless.

### The CIS Azure catalogue named the wrong controls

Mapping the new rules meant looking up leaf numbers, and the numbers already in
the catalogue did not match the benchmark. It listed nineteen entries, three of
them whole sections ("2", "8", "9"), and several of the leaves meant something
else in 2.0:

- `1.21` was cited by ten rules as "no excessive subscription administrators".
  In 2.0 it is whether users may create Microsoft 365 groups. The control about
  custom administrator roles is `1.23`.
- `6.5` was cited for WinRM, unrestricted inbound rules and unguarded VMs. It is
  flow log retention.
- `4.1.1` was cited for public network access and encryption. It is auditing.
- `5.3` does not exist in 2.0, and `7.1` is whether a Bastion host exists.

The catalogue is rebuilt from the benchmark's own index: all 151
recommendations, in CloudGuard's wording, grouped by the benchmark's sections.
The index came from the public compliance mapping Prowler maintains, cross-checked
against Microsoft's Azure Policy regulatory-compliance initiative for CIS 2.0,
which corrected the two titles Prowler duplicates (2.1.20 and 4.5.1). Four are
marked as beyond a scanner: guest reviews on a schedule (1.5), SAS token lifetime
(3.6, since issued tokens are recorded nowhere readable), periodic public IP
review (6.7), and an approved-extension list (7.5, which needs the customer's
list).

Every existing rule was re-mapped against it, and several lost their CIS
mapping entirely -- WinRM, SMB, the SQL port, too many Owners, a guest or
disabled account holding a privileged role. That lowers the Azure CIS coverage
number, and it should: the benchmark has no control for those, and evidence
filed under a control it does not answer is the overclaim §81 was about. The
rules still map to ISO, NIST, SOC 2, PCI and GDPR, where they do answer
something. After the rebuild, 41 of 151 controls are cited by a rule.

Compliance coverage is computed live from the registry, so no stored finding
carries the old numbers; the next compliance view shows the corrected ones.

### The recording carries the new readings

`tests/fixtures/azure_raw/snapshot_mixed.json` -- replayed by the demo (until
§102 moved it to a superset) and by the integration suite -- gained the six readings, a managed OS
disk and a SQL
minimum TLS version, so no new rule is blind on it. Four fail there on purpose:
an SQL server with no Entra administrator, the Servers plan off, an older storage
account permitting cross-tenant replication, and a web app with no identity.

## 90. The beat sweeps release their connections too, and the test now reads the call sites

Every Celery task enters async code through its own `asyncio.run`, while the
engines in `app/core/db.py` are cached for the life of the process. asyncpg
binds a connection to the loop that opened it, so a task that ends without
calling `dispose_engines()` leaves its child holding connections belonging to a
loop that no longer exists. The next task that child picks up dies at the first
pool checkout:

```text
RuntimeError: got Future attached to a different loop
RuntimeError: Event loop is closed
```

That rule is stated in `scan_tasks.py`'s internals comment and was applied to
the five scan entrypoints. The two beat sweeps added later -- `_derive_all_notifications` and
`_prune_all_evidence` -- were not, and neither was the test, which compared
against a list of names typed by hand rather than against the code. Staging
shows the consequence with the clarity of a clock: the notification sweep runs
every five minutes, and in the same minute that it ran, the reaper and the
change-event sweep failed on the same fork worker -- 23:46 derive, 23:47
`reap_abandoned_scans` raised; 23:51 derive, 23:52 raised; 23:56 derive and
`scan_changed_environments` raised inside the same second.

Both sweeps now dispose in a `finally`, like everything else reached through
`asyncio.run`. The invariant test walks the module's AST for `asyncio.run(...)`
call sites and checks the coroutine each one names, so a task added tomorrow is
covered by the test the day it is written rather than the day somebody
remembers to extend a list. A hand-maintained list is what let this ship.

The failure is cheap to misread and that is the reason it lasted. Each miss
costs exactly one task, because the failing checkout empties the stale
connection out of the pool and the following task opens a fresh one on its own
loop -- so the logs show a beat task failing, then succeeding, then failing,
which reads like an intermittent database problem rather than a certainty with
a period of five minutes.

## 91. A refused Azure call says so in CloudGuard's own logs

`probe` decides whether a connection may read its environment yet, and the
setup screen turns that one bit into a spinner or a green tick. Returning
ok/not-ok is right -- a connection whose role is still being deployed fails on
every five-second poll, and none of those failures is an incident. Discarding
Azure's account of _why_ was not: a connection that would never verify looked
exactly like one deploying normally, for the thirty minutes before the stalled
panel appears, and finding out what Azure objected to meant opening Azure's
portal, because nothing in CloudGuard had written it down.

Two changes, and they are deliberately at different levels.

`_BaseClient` logs every response of 400 or worse as `azure.request_failed`,
with the method, the URL, the status, and Azure's `x-ms-request-id` and
`x-ms-correlation-request-id`. Those two ids are the first thing Microsoft
support asks for and cannot be recovered once the response is gone. It sits in
`_request`, before the raise, because the raise is caught in several places and
one of them -- the probe -- is the place the evidence was being lost.

`probe` logs `azure.probe_failed` with a reason and Azure's message. The four
reasons are separate on purpose, because they send somebody to different
places: `no_token` is an application missing from the tenant, before any ARM
call; `subscriptions_unreadable` is ARM refusing the listing;
`no_subscriptions_readable` is a listing that worked and returned nothing, which
is what Azure says for a principal that holds no role anywhere -- "nothing
deployed yet", not a refusal; and `resources_unreadable` is a role that grants
the subscription listing and nothing beneath it.

The detail is now read for its text. Azure answers an authorization failure with
JSON, and several things _in front of_ Azure answer with an HTML page, which is
itself worth knowing: it says the call never reached the service being asked.
Reading 200 characters of raw body meant `<!DOCTYPE html PUBLIC "-//W3C//DTD
XHTML 1.0 Transitional//EN"...` -- a body truncated before the first word that
would have explained anything. Markup is reduced to its text and capped at 400
characters, which holds Azure's longest authorization message and cannot let a
five-second poll fill a log.

This is what a live staging connection cost to diagnose without it: the
enterprise application had been deleted and recreated three times, the failure
moved from "no service principal" to an HTML 403 as it went, and the logs
carried the same six words throughout.

## 92. Onboarding reads as a product, not as a document

The connection wizard was correct and hard to move through. Every scope option
carried two paragraphs, the rail repeated four more, and a "who you will need"
block under the form added a third wall of prose, so the first screen a new
customer met was something to study before anything could be chosen. The
radio cards shrank to their own content -- the field primitive's label is
`w-fit` -- so three options in one group were three different widths, the
single clearest sign of a screen nobody had looked at. The only way forward was
a small button below all of it.

Nothing the flow _says_ was cut; where each sentence sits changed.

- **Choices are cards, requirements are shown once.** Cloud and scope are
  full-width card groups (`ChoiceCard` in `StepScope`): an icon, a name, one
  line of what it covers, and a tag on the widest ("Full coverage") and the
  narrowest ("Quickest"). The permission a scope takes to _finish_ -- the fact
  that decides whether setup will succeed -- is printed once, for the scope that
  is selected, directly beneath the group. The reasoning in the old comment
  still holds; it is enforced by position now rather than by repetition.
- **"Who you will need" is a checklist.** Two rows, each an icon, the person,
  one sentence; AWS overrides the same two keys with its own two facts.
- **The way forward is always on screen.** The first step's footer is sticky and
  carries the primary action with the read-only promise beside it. Every step's
  primary action is a large button; the two that leave the application carry an
  external-link mark and say so.
- **The rail says where you are, not everything.** Only the current row shows
  its detail; finished rows are ticked and joined by a connector that fills, and
  a bar with "Step n of m" sits on top. Below `lg` only the bar and the current
  row are drawn, so on a phone the step itself is above the fold.
- **Waiting looks like listening.** `WaitingNote` is a pulsing dot with a second
  line saying the page does not have to stay open, rather than a spinner that
  implies a request in flight.
- **Leaving is in the header.** "Finish later" and "Cancel setup" moved from a
  footer under the panel to the page header, where they are visible on every
  waiting step without competing with that step's own action.
- **The wizard ends on the scan itself.** "Run the first scan" calls
  `useScanWizard().start(connection.id)`, opening the scan wizard (§87) on this
  connection's review step. It used to link to `/scans`, which left one more
  page to find the button on at the moment the customer was most ready to use
  it.
- **The organization step names what follows it.** Two labelled segments --
  Organization, Connect a cloud -- replace "Step 1 / 2", and industry and
  country share a row with industry marked optional.

The icons the flow uses are in `lib/icons.ts` like every other meaningful icon
(§86): `SCOPE_ICONS` keyed by scope, so an AWS organization and an Azure tenant
draw the same shape because they make the same claim about coverage, and
`SETUP_ICONS` for the two grants and the waiting states. Motion stays inside
§84's vocabulary -- the panel slides on a stage change, which happens when a
grant lands rather than when a button is pressed, and the one spring is the
tick on the connected state.

## 93. Lists are lists, actions are on top, labels are sentence case

§92 rebuilt onboarding. The rest of the product had the same habits, and they
were visible from across the room: every row of every list was its own padded
card, the one action a page existed for sat at the bottom of it, explanations
were repeated on every row that needed them once, and small labels shouted in
tracked capitals. Each habit, and what replaced it:

- **A list of like things is one container with divided rows.** Scans,
  remediation tasks, rules and the changes feed were stacks of separate cards;
  they are now `divide-y` rows inside one bordered container. A month of scans
  or a hundred rules is scanned as a list, and a failure stands out by its
  status rather than by being one more box. Risks keep a card per row because a
  scenario carries its route, but the card leads with the score (below).
- **The score leads the row.** `ScoreTile` (`components/security/`) draws a risk
  score as a tile tinted by its level with `levelStyle`, so a 96 and a Critical
  badge beside it are visibly one claim. It replaces a grey number at the far
  edge of the card, a screen-width from the title it ranked. The level is named
  in the tile's accessible label, so the tint is never the only signal.
- **Headline numbers are a strip above the list.** `StatStrip`
  (`components/common/`) answers how many, how much and how late before the
  rows: remediation shows open, in progress, effort left and overdue; attack
  paths show routes, exposed assets and sensitive assets, which were a single
  line of grey text reading "2 · 3 exposed assets · 4 sensitive assets".
- **The action is where the eye starts.** A finding's Rescan / Mark in progress
  / Accept risk moved from a card at the foot of the page to beside the title,
  and the recommended fix moved up to second place, under why it matters. The
  finding's history moved below the score and the asset: how bad and where come
  first, how it got here after.
- **An explanation is said once.** Each scan row printed three lines on what
  re-evaluating does. The sentence is now the button's description (`title`
  and an `aria-describedby` target), so it is read by assistive technology and
  shown on hover, and the history is a list of runs rather than of paragraphs.
  Delete became an icon button with its label. Page descriptions under every
  header were cut to one line; the long versions were arguments for the page's
  existence, which belong here rather than on the screen.
- **Settings are two columns.** `SettingsSection` puts the topic and its
  explanation on the left and the controls on the right, with each form saving
  from a footer bar. The page was a column of cards whose explanations competed
  with their fields for width.
- **Labels are sentence case.** The `uppercase tracking-wide` eyebrow pattern is
  gone from every page and component; table headers are small muted text on a
  quiet band (`ui/table.tsx`) rather than bold foreground. Hierarchy comes from
  size and weight, not from capitals.
- **Every card that goes somewhere is the link.** Compliance framework cards are
  wrapped in the `Link` and end on "View controls →". They used to end on an
  outline `Button render={<Link/>}`, which §31 rules out, and the largest target
  on the page did nothing when clicked.

`Card` with `CardContent className="p-0"` still carried the card's own vertical
padding, which is what left the changes feed and the table skeleton floating a
row's height inside their borders; both pass `py-0` now.

## 94. The dashboard says where to start before it explains itself; sign-in shows the product

**Dashboard.** The page argued well and in the wrong order: score, severity
counts, then three analytic panels and a coverage essay before the first thing
a reader could act on. Priority risks and the shortest attack path now sit
directly under the severity strip, where they are above the fold at a laptop's
height; the status and risk-band breakdown and the coverage panel follow them,
as the explanation of the numbers rather than a gate in front of the work.

The breakdown lost its severity-mix bar. The strip above it counts the same four
numbers, and drawing them twice spent a third of a row repeating one fact. The
sentence on how the score is deducted moved from a paragraph under the bar to
the heading's description (`title`): it is read once, and after that it was the
same sentence on every visit. Priority risks lead each row with the tinted
`ScoreTile` (§93), so the dashboard ranks risks the way the risks page does.

"Scan now" starts a scan. It was a link to `/scans`, which put the button a
reader had just pressed on another page to be found and pressed again; it now
opens the scan wizard (§87) from the header, and is the page's primary button.

**Sign-in.** The brand panel was a dark stone rectangle with a headline and
three ticks, drawn from Tailwind's stone palette and a raw `#fff` wash. It now
carries the `dark` class, which scopes the dark theme's tokens to the panel, so
its background, borders and severity colours are the product's own in both
themes. It shows a small preview of the product -- a score and three ranked
risks, built from `ScoreTile` and the severity tokens -- because a glance at the
thing is a stronger argument than three sentences of promise at the moment
somebody decides whether to hand over credentials. The preview is
`aria-hidden`: it holds example values, and read aloud it would sound like
somebody's real findings.

## 95. Findings and assets: views on screen, rows as targets, links that land where they point

**A dashboard link that did nothing.** The severity strip (§94) links each tile
to `/findings?severity=CRITICAL`, and the findings page started its severity
filter at "all" whatever the URL said, so all four tiles opened the same
unfiltered list. The filter is now seeded from the URL through the router,
the same way `status`, `rule_id` and `evidence_id` already were, and a test
holds it there.

**Status is a view, so every view is on screen.** Open is the queue; in
progress, verified fixed and risk accepted are its history. They were four
options behind a select, which hid what else there was to look at and made
switching between two views two clicks each way. `SegmentedFilter`
(`components/common/`) lays them out as a row of toggles -- buttons with
`aria-pressed` in a labelled group rather than a tab list, because they narrow
one table rather than swap panels. Assets' List / Hierarchy switch uses the same
component, replacing two ad-hoc buttons that looked like a different control.

**The row is the target.** Both tables made only the title clickable. The
findings title already carried `after:absolute` for a full-row overlay, but
with no inset and no positioned row it covered nothing; rows are now `relative`
and the overlay is `inset-0`, so the whole row opens the finding or asset. The
asset page's list of findings does the same, and leads each row with the tinted
`ScoreTile` (§93).

**Times read as time.** "Last detected" and "Last seen" are relative ("2 hours
ago") with the full date on hover. The absolute date was the same for every row
of a fresh scan, so the column said nothing a glance could use.

**Small things.** A non-zero open-findings count on an asset is a chip, so rows
with work on them stand out from rows without; it takes no severity colour
because it is a count, not a verdict. The asset page's header carries the
resource type's own icon, the glyph its inventory row uses, and the findings
section title carries its count.

## 96. A framework is filtered by verdict; risks are filtered by kind

**Compliance framework.** Every control was its own card and every failing or
inconclusive one opened by default, so CIS Azure rendered as a long column of
boxes with the nine that fail spread among the fifty-eight that pass. A
`SegmentedFilter` (§95) above the list names each verdict with its count --
All, Failing, Inconclusive, Passing, Not covered -- and narrows the list to
one. Filtering hides rows and never reorders them: the controls stay in the
framework's own section order, which is the order an auditor's spreadsheet is
in. Each section is now one container of divided rows with its count beside the
heading, and the default-open rule for failing and inconclusive controls is
unchanged.

The "What this covers" card is folded into the coverage card's footer. The
scope note and the source link both qualify the coverage number, and as a third
box before the controls they pushed the list a screen down.

**Risks.** The kind -- findings, attack paths, escalations -- is the view, so it
is a `SegmentedFilter` on the left, as status is on the findings page; level,
status and search stay as refinements on the right. Each risk card is now one
link (`after:inset-0` on the title over a `relative` card), and the kind badge
on a scenario carries its `RISK_KIND_ICONS` glyph, which the filter used to
show and which would otherwise have been left defined and unused.

## 97. A getting-started checklist read entirely from the server's state

A new organization met a dashboard that, before the first scan, was one empty
state with one button, and after the first scan was a full dashboard with no
indication of what setting CloudGuard up still involved. Five things decide
whether a trial turns into a product somebody relies on -- a connected cloud, a
scan, a verified fix, a schedule, a declaration of what each environment is
for -- and three of them lived on pages nobody was sent to.

`GettingStarted` (`components/dashboard/`) lists them in that order. **Every
tick is derived from state the server already holds:** a connection that
`is_ready_to_scan`, a `last_scan`, a resolved finding
(`findings_by_status.RESOLVED` or `verified_resolved_last_30_days`), a
connection with a `scan_interval_hours`, and a context declaration on any
subscription (read under the same `account-context` cache key the settings form
uses, so declaring there ticks the step here with no extra request). Nothing is
recorded when a step is clicked. A checklist that remembered clicks would tick
"fix a finding" for somebody who opened one and closed it, would be wrong on a
second device, and would say nothing to a teammate who never saw it; this one is
right for all three, and a step done somewhere else entirely ticks itself.

Only the next undone step carries a button. The rest keep a quiet link, so they
stay reachable out of order once a cloud is connected, and a step whose
prerequisite is not done says "After the step before" instead of offering an
action that cannot work -- a scan with no connection, a declaration with no
discovered subscription.

Before the first scan the checklist _is_ the dashboard, in place of the empty
state, and cannot be dismissed into a blank page. After it, it sits compact
above the score until every step is done, when it disappears, or until it is
put away. The dismissal is the one thing held in the browser, in `localStorage`
per organization, because it is a preference about this screen rather than a
fact about the estate; losing it in a private window costs one click.

## 98. Filters live in the URL, lists answer to the keyboard, and a fix is verified where it is made

**Filters in the URL.** Findings, risks, assets, rules, changes and a
framework's verdict filter held their filters in component state, so a filtered
view vanished on reload, the back button lost it, and "look at the critical
open findings" could not be sent to anybody. It also broke links _into_ views:
the dashboard's risk-band bars link to `/risks?level=CRITICAL` and landed on the
unfiltered ranking, the same defect §95 fixed for severity on findings.
`useUrlFilters` (`lib/`) now holds every filter, sort, view and page in the
query string. A value equal to its default is omitted, so an unfiltered page has
a clean address. Updates are patches applied in one write, because a filter
change and a page reset written separately would each start from the same
snapshot and the second would put back what the first removed. Writes use
`replace`, so narrowing a list does not fill the history. Search boxes hold what
is typed locally and write it after a pause; the assets search, which sent a
request per keystroke, now waits for the pause as well. The assets environment
filter is built from the environments present instead of a fixed
"Production / Development", which made staging impossible to filter.

**The keyboard.** `KeyboardShortcuts` in the shell handles `g` then a letter
(overview, findings, risks, attack paths, assets, remediation, compliance,
scans), `/` to focus the page's search (pages mark it `data-page-search`), and
`?` for a sheet listing all of it. `useRowNavigation` gives findings, risks and
assets `j`/`k`/`Enter`, marking the row with a tint and a leading bar, and
nothing is marked until the first key. Every shortcut stands down while the
reader is typing, while a modifier is held, and while a dialog is open. The ⌘K
palette gained actions -- run a scan, connect a cloud, keyboard shortcuts -- so
it starts work as well as navigates.

**Verifying a fix.** "Rescan to verify" ended on a toast, and the most
persuasive moment in the product -- a fix proved by looking again -- happened
off-screen. The rescan endpoint already returns the `scan_id` it queued;
`FixVerification` follows that scan on the finding, phase by phase from its real
status (queued, reading, checking, result), re-reads the finding when it ends,
and states the finding's verdict: verified fixed, still failing (with "Verify
again"), or a scan that could not finish and so proves nothing either way.
Nothing is inferred from elapsed time. The fix panel ends on "Applied the fix?
Verify it now", so applying and proving are one motion.

The fix panel's CLI fills its placeholders from the resource the finding was
raised on (`lib/remediationFill.ts`): the resource group, subscription and
resource id from the provider id, the region, and the resource's own name --
but only into the placeholder for its own kind (`<account>` on a storage
account, `<server>` on a SQL server), never into one naming some other object
the command touches (`<rule>`, `<user>`). Everything else stays in angle
brackets, which keeps the rule's original promise: a command never carries a
value CloudGuard made up.

## 99. One shared, read-only demo organization

A new customer met an empty product. Nothing could be shown until a Global
Administrator consented and somebody deployed a role -- two people, often two
days -- which is precisely where a trial is abandoned. The pieces for a demo
already existed: `database/seed/demo_environment.py` runs a recorded capture
through the real normalizer, rules and risk engine. But it was a development
tool: it refused production, and it attached the demo to one named user as
OWNER.

**One organization, joined, not copied.** Migration `0036` adds
`organizations.is_demo`, unique among true values, so there is at most one. A
signed-in user joins it with `POST /organizations/demo/join`, through
`app.join_demo_organization()` -- SECURITY DEFINER, for the reason
`app.create_organization` is: the caller is not a member, and no membership
policy lets anybody insert themselves into an organization, which stays true for
every other one. The function fixes the role at `VIEWER`; nothing the client
sends can make somebody more than a viewer of the demo. Joining twice is a no-op.
`POST /organizations/demo/leave` removes only the caller's own row, through
`app.leave_demo_organization()`, since nobody in the demo holds the OWNER or
ADMIN that `member_delete` requires. Per-user copies were rejected: a scan per
sign-up is a cost with no benefit when the estate is the same for everybody.

**Visitors do not see each other.** Every member of an organization could read
its whole membership list. In the demo the members are strangers -- everybody
who ever clicked "explore" -- so `member_select` now shows a demo member only
their own row. Ordinary organizations are unchanged, and an integration test
holds both.

**Read-only by flag as well as by role.** `TenantContext` carries `is_demo`, and
`require_write` and `require_role` refuse in the demo whatever the role, with a
sentence that says to create an organization. Joining always grants VIEWER, so
this is a second lock -- but "nobody can change the demo" should not rest on
every membership row in it being right. Deleting an organization checks its role
outside the tenant context, so it refuses the demo itself.

**Reading the demo calls nothing.** `GET /cloud-connections/{id}` finishes an
unverified connection's setup by probing the provider, and the seed had stamped
the demo's grants proven but not its discovery -- so the first visitor to open it
would have called Azure about a recorded tenant and written the failure into a
row every visitor reads. The route now skips auto-validation in the demo, and
the seed stamps discovery done. Scheduled scans, change events and verification
never touch it: it has no schedule, no subscription and no claim.

**An own organization always wins.** The API's fallback when no organization is
named, and the list the client defaults from, both order own organizations
before the demo. Somebody who explored first and signed up after lands in their
own estate.

**The seed's `--shared` mode** builds or rebuilds it, and runs in production: it
touches no customer's organization and grants nobody anything. It scans the
recording twice -- as captured, then with its two headline problems repaired --
so the demo shows what the product is for: a score that moved and findings a
later scan proved fixed, by the real lifecycle rather than rows marked resolved.
A rebuild keeps the organization id and its members, so nobody's list or stored
selection is broken by it. The per-user mode now skips the demo when it looks for
a user's organization, since it writes into whatever it finds.

**In the app.** Onboarding and the pre-scan dashboard offer "Explore a demo
environment". Inside it a banner on every page says it is a recording, with the
way out on the same line -- back to an own organization, or to creating one --
because everything in the demo looks real on purpose and a screenshot of it must
not pass for a customer's estate. Write actions are not drawn there (scan,
rescan, accept risk, mark done, schedule, connect): the API would refuse them,
and a button that can only ever answer "read-only" is one that should not exist.
The getting-started checklist (§97) is hidden in the demo; its setup is not the
reader's to do. The organization switcher marks the demo with a badge.

## 100. Scenario correlation: every member, only what the scan could see, and choke points past the redundant ones

Three defects in how routes become risks and cuts, found by checking the attack
paths end to end.

**Every open finding on an asset is a member.** `_correlate_paths` collected
open findings into a dict keyed by asset, so a host with five failing checks
kept whichever row the database returned last. The route was scored from an
arbitrary member and could move between scans with nothing in the environment moving. It is now a
list per asset.

**A scan closes only routes it could have seen.** The existing scenario risks
are read for the whole organization, but the graph is built from this scan's
scope. A rescan of one subscription therefore resolved every route in every
other subscription — and in the organization's other connections — and the next
full scan raised them again, leaving a fix in the history that nobody made. A
route missing from this graph is now resolved only if none of the assets on its
stored path belongs to a scope this scan did not read (`_asset_scope`, the same
predicate the rest of the pipeline uses). An asset with no row left at all
counts as inside, because it is gone and so is every route through it.

What this does not do: a scan of one subscription still cannot _create_ a route
that crosses into another (an identity here holding a role over a subscription
there), because its graph never contains the far end. It no longer closes one
either; the next scan whose scope covers the whole route decides. Building the
correlation graph from the database rather than the scan's state would answer
both, and is the change to make if single-subscription scans become the common
case.

**Choke points check past links with a way round.** `choke_points` verified the
top `limit` candidates by containment and dropped those that severed nothing —
so five redundant links, each on many routes, used up every check and a real
choke point further down was never looked at. The panel then said there was
nothing to cut. It now keeps checking in containment order until no unchecked
link could make the list: containment bounds severance, so a link sitting on
fewer routes than the weakest one kept cannot displace it. Worst case is a check
per removable link, which is what an honest answer to the question costs.

## 101. A graph around one asset, beside the route rather than instead of it

Attack routes stay drawn as a straight line (`AttackPathRoute`). A route answers
"which link do I cut", and a chain with a visible spine answers that faster than
a canvas of nodes does. What the line cannot answer is "what is around this
asset" — what can reach it, what it can reach, and how the two meet — and that
is the question the graph view on the asset page is for. It is for exploring,
not for acting, so it is an addition on the asset page and nowhere replaces a
route.

**One asset at a time, never the whole tenant.** `GET
/attack-paths/neighborhood/{resource_id}?depth=1..3` walks the cached asset
graph (`load_graph`) both ways from the asset: forward along `_out` for what it
reaches, backward along a new `_in` index for what reaches it. The walk
alternates by hop, so each asset lands at its shortest distance, and on a tie it
sits downstream — reach from the asset is what the view is opened to ask about.
A canvas of the whole tenant is the picture every CSPM demo shows and nobody can
read; a bounded neighbourhood can be read.

**Only reach is drawn.** The walk follows `is_capability` edges — the same ones
`reachable_from` follows — and nothing else. A network security group
protecting a VM is configuration, and drawing it beside a role assignment would
make it look like reach. Containment is reach here (a role over a subscription
reaches what the subscription holds), but it is drawn faint and unlabelled,
because it is never the link somebody cuts; the identity hops are drawn strong
and named with the same verbs a route uses (`RELATIONSHIP_VERBS`).

**Bounded, and every bound folds rather than drops.** A subscription contains
every resource group under it, and four hundred boxes answer nothing. Past
`NEIGHBOURHOOD_FAN_OUT` (12) new neighbours of one asset, the rest are counted
into a dashed group box — except entry points and sensitive assets, which are
drawn first, because "412 resources" hides the one that matters. Past
`NEIGHBOURHOOD_MAX_NODES` (150), every remaining neighbour is folded, the walk
goes no further, and `meta.truncated` makes the card say that what lies beyond
was not read. A canvas that silently stopped at twelve would claim an identity
reaches twelve things when it reaches four hundred — the same overclaim as a
PASS nobody earned.

**Laid out by hop, not by simulation.** The frontend places each box in the
column its hop count names — what reaches the asset to the left, what it
reaches to the right — and orders each column by the average height of the
boxes it joins one hop nearer the focus, breaking ties by kind, type, name and
id. The same estate therefore draws the same picture on every visit, whatever
order the database returned the rows in, and two people looking at one asset
are looking at the same thing. A force-directed layout settles somewhere new
each run; that is the property this avoids.

**React Flow for the canvas.** `@xyflow/react` provides pan, zoom, edge
routing and node virtualisation, which a hand-written SVG would have to rebuild.
It is a canvas kit rather than a UI or chart kit, so it does not compete with
shadcn or Recharts. It loads only `base.css`, the structural stylesheet; its
theme stylesheet is not imported, and edges, labels and background are coloured
from the tokens in `index.css`, so dark mode and the severity scale are
untouched. It sits in its own lazy chunk (about 57 kB gzipped) that loads only
when somebody asks for the graph, and the endpoint is called only then too, for
the same cost reason as the blast radius beside it. The canvas is read-only:
nothing can be dragged, connected or selected, because a box somebody had moved
would be a picture of their arrangement rather than of the estate. A wheel does
not zoom it, so a person scrolling the page past it is not trapped; zoom is on
buttons and on a pinch. Each box other than the focus is a link to that asset's
page, which is how somebody looks further.

**What a box carries.** Each box marks what makes it matter on a route: a
globe for an entry point, a cylinder for sensitive data, both coloured by level,
and a count of open findings tinted by the worst of them. `entry` and
`sensitive` are the graph's own predicates (`ENTRY_EXPOSURE`, `SENSITIVE_DATA`),
sent by the API rather than re-derived from the levels in the browser, so a box
marked as a way in is exactly an asset a route may start from. Exposure
CloudGuard could not work out gets a muted globe of its own: UNKNOWN is never an
entry point, and drawing nothing would make "do not know" look like "not
exposed". Open findings means OPEN or IN_PROGRESS, as on the security score, so
the number on a box and the number on the asset's page agree. Every marker also
carries its meaning as screen-reader text, which is what a box's link is named
from.

**Routes are traced, not drawn instead.** The endpoint returns the attack paths
the asset sits on (`paths_through`, the same question the finding page asks),
the shortest twenty with the full count in `meta.routes_total`. With nothing
picked, hops on any of those routes are drawn darker than reach that leads
nowhere sensitive. Picking a route from the list beside the canvas traces it:
its hops go strong, everything else fades, and its cheapest break is drawn
dashed in the "this makes it better" colour — the same way `AttackPathRoute`
draws a severed link. The route is then drawn again under the canvas as the
straight line, because the canvas shows where a route runs through the
neighbourhood and the line shows which link to cut. The canvas holds only what
lies within the chosen hops, so when part of a traced route is off it, the card
says so and points at the line as the whole route. Hops are keyed by source,
relationship and target, because one pair can be joined twice — a role over a
scope and the right to grant roles over it — and tracing one must not light up
the other.

Organization-wide choke points are not shown on the canvas. They cost a full
re-traversal per candidate (§100), and the per-route cut answers the question
this view is asked.

**Walked without leaving the page.** Pressing a box centres the graph on it
instead of opening its page: the canvas is for walking the estate, and a click
that left the page ended the walk after one step. The centre is kept in the URL
as `?around=<provider id>`, written as a new history entry rather than
replacing the current one — unlike list filters (§98), where narrowing a list
should not fill the history, each re-centre is a step somebody took, so Back
retraces it. A link to a re-centred view opens with the graph already drawn.
While centred elsewhere, the centre box is a link to that asset's page, and a
strip above the canvas names it and offers the way back. (§134 made a press
select, as on the estate map; re-centring is a double click, Enter, or the
panel's button.) Folds that were opened
belong to one centre and are forgotten when it moves.

**Folds open in place.** Pressing a dashed group sends its id back as
`expand=`; the id is the fold's own identity (`group:<layer>:<relationship>:<parent>`),
not a counter, so it means the same thing on the next request and at another
depth. Opened members are drawn whatever the fan-out and walked on from like
any other asset, but the node cap still applies: opening a fold of four thousand
draws up to the cap and says it stopped. An id that names no fold — a stale page,
a hand-edited URL — is ignored rather than refused, because drawing the graph
without it is the correct answer to it. At most twenty folds are accepted per
request.

**One tab stop, then arrow keys.** A canvas where every box is a tab stop is a
wall between the reader and the route list under it. The canvas takes one stop
(a roving `tabIndex`) and arrow keys move it: left and right to the nearest box
in the next column, up and down within a column, worked from the drawn positions
so the keys follow what the reader sees. The view pans to the marked box. Enter
does what a click does. When a keyboard press re-centres the graph or opens a
fold, the redrawn canvas takes focus back onto its centre; a depth change or a
Back press does not pull focus off the page, because the request to take it is
tied to the exact picture it was made for. React Flow's own node wrappers are
not focusable, so no box carries two stops.

A new centre, depth or opened fold remounts the canvas rather than updating it,
so the new picture is fitted to the frame rather than left under the old
viewport. Tracing a route does not remount.

**What if you cut it.** A traced route offers each removable hop on it —
every hop but containment, which is where a resource lives and cannot be
removed — starting on the cheapest break. Picking one draws it as the cut on
the canvas and on the straight line, and asks `GET /attack-paths/what-if` what
removing it would close. The answer is about the whole organization, not the
traced route: `AssetGraph.cut` removes the link and re-asks the whole question,
the same check `choke_points` makes of its candidates, and a route counts as
closed only when no route between the same two ends is left. A link that ends
this route while its target stays reachable another way is reported as closing
nothing, with the way round as the reason, because a customer who removes a role
assignment expecting a route to close and finds it still open will stop trusting
every number on the page. It costs one re-traversal, so it is asked for the one
link picked rather than for every link on every route.

**From the line to the graph, not a toggle.** The plan was a Route/Graph toggle
on each route card. The Attack paths and Risk pages instead carry an "Explore
in graph" button that opens the entry point's asset page with the graph drawn
three hops deep and the route traced (`?trace=<entry>|<target>`). A canvas per
card would put fifty React Flow instances on one page for a question nobody
asks of fifty routes at once, and the graph already lives on the asset page with
re-centring, folds and the what-if; a second, thinner copy of it on each card
would drift. Routes know their assets by provider id and the asset page by row
id, so the button resolves the one it needs through `GET /assets/resolve` when
followed, rather than every route list carrying a surrogate key. An escalation
ends at a scope rather than at data, so it is not one of the attack paths the
graph traces; its button opens the graph around the entry point untraced.

The blast-radius list stays on the asset page as the text form of the same
reach.

## 102. The demo recording grows an estate, and identities and subscriptions are named

**The demo could not show the graph.** It replayed `snapshot_mixed.json`: ten
assets, two routes, no escalation, nothing large enough to fold, and every
identity called "ServicePrincipal". That recording exists to exercise rules, and
it does that well; the demo is where most people first see the graph, and it
needs the shapes the graph exists to show.

**A new recording, built as a superset.** `tests/fixtures/azure_raw/snapshot_demo.json`
is the mixed recording with an estate added around it, generated by
`build_snapshot_demo.py` beside it: an internet-facing payments app whose
identity can write the payments ledger and read the payments vault; a build
agent with SSH open to the internet whose identity holds User Access
Administrator over the payments resource group, which makes it an escalation as
well as a route; and a data resource group of sixteen archives and one account
of customer records, which folds with the sensitive account drawn out of it and
is reached by three routes from two entry points, so no single cut closes every
way to it. It is raw ARM JSON in the collector's shape and replayed through the
real normalizer, rules and risk engine, like the recording it extends — nothing
on the demo page is a fabricated row. The seed replays it for Azure
(`database/seed/demo_environment.py`); the mixed recording is unchanged, and so
is every test that reads it.

Generated rather than hand-written because four thousand lines of JSON do not
review as intent. `test_demo_recording.py` fails when the committed JSON and the
script disagree, and pins what the demo relies on: every asset and every failing
rule of the mixed recording still present (so the `--fix` replay still closes
what it used to), no rule newly unable to reach a verdict, at least ten routes
from more than one way in, the build agent's escalation, the fold, choke points
that are not all the same size, and identities that can be told apart.

**An identity is named after the workload it belongs to.** A principal
CloudGuard creates from a role assignment used to be named by its
`principalType`, so three managed identities on one route all read
"ServicePrincipal". Azure creates a system-assigned identity for exactly one
resource and names it after that resource in the directory, so its workload's
name is the principal's real name rather than a guess; the normalizer now uses
it ("vm-jumpbox (managed identity)"). This applies to customer scans, not only
the demo. A user-assigned identity is a resource with its own name, which the
workload's payload does not carry, so it keeps the generic name.

**A subscription is called by its display name.** Every subscription-wide
role assignment lands on the subscription node, so on the graph and on a route
it is often the most connected thing on the screen, and it was named by its
GUID. Onboarding knew the display name but stored it only on the account row,
not in the capture the graph is built from. The collector now reads the
subscription's own record (`GET /subscriptions/{id}`, evidence key
`subscription`) and the normalizer names the node from its `displayName`,
keeping the id in metadata. Taken from the capture rather than joined from the
account row at display time, because a capture that says what the provider
said is the rule everywhere else (§72), and a later rename in the portal then
arrives with the next scan like any other change.

It needs `Microsoft.Resources/subscriptions/read`, which every version of the
scanner role has granted from the start, so no customer redeploys anything and
`ROLE_VERSION` does not move. No rule judges it, so it is declared baseline
evidence beside the inventory: a failed read costs nothing but the name, and
the node falls back to its id — as it does for every capture taken before this
change, until the next scan. The endpoint guard, which refused a declared path
ending in a placeholder, now checks such a path by the segment before it
followed by an interpolated id, which is the only way the client can build the
call.

## 103. The risks list becomes the triage queue, and a risk can be decided about

**Three pages were one question.** Findings, Risks and Attack paths each listed
some of "what should we deal with first", and the data model had already merged
them: `Risk` is `FINDING`, `ATTACK_PATH` or `ESCALATION`, findings are linked
through `risk_findings`, and a grouping rule folds forty failures into one risk
(§44). What the risks list lacked was the ability to act. Every triage action
lived on the finding, `risks.py` had only reads, and `Risk.owner_id` and
`Risk.due_date` existed with nothing writing them.

**Decisions taken, and the ones rejected.**

- _The unit of the queue is the risk._ It is scored, deduplicated, and ranks a
  route above its parts. A union of findings and routes at the API was rejected
  -- two score scales and a route counted twice, as itself and as its hops. A
  fix-first queue ("cut this link and four routes close") was rejected as the
  row: a fix has no identity and no status, so nothing can be accepted or
  tracked against it. It becomes a view over the queue, from the choke points.
- _The page keeps the name Risks and the URL `/risks`._ "Risk" is already the
  product's word for exactly this merged object -- the score, the dashboard and
  RISK_ENGINE.md use it -- and "Issues" would have been a third word for it.
- _Status stays where the fact is._ A finding risk writes a decision through to
  its findings, because the finding is what compliance cites and what an
  exception hangs off; moving the status onto the risk would have broken both
  and needed a migration of every accepted finding. A route or an escalation
  has no finding of its own, so its status is its own -- and accepting one says
  "this reach is by design", which is a different claim from accepting any
  finding along it. A false positive stays per finding: it says the rule was
  wrong about that asset, which is never true of a group.
- _Ownership stays on the remediation task,_ which already has `assigned_to`
  and `due_date` and is keyed on the finding. `Risk.owner_id` and
  `Risk.due_date` are left unwritten and should be dropped.
- _Remediation stays a page of its own._ Triage (deciding) and remediation
  (doing) are different jobs, often different people, and merging them puts
  the engineer back in the undecided queue.
- _Attack paths stays, as analysis rather than a list to work._ It is the only
  place a route with nothing misconfigured on it is visible -- real reach that
  the scanner deliberately mints no risk for, since no rule objected to it --
  along with choke points, what-if and blast radius.
- _The findings list leaves the navigation and keeps its URL:_ compliance links
  to `/findings?rule_id=`, and `/findings/{id}` is the evidence page.

**What this change does.** The backend half:

- `POST /risks/{id}/status` and `POST /risks/status` (bulk, at most 100, all or
  none, every refusal checked before anything is written). `RESOLVED` is
  refused, as it is for findings. A finding risk's decision goes through
  `findings.accept_risk` and `findings.set_status` for each open, in-progress or
  accepted member, so it leaves the same events, audit rows and exceptions the
  finding page would. A route refused `expires_at` rather than storing a date
  nothing acted on -- until §104.
- `/risks` rows carry `finding_count` and `route_count`, so a row says what
  deciding about it decides about.

**Two bugs the queue would have made visible.** `Risk.status` did not mean one
thing. The scanner set a finding risk OPEN whenever its finding was open _or in
progress_, so a risk somebody had picked up was untriaged again by the next
scan; accepting one finding of a group marked the whole group accepted; and
every scan that saw a route set it back to OPEN, undoing an acceptance the
moment the next reading arrived. Both rules now live in `app/risk/triage.py`
and every writer uses them: a finding risk's status is its least-settled live
member (open, then in progress, then accepted), and a route seen again is
reopened only if it had closed. Separately, taking an acceptance back left its
exception ACTIVE; moving a finding out of ACCEPTED_RISK now revokes it.

**The queue.** The risks page decides as well as ranks. A checkbox per row
(raised above the card's link overlay, which otherwise took the click) and `x`
on the row `j`/`k` has marked select; a bar over the list offers Mark in
progress, Accept… and Reopen, each only when it would change one of the
selected rows. The accept dialog says how far the decision reaches -- "40 open
findings, each recorded as an accepted risk", "1 route marked as by design --
the findings along it stay open" -- because forty accounts is one click here and
has to be visible before it rather than discovered after. Rows carry "40
findings" and "On 2 routes". The status filter's OPEN is labelled _Needs
triage_, which is what it means in a queue. Top fixes -- the three strongest
choke points -- sit above the list on its unfiltered first page, and only once
a route is listed, since each costs a re-traversal. Findings left the
navigation; Attack paths stays beside Risks, and each route card says whether
the queue tracks it (matched by entry and target, which name a route on both
sides) or is reach with nothing misconfigured on it.

**Not done here.** Exception expiry was recorded and never enforced, which is
why a route refused one; §104 enforces it. Grouping the queue by asset, rule or route, and a side
panel for triage
without leaving the list, wait until the queue is in use.

**Shipped broken, and why nothing local caught it.** The first deploy returned
500 on every `/risks` request: `dict(result.tuples())` fails because a SQLAlchemy
result has a `.keys()` method, so `dict()` takes it for a mapping and indexes it.
The type checker accepts it and the unit tests never build a real result, so
only CI's integration tests (and production) could see it. Results are now
materialised with `.tuples().all()` before `dict()`, as `graph.py` already did.

## 104. An acceptance ends when its date passes

**The date was a promise nothing kept.** `accept-risk` has always taken an
`expires_at` and written it to the exception row, and nothing ever read it
again: a finding accepted "until the migration finishes" stayed accepted for
ever, the queue had no way to say when anything would come back, and the risk
triage endpoint had to refuse an end date on a route because there was nowhere
to keep one and nothing to act on it.

**A sweep, every five minutes.** `cloudguard.expire_acceptances` asks one
question across tenants on the owner session -- which organizations have an
ACTIVE exception or an accepted route past its date -- and works each of those
inside its own `scan_session`, as the other sweeps do. For a finding it marks
the exception EXPIRED and, if the finding is still ACCEPTED_RISK, moves it to
OPEN with a timeline event (no user, and a sentence naming the date and the
reason it had been accepted for) and an audit row, then re-reads its risk's
status from the members (§103). For a route or escalation it sets OPEN and
clears `risks.accepted_until`, the one new column (migration 0037).

**OPEN, not IN_PROGRESS and not RESOLVED.** Nobody has decided anything since
the acceptance ran out, and nothing about the environment was observed to
change. The finding is exactly as failing as it was, so it goes back to where
undecided things live -- Needs triage.

**One running acceptance per finding.** Accepting again used to add a second
ACTIVE exception beside the first; with expiry enforced, the older date would
have reopened a finding the newer decision still covered. Accepting now revokes
the running exception first (reopening already did, §103), and the sweep skips a
finding another unexpired acceptance still covers, for rows written before this.
Accepting an accepted risk from the queue is therefore how an end date is
extended or removed, so Accept… is offered on accepted rows too.

**Refused if already past.** A date at or before now is a 422 on both the finding
and the risk endpoints: stored, it would be expired by the next sweep, and the
person accepting would see their decision undone minutes later with no idea
why. A naive timestamp is read as UTC.

**On screen.** The accept dialog takes an optional day, sent as the end of that
day in the reader's timezone, and says what happens after it. An accepted row
shows "Accepted until …" -- the earliest end date among a group's members,
because one member coming back is enough to put the row back in the queue. The
finding page's accept form takes the same optional day, and the page shows
"until …" beside an accepted finding's status, read from `GET /findings/{id}`'s
`accepted_until` -- so an acceptance can be given an end on whichever page it
is made, and seen on both.

## 105. Queue rows say which asset and what was found

**The queue read as one row repeated.** On a real tenant, the Misconfigurations
view of the risks list showed rows like "Identity can grant itself any role —
User" three times over, each with the same paragraph under it. Two causes:

- _A principal with no name was named by its type._ A role assignment whose
  principal is not in the directory capture, and is not a workload's
  system-assigned identity (§102), became a node called "User" or
  "ServicePrincipal". It is now the type followed by the first eight characters
  of the object id -- "User 3f2a91c0" -- which tells rows apart and is what a
  person searches Entra for. The directory name, when the capture has it, still
  wins.
- _A finding risk's description was the rule's rationale,_ the same sentence on
  every row one rule raises. It is now the finding's own message ("User 3f2a91c0
  holds User Access Administrator, which permits writing role assignments"),
  which names the asset and what it holds. A grouped risk keeps the rationale,
  because its one row stands for every member and the worst member's message
  would name one asset on a row about forty.

**The kind filter says Misconfigurations, not Findings.** The segment selects
risks scored from a single failed check. Labelled "Findings", it read as the old
findings page inside the new one -- the confusion §103 set out to remove.

Both text changes are written by the scanner, so existing rows change at the
next scan of each subscription; nothing is rewritten in place.

## 106. Findings goes back in the navigation

**Supersedes the navigation half of §103 and the label half of §105.** The
findings list is a navigation item again, first under Exposure, above Risks, and
the risks page's kind segment is labelled _Findings_ rather than
_Misconfigurations_. Taking the list out of the navigation left no direct way to
work finding by finding, which is still how the list is used, and the relabel
only existed to paper over its absence.

Everything else §103–§105 did stays: deciding about risks one at a time and in
bulk, the status rules in `app/risk/triage.py`, acceptances that end on their
date, and rows described by the finding's own message.

## 107. A finding is decided about on its risk, and nowhere else

**Two places to decide about one problem.** After §103 a finding could be marked
in progress or accepted on its own page, and the same finding could be decided
about through its risk, in the queue. The two did not agree on scope: accepting
one member of a grouped risk from the finding page accepted one account of
forty, and the queue's next read of the group (§103's least-settled rule) still
showed it as needing triage -- a decision made and, as far as the queue was
concerned, not made. The risk page, meanwhile, could decide nothing at all.

**The risk is the one place.** Its page now carries the same decisions as the
queue's bar -- Mark in progress, Accept… (reason, optional end date, and a
sentence saying how many findings it reaches), Reopen -- through one component,
`RiskDecisions` in `RiskTriage.tsx`, which the bar now wraps. The finding page
loses its Accept and Mark in progress and gains **Decide on its risk**, a link;
it keeps Rescan and Assign, which are about fixing rather than deciding, and
still shows the status and the acceptance's end date, which remain stored on
the finding for compliance and exceptions (§103).

**The API is unchanged.** `POST /findings/{id}/status` and
`/findings/{id}/accept-risk` stay: the risk endpoints write through them, and
API clients may use them. The single place is a product decision about where a
person decides, not a removal of the finding's own record of it. A false
positive, if one is ever offered in the UI, belongs on the finding -- it says
the rule was wrong about that asset, which is never true of a group.

## 108. The scan pipeline is a package, and every step commits through one fenced writer

**`scanner.py` had become the pipeline's only unit.** 3,700 lines, one class,
sixty methods, and five jobs that share nothing but the class: driving steps,
collecting, storing and rebuilding captures, ordering the analysis, and writing
every table a scan touches. The stages passed the same six to nine arguments --
session, organization, scan, reading time, subscriptions, connection, which
subscription each asset came from -- through every helper by hand, and a test
of one stage had to build the whole pipeline to reach a private method on it.

It is now `app/services/scan/`, split along the seams the file already had:

| Module | Holds |
|---|---|
| `pipeline.py` | `ScanPipeline`: claim, run and settle a step; `plan`, `collect`, `analyze`, `replay` |
| `errors.py`, `lease.py` | the step errors; `LeaseKeeper`, the heartbeat and phase callbacks, `StepFence` |
| `collection.py` | reading a subscription or the directory, evidence rows, blobs, role drift |
| `capture.py` | the manifest a capture is stored as, and the reconstruction ANALYZE and replay share |
| `analyze.py` | `evaluate`: the order of the stages, and nothing else |
| `assets.py`, `coverage.py`, `findings.py`, `risks.py`, `remediations.py`, `correlation.py`, `posture.py` | one stage each |
| `scope.py`, `context.py`, `writer.py` | the scope predicates, `AnalyzeContext`, `ScanWriter` |

`AnalyzeContext` is the argument list said once. The comments came across
verbatim -- they are the reasons, and the move is not a reason to lose them.
Callers import from `app.services.scan`; nothing re-exports the old path, so
there is one name for each thing. Two places monkeypatched `get_connector` on
the old module (the integration suite's replay fixture and the demo seed); both
now patch `collection` and `capture`, the two modules that build a connector.

**The fence covered the step row and nothing the step wrote (§65).** A step is
fenced on the attempt it was claimed under: its renewals, its phase marks and
its settle all refuse to land once the row carries a later attempt. Its _work_
was not fenced at all. `LeaseKeeper` learns a step was taken on a clock, a third
of a lease at a time, and ANALYZE commits a dozen times on its way through --
so a worker that lost its step kept committing findings, risks, resolutions and
posture until the next renewal noticed, beside the worker that had taken over.
The lease was designed to make that window rare; nothing made it harmless.

`ScanWriter.commit` closes it. Every commit a step makes -- PLAN's, COLLECT's,
and each of ANALYZE's -- goes through the writer, which flushes, then asks
`orchestrator.hold` whether the step row is still RUNNING at this attempt, and
rolls back and raises `StepLeaseLost` when it is not. The question is asked
inside the transaction about to commit, and asked with `SELECT … FOR SHARE`: the
reaper returning the step to PENDING and the next claim raising its attempt are
both updates of that row, so neither can land between the check and the commit
-- they wait for it, and the attempt that takes over starts from what this one
committed. It is asked last, after every write, so the row is locked for the
length of a commit rather than of a stage; the renewal beside it waits that
long and no longer. A replay is one task rather than a claimed step, has no
attempt for anyone to take, and commits unfenced. `test_scan_writer.py` holds
the package to this: the only commits in it are `ScanWriter.commit` and a
replay recording its own failure.

**Rows nothing reads back go in bulk.** Change events, finding events, coverage
rows, evaluation gaps, evidence rows, citations, edges and risk links are
appended and never looked up before the commit. They were ORM objects all the
same -- each one in the identity map, through the unit of work, tens of
thousands of them on a large tenant's first scan. The writer takes them as
plain rows and sends each table as one `executemany` at the next flush, after
flushing the ORM so the rows can name the findings and risks they point at.
Rows are grouped by the columns they set, because one `executemany` compiles
one statement and a row leaving a column to its default must not be sent an
explicit NULL for it. The writer stamps each row's `organization_id` and
refuses one naming another tenant, and refuses any table outside
`APPEND_ONLY` -- two doors for one table is how a row gets written twice.

Edges and risk links are facts, recorded or not, and are inserted with `ON
CONFLICT DO NOTHING`. That retires two reads whose only purpose was avoiding a
unique violation: the edge read in `_persist_relationships`, and the per-route
read of existing links in `_link_members`. A new route's risk is given its id
as it is built, so its links are queued without the flush each route used to
cost. Everything else fails on a duplicate, as it should: a finding event
written twice is a scan that did one thing twice.

**What stays on the ORM, and why.** Assets, findings, risks, posture entries,
verifications and captures are read back and changed in place -- a finding is
reopened, a risk's status is derived from its members, the next stage needs an
asset's id -- and the unit of work is the right tool for that. An upsert of the
asset inventory was considered and not done. The existing rows have to be read
regardless, because a change event records the value before the change and an
asset's `absent_since` is a transition; directory assets conflict on a
different (partial) unique index from subscription assets, so it would be two
statements with two conflict targets; and the ORM already batches the updates
it emits. It would save the identity map and nothing else, and nothing has
measured that as the cost. The writer is where that change would go if a
profile ever says so.

## Settings: the evidence a person supplies

`PATCH /organizations` takes no id in the path. Deleting a _different_
organization from the one on screen is a real thing to want and DELETE keeps
its id; editing one is not, so the target comes from the tenant context and the
membership check has already happened.

Two write shapes sit on this screen and they are deliberately opposite. The
organization profile is patched — only the fields sent are written, so saving a
corrected name cannot clear a country nobody touched. A context declaration is
a _statement_, replaced whole, so a reader always knows what it currently
claims without diffing. `UNKNOWN` is refused by the API and absent from the
menus for the same reason: it is CloudGuard's own answer for "nothing said
anything", and a customer declaring it would assert an absence that leaving the
field unset already asserts.

Declarations are not retroactive and the screen says so. A risk score is what a
scan concluded; rewriting stored scores from a form would leave findings
carrying numbers no observation ever produced.

## 109. A report is laid out as a document, and its stylesheet is no longer escaped

**Every quoted value in the report stylesheet had been silently dropped.** The
templates render with autoescape on, which is right for everything a customer's
cloud can name -- and `base.html.j2` passed the stylesheet through the same
`{{ css }}`. Escaped, `"DejaVu Sans"` became `&#34;DejaVu Sans&#34;` inside
`<style>`, which is raw text: nothing decodes the entity, the declaration is
invalid, and the renderer discards it. So every PDF printed in the renderer's
default serif, and the running footer (`content: "CloudGuard — confidential"`)
never appeared. The stylesheet is this package's own file, so it is now marked
`safe`, and `test_the_stylesheet_is_not_html_escaped` pins it. Nothing a
customer controls reaches it.

**The document is laid out like one.** The report had been a styled web page
printed onto A4. It is now:

- **A cover.** A full-bleed band with the product mark, the report's name and
  the organization, then when it was generated, when the evidence was
  collected and the activity window. The caveats sit on the cover under "Read
  this first", before any number, as §32 and the Phase 9 note require -- the
  staleness warning still precedes the score in the HTML, and a test still
  says so.
- **A contents list** with page numbers (`target-counter`), built from the same
  conditions the body branches on so it can never name a section the document
  leaves out. Sections are numbered by a CSS counter, so the numbers in the
  contents and on the headings cannot disagree.
- **Running headers and footers** on every page after the cover: report name,
  organization, "Confidential", page _n_ of _m_.
- **The posture as a picture as well as numbers.** The score is a ring filled to
  its share of 100 (`score_ring_svg`, beside `score_trend_svg`: inline SVG
  from a bounded integer, no `xmlns`, so the document still contains no URL at
  all). The ring is ink, not a severity colour -- a score is not a finding.
  Open findings by severity are bars scaled to the largest count; the headline
  counts are cards. Top risks and compliance coverage carry a meter beside the
  figure; a framework nothing has assessed gets no bar and says "not yet
  assessed", because a 0% bar would read as total failure. Attack paths number
  their steps and set the link to cut apart; findings are cards edged in their
  severity, with remediation in its own block.
- **"How to read this report"** closes both documents: the score, finding
  against risk, verified fixed, accepted risk, no verdict, attack path. A PDF
  is read by people who have never opened CloudGuard, and those are the
  distinctions they would otherwise guess at. It states no figure the body
  does not measure.

Colour is reserved for severity; the document's own chrome is neutral ink.
The severity hues are the print equivalents of the `--sev-*` tokens, so low is
blue in the PDF as it is on screen, where it had been green. Attack paths no
longer force a page break, which had left a page mostly empty after top risks;
the findings list still starts on its own page. Two tests that asserted `<svg`
was absent without a trend now look for the trend itself, since the ring and the
mark are SVG too.

Checked by rendering both reports through WeasyPrint 63.1 in a container built
with the API image's apt packages, which is also where DejaVu comes from.

## 110. The asset list is ranked and faceted on the server

**The asset list claimed to be worst first, but only within a page.** The
`/assets` endpoint ordered by name. `Assets.tsx` then re-sorted the fifty rows it
had been handed by open findings. So on an estate larger than one page, an
asset with twenty open findings whose name sorted late was on page five, and
page one led with whichever asset had the most findings among the first fifty
names -- often none. The list promised a queue and delivered a directory with
a local shuffle. It is the failure §27 closed for `/findings` and `/risks`: a
paginated endpoint whose client orders or filters only the page it holds.

The API now orders by the open-finding count it already computes, then by name,
then by id. The id tiebreak matters for paging: without it two assets with the
same count and name could swap between requests, and an offset would repeat one
and skip the other. The page keeps the order it receives, and its grouping
keeps that order within each group.

**The type and environment filters offered only what was on the page.** The
menus were built from the rows on screen, so a type that did not appear in the
first fifty rows could not be chosen at all -- and the list's own ordering
decided which types those were. `meta.facets` now carries both option lists
with counts, computed over the whole filtered set. Each dimension is counted
under every filter except its own, which is the usual faceting rule: after
choosing "virtual machine", the type menu still offers storage accounts rather
than collapsing to the one value already chosen, while the environment menu
narrows to the environments virtual machines are in. The filters are kept as a
dict keyed by what each one narrows, so leaving one out is a key lookup rather
than a second copy of the filter code. The currently selected value stays in
its menu even if its count falls to zero, so the control never loses what it
is showing.

Two more queries per request -- one grouped count for each dimension over the
tenant's resources. That is the same scale as the `total` and `unchecked`
counts the endpoint already runs.

## 111. The estate is drawn as its containers, opened one at a time

§101 refused to draw the whole tenant, because a canvas of every asset is the
picture every CSPM demo shows and nobody can read. That refusal left the
question before §101's unanswered: not "what is around this asset", but "how is
my estate wired together, and where should I start looking". The Assets page
now has a third view, **Graph**, beside the list and the hierarchy. It answers
that question by drawing containers instead of assets.

**Containers, not assets.** `GET /attack-paths/estate` draws the estate through
a _lens_:

- With nothing opened, each subscription is a box, and so is the directory.
- With one subscription opened, its resource groups are boxes, and what sits
  directly in it is drawn as itself. Above all that is the subscription
  resource, which is what a role over the subscription lands on.
- With one resource group opened, its assets are boxes.

Anything outside the lens is drawn only when reach crosses into or out of it.
It then appears as the coarsest box that names it: another subscription, or
another group in the same one. This is the whole tenant, bounded by grouping
rather than by hops, and each level can be read.

**The lens is the list's scope filter.** The lens is carried as
`subscription_id` and `resource_group`, the same pair the list filters by and
the hierarchy links into. The directory is the same `directory` key. Placement
is read the same way in all three: the account's subscription id, and the
resource group taken from the ARM id's fifth segment. `RESOURCE_GROUP` moved
from the assets route into `services/placement.py` so there is one copy of it.
So switching from the graph to the list shows exactly the assets the map was
drawing, and a link to an opened map is a link like any other. Opening a box
pushes a history entry, the way re-centring the neighbourhood does (§101), and
Back retraces it. Narrowing the list still replaces its entry (§98).

**Only reach crosses a box, and only reach that crosses is drawn.** Between
boxes the map draws the identity hops: `HAS_IDENTITY`, `GRANTS_ROLE` and
`CAN_GRANT_ROLES`. These are counted by relationship and labelled with the verbs
a route uses, for example "can act over ×3". A link between two assets in the
same box is inside it and is not drawn. Containment is what the boxes _are_, so
it is drawn only where an attack path runs along it, unlabelled. Otherwise a
subscription would carry an edge to every group it holds, and the one route
through them would be lost among forty statements of where things live. A link
between two neighbours that are both outside the lens concerns somewhere else,
and is left out.

**Every box carries the same counts.** Each box shows assets, entry points,
sensitive assets, open findings with the worst of them, and the attack paths
that pass through it. Entry points and sensitive assets are counted with the
graph's own predicates, as the neighbourhood's markers are. Open findings mean
OPEN or IN_PROGRESS. A subscription box and a single virtual machine are
therefore read the same way. Arrows on an attack path are drawn darker.
`routes_total` counts the paths that touch what the lens opened, not the whole
organization.

**Folded, never dropped, and inventory is always folded.** A lens draws at most
`ESTATE_MAX_ASSETS` (40) asset boxes. They are chosen in this order: entry
points and sensitive assets, then assets a route runs through, then the assets
carrying the most reach. The rest go into one dashed box. An asset with none of
those properties is inventory, which the list answers better, so it is folded
even when there is room. Folded assets keep their reach: their links are drawn
from the fold, and `folded_with_reach` makes the page say how many of them have
reach. The fold links to the list filtered to the same lens.

**Laid out by reach, not by simulation.** There is no focus to count hops from,
so `layoutEstate` counts from where reach starts. That is every box holding an
entry point, plus every box that nothing reaches. Each box sits at its shortest
distance from one of those starts, so reach reads left to right and a box
holding a way in is always in the first column. A cycle that nothing leads into
is entered at its first box in a fixed order, so it is still drawn. Boxes with
no reach at all go after the rest, stacked eight to a column so that a quiet
estate becomes a grid rather than one tall column. Within a column, boxes are
ordered by the average height of their placed neighbours, with ties broken by a
fixed order. The same estate draws the same picture on every visit, as §101
requires. (§134 replaced shortest distance with a layering that breaks loops
and places each box past the furthest box that reaches it, and a way in is no
longer always in the first column.)

**The same canvas, not a second one.** `EstateCanvas` is its own lazy chunk,
built on React Flow the way `NeighborhoodCanvas` is: `base.css` only, colours
from the tokens, read-only, no wheel zoom, and one tab stop with arrow keys
inside. What the two canvases share (the flow tokens, the fit, the arrow keys
and the zoom buttons) moved into `flowChrome.ts` and `ZoomButtons.tsx`, so they
cannot drift into two looks. Pressing a subscription or group opens it on the
map (since §133, a press selects and Enter or a double click opens). Opening
an asset opens its page with its own graph already drawn: the
link sets `?around=` to the asset itself, and a neighbourhood card now draws on
arrival whenever `around` is present, not only when it names another asset. The
map hands the "what is around this asset" question to the view that already
answers it, rather than growing a thinner copy of that view. Under the canvas,
the arrows are listed again as sentences, with reach on a route listed first.
That list is the text form of the picture, as the blast-radius list is for the
neighbourhood.

**Considered and not built.** Three alternatives were weighed:

- A graph tab that is the neighbourhood with a picker. It would only have moved
  the asset page's view to another page.
- A from→to explorer. It overlaps the attack-paths page and belongs there if
  anywhere.
- A layer showing reach that appeared since the previous scan. This is the most
  distinctive of the three, but it needs a graph built from an older snapshot,
  and the graph is computed on read from present state (`services/graph.py`
  says why). It waits for the per-scan `attack_paths` table that module
  describes.

## 112. The asset page answers "is this in trouble" first, and the hierarchy is the map's list

**The asset page made the reader do the work.** The header named the asset and
nothing about its state: whether anything was wrong had to be counted off the
findings list. That list mixed resolved findings in with open ones. The page
was one long scroll: two cards, a neighbourhood graph 28rem tall, blast radius,
then the raw configuration. The two graphs each sat behind their own button
("Draw the graph", "Work out reach"), so the page looked half loaded. The
breadcrumb went to a bare `/assets`, so a reader who had filtered the list to
one subscription's exposed assets lost all of that by going back. The provider
id sat in grey type in a card footer with nothing to copy it with.

**What the page is now.**

- **The trail returns to where the reader was.** Every link into an asset from
  the list, the map, or the map's contents list carries the page's own URL in
  router state. The "Assets" crumb goes back to exactly that: filters, page,
  grouping, or the map as it was opened. Arriving any other way, it goes to
  `/assets`. After it come the subscription and the resource group, each
  linking to the map opened at that level. The map is the one view that shows
  a group as a place.
- **The header gives the facts a person acts on.** Type, region, environment,
  first seen and last scanned sit under the name. **Copy ID** copies the whole
  provider id. **Open in Azure** appears for ARM ids only, and its URL names the
  tenant (`portal.azure.com/#@{tenant}/resource{id}`). Without the tenant, the
  portal opens in the viewer's default directory, where a resource in another
  tenant (every tenant an MSP manages) reads as "not found". Directory objects
  get no link, because they live under a different Entra blade, and AWS gets
  none because AWS is not in the UI.
- **A summary strip answers "is this in trouble".** It shows open findings with
  counts by severity, then criticality, data sensitivity and exposure. The
  first two keep their "where this came from" tooltip, and a caption says what
  none of these screens said before: these three multiply the risk of every
  finding on the asset. There is no asset-level score. Scores belong to
  findings and risks, and a third kind of score would be one more number for a
  customer to reconcile.
- **A banner for an asset that is gone.** `absent_since` is now on the detail
  response. When it is set, the page says the asset was not found by the last
  scan, that its findings are frozen as of the last scan that saw it, and that
  it is on no attack path.
- **Tabs, and opening a tab is the request.** The tabs are Findings,
  Connections and Configuration, kept in `?tab=`. The graph and blast radius
  sat behind buttons for a reason: blast radius works over the tenant's whole
  graph. A tab keeps that reason, since nothing is asked for until
  Connections is opened, and the extra click is gone. A long single page could
  not express "only when asked" without a button. A link carrying `?around=`
  or `?trace=` came for the graph (the map's asset boxes and a finding's route
  both send one), so it opens on Connections. The tabs are underlined, span the page, and
  each carries an icon (`ASSET_TAB_ICONS`), with the open-findings count in a
  neutral chip. They were first a segmented pill, which reads as a filter on
  the panel below rather than as a switch between sections of the page.
- **Open findings first, and two different empty states.** Closed findings
  (resolved, accepted, false positive) are one press away, and the switch
  appears only when there are any. With nothing open, a modelled resource type
  says "No open findings. Last scanned …". A type CloudGuard has no rules for
  says it has no checks for that kind of resource yet. "No findings" on a
  resource nothing was checked against would present the absence of a check
  as a clean bill of health, which is what the list's "unchecked" count exists
  to prevent.
- **Blast-radius rows open their asset.** The endpoint now returns each row's
  `asset_id`.

**The hierarchy view is the map's contents list.** After §111, Assets had three
views. Hierarchy and Graph answered the same question: subscription, then
group, then what is in it, with counts. Three view buttons is one decision too
many. The view switch is now **List** and **Map**. Under the canvas, the boxes
inside the opened lens are listed worst first: open findings, then attack
paths, then size. Each row carries the same marks as its box. Pressing a
subscription or group row opens it on the map, just as pressing the box does.
(§133 moved the list into the panel beside the canvas, where a row selects its
box as a press on the canvas does.)
That list is what the tree was, and it is also the map's text form, which a
canvas alone does not have. The hierarchy's treemap went with it, because the
boxes carry the same counts. `AssetTree` and `EstateTreemap` are deleted. The
web app no longer reads `/assets/hierarchy`, but the endpoint stays for API
clients. An old `?view=tree` link opens the map rather than falling back to
the list.

**The map, made readable.**

- The paragraph-long legend under the canvas is now a row of chips (globe,
  cylinder, route, findings count, darker arrow), with the rest of how to read
  the map in a popover behind a question mark.
- Each sentence in "Reach across boundaries" is now a toggle. Picking one
  fades every box and arrow except that arrow and its two ends. The arrow is
  still shown in its place in the estate rather than on its own.
- When the list's search, type, environment, exposure or signal filters are
  set, the map says they apply to the list only and offers to clear them. The
  map draws everything in the opened scope. If it silently ignored a filter
  that is visible in the URL, it would read as having applied it.
- The list's own request no longer runs while the map is open.
- The markers moved to `estateMarkers.tsx` so the contents list can use them
  without importing `EstateCanvas`, which is the lazy chunk holding React Flow.

**Only a 404 means "nothing is there".** The map, the neighbourhood and blast
radius each said the scope or asset was not in the graph whenever their
request failed, including on a 500 or a timeout. That presented an outage as a
fact about the customer's estate, the misleading kind of error §66 exists to
prevent. Each now checks `ApiError.status === 404`. Any other failure shows the
standard error state with a retry.

**The list says what the map marks.**

- **Filter.** A new list filter narrows to what the map marks: reachable from
  the internet, holds sensitive data, or on an attack path. On the API these
  are `entry_point`, `sensitive` and `on_attack_path`. The first two are the
  graph's own predicates (`ENTRY_EXPOSURE`, `SENSITIVE_DATA`) applied as column
  filters. So a box that counts "2 reachable from the internet" and the list
  filtered to entry points agree by construction, not by two definitions
  staying in step.
- **Row mark.** Every row carries `on_attack_path`, and a row that is on one
  shows a small route mark. That is the strongest thing an inventory row can
  say. It is a mark rather than a column, so rows that are not on a path stay
  quiet.
- **Cost.** Membership comes from the tenant's cached graph. The list now asks
  for attack paths on every page, so `AssetGraph` keeps them once per graph
  (`_paths`) and hands out copies. The cached graph is never changed after it
  is built, and `_without` builds a new graph, so its answer cannot go stale
  within one graph.

## 113. The dashboard shows where the estate runs, coloured by what is wrong there

**The question.** Where do my services run, and where is the trouble? The
data was already there: `cloud_resources.region` comes from Azure's `location`
and from the region an AWS reading was taken in. It was shown only as one fact
on an asset's page, so nothing answered "which regions am I in, and which of
them is the problem".

**Why it is on the dashboard, and in which form.** The dashboard carries no
inventory figures as headlines (UI.md §1), and a map of where assets run is
inventory. What earns it a place is the second half of the sentence. Each
region is coloured by the worst open severity on the assets in it. The list is
ranked severity by severity from the top, so one critical outranks any number
of lows. Size shows how much runs there, scaled gently (square root), and a
region with nothing open is drawn muted. A panel sized by asset count alone
made the biggest clean region the loudest mark on a page about what is wrong.
It sits after coverage because the two finish one sentence: how much was seen,
and where.

**What was considered and not built.**

- _A map library_ (react-simple-maps, d3-geo, Leaflet/MapLibre). Tile maps
  fetch third-party tiles, which a CSP and a no-cookies product do not want.
  A projection library is a second visual kit for the job of placing about
  thirty points. The map is a hand-drawn SVG, like `ScoreRing`: an
  equirectangular 2° grid of land cells (`lib/geo/worldDots.ts`, 3.9 KB),
  generated once by `apps/web/scripts/build-world-dots.mjs` from Natural
  Earth's public-domain 1:110m land. The script's three packages are not app
  dependencies. The land is drawn as a dot pattern revealed through a mask of
  horizontal runs, a few hundred rectangles rather than 2,700 circles.
- _Data residency_ ("these three resources are outside the regions you
  allow"). It is the most CSPM-shaped use of a region, and it needs an
  organization setting, a rule and a compliance mapping, so it is a feature of
  its own and not part of a map. It is listed under open items below.
- _Coordinates from the API._ A coordinate is a drawing concern. The API
  returns what the provider said, the region code, and the web app's
  `lib/geo/regions.ts` holds display names and metro coordinates for Azure's
  and AWS's public regions. The two clouds' codes cannot collide (AWS codes
  always contain hyphens, Azure's never do).

**The rules the panel keeps.**

- **One spelling.** ARM returns `westeurope` from a listing and `West Europe`
  from some detail calls. `placement.REGION` lower-cases the value and strips
  spaces in SQL, and `region_key` does the same in Python. The map groups with
  the first and the asset list's `?region=` filter uses the second, so a dot
  and the list it opens always contain the same assets.
- **"Global" is not a place.** The directory, anything ARM calls `global`, and
  findings about the tenant rather than an asset form one bucket with
  `region: null`. It appears as a line under the list and never as a point on
  the map. A link reaches it as `?region=none`.
- **An unknown code is listed, not guessed.** A region missing from the
  catalogue is listed by its code and left off the map. A dot in the wrong
  country is worse than no dot.
- **Unread is not clean.** `readings` and `unread` count only readings that
  were _of_ a region, so every Azure reading is excluded (all are global),
  while each AWS region is read separately. An unread region gets a dashed ring
  and the words "could not be fully read". Nothing open in a region nobody
  could look at is not a clean bill of health (§69).
- **The list is the content.** The SVG is `aria-hidden` and out of the tab
  order. Every region it draws is a link in the list, which is what a keyboard
  reaches, the same split the estate map makes (§112). Clicking a dot is a
  shortcut for mouse users.

**The demo spans three regions.** `build_snapshot_demo.py` puts the sixteen log
archives in North Europe (West Europe's paired region) and the build agent in
East US. The panel then draws an estate rather than a single dot, and the
region with the most assets (North Europe, the archives) is not the one with
the most wrong. Only the `location` strings changed, and no rule reads
location, so every finding the demo showed is unchanged.

## 114. "Consent granted" is read from the grant, not from the callback

**What happened.** A live tenant connected cleanly. Admin consent completed,
the callback recorded GRANTED, and the access panel said "Admin consent:
Granted" in green. Every identity category then failed with "Applications
without a signed-in user are not allowed". The tenant's Cloud Guard
enterprise app held one grant, delegated `User.Read`, which is the permission
a new app registration starts with. The nine Graph permissions had never been
declared on the registration as _application_ permissions. Consent to
`/.default` granted what the registration declared, which was nothing a
scanner can exercise.

**What was already right.** The manifest declares all nine as `type: "Role"`
(`app_registration_manifest()`), and the consent link is the v2.0
`/adminconsent` endpoint with Graph's `/.default`. Neither needed changing.
The registration is configured by whoever operates CloudGuard, and no code in
this repository can do that step for them.

**What was wrong is what the product said about it.** `grant_problem()`
already read the token's `roles` claim at the callback and wrote the gap into
`status_detail`. The next status change overwrote it ("Connection verified."),
and the panel never read it. The consent line looked only at
`consent_status`, and that value is Entra saying an administrator clicked.

**The change.**

- `cloud_connections.missing_permissions` (JSONB, migration 0038) records what
  consent left out, by name. NULL means not checked, and an empty list means
  nothing is missing. The two stay distinct, because an unreadable token must
  not be shown as a complete grant or as nine missing ones.
- It is written at the consent callback, and again on every "Re-check
  access". That covers a grant changed outside the callback: an administrator
  who consents again, or one who assigns the app roles to the service
  principal by hand (`POST /servicePrincipals/{id}/appRoleAssignments`, the
  per-tenant hotfix used on the tenant that surfaced this).
- `ProviderOnboarding.missing_grants()` is the seam. Azure reads the token's
  `roles` claim, and every other cloud answers `None` because its grant cannot
  succeed partially.
- The panel says "Granted, incomplete" in the high colour, and lists the
  missing names with what to do about them.

**Why the token and not `appRoleAssignments`.** Listing the service
principal's app-role assignments needs `Application.Read.All`, one of the
permissions whose absence is being diagnosed. The `roles` claim needs nothing,
and it is also what Graph enforces against.

**Two smaller fixes from the same tenant.**

- The app-registration endpoint's lookup command searched for the display name
  `CloudGuard`. The live registration was named "Cloud Guard", so `APP_ID` came
  back empty and the update after it failed without naming either. The
  command now sets `APP_ID` to the configured client id, and falls back to
  the name search only when there is no client id.
- ARM answers a subscription that has never registered a resource provider
  with 404 "Subscription Not Registered" (Defender's plans without
  `Microsoft.Security`), or with 409 `MissingSubscriptionRegistration`. That
  read like missing access. The error now names the namespace and gives the
  `az provider register -n <namespace>` command. CloudGuard holds no write
  permission, so it cannot run that command itself; this is the same stance
  as change events.

## 115. The deploy step waits three minutes after consent before calling a missing principal a fault

Entra creates CloudGuard's service principal during admin consent, and
publishes it to the directory when replication gets there. Until then, the
lookup that the ARM template needs is refused or comes back empty. The setup
page showed the result immediately as "CloudGuard cannot generate the
deployment yet", so every new tenant opened on an error that was usually just
timing.

For three minutes after `consented_at`, the step shows a `WaitingNote` with a
countdown to when it will report instead. This is not the timer-driven
progress that §87 rules out. The page re-reads the connection every five
seconds, and each read retries the lookup (`try_auto_validate` →
`ensure_principal`), so the wait is real and ends early as soon as the
principal appears. The countdown only says when the page will stop calling it
a wait. It is measured from the server's `consented_at`, so a reload does not
restart it.

When the window closes, the reason is shown unchanged. A registration with no
application permissions never publishes a lookup that works, so after three
minutes the fault is shown for what it is (§114).

## 116. The demo seed replays through the pipeline the scanner has now

**The shared demo showed an empty estate** -- score 100, every count zero, "one
scan so far". Nothing was wrong with the recording or the rules. The seed's
`ReplayConnector` had stopped matching the connector seam twice over. The
pipeline began passing a `CollectionPlan` to `collect` (§ "Decide what a scan
collects before it collects it"), and the replay's `collect(on_progress)` took
no plan, so every COLLECT raised a `TypeError`. And a capture became a manifest
of payload hashes that ANALYZE rebuilds from `snapshot.payloads`; the replay
handed over `data` and no payloads, so even a collect that ran stored a
manifest naming nothing. The directory half fails soft by design, the account
half left an estate with no readings, and the rules judged nothing and passed.

The integration suite's replay had been kept up with both changes; the seed's
had not, because nothing ran it. So the seed's replay now takes the plan and
ignores it (a recording has nothing to narrow), builds one payload per coverage
entry -- `authentication_methods` folded into `user_role_map`, as the real
task produces it -- and answers `baseline_evidence` and `evidence_keys_in` with
the provider's own answers rather than the base class's empty ones. A unit test
calls it the way `collection.py` does and rebuilds its capture the way ANALYZE
does, and holds that the rebuild adds back up to the recording, so the next
change to the seam fails a test rather than the demo.

The demo already built in production is still the empty one: rerun
`demo_environment.py --shared` on the API service after deploying. It keeps
the organization id and its members.

## 117. A 403 from Azure's front door is not blamed on the role

**A staging connection sat on "Waiting for the read access grant" for ten
minutes** with the scanner role deployed. Every `GET /subscriptions` from
Railway came back 403 with an HTML page, "The request is blocked", which is
Azure Front Door refusing the call before ARM sees it. ARM itself never answers
that listing with 403 when a role is missing: it answers 200 with an empty
list, which the probe already reports as `no_subscriptions_readable`. Graph
calls from the same service were succeeding the whole time. The block was
about where the requests came from. Nothing was wrong with what CloudGuard
had been granted.

Two things made this slow to see, and both are fixed in `client.py`.

Every 403 raised the surface's access-denied hint, so the log and any
collection error said "the scanner role is not assigned" and sent the reader
to IAM, where the role sat correctly assigned. A 403 whose body is Front
Door's block page now raises its own message: blocked at Microsoft's network
edge, not a permission problem, quote the reference to Microsoft support or
send the calls from another address. `azure.request_failed` carries
`edge_blocked` so the logs can be filtered on it. The match is the page's
wording, not "any HTML": other gateways answer in HTML for other reasons, and
an unrecognised HTML 403 keeps the role hint (§91's test still holds).

The detail lost the block reference. §91 reduced markup to its text, but text
between `<style>` tags is still text, and Front Door's page opens with about
300 characters of CSS. That filled the 400-character limit and cut the "Ref A"
off partway through, and Ref A is the string Microsoft support asks for.
Stylesheets and scripts are now dropped before tags are stripped.

The fix does not unblock anything. If the block persists, the deployment
needs a different outbound address (Railway's static egress IPs, or another
region) or a ticket with Microsoft quoting the references.

## 118. The asset list keeps the filters that narrow a queue

The list's toolbar had grown to a search box and six menus, and they did not
all do equal work. Type, exposure and what the map marks (reachable from the
internet, holds sensitive data, on an attack path) each answer "which of these
should I look at first". Environment and region mostly answer "where is it".
Environment depends on a tag many estates never set, and region already has
its own view, the dashboard's map (§113). The menus now are search, type,
exposure, map marks and grouping. Grouping by environment stays available.

The two parameters are still supported. `?region=` is how a dot on the
dashboard map opens the list, and `?environment=` may be in links people have
saved. When either is set it shows as a removable chip beside the scope chip,
so a narrowed list says it is narrowed. The API and its facets are unchanged.

## 119. An open machine reaches the machine beside it, and an empty attack-path page says where each way in stops

**A lab tenant with internet-facing virtual machines showed "Nothing exposed can
reach anything sensitive".** Reading the graph code against that estate found
four ways a real route went missing, and one way the empty page misled.

**ARM ids were joined case-sensitively in three places.** ARM treats ids as
case-insensitive and does not keep one casing: a machine's own record routinely
spells its resource group `LAB-RG` while the interface listing, the network
security group and the storage account beside it say `lab-rg`.

- The machine-to-interface join missed, so the machine's exposure was UNKNOWN.
  UNKNOWN is deliberately not an entry point (the graph refuses to start a route
  from a gap in collection), so an open machine was never where a route began.
  The interface and public IP lookups are now keyed by the lower-cased id.
- The resource-group nodes were keyed by exact spelling, so one group became two
  nodes, and a role over the group reached only the half whose casing matched
  the assignment. Groups are now keyed by lower-cased name, one node each.
- A role assignment's scope, and the ends of every other edge, had to match a
  node exactly or the edge was dropped as dangling. Scopes are now looked up by
  any casing, and a last pass in the normalizer rewrites every edge's ends to
  the spelling of the asset they name (`_canonical_edges`).

**User-assigned identities were ignored.** Only `identity.principalId` was read,
and Azure sets it only for a system-assigned identity. A user-assigned identity
sits under `identity.userAssignedIdentities`, keyed by its resource id, with its
principal inside. A workload running only as one had no "runs as" edge, so every
route through it was missing. Both kinds are read now
(`_workload_identities`), and a user-assigned principal is named after its
resource, "app-id (user-assigned identity)".

**There was no network hop.** Routes only followed identity, role and
containment edges, so an open machine without an identity was a dead end even
when the machine beside it ran as an identity with Contributor. The new
capability edge `NETWORK_ACCESS` ("can reach over the network") runs from an
internet-facing machine to every other machine in the same virtual network
whose network security groups let some traffic through
(`connectors/azure/network.py`). It is deliberately narrow, because a false edge
is a route through an estate that does not have it:

- Machine to machine only. Reaching a storage account or a database over the
  network is not reaching its data, which still takes a key or a role, and the
  role is already an edge. Reaching another machine is a second foothold that
  runs as that machine's identity.
- Same virtual network only. Peering is not collected, so a machine in a peered
  network is not reached rather than guessed at.
- Drawn only from machines with a public address. Every pair in a network would
  be quadratic in its size, and a hop between two internal machines matters only
  after a foothold, which is where these edges start.
- The groups are evaluated with Azure's own defaults beneath them
  (`AllowVnetInBound` and `AllowVnetOutBound` at 65000, deny-all at 65500):
  outbound on every group guarding the source, inbound on every group guarding
  the target. The question is whether _some_ traffic gets through, not whether
  a given port is open. A deny on port 3389 leaves the rest answering. A deny
  covering every port and protocol closes the hop. Address prefixes are matched
  against the machines' private addresses.
- Unknown is no edge. A guarding group the scan did not collect, a machine whose
  interfaces were not resolved, or an all-ports deny naming an application
  security group this reading cannot resolve all produce nothing.

The hop is a capability edge like the others. It is walked by traversal, is
the preferred cut on a route that starts with it (tighten the group between the
two machines), and appears in choke points and in the estate map's reach.

**The empty page misled.** Every directory user is internet-exposed by design,
and every user holding a directory role is sensitive. So a tenant with one
administrator showed both counts above zero, and the page said "CloudGuard found
assets reachable from the internet and assets holding sensitive data" when both
were accounts rather than machines or data. `GET /attack-paths` now also returns
the counts by resource type (`entry_point_types`, `sensitive_target_types`).
When there are ways in, sensitive assets and no route, it adds `dead_ends`,
each way in with the reason it stops (`AssetGraph.dead_ends`):

- `reaches_nothing`: a machine with no identity and no neighbour it can reach,
  or an account with no role over anything scanned.
- `identity_without_role`: it runs as an identity that holds no role.
- `nothing_sensitive`: it reaches N assets, none classified as sensitive.

The list is capped at 25, with machines and apps sorted before people. The page
lists them under "Where each way in stops". Where every sensitive asset is an
account, it adds that storage, databases and vaults need a data classification
tag. A verdict nobody could check becomes a list of statements somebody can
open and disagree with.

**What this does not change.** Sensitivity is still only what tags, names and
type floors declare. An untagged lab storage account is still not a target, and
the page now says so rather than calling the estate clean.

## 120. A link between two assets is removed when the scan that re-read it does not see it

Edges were inserted and never deleted. `_persist_relationships` wrote every
edge a scan saw, `ON CONFLICT DO NOTHING` absorbed the repeats, and nothing
ever took one out — so an NSG unbound from a machine, a role assignment
revoked, a workload's identity removed all left their edge behind as a
permanent fact about an environment that had moved on. The estate map drew it,
`AssetGraph` traversed it, and the attack-paths page went on showing a route
after the customer severed it. §52 already settled what that costs: a stale
path is not a weaker claim than a real one, it is a false one.

**A scan may delete an edge only when it re-read both of its ends.** An edge is
reported by the scope its endpoints sit in — a role assignment over
subscription A is read when A is collected, and collecting B says nothing about
it — so "this scan did not report the edge" is evidence the edge is gone only
where the scan actually covered both ends. A directory user rescanned beside
one subscription therefore keeps every role it holds over the others, whose
scopes are not in this scan's, and loses the assignment it no longer has inside
the scanned one. Scoping the prune to the source alone would have deleted the
first kind: the tenant-wide half of a graph disappearing on a
single-subscription rescan.

**An edge touching an absent asset is left alone.** An asset a scan looked for
and did not find keeps its row (`absent_since`), because a resource that
vanishes for a week and returns is one asset rather than two. Its edges are
kept for the same reason, and the graph already refuses to traverse them.

The prune is one read and one delete per batch of 1000 ids, scoped by a
subquery over the assets this scan covered rather than by the ids themselves —
a tenant with fifty thousand edges is not a parameter list anything should be
asked to carry. It is the only read the edge stage makes: inserts still answer
"is this already stored" inside the statement.

**The graph's cache key grew an edge count.** It was three aggregates: the
newest asset `updated_at`, the newest edge `created_at`, and the count of
present assets. A scan whose only write is a delete moves no timestamp and
changes no asset count, so the first pruning scan would have been invisible to
the cache — the page answering the one change a customer makes _because of_ it
by serving the severed route back. `graph_version` counts edges too.

## 121. A hop names its evidence, and the evidence is read off the assets

`RELATIONSHIP_VERBS` turned an edge into a sentence: "mi-app can act over
sub-prod". True, and unactionable — the one thing a customer would have to
change to make it false is the role, and the sentence did not name it.
CloudGuard collected the role, stored it on the principal, drew a line for it
and then declined to say it.

`PathStep.detail()` says it: "mi-app can act over sub-prod (Contributor)".
Beside `describe()` rather than replacing it, because the plain sentence is
what a risk is titled by, and a title that moved when a second assignment
appeared would read as a different route.

**Derived from the two assets, not carried on the edge.** An edge is
`(source, kind, target)` in the normalizer's payload, in
`resource_relationships`, and in every traversal that walks it. Threading a
fourth element through all of that means a column, a migration, an
`ON CONFLICT` that updates it, and a producer change per provider — to restate
facts already sitting on the assets the edge joins. A principal's roles are on
the principal (`metadata["roles"]`, which the normalizer already writes so a
rule can state "this person holds Owner over your subscription"); a machine's
subnets are on the machine. So `graph/facts.py` reads them back,
which makes the evidence exactly as fresh as the assets are and impossible to
leave stale behind them.

Nothing is guessed. A fact appears when the asset states it and is absent
otherwise, and an unresolved role is already "Unknown role" by the time it
reaches metadata. An escalation hop names only the assignments that escalate:
a principal may hold Reader over the same scope, and printing Reader beside
"can grant itself any role" would put the harmless assignment's name on the
dangerous claim.

## 122. What a link holds up is answered for every link, exactly, in one pass

`choke_points` used to rank candidates by how many routes they sat on, then
verify the leaders by removing each one and re-asking the whole question. The
ranking is sound as far as it goes — containment bounds severance — but each
verification was a full re-traversal over every entry point in the tenant, so
only a handful were affordable, and about every other link the page had nothing
to say at all.

`graph/severance.py` answers for all of them. From one entry point, walk
forward layer by layer to the depth bound, carrying with each node the set of
removable links that appear on _every_ walk of that length to it:

```text
necessary(entry, 0) = {}
necessary(v, d+1)   = intersection over each u with an edge u->v of
                      necessary(u, d) + {that edge, when removable}
necessary(v)        = intersection over every d at which v is reached
```

A link is in `necessary(v)` exactly when no walk to `v` within the bound avoids
it — which is exactly when removing it puts `v` out of reach. The severed set
is read off the targets rather than searched for, and one walk per entry point
answers for the whole graph. The cost is the walk the route list already pays.

**Layers rather than a visited set.** The traversal that enumerates routes
stops at a node it has already seen, because it wants the shortest route to it.
This one must not: a longer way round is the whole reason a link might not be
worth cutting, and stopping at the first arrival would call every link on the
shortest route necessary and promise closures that never happen. Keeping the
layers is affordable for the same reason the routes are short — a set carried
here can never hold more links than the walk has hops.

**One analysis, three readings.** The ranked list, the what-if on a single link
and the number drawn on a line are the same map read three ways, cached on the
graph. They used to be two computations of one thing, and two computations of
one thing eventually disagree in front of a customer.

Two consequences worth stating. A link that closes nothing is never offered,
because every route through it has another way round — and that is a real
answer to "what if I cut this", not an absence. And `on_routes` is never
smaller than `severs` by construction rather than by luck: a link severing a
route is on every walk to that target, including the one drawn.

## 123. The attack-path page draws every route, and says the repeated ones once

Two problems with a ranked list of routes, and they are the same problem.

Forty routes through one identity are forty rows that never say "one identity".
The list ranks by hops, which is the right order for reading a route and the
wrong one for seeing an estate: the shape is in what the routes _share_, and a
list can only show it by repeating it.

And twelve machines in a scale set reaching one storage account through one
identity is one sentence printed twelve times, which buries every other shape
under a repetition of one.

`/attack-paths/graph` answers both in one request. The page draws the route
subgraph — only the assets a route runs through, never the estate — laid out by
`column`, the fewest hops from any way in, so reading left to right is reading
an attacker's progress. Every line carries what cutting it would close (§122)
and is weighted by that number, never by how many routes it merely sits on.
Pressing a line simulates the cut: the routes that would close grey out, from
the same answer the number came from, so the claim and the picture cannot
disagree. Nothing is sent to Azure.

`graph/patterns.py` collapses the repetition, and only where the routes are
_identical_ apart from one end — many ways in to one target, or one way in to
many targets. Similar is not the same: two routes through different identities
are two problems, and folding them because they end alike would hide one. A
route belongs to at most one group, and to the larger one where it could join
either, so the groups and the loose routes partition the list exactly; both
readings are true of a fan that opens at both ends, and a route counted twice
would make the totals add up to more than the estate holds.

**The canvas obeys the laws §101 and §111 already set.** React Flow with
`base.css` only, coloured from the tokens, laid out by hop count rather than a
force simulation, lazy-loaded, nothing draggable, one tab stop with arrow keys
inside. A simulation settles somewhere different on each run, so one estate
would draw a different picture every visit and two people looking at it would
not be looking at the same thing.

**Motion that carries data, and nothing else.** Columns arrive left to right, so
the drawing is read outside-in once; the traced route's hops march in the
direction reach runs; a cut greys out what would go. Each degrades to its final
state immediately under reduced motion, and there is no timer-driven progress
anywhere on the page — the same rule §87 set for the scan view.

`AttackPathRoute` is unchanged and still the answer to "which link do I cut" for
one route: it is what the rail opens into, what a finding shows, and what the
PDF report can draw, which a canvas cannot.

## 124. A delete that takes a risk's findings takes the risk

Deleting a connection cascaded its subscriptions, assets, scans and findings,
and every `risk_findings` link with them. The `risks` rows stayed, because a
risk hangs off the organization rather than an asset and had nothing to
cascade from. The risks list keeps a risk linked to nothing on purpose (its
missing links are not proof it is over), and the dashboard keeps any route
that is not resolved, so both went on showing risks about an estate nobody was
watching any more. Purging a scan's findings (`DELETE /scans/{id}?purge_findings=true`)
did the same.

Both delete paths now read the risks the doomed findings belong to before the
delete, flush the cascade, and delete the ones left with no member
(`risks.linked_to`, `risks.delete_emptied`). Connection delete moved out of the
route into `cloud_connections.delete_connection` to do it.

**Deleted, not resolved.** Nothing was fixed. The estate stopped being watched,
and a resolved row would record a remediation nobody made — the same reason a
superseded group member's risk is deleted rather than resolved.

**A risk with a member left stays.** A route that crosses into another
connection keeps its members there, and the next scan of what remains decides
it: correlation already treats an asset with no row as gone, and closes every
route through it.

Migration 0039 deletes the risks already left behind. Every writer of a risk
links its members in the same commit, so a risk with no link can only be one
of these. It cannot be undone.

The list's rule stands: a risk linked to nothing is still listed. The only
thing that made one was a delete, and that no longer does.

## 125. A role edge reaches only what the role controls, and an asset says who holds it

The graph knew one thing about a role assignment: that it existed. The
normalizer drew `GRANTS_ROLE` from the principal to the scope, the traversal
descended from the scope through `CONTAINS`, and everything underneath counted
as reached. So Reader over a subscription was a route to the payments ledger.
A machine running as Storage Blob Data Reader "reached" every other machine in
its resource group, and from there every identity those machines run as, and
from there whatever _those_ identities held. The role name was on the hop
(§121), but the traversal never read it. The demo showed a route through
Contributor to a Key Vault whose secrets Contributor cannot read.

That is the overclaim this product refuses everywhere else. UNKNOWN is never
PASS, an unknown exposure is never an entry point (§100), and a route that
exists only because CloudGuard ignored what a role permits is the same mistake.
It is also what makes a feature like this get switched off.

**The connector evaluates each role; the graph reads a neutral answer.**
`connectors/azure/access.py` takes a role definition's permission blocks and
says, per neutral `ResourceType`, which `AccessKind`s they amount to: `read`
(configuration), `manage` (changes configuration), `read_data`, `execute`
(runs code as the resource), `edit_policy` (edits the resource's own access
list) and, separately, `grant_access`. Each block's `actions` less
`notActions` and `dataActions` less `notDataActions` are evaluated on their
own, with ARM's wildcard matching, and the blocks are unioned. The role is
never judged by its name. The normalizer writes the answer onto each role entry
in the principal's `roles` metadata (`access`) beside the node the edge was drawn to
(`target`), where it came from if inherited (`inherited_from`), and whether it
carries a condition (`conditional`). The graph reads only that. Nothing
provider-shaped crosses the seam, and an AWS connector evaluating IAM policies
would write the same keys.

Choices worth keeping:

- **Control is `read_data` and `execute`, and `edit_policy` only where the
  resource says its own policy governs it.** A holder who can change a
  machine's size has not run anything on it, so `manage` alone is not reach. A
  Key Vault on access policies is held by anyone who can write those policies.
  One on Azure RBAC is not. The normalizer states which model a vault uses
  (`governed_by_own_policy`) only when the vault said so: an absent flag claims
  nothing.
- **Some management operations are data access by another name, and are
  counted as it.** `listKeys` opens a storage account whatever its data-plane
  roles say. Writing a SQL or PostgreSQL server resets its administrator
  password. Writing a web app sets what it runs, and its publishing profile is a
  deployment. `runCommand`, managed run commands and extensions are code on a
  machine.
- **Every string in `access.py` is matched, never deployed.** Unlike
  `rbac.py`, none of these reaches ARM, so a wrong one cannot fail a customer's
  deployment. It can make CloudGuard claim less than a role allows, so each is
  a documented operation, and the tests hold the built-in roles to what
  Microsoft documents them as doing.

**The walk carries a lens.** A `GRANTS_ROLE` edge is crossed with the union of
what the principal's roles at that target control (`graph/access.py`, `Lens`).
Crossing `CAN_GRANT_ROLES` controls everything, because the holder can grant
itself the rest. The walk still descends through subscriptions and resource
groups, which is where reach lands. An asset under them is _reached_, and
walked on from, only when the lens controls it. An asset the lens does not
control is passed beneath, so a role over a SQL server still reaches the
databases on it without reaching the server. A role edge that controls nothing
is not crossed at all. A walk state is `(node, lens)`, with no lens meaning the
walk holds the node.

That makes the running-code pivot a route. Virtual Machine Contributor over a
group reaches the machines in it, and their identities, and what those
identities hold: the path the demo now draws from the jump box to the payments
vault. It is also why the demo's User Access Administrator reaches data only
through its escalation edge.

**The canvases draw what the walk walks.** The neighbourhood and the estate
map draw a role edge only when its roles control something
(`AssetGraph.conveys`). Otherwise a Reader line would sit on a canvas of reach
and say what the routes no longer do. The role is not lost: the access view
lists it.

**Severance walks the same states.** §122's one-pass analysis intersects the
necessary links per walk state and then per node over the states that count as
reaching it. Without that, a Reader edge beside an Owner edge would read as a way
round the Owner edge, and the what-if would promise nothing closes when
everything does. `severance.py` is generic over the state and names only the
graph's own links, because a lens is a way of standing on a node, not a link
anybody could cut.

**What cannot be established is not claimed.**

- A role whose definition was not read (`access: None`) controls nothing, and
  the access view lists it as unread.
- An ABAC condition is evaluated against request attributes CloudGuard never
  sees, and applies to data actions and to role-assignment writes. An
  assignment carrying one keeps what its control actions grant. It loses
  whatever it had only through data actions, and is not drawn as
  `CAN_GRANT_ROLES`: a condition is how a delegated administrator is confined
  to handing out Reader, and calling that an escalation would be the false
  alarm `_grants_role_assignment` was written to avoid.
- An identity whose roles all control nothing is a new dead end,
  `roles_without_control`. It is distinct from `identity_without_role`: there
  is a role, and it is one change away from mattering.

**A stored scan keeps its routes until it is rescanned.** Metadata written
before this change has no `access` key, and such an entry, or a role edge with
no entry at all, walks with a lens that controls everything, exactly as before.
Otherwise a deploy would silently empty every tenant's attack-path page until
its next scan. The next scan replaces the entry with a verdict, and routes that
existed only through read-only roles close then. The risk correlation resolves
them the ordinary way, because they are no longer observed.

**Assignments above the subscription are drawn.** A subscription's listing
returns assignments made at a management group or the tenant root only when
they apply to it. They were dropped because their scope was no node, so the
estate's most powerful principals were drawn holding nothing. They are now
drawn to the subscription, and the hop says where they came from ("Owner from
management group contoso-root").

**An asset says who holds it.** `GET /attack-paths/access/{id}` and the asset
page's Access tab answer what a route cannot, because a route needs a way in:
every role assigned on the asset or above it, grouped as can take what it
holds, can change its configuration, can read its configuration, and could not
be read, each with the workloads that run as the holder. On an identity's page
the tab leads with every role it holds and counts the assets each one controls.
It reads the same evaluation the routes are walked with, so a holder listed as
able to take the asset is one a route may pass through. The one exception is a
legacy entry, listed as unread while it is still walked.

**Not built, and why.**

- **Group membership.** Built in §126.
- **PIM eligibility and deny assignments.** Eligibility is built in §130.
  Deny assignments are deliberately not read (§130), and not subtracting them
  errs towards claiming reach.
- **Entra escalation.** Built in §128 and §129.

## 126. One identity is one node, and a group's role reaches its members

§125 made a role edge honest about what it controls. It could not make it
honest about _who_ holds it, for two reasons, one of them a bug that had been
in every production scan.

**The bug: a person was two nodes.** A scan normalizes the directory capture
and each subscription capture separately (§108). The directory produced
`/users/<id>`, the account: its MFA, its sign-ins, and a public exposure of
HIGH, because an account is reachable from the internet by design. That makes
it an entry point. The subscription produced a stand-in, `/principals/<id>`,
minted from the role assignment and carrying the roles. The normalizer's
attempt to reuse the directory node only worked when both were in one snapshot,
which only the tests and the demo ever were. So in production the account was
an entry point that reached nothing, and the roles belonged to an identity
nothing could reach. A phished administrator holding Owner was never a route,
and the Access tab named them "User 1a2b3c4d".

The same split hid in plainer form. A principal holding roles in two
subscriptions was minted once per subscription, one asset row each, and
building the graph kept whichever row came last, with only that subscription's
roles on it. §125's lens then found no entry for the other subscription's
edge and walked it as legacy, which means as if it controlled everything.

**The join happens when the graph is built** (`graph/identity.py`), because
that is the only place both readings exist together. Captures stay what they
are: pure, per-scope readings.

- Copies of one node id merge, with their roles combined. The first copy keeps
  its other fields.
- A node the connector minted to stand in for an identity it did not read
  itself is marked `stub`. It is folded into the node that carries the same
  `identity_id` and is not a stub, which is the directory's record. Its roles
  move across, and its edges are redrawn from the directory node. The normalizer now
  writes `identity_id` on directory users, on every stand-in, and on groups.
- The stand-in's id still resolves (`AssetGraph.resolve`). The asset rows keep
  their ids, so findings and risks keep their anchors, and a page opened on a
  stand-in row is answered about the person it stood for.
- Neutral: the join reads `identity_id`, `stub`, `members` and `roles`, and no
  provider id. Rows stored before this change carry no `identity_id` and are
  not joined until their next scan, which is the same stance §125 takes on
  stored roles.

Routes change on the next scan. Every directory account holding a role that
controls something becomes a way in to what it controls. That was always what
the model meant; it now draws it. `patterns.py` already says a repeated route
once (§123), so a hundred analysts reading one account collapse into one line
with a count, not a hundred.

**Groups.** A role assigned to a group was a principal named "Group 1a2b3c4d"
that reached nobody. Now:

- **Collected per subscription, for the groups that hold a role there**
  (`role_group_members`). The subscription's role assignments are what say
  which groups matter. Reading every group once per tenant would be a directory
  dump to answer a question about a handful of them. Names come fifteen to a
  call through Graph's `in` filter. Members come from `transitiveMembers`, so
  someone two nested groups down is listed directly. Both run under
  `Group.Read.All`, which every tenant has already consented to. There is no
  new permission, no role version bump and no redeploy. The read is bounded at
  `ROLE_GROUP_LIMIT` groups per subscription. A group whose members could not
  be read is absent from the payload and the task reports partial. It is never
  an empty list, because "this role reaches nobody" is the one wrong answer.
- **A new type, `GROUP`.** The node id is unchanged (`/principals/<id>`), so
  the asset rows keep their findings. The role-assignment rules now apply to
  groups too, because a group was a service principal of unknown kind until it
  had a type.
- **Members are recorded on the group, and the edge is derived.** A member is
  usually a directory account read in another capture, so the `MEMBER_OF` edge
  from it can only exist once both are in one graph. It is drawn at build time
  from the group's `members` and never stored, following §121's rule that
  evidence is read off the nodes. `MEMBER_OF` is a capability edge and is
  removable: taking a person out of a group is a fix, and severance counts it.
  Nested groups are recorded and not walked, since the listing is already
  transitive. A member no node holds, such as a guest the directory reading did
  not include, is listed by name and cannot be walked through.

**The access view names the people.** A group holding access lists its
members: the accounts CloudGuard read, linked to them, then the names it read
only as names, capped at `ACCESS_MEMBERS_LIMIT` and counted in full. A group
whose membership was not read says so. A person's own page lists the roles
they hold through each group, with the group named ("through Data analysts").

The demo recording gains a group, Data analysts, holding Storage Blob Data
Reader over the data resource group, with Normal User and a guest contractor
as members. Normal User was a dead end and is now a route to the customer
records, through a group edge the what-if can cut.

## 127. Removing an Owner assignment is one cut, and the queue is in the order it says

Two bugs, and a decision about where "route-aware" belongs.

**An Owner assignment was never a choke point.** A principal that can write
role assignments is drawn twice between itself and the scope: `GRANTS_ROLE`
for what its roles do there, and `CAN_GRANT_ROLES` beside it for the ceiling
(§19). Severance treated them as two removable links, so each was the other's
way round. `GRANTS_ROLE` never severed anything. `CAN_GRANT_ROLES` severed
only what the grant line alone reached. Removing the Owner assignment, the fix
a customer most often makes, closed nothing on the ranked list, and the choke
points offered "detach the identity" instead. The two lines are one fact: the
same role assignments, which removing them takes away together.

`AssetGraph.removal_key` names what removing a link removes. That is the link
itself, except for an escalation line drawn beside a role line, which is keyed
as the role line. The walk hands severance that key, so a choke point, the
what-if on either line, the number drawn on each line of the route map and the
routes each line sits on all speak of the assignment. The two oracle tests
that rebuild the estate without a link now remove everything the removal key
covers. They failed first, which is how the bug showed itself. Drawn edges keep
their own keys, so the canvases and the route highlighting do not move.

**The remediation queue was not in the order it claimed.** The page said
"ordered by impact against effort". The API returned tasks newest first, and
the page never sorted them. `GET /remediation` now orders on the server:

1. Open work (to do, in progress) first, then done, then cancelled.
2. Priority, which is already impact against effort (RISK_ENGINE.md §4).
3. How many attack paths run through the finding's asset, wherever on them it
   sits (`on_routes`, on each row).
4. The finding's risk score, then the newest first.

**Routes break ties; they do not change a score.** The open item from §125
proposed raising a finding's score when its asset sits on a route. That would
count the route twice. The risks queue already ranks a route above its parts,
because a scenario's floor is its worst member plus an amplifier (§100), and
§103 rejected listing a route beside its hops for the same reason. What was
missing was in the work queue, where two equally urgent fixes are chosen
between. There the one on a route should come first. The row says "on 3 attack
paths", which is a fact about the asset. It does not say "closes 3", which
would be a promise about the fix that only a link can keep. The link-level
question stays with the choke points, now correct for role assignments.

## 128. The directory's say over the estate is drawn as reach

The graph drew Azure role assignments and nothing the directory decides. Two
of the directory's powers are the shortest routes an attacker has, and neither
was an edge.

**A Global Administrator can make themselves owner of every subscription.**
Entra lets a Global Administrator elevate to User Access Administrator at the
tenant root, which covers every subscription below it. A Privileged Role
Administrator can make themselves Global Administrator. A Privileged
Authentication Administrator can reset a Global Administrator's credentials.
None of the three holds an Azure role, so the graph showed the most powerful
accounts in the tenant as reaching nothing. The directory reading already had
the membership: `user_role_map` lists every directory role's members, for the
MFA rule.

**An application's owner, or its own credential, signs in as its service
principal.** An owner can add a client secret to a registration and
authenticate as the principal, holding every Azure role that principal holds.
An Application Administrator or Cloud Application Administrator can do that
to every registration. A registration holding a credential is itself a way in:
its public exposure was already HIGH, for the reason a directory account's is,
and now it leads somewhere.

**Collection.** One new directory task, `application_owners`. It reads each
registration's owners, one call each, bounded at `APPLICATION_OWNER_LIMIT`. It
also reads the service principal each registration signs in as, fifteen app ids
to a call through Graph's `in` filter. Role assignments name a principal by
object id and a registration knows only its app id, so this is the join. Both
run under `Application.Read.All`, already consented. There is no new permission
and no redeploy. A registration whose owners could not be read has
`controllers: None`, never an empty list, and the task reports partial.

**Normalization, in neutral terms.** An account's directory roles become
`directory_powers`, each naming the role it comes from:
`control_all_scopes` for the three roles above, and `act_as_any_application`
for the two application roles. Roles are matched by name, as `_mfa_policies`
matches them, rather than by template ids recalled from memory. A registration
records `acts_as`, the principal's object id; `controllers`, its owners; and
`can_sign_in`, whether it holds a credential.

**Edges, derived when the graph is built** (`graph/identity.py`), as §126 did
for group membership, because the principal is minted in a subscription
capture and the owner and the registration are read in the directory's.

- `CAN_ACT_AS` runs from each owner, from the registration itself when it holds
  a credential, and from every holder of `act_as_any_application`, to the
  principal. It is drawn only to a principal the graph holds. One holding no
  Azure role never reached a subscription's graph, and signing in as it
  reaches nothing here.
- `CAN_TAKE_OVER` runs from every holder of `control_all_scopes` to every
  subscription. It is walked with a lens that controls everything, as
  `CAN_GRANT_ROLES` is.
- `CAN_TAKE_OVER` is its own relationship rather than a derived
  `CAN_GRANT_ROLES`, because of §127. `removal_key` folds an escalation line into
  the role line beside it, since both are one Azure assignment. A Global
  Administrator who also holds Owner would then have had their directory role
  folded into their Azure assignment, and the what-if would have promised that
  removing Owner closes routes the directory role keeps open. They are two
  fixes, done in two places, and severance now keys them apart.
- Both are capability edges and both are removable: removing an owner,
  revoking a directory role, or deleting a credential is a fix.
- A hop names what somebody removes: the directory role, "owner of its
  application registration", or "its own credentials".

**An escalation over a scope already held is a loop.** A Global Administrator
who takes the subscription can walk down to a machine whose identity may grant
roles over that same subscription. That chain gains nothing, and raised as an
escalation risk it doubled the real one. `escalation_chains` now drops a chain
whose route already crossed a line that controls everything (`CAN_GRANT_ROLES`
or `CAN_TAKE_OVER`) onto the scope or a container of it. A route that reached
the scope through a narrower role, such as Virtual Machine Contributor, keeps
its chain: there the escalation is real.

`AssetGraph.build(..., derive=False)` takes edges exactly as given. A test
that rebuilds an estate from another graph's `links()` to check a severance
claim must not re-derive the link it just removed. That is how the oracle
tests first failed.

**The access view.** An asset's holders now include the directory roles that
can take its subscription, marked `through_directory`, and on a service
principal, whoever can sign in as it (`act_as`). An account's grants include
each subscription its directory role can take over, with the assets under it
counted, and the roles of every principal it can sign in as ("by signing in
as ...").

**What changes on the next scan.** Every Global Administrator is a way in to
every sensitive asset. That is what the role means, and it now sits where the
choke points put it, at the top. The demo's administrator, Arben K, is now its
largest choke point. The recorded environment test now expects two ways in.

**Not built.** Service principals and groups holding directory roles get no
power, because the directory capture has no node to put it on; only users do.
Service principal owners are not read, only application owners. Graph
application permissions, which let a principal grant itself a directory role,
are not drawn. PIM-eligible directory roles are not read, because
`directoryRoles/{id}/members` lists active members only.

## 129. A Graph permission that is a directory role by another name is drawn as one

§128 drew the directory's powers for users and left a gap. A service principal
or a managed identity holding a Global Administrator role, or granted a
Microsoft Graph application permission that is one step from it, reached
nothing. These are the principals attackers look for first, because their
credentials sit in pipelines and on machines rather than behind MFA.

**Which permissions.** Three, each matched on its own value:

- `RoleManagement.ReadWrite.Directory` writes directory role assignments, so
  it can make itself Global Administrator. That is `control_all_scopes`.
- `AppRoleAssignment.ReadWrite.All` grants app roles, so it can grant itself
  the permission above. Also `control_all_scopes`.
- `Application.ReadWrite.All` adds credentials to any application. That is
  `act_as_any_application`.

The power's `via` names the permission ("Graph permission
RoleManagement.ReadWrite.Directory"), which is what somebody revokes.

**Reading them.** One directory task, `graph_permission_grants`, under
`Application.Read.All`:

- Graph's own catalogue, the `appRoles` on Microsoft Graph's service principal
  in the tenant, turns an app role id into a permission name. No id is written
  down here, for the reason `auth.py` gives about identifiers recalled from
  memory. If Graph's principal is not found, the task reports partial rather
  than an empty tenant.
- Every grant is read from Graph's side (`appRoleAssignedTo`). One paged
  listing covers every service principal and managed identity, instead of a
  call per principal.

The directory role reading also records each member's kind
(`directory_role_member_types`), so a group holding a directory role is typed
as one.

**A node for them.** The directory capture produced a node for users only, so
a principal's powers had nowhere to go. It now writes a record,
`/principals/<id>`, for each non-user principal that holds a power, and only
those; a record for every service principal would be a directory dump. That
id is the one a subscription mints for the same principal from its role
assignments or a workload's identity, so the graph merges the two when it is
built. The merge now:

- keeps the directory record's fields over a stand-in's, whichever copy arrives
  first;
- combines roles and powers;
- keeps any key only one copy has;
- takes a name a reading gave over one made up from an id (`unnamed`);
- leaves the principal's kind to the stand-in, except for a group. Graph calls
  a managed identity a service principal, and the stand-in knows it is managed.

**What this draws.** A machine running as a managed identity granted
`RoleManagement.ReadWrite.Directory` now has a route that crosses no Azure
role: it runs as the identity, which can take ownership of every subscription.
It is keyed as `CAN_TAKE_OVER` (§128), so the fix it names, revoking the
permission, is never folded into an Azure assignment.

**Known wrinkle, unchanged.** The role-assignment rules judge a directory
record the way they already judge a directory user: it carries no Azure roles,
so they answer UNKNOWN on it and judge the subscription's copy. That was true
for every user before this change.

## 130. A role that could be activated is listed, and is not a route

Privileged Identity Management turns standing access into access on request.
CloudGuard read only the roles a principal holds. An eligible Owner, the
access pattern every PIM rollout aims for, was invisible. The Access tab said
nobody could take the ledger when three people could activate Owner over it,
and a tenant that had moved its Global Administrators to PIM looked the same
as one that had removed them.

**Collected in both places, and the role goes to v8.**

- Azure eligibility is read per subscription from
  `roleEligibilityScheduleInstances` (api-version `2020-10-01`), under one new
  action, `Microsoft.Authorization/roleEligibilityScheduleInstances/read`. It
  was verified on 2026-09-22 against the published operations reference, as
  `rbac.py` requires. Instances, not schedules: an instance is an eligibility
  in force now. Only `Provisioned` instances count.
- Directory eligibility is read from Graph's
  `roleManagement/directory/roleEligibilityScheduleInstances`, with the role
  definition and principal expanded. It runs under `RoleManagement.Read.Directory`,
  already consented. It needs Entra ID P2, so it goes through the licence-aware
  call and has its own evidence key: a tenant without P2 loses only this
  reading. Only eligibilities scoped to the whole directory (`/`) count. One
  scoped to an administrative unit governs that unit, not the tenant.
- Bumping to v8 prompts every connection for a redeploy. It costs a v7
  connection nothing it had. `degraded_categories` names Authorization, and
  the only key behind it is the new one, so every assignment, route and verdict
  stays. The rules degrade per evidence key, never per category.

**Recorded apart from the roles held.** An eligible Azure role goes into
`eligible_roles`, not `roles`. The role-assignment rules read `roles`, and PIM
is the fix they recommend: counting an eligible Owner as "a person holds full
control" would fault the customer for following the advice. An eligible
directory role becomes `eligible_directory_powers`, in the same neutral terms
as §128. A non-user principal with one gets a directory record, as in §129.
Merging an identity's copies combines these lists as it combines roles. The
merge and the stand-in fold now share one step (`_absorb`), because the fold
was carrying roles across and dropping everything else. The eligibility tests
caught that.

**Listed, never walked.** `ELIGIBLE_FOR` is not a capability edge. Activating
can require MFA, a justification or an approver's decision, none of which
CloudGuard reads. Walking an eligibility would claim standing reach that does
not exist, the overclaim §125 removed from Reader. The access view lists
eligible holders in their own group, "Eligible to activate", with what
activating would give (`kinds`) and `controls` false. An identity's page lists
the roles it could activate. An eligible role never widens the lens of the
role held beside it.

**Deny assignments: deliberately not read.** In practice they come only from
managed applications, Azure Blueprints and deployment stacks. A customer
cannot write one directly. Subtracting them would take per-resource deny sets
inside the lens, evaluated at arrival, for a case most tenants never have. Not
subtracting them errs towards claiming reach. The claim is still true of every
principal a deny assignment excludes, and a managed application's own
resource group is where one would sit. Revisit if a customer's estate shows a
route through a resource group a deny assignment locks.

## 131. `alembic_version` is closed to the API roles

Supabase's advisor flagged `public.alembic_version` as the one table in
`public` without row-level security. It was worse than unguarded. Alembic
creates the table before the first migration runs, so migration 0001's
`GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO
authenticated` included it, and Supabase's default privileges give every new
`public` table to `anon` too. PostgREST serves `public`, so anyone holding the
publishable key the web bundle ships could read the schema revision, and any
signed-in user could rewrite it. That value decides what the next
`alembic upgrade head` runs on deploy.

Migration 0040 enables RLS on it with no policy, which denies every row to
every role that does not own the table, and revokes `anon`'s and
`authenticated`'s privileges. Migrations connect as the owner, and RLS does
not constrain the owner unless forced, so Alembic keeps working. Nothing in
the API reads the table.

Moving it out of `public` (`version_table_schema`) would also hide it from
PostgREST, but an existing database would then look unmigrated and re-run
everything from 0001. Closing it in place changes nothing about how Alembic
finds it.

`test_rls.py` now fails if any table in `public` lacks RLS, so a table created
without a policy block is caught in CI rather than by the advisor.

## 132. An attack path is walked on the estate map, one hop at a time

The estate map's list under the canvas said "32 attack paths through here" and
then listed links: arrows between two boxes, each a toggle that lit its own
two ends. Nobody could follow a route from where it starts to what it reaches.
Picking a link also left the canvas where it was, and reach that ran back
against the columns was drawn as a curve across every box in between, with
labels over the boxes beside it.

**The estate sends its routes.** `GET /attack-paths/estate` now carries the
routes `routes_total` counts, shortest first, capped at `ESTATE_MAX_ROUTES`
(100). Each is the attack-path page's own shape (`serialize_path` plus `key`
and `pattern`) with one field added: `boxes`, the box each node of the route is
drawn in under this lens, running entry first so that step `i` goes from
`boxes[i]` to `boxes[i + 1]`. A node whose box this lens does not draw is
`null`. A route that runs out to a neighbour of a neighbour passes somewhere
the map does not show, and the page says so rather than lighting a box that is
not there. Repeats are grouped by the same `route_patterns` the attack-path
page uses (§123), and that serialization moved into `serialize_patterns` so
both endpoints say one pattern in one sentence.

**Routes first, links second.** (§133 folded these tabs, with the contents
list, into one panel beside the canvas.) The panel beside the contents list is two
tabs: **Attack paths**, the default whenever there are any, and **Links**,
which is the old list unchanged. The route rows are the attack-path page's
rows, moved to `components/graph/RouteRows.tsx` rather than copied.

**Picking a route walks it.** The canvas frames the route's boxes. Each box
gets a badge giving where the route visits it ("1", "3–5" for a route that
runs down through one subscription), the route's arrows are drawn at full
strength, and everything else fades. A step bar across the top of the frame, above the
canvas rather than over it so it never hides the route's first row, reads one
hop at a time: "Hop 2 of 4", the hop's own sentence with the role
named (§121), and the scissors on the hop the route's `cheapest_break` names.
The previous and next buttons, the arrow keys and a row of pressable hop
segments all move along the route. The hop being read is ringed on both of its
boxes, its arrow moves (except under reduced motion), and it alone shows its
full label. The route's other arrows keep their short one. Stepping leaves the
view where it is when the hop is already in frame, and pans at the same zoom
when it is not. The route is framed two frames after it is picked, because
the step bar arriving shrinks the canvas and React Flow learns the new size
from a resize observer. A hop inside one
box, or out of the lens, is still counted and is said in words. Escape puts the
route down. From the bar, the graph around the entry opens with the route
traced (`OpenInGraph`), which was already the way from a route to its
neighbourhood.

**Backward reach goes round the boxes.** An arrow into a box in the same column
or an earlier one leaves its source's right side into the gap between
columns, drops to a lane below every box, runs along it, and climbs the gap
before its target to enter from the left like every other arrow. The gaps and
the lane hold no boxes, so no arrow crosses one. Before, the arrow curved back
across the canvas. A first version ran from under one box to under the other,
and the harness showed it running straight down through whatever was stacked
below in the same column. Each backward arrow has its own lane and gutter
offset, so two never share a line. An invisible node below the last lane is
what fitting the view, including the zoom buttons' fit, frames down to. The
column gap widened from 380 to 440 to leave room for labels and gutters.

A map where many boxes hold a way in, as the demo's subscription does, still
draws most of its arrows backward: §111 puts every entry-holding box in the
first column, so reach between them runs within it. Those arrows are legible
now, but a layering that breaks cycles and places boxes by longest path
would draw fewer of them. It would change §111's promise that a way in is
always in the first column, so it is left as a decision rather than made
here. (§134 made it.)

**Short labels on the canvas.** An arrow carrying several kinds of reach reads
as the commonest and a count ("can act over ×3 +2 more"). A picked link or a
walked route shows the full label, and the Links tab always does.

**Not built.** Putting the walked route in the URL was left out. The picked
link was never in the URL either, and a route is placed on one lens's boxes, so
a shared link would need both. (§133 put it in the URL: a route's key names it
in every lens, and each lens places it on its own boxes.)

## 133. The estate map is one frame, a click selects, and it owns walking a route

After §132 the estate map was a canvas with three cards under it: the contents
list, and the attack paths and links in tabs. Reading a route meant choosing it
below the fold and finding it above. A press on a box opened it at once, so the
canvas could not be asked "what runs through here" -- every question went
through a list somewhere else. And the attack-path page traced routes as well,
so two places each half-answered one question.

**One frame.** The canvas and a panel beside it are the whole view, as tall as
the window allows (`max(34rem, 100dvh − 15rem)` from `lg` up). Below `lg` the
panel stacks under the canvas. With nothing selected, the panel is three tabs:
**Paths** (the default whenever there are any), **Contents** (the list §112
made of the hierarchy) and **Links** (the arrows as sentences). These are the
map's text forms, and they are how the keyboard reaches an arrow, since arrows
are not tab stops. The cards under the canvas are gone.

**A click selects; opening is a second act.** Pressing a box selects it:
`aria-pressed`, a ring, the box, its neighbours and the arrows between them
kept, the rest faded. The panel then says what the box is, with the same marks
it carries, gives an "Open" button, and lists the attack paths that run
through it, each walkable from there. Pressing an arrow does the same for the
arrow: its two ends, everything it carries, and the routes that run along it.
A press on empty canvas clears the selection. Opening is a double click, Enter
on the focused box, or the panel's button. A subscription or group redraws the
map, an asset opens its page, and the fold lists what is in it. A row in the
Contents or Links tab selects too, and brings its box or arrow into view. This
reverses §111's "pressing a box opens it" and §112's "a row opens it". A single
press that navigated left nothing to select with, and selecting is what makes
the canvas answer questions. Only a selected arrow shows its full label. Around
a selected box the arrows keep their short labels, because a hub touches most
of the map and full labels would cover the boxes beside them.

**Attack paths only, on by default.** A switch at the canvas's top left draws
only the boxes a route passes through and the arrows a route runs along, and
counts the rest as hidden. Whatever is selected is always drawn, so a box
picked from Contents can be found. Contents marks a row "not on an attack path"
when the switch is hiding its box. Turning the switch remounts the canvas, so
the smaller picture is laid out afresh rather than keeping the holes. It is off
by necessity when the lens has no routes.

**The walk is in the URL, and follows the route down.** `walk` (the route's
key) and `hop` sit beside the lens parameters. Stepping replaces the history
entry, and opening a box pushes one, as before. Opening a box keeps the walk,
so a route that runs into the box opened is still being walked there, placed
on that lens's boxes. That is what the step bar's **Follow into …** button
does: it appears when the hop lands in a subscription or group that has
assets, and opens it at the same hop. A route therefore reads from the
subscriptions down to the assets it runs through without being picked again.
The button offers only where the hop lands. Offering where it came from read
as a step backwards.

**Linked routes are always found.** `GET /attack-paths/estate` takes
`route=<entry|target>` and traces that route even past `ESTATE_MAX_ROUTES`.
The map sends the walked route on every read. The key is not part of the
query's cache key: a route picked from the list is already in the payload, and
a linked one needs the parameter only on its first read of a lens.

**The estate map owns walking a route.** The attack-path page keeps what only
it does: the choke points, the cut simulated across every route, and the rail
that ranks routes. Its traced-route card gains **Walk it on the estate map**,
a link to `/assets?view=graph&walk=…`. Hop-by-hop reading lives in one place.

**Checked in a browser.** This was built against the harness §132 used: the
real map, with payloads computed by the real estate code from the demo
recording. That harness found that selection panning inside a canvas with no
size produced `NaN`, because d3's zoom interpolation divides by the width. The
view no longer moves while the canvas has no size.

**Not built.** Search inside the canvas (`/`) was left out, because it matters
only past about 40 boxes, which a lens caps at anyway. A minimap was left out
because panning is not the problem. Expanding a box in place was left out
because it breaks the lens being the list's scope filter.

## 134. The estate map is layered by longest reach, and every canvas selects the same way

**Few arrows run back.** §111 placed every box at its shortest distance from
where reach starts, and counted every box holding a way in as a start. On a
tenant where many boxes hold a way in -- the demo's subscription is one -- they
all stood in the first column, reach between them ran within it, and §132 had
to route most of the map's arrows backwards round the boxes. `layoutEstate` is
now a layered drawing in four steps:

1. The wired boxes are put in one order that as few arrows as possible run
   against (Eades, Lin and Smyth's greedy ordering): boxes that reach nothing
   off the end, boxes nothing reaches off the front, and otherwise the box
   whose arrows most run out. An arrow against the order is the one drawn back,
   so an arrow runs back only where reach loops. Where a loop has to be entered
   somewhere, a box holding a way in goes first, because an attacker starts
   there, and the arrow drawn back is the one into it.
2. Each box sits one column past the furthest box that reaches it, the arrows
   drawn back counted reversed. Every other arrow runs strictly rightwards.
3. An arrow crossing more than one gap gets a slot in each column between, a
   row kept empty for it, and passes straight across the slot rather than over
   the boxes stacked there. `layoutEstate` returns those slots as `bends`, and
   `EstateCanvas` draws such an arrow as a `long` edge: the same curve a
   one-gap arrow draws in each gap, joined by a straight run through each slot,
   with its label in the first gap as a one-gap arrow's would be. A slot at the
   top or bottom of its column is an empty node too, so fitting the view keeps
   it in the frame.
4. Sweeping right and left, each column is ordered by the average place of what
   it joins in the column beside, and the order with the fewest crossings is
   kept. Before, one rightward pass ordered each column by average height.

This gives up §111's promise that a way in is always in the first column. A
box nothing reaches is still there, so reach still reads from where it starts.
A box holding a way in that another box reaches now sits after that box, and
its globe says it is a way in, wherever it is. On the demo's subscription
rg-build and rg-prod lead into the directory, rg-payments -- which holds a way
in too -- sits where reach arrives at it, and two arrows run back where reach
loops, where before most arrows did. The layering is
wider: a chain of five boxes takes five columns, which shortest distance could
fold into fewer by drawing the arrows back. The legend says how columns are
read.

**A click selects on every canvas.** §133 made a press on the estate map
select, and the panel beside it answer, with opening a second act. The
neighbourhood on an asset's page still re-centred on a press (§101), and the
attack-path page's route map picked a box without showing which. So:

- **The neighbourhood** is one frame of canvas and panel, as the map is. A
  press on a box or an arrow selects it: `aria-pressed`, a ring, the box with
  its neighbours and the arrows between them kept, the rest faded. The panel
  says what an asset is -- its type, and its exposure, sensitive data and open
  findings in words -- with **Centre the graph here** and **Open its page**,
  and lists the routes here that run through it, each traceable. A fold says
  what it counts, by type, with **Show them**. An arrow says its hop. With
  nothing selected, the panel is the list of attack paths through the centre
  that sat under the canvas; the traced route's line and the what-if cut stay
  under the frame, where they have the width. A double click or Enter
  re-centres on a box, opens the centre's page when it is not the page's own
  asset, or draws a fold's members. The centre is a button like every other
  box rather than a link, so a press on it selects too.
- **The route map** rings the box picked and fades what it does not touch
  while no route is traced and no cut simulated, and a press on the empty
  canvas puts the box down. A press on a line still asks what cutting it
  would do: that is the question this map is for.
- What a selection keeps is one function, `kept` in `flowChrome.ts`, which all
  three canvases call, as they share the tokens and the keys.

**Pointing previews.** With nothing selected or walked, the box or arrow under
the pointer, or the box the keyboard is on, fades the rest as a selection
would, without selecting it. A hovered arrow shows its full label. It is off
while something is selected, because the panel answers for the selection and a
canvas redrawn under the pointer would contradict it, and off while a route is
traced or a cut simulated, which draw their own fading.

**Checked in a browser.** Against the §133 harness, rebuilt: the real
components, fed estate and neighbourhood payloads computed by the real
serializers from the demo recording, plus a made-up estate of twelve
subscriptions with two loops and several long arrows. Light, dark, and phone
width. That turned up an existing fault that is not fixed here: a `Link`
carrying `buttonVariants({ variant: "outline" })` has no visible border,
because `border-transparent` from the base classes wins over `border-border`
in the generated CSS and `buttonVariants` does not merge them. `Button` is
unaffected. It shows on every outline link, the neighbourhood's "Open its
page" among them. (§135 fixed it.)

**Not built.** A preview while something is selected, for the reason above.
Edge bundling, which grouping repeated arrows would need. Compacting the
columns a long chain makes, which would put arrows back.

## 135. `buttonVariants` merges its classes

§31 made a navigation styled as a button a `Link` carrying
`buttonVariants({ variant, size })`. cva concatenates; it does not resolve
conflicts. The base classes carry `border border-transparent` and the outline
variant adds `border-border`, two border colours on one element, and whichever
Tailwind emits later wins. That is `border-transparent`, so an outline link
given the classes bare drew no border -- "Scan history" after a scan, "Run a
scan" on an empty Assets page, the way back to the risk list, and the
neighbourhood's "Open its page" -- while the `Button` beside it did, because
`Button` already ran the classes through `cn` (`tailwind-merge`). The links
that happened to wrap them in `cn` themselves, such as "Connect Azure" and the
setup steps' way back, were already right.

`buttonVariants` is now `cn` over the cva function, so a link and a button
given the same variant get the same classes, and a class passed in replaces
the variant's rather than competing with it. The cva function itself is
`buttonStyles`, kept for `VariantProps`. This edits a vendored primitive, which
§24 allows: the fix is two lines, and re-running the shadcn CLI over it would
need them again, so the comment in `button.tsx` says why.

`ui.test.tsx` pins it: an outline variant carries `border-border` and not
`border-transparent`, a ghost one keeps its transparent border, and a class
passed in wins.

## 136. Every graph has a legend

The estate map had a legend (§133): each mark once with its word, and how to
read the map behind a question mark, because a paragraph under the canvas is
the one place a legend is not read. The neighbourhood still had that
paragraph, and the attack-path page's route map had one sentence of help under
it and no key to its marks at all -- a line's thickness, the dashed green cut,
the greyed boxes a cut would close.

`GraphLegend` (`components/graph/GraphLegend.tsx`) is the estate map's legend
made shared, and `MARKS` holds each mark drawn as the canvases draw it. The
glyphs come from `lib/icons` (§86); the line marks -- a thin and a thick line
for weight, a dashed line in `text-ok` for a cut -- are hand-drawn SVG, as a
one-off visual is. One glyph therefore means one thing on all three graphs.

- **Estate map**: unchanged in what it says; now built from the shared parts.
- **Neighbourhood**: beside the depth buttons -- reachable from the internet,
  exposure unknown, sensitive data, open findings, on an attack path, and
  "counted, not drawn" only when a fold is drawn. How to read it moved into
  the question mark. What stays under the canvas is what this drawing admits
  about itself: the fold's cap and the node cap, which are facts about this
  picture rather than how to read pictures.
- **Route map**: above the drawing -- reachable from the internet, sensitive
  data, open findings, and "thicker: closes more routes if cut"; while a cut is
  being tried, also the dashed cut and "out of reach after the cut". Its help
  sentence moved into the question mark; "drawing N of M routes" stays visible,
  as a cap is. Its words are in `i18n/en.ts` with the rest of the page's.

A legend entry appears only while its mark can: the fold's only with a fold,
the cut's only during a cut. A key to marks that are not drawn is a list of
things to look for and not find.

**Checked in a browser**, light and dark, every mark in one legend on a scratch
page. The dashed box first drew as a dashed circle at that size and the greyed
box nearly vanished; both are now squarer, and the greyed one is filled from
the muted foreground rather than faded. Tests read the words, not the pixels.

## 137. The attack-path page's drawing and its routes are one frame

The estate map (§133) and the neighbourhood (§134) are each one frame: the
canvas, and a panel on its side that answers for it. The attack-path page was
still two columns of cards -- the drawing in one, and beside it a stack of
cards for the repeated routes, the other routes and, once a route was traced,
the route itself at the foot of that stack, often below the fold and out of
sight of the drawing it was tracing.

Now it has the same shape. Above the frame, the title and the legend (§136).
In it, the canvas, and a panel on its right -- below it on a narrow screen --
that lists the repeated routes and then the rest, scrolling on its own. Tracing
a route turns the panel into that route read hop by hop, with a button back to
the list, as selecting a box does on the map. Pressing a box narrows the list to
the routes through it, and the panel says whose routes they are with a button
to show every route again. While a cut is being tried, a strip across the top
of the frame says that nothing in Azure has changed, where the drawing it
qualifies is.

The changes that close the most stay above the frame as their own card: they
are what to do about everything in it, and "Simulate the cut" acts on the
drawing from there.

**Not checked in a browser.** Checked by tests, which read the panel's words
and find them beside the drawing, not the layout.

## 138. The estate map explores connections; attack paths are read on their own page

Supersedes the walking half of §132 and "the estate map owns walking a route"
in §133.

The estate map had become two tools in one frame. It drew how the estate is
wired -- which subscription's identities reach which other, where the
directory's principals land -- and it also listed every attack path, walked
one hop at a time with the boxes numbered, and by default ("Attack paths
only") drew nothing a route did not run through. The attack-path page, which
ranks the routes, weighs the cuts and draws every route, then sent its reader
to the map to walk one (§133, §137). A route was read in two places, and the
map's default picture answered the page's question instead of its own.

Now each answers one question.

- **The estate map is for connections.** No paths tab, no walk, no step bar,
  no "Attack paths only" switch, no numbered boxes, no darker arrows on a
  route and no route count on a box. The panel lists the contents and the
  links. A selected box lists what reaches it and what it reaches on this map,
  each row selecting that arrow, and a selected arrow offers its two ends. A
  quiet box is drawn like any other: this is a map of the estate, not of its
  routes.
- **It links to the routes, once.** Where attack paths run through a selected
  box, one line -- "On 3 attack paths -- see them" -- opens the attack-path
  page narrowed to it: an asset by `through=<provider id>`, a subscription by
  `scope=`, a group by `scope=` and `group=` (an empty group is what sits
  directly in the subscription). The fold has no one place and no link.
- **The attack-path page walks a route.** Tracing one puts the step bar across
  the top of the drawing, as it was on the map: previous and next, the hop's
  own sentence with the role named (§121), whether cutting it severs the
  route, pips for every hop, arrow keys to step and Escape to stop. The drawing
  marks the hop in the primary colour with its two boxes ringed, frames the
  route when it is traced, and pans only when the hop is out of view.
- **Where each hop lands.** Each node on the route map now carries its
  placement (`scope_id`, `scope_name`, `group`), read by `load_placements` as
  the map reads it. The step bar says which subscription and group the hop
  lands in, and the traced route's panel lists every place the route runs
  through in order; each is a link to the estate map opened there. That is how
  a route is followed down into a group now: by going to the map to see its
  wiring, rather than by the map drawing the route.
- **The page's state is in the URL.** `trace`, `hop`, `through`, `scope` and
  `group`, so the map's link and any other opens on them. Each change replaces
  the entry, as a step along a route did on the map. A simulated cut stays out
  of the URL: it is a question asked, not a place.
- **Old links still land.** `/assets?view=graph&walk=<key>&hop=<n>` redirects
  to `/attack-paths?trace=<key>&hop=<n>`.

**The API.** `GET /attack-paths/estate` sends no routes, patterns or `loose`
any more, and takes no `route`; its edges lose `on_route`. A box still counts
the routes through it (`routes`), which is the number its link carries, and
the routes still decide which containment is drawn and which assets are drawn
before the fold -- what a route runs through is still worth drawing, it is
just not drawn as a route. `GET /attack-paths/graph` gains the placement on
each node.

The count on the map's link is the server's, over every route; the page it
opens narrows the routes it has drawn, which past the drawing's cap can be
fewer. The panel says how many it shows.

The neighbourhood on an asset's page still lists and traces the routes
through its asset. Whether it should also only link to them is left for now.

**Not checked in a browser.** The page and the map were checked by tests,
which read the step bar, the panel and the links, not the layout.

## 139. The dashboard opens a risk's graph directly, and loads it on the way

The ask was a card on the dashboard that expands smoothly into the node-link
graph. Before any animation, the path from the dashboard to a graph was slow
and indirect, and a transition played over that wait would have made it look
worse, not better. Opening a route meant a round trip to
`/assets/resolve` (the risk knew its assets by provider id, the page is
addressed by row id), then the page's chunk, then React Flow's chunk, then the
graph itself, each one waiting for the last. The dashboard's risk rows went
only to the risk, and the shortest-path panel only to the unfiltered list.
This entry fixes that path. The transition is a separate decision, left until
this is measured.

- **A risk says where its graph is.** Each `top_risks` row gains `asset_id`,
  the asset a finding risk is about when it is about exactly one, and `route`,
  the `entry_id` and `target_id` a scenario's route is keyed by on the
  attack-path page. A risk grouped across several assets gets neither: there
  is no single place to open, and sending the reader to the worst asset would
  present that asset as if it were the whole risk. A tenant-scope finding is on
  no asset.
- **The link goes to the existing pages, not a new one.** A route opens
  `/attack-paths?trace=<key>`, where routes are read (§138). An asset opens
  `/assets/<id>?tab=connections`, centred on itself. An expansion on the
  dashboard was considered and rejected: it would have been a third place
  hosting a canvas, with its own selection and URL state, after §133 and §137
  worked to reduce them to one frame per question.
- **Beside the row, not instead of it.** The row still opens the risk, which
  explains the rank. A small graph link sits next to it. A risk with no single
  place to open keeps an empty slot of the same width, so the badges stay
  aligned. The shortest-path panel gains "Trace this route".
- **Loaded before the click.** `GraphLink` starts the page's chunk, the
  canvas's chunk and the graph's query when the keyboard reaches the link, or
  when a pointer has rested on it for 100ms. That delay is long enough that
  sweeping down five rows does not request five graphs. An asset's
  neighbourhood is addressed by provider id, so the asset row is fetched first
  and the neighbourhood second. Every part is fire-and-forget: a failure leaves
  the page to ask again and show its own error.
- **The queries are declared once.** `components/graph/graphQueries.ts` holds
  the asset, neighbourhood and route-map queries that the pages and the
  prefetch share. A prefetch only helps if it fills the exact entry the page
  reads, and a key changed on one side alone would silently turn every
  prefetch into a wasted request.
- **Arrival.** A page opened with `trace=` scrolls its drawing into view once,
  since the drawing sits below the counts and the choke points. Tracing from
  the rail afterwards does not scroll. A `trace=` that names a route missing
  from the latest reading now says so, with a way to clear it, instead of
  showing every route with no explanation.

The risk page's "Explore in graph" still opens a scenario on the neighbourhood
around its entry point, traced there, rather than on the attack-path page.
Whether it should follow §138 is left for now.

**Not checked in a browser.** Tests cover the links, the prefetch requests,
the one arrival scroll and the missing-route notice. They do not show how long
the handoff takes, which is the thing a transition would be judged against.

## 140. A link into the graph grows into the graph's frame

The step §139 left for later. A dashboard row, or the shortest-path panel,
now grows into the frame of the graph it opens: the neighbourhood card on an
asset's page, or the drawing on the attack-path page. The row is the thing
that becomes the graph, so the reader never has to look for it on arrival.

- **The browser's View Transitions API, not `motion`.** `motion` animates
  elements React holds. The two ends of this movement are on two pages, and
  the first is unmounted before the second mounts. `document.startViewTransition`
  pictures the page before and after a change and moves between the two,
  matching elements by name. It is called by hand, since React Router 6 only
  offers it with a data router, and this app uses `<Routes>`. It is a platform
  API, not a second animation kit: nothing is installed, and nothing is drawn
  that the page does not already draw.
- **What is named.** The click names the nearest `data-graph-source` (the risk
  row, the panel), or the link itself when there is none. Once the first
  picture is taken that name is cleared, and a class on `<html>` names the
  destination's `data-graph-frame`. A frame is named only while a morph runs,
  so an ordinary visit to the page is untouched, and two names never exist at
  the same moment.
- **It never holds the page long.** Between the browser's two pictures the page
  is frozen. `morphInto` waits for a frame to appear (a mutation observer and
  timers, not animation frames, which are not drawn while frozen), for at most
  300ms, and then two more turns so an arrival scroll has already happened.
  The preload from §139 means the frame is usually there at once. When it is
  not, the morph goes ahead with the page as it stands, rather than freezing
  it for a slow network.
- **`PageTransition` holds its key across a morph.** Its exit is counted in
  animation frames, which would never finish while the page is frozen, and
  the new page would never mount. On a navigation carrying the morph's history
  state, the same element takes the new page and the old one leaves at once.
  The key still changes only with the pathname, so the next ordinary
  navigation animates as it always did, and a later search change on the
  arrived page does not remount it.
- **Timings are `lib/motion.ts`'s.** The frame grows over `page` (240ms) on its
  ease-out, clipped as it grows, from the source's top edge. The source's
  picture leaves over `instant` (120ms) on the ease-in, so the two never read
  as one image stretched. The rest of the page crossfades on the same two.
- **An enhancement only.** Without the API, for a reader who has asked for
  less motion, or for a modified or middle click, the link is the ordinary
  link §139 made. The reduced-motion media query in `index.css` also removes
  the view-transition animations, as a backstop. After a morph the attack-path
  page's arrival scroll is instant rather than smooth, because the browser
  pictures the page once it has scrolled.

**Not checked in a browser.** Tests cover what is named when, that the frame's
page is mounted before the second picture, that the old page leaves into the
same element, and each fallback. jsdom has no View Transitions and draws
nothing, so how the movement looks, and whether 300ms is the right wait, still
need a real browser, in Chrome and Safari at least.

## 141. Changes are simulated as a plan, in a tab beside the drawing

The attack-path page could try one cut: a choke point's button, or a pressed
line, greyed out what that link's severance closed. Nobody makes one change.
What goes to a change window is a list, and a list is the one thing severance
per link cannot answer: two network hops into one identity each close nothing,
because each is the other's way round, and together close everything behind
them. A page that added up the numbers on the lines would tell that customer
the plan does nothing.

- **The plan is answered whole, on the server.** `POST /attack-paths/simulate`
  takes up to ten links, removes them all (`AssetGraph.without`, keyed by
  `removal_key`, so an Owner assignment takes its escalation line, §127) and
  enumerates the routes again from the resources and edges, the way the
  severance oracle in the tests checks one link. The browser never derives a
  plan's outcome from `closes`; the union of those is a lower bound, and a
  lower bound shown as the answer is the overclaim §122 exists to avoid, pointed
  the other way.
- **Where the whole beats its parts, the page says so.** `together` names the
  routes no single cut closes alone. That is the thing nobody could have read
  off the drawing, and the reason to simulate rather than eyeball.
- **Each change is weighed against the rest.** `alone` is the number on the
  line; `needed_for` is how many routes reopen if the change is taken out of
  the plan, found by rebuilding without it — one rebuild per cut, which is
  what caps a plan at ten. A change with `needed_for` zero is work the rest of
  the plan already does, and is marked "you can leave it out".
- **What to add next is ranked with the plan made.** The choke points above
  the drawing are the estate as it stands. Once the plan removes a link, a hop
  that had a way round may be the only way left, so the tab's suggestions are
  `choke_points` of the rebuilt estate against what remains. An empty tab starts
  from the estate's own choke points.
- **A tab, not a mode.** The panel beside the drawing has two tabs, Routes and
  Simulate. Pressing a line adds it to the plan (or takes it out) and opens
  Simulate; tracing a route or pressing a box opens Routes. The drawing shows
  the plan in either tab — its lines dashed in the ok colour, what it closes
  greyed — with a bar above saying how many changes are simulated and that
  nothing in the cloud has changed.
- **No choke-point card above the drawing.** It listed the same links the
  Simulate tab starts from, so the page said one thing twice, and the card's
  button only fed the tab. The tab now leads with them under the card's title
  — each with what it closes, named, and "it sits on N" where it has a way
  round — and the page goes from the counts straight to the drawing. The risks
  queue still leads with the same rows, from `/choke-points`.
- **The plan is in the URL.** `cut=source|relationship|target`, one per link,
  so a plan can be sent to whoever makes the change, and the page opens on the
  Simulate tab when a link names one. The API call is a POST body because ten
  Azure ids three times over outgrow what some proxies accept; the page's own
  URL never reaches the API. A link not in the latest reading comes back in
  `missing` and is shown as such rather than failing the plan — a plan in a
  URL outlives the scan that drew it, and one change already made should not
  hide what the others still do.
- **Still open, and longer.** Routes the plan leaves are listed with the hops
  they now take. A route that runs longer goes round a cut, which is the plan
  partly working; saying "4 → 6 hops" keeps that from reading as failure.
- **"Copy the plan"** puts the changes and what they close on the clipboard,
  for the ticket. No export format beyond that until somebody asks for one.

**Cost.** One rebuild and traversal for the plan, one more per cut, and one
severance pass over the rebuilt estate for the suggestions. A tenant whose
route map is already slow will feel a ten-cut plan; the page keeps the last
answer up, faded, while the next is checked, rather than emptying the panel.

**Not checked in a browser.** Tests cover the plan in the URL, the request
body, the together callout, a covered change, and a missing link. How the tab
reads beside a large drawing still needs a real screen.

## 142. A route is read in one navigator in the panel, stop by stop

Supersedes the step bar in §138 and the traced-route panel in §137.

A traced route was read twice, and the two readings did not agree. A step bar
across the top of the drawing showed one hop at a time, with previous and next,
the hop's sentence and six-pixel pips. The panel showed every hop as a spine,
which could not be stepped along and did not mark the hop the bar was on. The
bar said the hop's `detail`, the spine its `description`. The two found the
cut differently: the bar matched the relationship, the spine did not, so where
one pair of boxes is joined by a role and by a grant the spine could mark the
wrong one. The bar and the plan's bar together took seven rows from a drawing
of fixed height. The entry was never a hop, so nothing said why the route
started there, and nothing said what the target held. Reading forty routes was
back, press, back, press. And every hop carried numbers the page already had --
what cutting it closes, whether there is a way round, the open findings where
it lands -- and said none of them.

Now there is one reading, in the panel (`RouteNavigator`).

- **Stops and links.** A route of four hops is five stops joined by four links.
  Every stop is always shown: its name (a link to the asset), its type, open
  findings, the entry's exposure and the target's sensitivity, and where the
  route enters a place -- the subscription and group, linked to the estate
  map, said once where the route arrives rather than at every stop in it. The
  links are what is walked. The one being read opens: its `detail` and facts,
  and what cutting it would do.
- **The cursor is on a link, never on a stop.** Stops are short enough to show
  whole, so there is nothing to open on them, and keeping the cursor on links
  leaves `hop` meaning what it has meant since §138 -- every link already
  made still opens where it did. A press on a stop in the drawing reads the
  link arriving at it.
- **What cutting it does, from the line's numbers.** "Closes this route and N
  others" only when the link's `closes` names this route; a link the route has
  a way round says so, with what it closes elsewhere; "It sits on M" where
  `on_routes` is larger than `severs`. Containment says it cannot be removed
  and offers no cut. Two marks: the earliest place to cut, which is the
  server's `cheapest_break`, and the link closing the most on this route, when
  that is another link and closes more than this one. The earliest removable
  link is the cheap one to reason about and often not the one worth making,
  and a reader choosing between them needs both in front of them.
- **"Add to the plan" is on the hop.** It plans the link without leaving the
  route (§141's tab does not open), and once the server has answered for the
  plan the navigator says whether it closes this route. The plan's bar above
  the drawing still says a plan is being simulated, with a way to it.
- **Route to route.** "Route 3 of 17", with previous and next, over the list
  exactly as it stands -- narrowed by box, place and search, in its sort.
  `listRoutes` (`routeOrder.ts`) is that order, and the list and the navigator
  both read it, so neither can skip a route the other shows. A route in a
  group says which group. A route the narrowed list does not hold shows no
  counter rather than a wrong one.
- **Keys where the reader is.** Up and down walk the links, left and right move
  between routes, Escape goes back to the list, while the focus is in the
  panel -- the drawing keeps its arrow keys for its boxes. A route chosen here
  moves the focus to its name; one a link arrived with does not, since the page
  has only just loaded. One live region says the hop being read, since a region
  mounted with its words is not reliably read.
- **The drawing selects what is being read.** A press on the traced route's own
  line or box reads that hop, as a click selects on every canvas. A line off
  the route still goes into the plan, and a box off it still narrows the list.
  Before, a press on the line being read put it in the plan and switched tabs,
  which took the reader away from the thing they were reading.
- **The list.** Searched by any asset on a route, not only its ends (`q`), and
  sorted by hops, sensitivity of what it reaches, exposure of where it starts,
  or tracked risks first (`sort`); groups stay above the rest whatever the
  sort, a group being one thing to decide about. Each row carries a dash per
  hop with the earliest cut in the cut's colour, "Tracked" where the risks
  queue has it, and "Closed by the plan", struck through, once the server has
  answered. Pointing at a row, or reaching it by keyboard, previews its route
  on the drawing -- faded around, but the view does not move and nothing
  marches, so sweeping down the list does not set the drawing swimming. A
  place narrowed to now narrows the groups' members too; before, only the
  loose routes were narrowed.

**Rejected.** Playing a route by itself, hop after hop on a timer: progress
nobody asked for (§87). Keeping the step bar alongside: the fault was two
readings. A cursor on stops: it would move what `hop` means under every link
already made, for stops that have nothing to open.

**Not checked in a browser.** Tests cover the navigator's walk, keys and URL,
what a hop says about cutting it, the two marks, route to route with the focus,
the plan from a hop, search, sort, the tracked mark and the narrowing. The
canvas is not mounted in tests, so the press on the traced route and the
preview on pointing are not covered by them, and how the panel reads beside a
large drawing still needs a real screen.

## 143. No label on the route map prints over another, and a group says what it holds on its row

Two things seen on the live page, with thirty-two routes in eight groups.

**Labels printed over each other.** Near the subscription the drawing read
"can gra can act over ıle over". A role and the escalation it grants join one
pair of boxes (§127), both are drawn along the same curve, and React Flow puts
each label at its curve's midpoint -- the same spot, twice. Where several lines
converge on one box, or a long line passes a short one, different pairs'
midpoints crowd too.

- **A pair speaks once.** `pairSpeakers` picks one line per pair of boxes to
  carry the label, naming both ("can act over · can grant roles over"): the
  line being read, then one on the traced route, then one in the plan, then the
  one closing the most, then the role over its escalation, then by key.
- **Then no label over another.** `placeLabels` estimates each label's box --
  from its text length, not measured, so the drawing does not depend on which
  font loaded -- at the midpoint of the two handles, and draws labels most
  important first, leaving out any that would overlap one already drawn. The
  order is what is picked or previewed, then the hop being read, the traced
  route, the plan, what closes the most, and the key, so one estate drops the
  same labels every time. A label left out is not lost: the line still carries
  its weight, and picking either end or tracing a route through it brings it
  back.

**Groups filled the panel.** All thirty-two routes were grouped, so the panel
was the three-line help about what a group is and then eight sentences, with
nothing about any of them but "3 hops".

- **The help is a question mark away**, beside "The same route, repeated · 8
  groups", as the drawing's own help is (§136).
- **Each group's row says what the rest of the list says of a route**: the
  shape (a dash per hop, the earliest cut in the cut's colour), the hops, the
  worst sensitivity it reaches, how many of its members are here when the list
  is narrowed ("2 of 3 here"), how many a risk tracks, and how many the plan
  closes. A chevron says it opens.

**Not checked in a browser.** Tests cover the pair's one label, the placement,
the group's row and the help behind its question mark. How many labels a
crowded estate loses, and whether the estimate of a label's width is close
enough, need the real page.

## 144. Cleave: one brand hue in the chrome, and a severity scale with more chroma

The redesign (`docs/design_handoff_cleave_redesign/`) renames the product to
Cleave and gives `--primary` a deep teal. §50 removed the last saturated hue from
the chrome on the grounds that a colour meaning nothing sits badly beside a scale
where every colour means something. This entry supersedes that part of §50, and
keeps its reason by narrowing what the one hue may mean.

- **Teal means "selected" or "the primary action", nothing about risk.** The
  selected nav item, the active tab, a traced route, the one filled button per
  view. It is 196° -- well clear of every severity hue (24°, 42°, 78°, 150°,
  263°) -- so it is not read as a level.
- **It appears in both modes** (`oklch(0.45 0.072 196)` light, `0.74 0.082 194`
  dark), which answers §50's other objection: an accent in one mode only reads
  as a bug. `--primary-soft` and `--primary-border` are mixed from `--primary`
  per theme rather than written out, so they cannot drift from it.
- **`destructive` is still not `critical`.** Neither token moved to the brand.
- **Only a scan's proof gets a status colour.** `StatusPill` draws open, in
  progress and risk accepted in one neutral tone and lets the word tell them
  apart; verified fixed is `ok`, and a failed or partial scan keeps its level.
  Risk accepted used to borrow the unknown tint, which drew a person's decision
  in the colour of the scanner's own gaps.

The severity scale keeps its hues and gains chroma in the tints, so a pill reads
at a glance in a dense row. Measured with the sRGB contrast formula against the
token values, every foreground clears 4.5:1 on its own `-bg`: light 4.86
(critical) to 7.12 (unknown), dark 5.51 (critical) to 7.81 (medium); on the page
the lowest is 5.96 (light ok). `--primary-foreground` on `--primary` is 6.98
light, 8.41 dark.

Also: `--radius` 0.625rem → 0.5rem (8px buttons, 12px cards), dark `--border`
10% → 12% and `--sidebar` 0.205 → 0.185 so the sidebar sits below the cards
rather than level with them, and Geist Mono as `--font-mono` for evidence, rule
ids and the mono link notation.

## 145. The overview leads with the link to cut, and says what a scan proved

The Cleave overview (`docs/design_handoff_cleave_redesign/`, "Overview") keeps
the argument's order -- score, what it is made of, what to do -- and changes
what stands at each step.

- **The score is a ring.** The previous `ScorePanel` chose a bar over a gauge
  so the digits stayed loudest. The ring here is 128px around 32px digits, so
  they still are, and it keeps `role="meter"` with a spoken value.
- **The trend is a sparkline, not a chart.** The Recharts `ScoreTrend` and its
  hover values are gone from the page; the exact figures are the score and the
  delta beside it. Under two readings nothing is drawn and the panel says the
  trend starts at the next scan.
- **"The link to cut" replaces "Shortest attack path".** The drawn route was
  one route; the cut is the one change that closes the most, from the
  choke-points the risks page already reads, and it opens the Simulate tab with
  the cut in the plan (`GraphTarget` kind `cut`, §141). Its number is the
  link's own `severs`, never summed across links.
- **"Fixes proved" replaces remediation progress.** Verified closes in 30 days,
  findings in progress (claimed, not proved), and what is still open. The
  weekly activity bars and the status/risk-band breakdown are off the page.
- **Removed, not moved:** `PostureBreakdown`, `RemediationProgress`,
  `AttackPathPanel`, `ScoreTrend`, `StackedBar`, `ActivityBars` and the
  per-severity sparklines. `GettingStarted` and the region map (§113) stay.
- The intro says "your cloud posture", not "your Azure posture" (§78).

## 146. The cut is played once its answer lands, never before

The redesign's signature moment on the attack-path page: when a simulated
plan's answer settles, the routes it newly closes are struck through one after
another in list order, 260ms apart, "Closed by the plan" rising with each, and
a target box greys 180ms after the last route to it.

- **Only a settled answer plays.** While the next plan is checked the last
  answer stays up at 60% with a spinner (§141); nothing is struck on a guess.
- **Only what is new plays.** The page keeps the last settled closed set and
  plays the difference, so an unrelated re-render, or a plan that adds a cut
  closing nothing new, strikes nothing twice.
- **The strike is a transition, not a new element.** A route's name is always
  struck in a transparent line; closing fades the line and the text to muted
  over 400ms after the route's delay. The mark arrives with `cg-rise`.
- **Reduced motion lands everything at once.** The media query in `index.css`
  shortens durations but not delays, so the delays themselves are zeroed when
  `usePrefersReducedMotion` says so. `SEQUENCED_CUT` switches the stagger off.

## 147. What every request passes through, and a consent link redeemed once

PR #7 hardened the API alongside the redesign. None of it changes what a
customer sees when things go right; all of it changes what a stranger can do
when they go wrong.

**A signed token names what it is for, and the signer checks it.**
`sign_state` stamps a `Purpose` (consent, template, event feed) and
`verify_state` demands one, both as keyword arguments with no default. The three
kinds share a secret and differ only by that field, so a caller that skipped the
check would accept the wrong kind -- and one of three did, the consent callback,
which is the one that binds a tenant. The purpose strings are wire format inside
webhook URLs customers already hold, so they never change.

**A consent link is redeemable once.** It is a bearer credential travelling to
an administrator who may hold no account, so it carries a nonce whose
counterpart is on the connection row (`consent_nonce`, migration 0041).

- While it is live, polling reissues the _same_ link, so the copy already sent
  keeps working; a new one is minted only when none is live.
- The callback spends the nonce in a commit of its own, before any provider
  call, so a refused rebind or a directory timeout cannot roll the spend back
  and hand the link to whoever else holds it.
- The row is read `FOR UPDATE`. Without the lock, two callbacks with one link
  both read the nonce live, both passed and both bound a tenant -- the second
  before the first had written its tenant, so the rebind refusal missed it.
- A connection bound to a tenant is never repointed by a callback; that is a
  delete and reconnect.
- The link is returned only to a caller who may administer the connection.

**Every request passes four layers, in an order that is load-bearing**
(`core/middleware.py`, ordered in `main.py`): the body-size limit innermost,
then the unhandled-error handler and the rate limit inside CORS so a browser can
read their refusals, and security headers outermost so every response carries
them.

- **Body size**: 1 MiB, from `Content-Length` and then counted as it arrives,
  because a chunked body declares nothing. The webhook is why: unauthenticated
  and parsed with `request.json()`.
- **Rate limit**: a fixed window counted in Redis, not in the process, since a
  per-instance counter hands out its allowance per instance. The smaller
  ceiling is chosen by _path_ -- the routes open by design -- never by the
  presence of an `Authorization` header, which nothing has verified yet. The
  caller is the `X-Forwarded-For` entry `trusted_proxy_hops` from the right, the
  one the platform wrote. It fails open: an abuse control is not worth an
  outage.
- **Headers**: a CSP of `default-src 'none'` (the API serves JSON and one
  self-contained HTML report), `nosniff`, `DENY`, no referrer. HSTS only when
  the caller's connection was HTTPS -- judged from the proxy's own
  `X-Forwarded-Proto` when a proxy is configured, because Railway ends TLS and
  forwards plain HTTP, and uvicorn trusts forwarded headers only from
  127.0.0.1. On the scheme alone HSTS was never sent in production.
- `/health` answers `ok` and nothing else; which environment a deployment is
  was a field any stranger could read.

**Around it**: the API image runs as an unprivileged user with the compiler
purged from its layer. CI refuses a drifted `openapi.json` or `RULE_CATALOG.md`,
headers that differ between the two `vercel.json` files (Vercel reads whichever
matches its root directory, and one of them used to carry none), npm advisories
of high or above, and any Python advisory not on a named triage list -- a list
that should only get shorter (`docs/SECURITY_AUDIT_2026-09.md` §6).

**The rename reaches sentences, not names.** Every message the API writes for a
person says Cleave. What exists by name in a customer's cloud keeps CloudGuard:
the Azure scanner role and its description, the AWS stack, role and policies,
generated Azure Policy definitions, the change-event resources, and the Entra
app registration with its service principal -- a customer told to find
"Cleave" in their portal would find nothing, and renaming a deployed role is a
migration, not a copy change. This is §78's line between identifiers and
sentences, applied to the product's own name.

## 148. React Router 7, for two advisories with no fix on 6

`npm audit` reported two moderate advisories against `react-router` 6.0.0
through 7.17.0: an open redirect through a backslash in `<Link>` and
`useNavigate` (GHSA-wrjc-x8rr-h8h6), and constructor injection through
`deserializeErrors()` in SSR hydration (GHSA-337j-9hxr-rhxg). The 6.x line
ends at 6.30.6 with neither fixed, so `react-router-dom` moves to `^7.18.4`.

- **The package name stays.** In 7, `react-router-dom` re-exports
  `react-router`; switching ninety imports to the new name buys nothing today
  and can be done on its own.
- **Declarative mode only, so the breaking changes miss us.** The app mounts
  `<BrowserRouter>` with `<Routes>` and has no loaders, actions, fetchers or
  data router, so the v7 changes to those do not apply. The one splat route
  (`path="*"`) navigates to the absolute `/`, so the change to relative
  resolution inside splats does not move it. Navigations are now wrapped in
  `startTransition`; the 585 tests pass unchanged.
- **The SSR advisory never applied** -- the app has no server rendering -- but
  it rides the same fix, and an audit that stays at zero is worth more than
  an audit read with exceptions in mind.

## 149. The ring is SVG, the motion engine and the palette load late

The build warned that the entry chunk was over 500 kB, and the question was
whether the redesign had done it. It had not: before it the entry was 609.6 kB
and the Recharts chunk 299.2 kB; after it, 612.7 kB and 309.9 kB. What the
redesign did change is who needed Recharts. It took `ScoreTrend`,
`StackedBar` and `ActivityBars` off the overview (§145), which left `Donut`
the only chart in the product -- so Overview and Compliance fetched 94 kB
gzipped of Recharts, Redux and d3 to draw two 64px rings.

- **`Donut` is hand-drawn SVG**, one stroked arc per slice, like `ScoreRing`
  (§38). What Recharts gave it is kept: the 1.5° gap between segments, the 4°
  floor that keeps one failure in four hundred visible, the sweep on mount and
  none under reduced motion, and the share on pointing -- now a `<title>` on
  each arc, the browser's own tooltip, rather than a themed card. That is the
  one thing given up, and the figures beside each ring already say what the
  card said. The geometry is `charts/ring.ts`, tested as arithmetic. It is
  imported directly now; there is nothing left to wait for.
- **Recharts stays the kit for charts with axes or series.** It has no
  consumer at the moment and ships nothing, and the next chart with an axis
  should use it inside `ChartContainer` rather than start a second way.
- **The motion engine loads after the first paint.** Every animated element
  is `m.*` under `<LazyMotion features={…} strict>` in `main.tsx`, and
  `domAnimation` arrives as `lib/motionFeatures.ts`. Nothing animates layout or
  drags, so the smaller feature set is enough; `strict` throws on a `motion.*`
  element, which would pull the whole engine back into the entry.
- **The command palette loads on first use.** `CommandPalette` keeps the
  header control and the ⌘K chord; the dialog, its queries and cmdk with the
  dialog runtime it brings are `CommandPaletteDialog`, fetched when it is first
  opened and ahead of that when the pointer or focus reaches the control.

The entry is 470.8 kB (152.4 kB gzipped) from 612.7 kB (197.0 kB), and Overview
no longer fetches the 309.9 kB (94.1 kB) Recharts chunk. What moved out arrives
later instead: the motion engine at 37.8 kB (14.2 kB) after the first paint, the
palette at 58.2 kB (19.9 kB) when somebody opens it. The entry is now mostly
`@base-ui/react`, which every page renders with. Measured with Vite's own
report; React Router 7 (§148) sits in the separate `react` chunk and does not
touch these figures.

## 150. A second engine: Prowler's checks, run beside Cleave's rules and audited against them — **superseded by §168**

Cleave's native rule engine is deep and narrow: 98 rules, each reading evidence
its own collectors stored verbatim, each feeding the graph. Prowler is the
opposite shape -- over eight hundred Azure and AWS checks and the compliance
frameworks mapped to them, with no graph at all. This decision runs Prowler as a
second engine inside every scan: it supplies breadth, and it checks the first
engine's answers where the two overlap.

### Where it runs: its own service, one step per process

Prowler cannot be imported into the API or its worker. It pins botocore 1.40 and
pydantic 2.12; the API's aiobotocore needs botocore 1.43. So it lives in
`apps/scanner`, its own package and image (`infrastructure/docker/scanner.Dockerfile`,
`infrastructure/railway/scanner.json`, set on the service rather than read from
it -- §152), sharing only the database and the broker.
A seam test fails the build if anything under `apps/api/app` imports `prowler`.

It is driven through `prowler.lib.scan.scan.Scan`, the interface Prowler's own
API service uses, rather than its CLI: results arrive per check, the run stops
between checks when its lease is gone, and nothing is written to disk.
Credentials go to the provider's constructor and nowhere else -- never
`os.environ`, never a command line.

Prowler keeps each service client in a module global built from a process-wide
"current provider". A second scan in the same process would run against the
first tenant's clients and data. The worker therefore runs
`--max-tasks-per-child=1`, as Prowler's own workers do, and
`refuse_reused_process` stops a step outright if Prowler service modules are
already loaded -- a changed start command should fail loudly, not scan one
customer with another's clients.

### A fourth step kind

`ScanStepKind.ASSESS`: created by PLAN for the same scopes COLLECT reads (plus
the directory where Prowler has directory checks -- Entra ID), runnable once PLAN
succeeds, parallel with COLLECT, and ANALYZE waits for both to settle. A scan
therefore takes as long as the slower engine, not both in sequence. The API's
worker claims the step and sends it by task name (`cloudguard.run_assess_step`)
to the `assess` queue; the scanner settles it and sends the next advance back.

The scanner cannot import the orchestrator, so it restates the step fence in SQL
(`apps/scanner/cloudguard_scanner/store.py`): renewals, settles and the capture
write all name the attempt the step was claimed at, and the capture is written
in a transaction holding the step row `FOR SHARE`. A heartbeat thread renews the
lease on a third of its length, because one Prowler service can spend minutes
building its clients before the first check runs. The names, the lease length
and the capture columns are held equal on both sides by
`tests/unit/test_prowler_engine.py`.

Nothing is created while `ASSESS_ENABLED` is off. A step nobody consumes would
hold ANALYZE back for three leases and then fail on every scan.

### A role that can do almost nothing

The scanner runs third-party code with a customer's credentials in memory, so it
connects as `cloudguard_scanner` (migration 0042) and holds column grants only:
read the scope it was handed, update its own step's lease and status, write its
capture (0043 narrowed "its own step" to ASSESS steps, §151). It cannot read a
finding, an asset, a snapshot or a consent nonce. It
learns a scan's organization through `app.scan_owner`, a one-column SECURITY
DEFINER lookup, because that is the one read before there is an organization to
be held to; every other statement runs under `app.organization_id` and the
policies 0042 adds for that role.

### Silence is never a pass

Prowler fails quietly. A service whose listing is denied logs an error and
leaves its resource list empty; every check over it then emits nothing. A check
that raises is caught, logged, and also emits nothing -- and is still counted as
completed. Read naively, both are a clean estate.

So the scanner captures Prowler's log for the length of the run
(`ErrorCapture`), filing each ERROR under the service whose module raised it or
the check whose id begins the message, and stores that beside the results. The
API (`app/prowler/ingest.py`) then applies the rule the native engine applies:

- a check that raised, or did not finish, is UNKNOWN for the scope;
- a check whose service errored is UNKNOWN for the scope _and_ for every asset
  of its type Cleave inventoried that it said nothing about -- while whatever it
  did say stands, because a FAIL is an observation whatever failed around it;
- MANUAL is UNKNOWN;
- a run that could not start, whose results were pruned, or that came from a
  different Prowler release than the catalogue is UNKNOWN for every check it
  was asked to run;
- a check that ran cleanly and emitted nothing had nothing to judge. It counts
  as run -- so a control is not "never assessed" -- and raises no verdict.

An incomplete run also makes the scan PARTIAL, named in `collection_errors`
exactly as a failed listing is.

### Every result on an asset Cleave knows

Prowler names resources its own way. `AssetResolver` joins its ids to the
inventory case-blind, then through ARM parents (a vault's key belongs to the
vault), then by last segment (an ARN's instance id), refusing a segment two
assets share. A result that still joins nothing but is plainly a resource
becomes an inventory asset of type UNKNOWN -- deliberately untyped, so no native
rule ever evaluates metadata it does not carry. Anything else is a verdict about
the scope.

What is stored per result is what a finding needs: status, message, resource id
and name, region, tags, Prowler's short description. Not `resource_metadata`,
which is the whole service object Prowler built -- configuration the customer
never asked Cleave to keep for months.

### One question, one finding -- and the engines audit each other

Every enabled check becomes a `SecurityRule` subclass (`app/prowler/rules.py`,
rule id `PRW-<cloud>-<check>`), so findings, risks, verification and compliance
treat its verdicts exactly as a native rule's. `matches` is always false and
`evaluate` answers UNKNOWN: the native engine never evaluates one, and cannot by
mistake. Rule ids are up to 101 characters, so every `rule_id` column went from
32 to 128.

Where a native rule already answers what a check asks, the catalogue records it
(`covered_by`, hand-curated in `tools/prowler/curation.json`). That check is not
registered as a rule. Its verdicts are compared with the native rule's, asset by
asset -- or, where the two never name the same asset (an aggregate rule against
per-plan checks), scope against scope -- and every disagreement becomes an
`engine_divergences` row: NATIVE_MISSED, PROWLER_MISSED, or one engine unable to
tell. Pairs that ask slightly different questions are recorded with a note
(`divergence_notes`) and listed as expected. `GET /engine-audit` and the Engine
audit page read them; an unexpected disagreement is a bug in one engine or the
other.

This is how §62's line is kept. Defender's vulnerability verdicts stay evidence
paired with exposure: Prowler's `defender_ensure_system_updates_are_applied` is
covered by AZ-VULN-001 and never raises a finding of its own.

A native rule also inherits the controls its counterparts map to, for frameworks
it does not map itself -- never overriding a hand-written mapping, and never for
a pair recorded as disagreeing by design.

### The catalogue is generated and pinned

`tools/prowler/build_catalog.py` reads the installed Prowler beside
`curation.json` and writes `apps/api/app/prowler/data/catalog.json`: every check,
its severity, remediation, derived exploitability, scope, and its compliance
mappings translated into Cleave's control ids. The API reads it to interpret
results; the scanner reads the same file to choose what to run. The Prowler
release is pinned in `curation.json`, `apps/scanner/pyproject.toml` and the
scanner Dockerfile, a unit test holds the three equal, and CI rebuilds the
catalogue from the pinned release and fails on any difference.

Thirty-seven checks are excluded, and excluded means never requested rather
than filtered afterwards: those that scan code, environment variables, user data
or logs for secrets; those that read activity records rather than
configuration; the one that sends public IPs to Shodan; the one that needs
Microsoft.Web list-keys; and two that judge against approved lists the customer
has not given.

### Permissions

On Azure the Graph permissions Prowler needs are ones Cleave's application
already holds. ARM is different: the custom scanner role is trimmed to exactly
the calls Cleave's collectors make, and Prowler reads several hundred other
resource types. The deployment template therefore also assigns the built-in
Reader role -- every `*/read`, no `listKeys`, no data plane -- so the claim that
Cleave cannot perform a write still holds. A connection deployed before this
reads those services as UNKNOWN until it is redeployed, and is prompted to
redeploy (§153). On AWS the role already
carries SecurityAudit and ViewOnlyAccess, which is what Prowler documents.

### Frameworks

Six frameworks come from Prowler's compliance files: CIS Azure 6.0, CIS AWS 7.0,
AWS FSBP, NIS2, HIPAA and MITRE ATT&CK. They list every requirement, so
coverage is measured against the whole framework. They are hidden while the
scanner service is off, when every control would read never assessed.

Their control titles are the benchmarks' own requirement names as Prowler
carries them -- the one place the catalogue does not use Cleave's own words,
which `app/compliance/catalog.py` otherwise requires because CIS text is
copyrighted. **This needs a licensing decision before the CIS frameworks are
offered commercially**; the fallback is identifiers only, with titles written
here.

Building the crosswalk also found a catalogue error: AWS-STO-002 and AWS-STO-003
were mapped to CIS AWS 1.x numbering. In 3.0, 2.1.1 is the HTTPS control and
bucket encryption has no control, so AWS-STO-003 now maps 2.1.1 and AWS-STO-002
maps no CIS control. The catalogue's 2.1.x titles are corrected, and 2.1.3 is
added.

### What replay gives up

A native capture can be re-evaluated against new rules. A Prowler capture can
only be re-interpreted -- new mappings, new severities, a new pairing -- because
Prowler's checks ran against the cloud, not against anything Cleave stored. A
capture from another Prowler release reads UNKNOWN rather than being read under
check ids whose meaning may have changed. Retention prunes old capture payloads
on the snapshot schedule, keeping the row and the newest run of every scope.

### Not done yet

- The scanner image installs Prowler's pinned direct dependencies but not a
  hash-locked transitive set; generate one on Linux and install with
  `--require-hashes`.
- No run has been made against a real tenant or account. The first sandbox run
  should be read through the engine audit before `ASSESS_ENABLED` is set in
  production.
- The demo organization replays native captures only, so it shows no extended
  checks.

## 151. The second engine, audited: stale messages, queue waits, silent refusals, and whose scope a verdict is — **superseded by §168**

An audit of §150 against Prowler 5.43.0's own source found six places where the
second engine could run twice, never run, read silence as a clean estate, or
let one subscription answer for another. Each is fixed here; none changes what
§150 decided, only whether the code does it.

### A message says which attempt it is for

The API claims an ASSESS step and publishes `[scan_id, step_id]`. The scanner
read the attempt off the row. So a message that sat on the queue past its lease
-- reaped, the step returned to PENDING, reclaimed at the next attempt with a
message of its own -- was later picked up and ran _as the new attempt_, beside
the scanner running the new attempt's message. Both passed the fence, because
both named the same attempt. Two Prowler runs against one customer, and two
capture writes racing on the unique index.

`orchestrator.claim` now returns the attempt each step was won at (`Claim`), and
`advance_scan` sends `[scan_id, step_id, attempt]`. The scanner refuses a
message whose attempt is not the row's (`NOT_OURS`). A message without one --
queued before this change -- is still read the old way.

### Waiting on the queue is not a lost lease

A claim leased every step for ten minutes. A COLLECT step is picked up in
seconds; an ASSESS step waits for a scanner process, and the scanner runs one
step per process for hours. Behind two or three long runs, a queued ASSESS step
was reaped before it ever started, re-sent to the back of the queue, and failed
on its third attempt having run nothing.

A claim now leases an ASSESS step for `assess_queue_seconds` (four hours by
default), and the scanner's heartbeat renews once on entry, before Prowler
starts. That first renewal replaces the queue lease with the ordinary one, so a
scanner that dies mid-run is still noticed in minutes, and a step already taken
is refused before a single check runs. A message genuinely lost costs the queue
lease to notice instead of ten minutes; the dispatcher's nudge (§65) does not
change that, and it is the rare case.

### The run's own deadline, because the soft time limit never fires

Prowler's `Scan.scan()` wraps each check in `except Exception` and logs it.
Celery's `SoftTimeLimitExceeded` is an `Exception`, so it was swallowed as one
check's error and the run carried on until the hard limit killed the process --
nothing stored, nothing settled, the lease left to expire and the whole run
retried to the same end three times.

The runner now takes a deadline (`SCANNER_RUN_BUDGET`, by default the soft
limit less thirty minutes) and checks it between checks, where it already checks
the lease. At the deadline it stops, stores what finished with
`errors["stopped"]`, and settles SUCCEEDED: the capture is PARTIAL, every check
it never reached reads UNKNOWN "did not complete", and the scan's gap list says
it stopped at its budget. A retry would stop in the same place, so it is a
result, not a failure. The soft and hard limits remain as the backstop for one
check that hangs.

### Refusals Prowler logs quietly

`ErrorCapture` filed ERROR records by the path they were logged from. Reading
Prowler's source showed three ways a refusal escaped it:

- An Azure resource group Prowler could not list is logged at WARNING (by
  `AzureService.list_with_rg_scope`), as is a key vault whose data plane refused
  it. Those services then report on nothing, which read as nothing to judge.
- The base class that builds every Azure service's clients logs its failure from
  `providers/azure/lib/service/service.py`, which names no service -- so it was
  filed under "other", which nothing read.
- "Other" errors never made a run PARTIAL.

Now a WARNING is kept when its message names a refusal (`_REFUSAL`:
AuthorizationFailed, AccessDenied, Forbidden, 403 and the like); Prowler's many
"not supported in this region" and "not found" warnings stay out. A record whose
path names no service is filed under the service whose module is on the stack
that logged it, found by walking the frames -- `emit` runs synchronously in
the logging thread, so the caller is a few frames up. What still belongs to
nothing makes the run PARTIAL, and the scan's gap list counts it. The scanner's
own and Celery's loggers are ignored, so a database blip during a lease renewal
is not mistaken for the cloud refusing something.

One silence remains that the log cannot show: `Scan.scan()` drops a finding it
fails to convert (`except Exception: continue`) without logging, and
`__threading_call__` swallows a worker thread's exception when the called
function did not log it. Neither can be seen from outside Prowler without
patching it, which this codebase does not do.

### Whose scope a verdict is

A result that joined no asset, and every UNKNOWN about "the scope" (a service
that errored, a check that raised, a run that could not start), was a verdict
on no asset. Findings are unique on (organization, rule, resource), and a scope
verdict's resource was nothing -- the same nothing in every subscription of a
tenant-wide scan. Two subscriptions' FAILs were one finding; one subscription's
PASS resolved another's FAIL.

A verdict about one account's scope now lands on that account's own asset
(`/subscriptions/<id>`, or the AWS account), which every account's normalized
state carries. Where there is none -- the account's collection failed while
Prowler's succeeded -- a PASS with nowhere to go is UNKNOWN rather than a
tenant-wide pass, and a FAIL is kept as an observation. The directory is one
scope per connection and keeps its verdicts on no asset.

And each (check, asset) now gets exactly one verdict. The UNKNOWNs raised for a
service error or a check that did not complete were appended beside the
results' verdicts rather than combined with them, so one asset could carry a
FAIL and an UNKNOWN for one check -- a finding and a gap for one question. They
go through the same worst-wins combination as several results on one asset do.
What a check said about the scope itself still stands beside a service error:
the scope is marked unknown only where the check said nothing about it.

### The scanner settles ASSESS steps and nothing else

0042's policies held `cloudguard_scanner` to the organization it declared, and
no narrower. Within it, the scanner could update any step: fail a COLLECT,
succeed an ANALYZE. Migration 0043 adds `kind = 'ASSESS'` to its select and
update policies on `scan_steps`, and `tests/integration/test_scanner_role.py`
proves the role's reach against the real grants for the first time -- what it
may settle, what it cannot see, what it cannot read at all.

What the policies cannot do is stop the role declaring another organization:
`app.organization_id` is its own `set_config`, as it is for `cloudguard_worker`.
Isolation between tenants rests there on the organization and scan ids being
unguessable, and on the queue message being the only place the scanner learns a
scan id. That is a weaker boundary than the request path's, and it is named
here rather than implied away. The larger exposure is not the database at all:
the scanner holds Cleave's multi-tenant Entra secret and its AWS identity, which
reach every customer who has granted access. See the open items.

## 152. No Railway config at the repo root

The first scanner deploy started the API. Railway reads `railway.json` at the
repo root for every service built from the repo that names no config file of its
own, and the new scanner service named none -- so it built `api.Dockerfile`,
ran `alembic upgrade head && uvicorn`, and crashed on the API's missing
environment. Pointing the scanner at `infrastructure/railway/scanner.json` was
refused: Railway has deprecated Config as Code, and a service that has never
used it may no longer opt in.

So the API's file moved to `infrastructure/railway/api.json` beside the
worker's, and the API service names it explicitly. With nothing at the root,
a service without a file of its own gets exactly what is set on it. The
scanner's Dockerfile path and start command are set on the service through the
Railway API (`docs/DEPLOYMENT.md` §2); `scanner.json` stays as the record of
them, and `test_scan_lease.py` still holds its queue list to the step kinds.

The first check of the deployed scanner found its `SCANNER_DATABASE_URL` in
the API's `postgresql+asyncpg://` form, with a `/` in the password. psycopg
refuses the first and its error quotes the whole string, password included --
into the log of every step it would have run. libpq does not refuse the second;
it reads the user name as the host. `store.connection_url` now drops a driver
suffix, refuses a URL that does not parse or does not sign in as
`cloudguard_scanner` with a message that names no part of it, and runs when the
worker starts, so a bad value fails the deploy rather than the first scan.

Config as Code stops working on 2026-12-01. Before then all three services move
to Railway's infrastructure-as-code file (`.railway/railway.ts`); see the open
items. `railway config migrate` cannot do it unassisted: it maps the one root
file onto the wrong service.

## 153. A connection without the extended checks' Reader is told to redeploy — **superseded by §168**, except the `atScope()` filter

§150 made the template assign the built-in Reader beside the custom role and
said a connection deployed before then "reads those services as UNKNOWN until it
is redeployed". Nothing told the customer. The custom role's actions did not
change, so `ROLE_VERSION` stayed v8, the access panel said the role was current,
and the first live scan showed why that mattered: Prowler was refused
`Microsoft.Storage/storageAccounts/fileServices/read` and
`Microsoft.Sql/servers/encryptionProtector/read` -- both inside `*/read` -- and
storage and SQL server read as unknown, with no prompt anywhere.

**The answer comes from the reading that already exists.** The grant-version
probe lists the assignments Cleave's principal holds and resolves each
definition; the same definitions are now asked whether any allows every read,
tested with a read no role names (`Microsoft.CleaveProbe/anything/read`), so
Reader, Contributor and Owner answer yes and the custom role answers no. By what
the grant allows rather than by Reader's role id, for the reason the version is
read that way: a customer who granted something broader is not missing
anything. Scan snapshots also hold the subscription's role assignments, and were
considered and not used: the prompt lives on the connection and has to clear
the moment a redeploy lands, not after the next scan.

**It is not a role version.** A v9 whose only difference was the Reader would
have created a second, identical custom role definition in every tenant that
redeployed, and a version is a set of custom-role actions -- `ARM_READ_ACTIONS`
stays exactly what the collectors call. So the answer is its own fact,
`provider_ref.every_read`, carried back through `ProviderOnboarding.detect_grant`
(which now returns a `GrantReading`: the version, and anything else the reading
established) and merged into the reference. `grant_upgrade_available` is true
for either cause, since the fix is the same redeploy; `extended_checks_blocked`
says which, so the panel reads "v8, Reader missing" instead of "v8, behind (v8)",
and `degraded_categories` stays about Cleave's own collectors, which lose
nothing.

**Only while the scanner service runs.** With `ASSESS_ENABLED` off nothing needs
the breadth, and prompting for it would be asking for access Cleave has no use
for. Unknown is not missing: a connection never read raises nothing, and is read
on its next detail request -- which is how every connection deployed before this
gets an answer without a migration. A no is read again on each detail request
until it becomes a yes, as a behind role already was.

**Only assignments at the scope or above it count.** The assignment listing was
unfiltered, and ARM then returns assignments beneath the scope too: Reader on one
resource group would have read as Reader over the whole connection, and the
version probe had the same gap. It now asks with `$filter=atScope()`, Microsoft's
documented form for "at or above", not yet exercised against a live tenant. Its
failure would be quiet rather than wrong: a refused or empty listing makes the
reading answer nothing, the recorded grant is left alone and no prompt appears.
So the first connection page after this deploys is the check --
`connection.grant_version_changed` in the API log, carrying `every_read`.

## 154. The scan wizard is a dialog, and the one view of any scan

§87 put the wizard in a side sheet and left the scan cards on the scans page
their own progress and details. That left two live views of one scan: the
sheet's pipeline, pushed over SSE, and a row of chips under the running card
(`ScanProgress`), polled on its own three-second clock and drawn from a
different vocabulary. A finished scan's steps were the chips again, inside
the card's expandable details. Three places drew a scan, and none agreed on
what it looked like.

**It is a dialog.** A centred `Dialog`, `sm:max-w-2xl`, the whole screen on a
phone, where the sheet's narrow column had squeezed the lanes. The header holds
the step bar, the body scrolls, and every step's actions sit in a footer that
does not. Closing still minimises -- the header's indicator reopens it -- and
while a scan runs the footer's main button says so: **Run in background**.
**Cancel scan** asks once more in place, because a scan stopped by a stray
click reads the whole estate again from the top.

**Four steps: Environment, Review, Scan, Result.** Finishing is a step the bar
reaches, not only a body swapped under a bar still on "Scan". Environment is
skipped when only one connection can be scanned, since there is nothing to
choose; Back still reaches the list.

**It is the one view of any scan.** A history row opens the wizard on its
scan -- **Watch** while it runs, **Open** once it has finished -- rather than
expanding in place. A finished scan opens on Result, with a **Details** tab:
what it covered, the identity it read as, its steps drawn by the same
`ScanPipeline` it was watched through, and `CollectionPanel`. `ScanProgress`
is deleted, and with it the row's live block, its Cancel and its detail poll.
`ScanPipeline` only draws; the scan is read by `useLiveScan` (stream, poll,
the once-on-finish invalidation, the previous run) so the step bar and footer
turn on the same answer the body does. The list itself still polls while a
scan is in flight: with the dialog closed nothing else keeps a row's status
current.

**The scan is in the URL.** `?scan=<id>`, over whatever page it was opened
on, so a scan is a link and survives a reload mid-run. Every change replaces
the history entry, as the attack-path page's reading state does. Once a scan
exists the URL alone holds the dialog open, so following **View findings** or
**Scan history** out of it closes it without a handler. Choosing an
environment is not in the URL: nothing exists yet for a link to name.

**It is loaded when first opened.** The provider stays in the entry chunk;
the dialog is `lazy()` and kept mounted after the first opening, the command
palette's arrangement (§149). Moving the details panel and the tabs into the
shell had taken the entry chunk from 472 kB to 488 kB; loading the wizard late
takes it to 423 kB.

`IN_FLIGHT` in `components/scans/status.ts` is now the only list of running
statuses -- the header indicator and the dashboard each had a copy -- and the
card's own duration formatter gave way to `formatSeconds`.

## 155. An accessibility pass over the whole app: landmarks, titles, focus, and shortcuts that can be turned off

An audit against WCAG 2.2 AA across the web app. Most of what it looks for was
already right: every page has one `h1`, filters and fields are labelled, icon
buttons are named, charts and marks carry their reading in text (§149), the
severity pairs clear 4.5:1 on their tints (§144), and reduced motion is
answered once. What it found, and what changed:

**One `main`.** shadcn's `SidebarInset` renders a `<main>`, and the shell put
its own `<main>` inside it, so every page sat in two nested main landmarks and
"skip to main" landed on the header. The vendored inset is a `div` now; the
shell's `<main id="main-content">` wraps the page alone.

**A skip link.** The first Tab on every page was the whole navigation. "Skip to
content" is the first element in the shell, hidden until focused, and moves
focus to `<main>` by hand rather than by following `#main-content`, which
would write a fragment into a URL the router owns (2.4.1).

**Every page has a title (2.4.2).** All of them were "Cleave". `lib/pageTitle.ts`
names each route after its sidebar label, names the routes the sidebar does
not list, and a detail page puts what it shows first once it has loaded
(`usePageTitle`): "Storage open to the internet · Finding · Cleave". The name
goes through `DocumentTitle`, around every route, rather than being written by
the page, because a child's effect runs before its parent's and the route's
title would overwrite it on the render it arrived in.

**Focus goes to the new page (2.4.3).** A route swap left focus on the link
that was pressed, which usually unmounts with its page, so focus fell to
`<body>` and the next Tab restarted at the navigation. `PageTransition` now
focuses the arriving page's `h1` (made focusable by script, never a tab stop),
or `<main>` while the page has not drawn one. Not on the first page, which the
browser already started at the top, and not on a morph into the graph, which
keeps its key and whose panel places focus itself (§140).

**Focus indicators with a solid line (1.4.11).** Controls drawn outside the
primitives -- dashboard rows, graph list rows, the segmented filter, the sign-in
buttons, twenty-two places -- showed only the 3px halo at half strength, 1.9:1
against the page, and a box-shadow is removed outright in forced-colours mode,
so there they had no indicator at all. They take `focus-ring` (or
`focus-ring-inset`), a `@utility` in `index.css` that draws a 1px `--ring`
outline under the halo, as `border-ring` does in the primitives. A
`focus-visible:outline-1` beside `outline-none` does not do this in Tailwind 4:
`outline-none` sets the style to none through a variable the width utility
reads back, which is why the scroll area's own outline never showed. The light
theme's `--sidebar-ring` moves from 0.708 (2.48:1 on the rail) to `--ring`'s
0.58.

**Single-key shortcuts can be turned off (2.1.4).** `g` then a letter, `/`,
`?`, `j`/`k`/`o`, and `x` on Risks fire on one unmodified key. Speech input
types a spoken word as its letters, so "go" opened the overview. A switch in
the shortcuts sheet turns them all off, stored per browser
(`cloudguard.shortcuts.single-key`); ⌘K is unaffected and opens the sheet
from the palette. Every one-key handler asks `singleKeyShortcut`.

**Enter belongs to the control that has focus.** After `j` marked a row, Enter
anywhere on the page opened that row -- on a button, a link, a tab -- and
`preventDefault` swallowed the control's own action. `Enter` and `o` open the
marked row only when focus is on nothing that answers keys itself
(`isControlTarget`).

**The account menu is a disclosure.** It carried `role="menu"` and
`menuitem`s with none of the menu's keyboard model, and held an address and a
destructive confirmation that no menu may contain -- a screen reader switched
into menu mode and then could not reach half of it. It is buttons in the tab
order after an `aria-expanded` trigger now: Escape closes it and returns to
the trigger, tabbing out closes it, the current organization is
`aria-current`, and asking to remove one starts the keyboard on **Keep**.

Smaller: the collapsed rail's wordmark link kept its name (`sr-only` rather than
`hidden`), the sign-up password's length hint is its field's description, and
the score ring's arc is hidden beside the number it repeats.

**Not changed.** The `j`/`k` mark is visual only: a screen reader already moves
through a table by row, and moving real focus with the mark would open each
row's hover preview in turn. The graph canvases were not re-audited; their
keyboard model is §101 and §134.

### The checks that hold it

**Every rendered test state passes axe.** `src/test/setup.ts` runs `axe-core`
after every test, over whatever the test left on the page -- a dialog open, a
filter applied, an error shown -- and a violation fails that test with the
element named. After every test rather than in chosen ones, because a check
that has to be remembered is missing from exactly the test that mattered. Two
rules are off (`src/test/axe.ts`): `color-contrast`, which jsdom cannot compute
(no layout, no custom properties), and `region`, because a test mounts a page
without the shell; the shell's own test holds the one `main` down. It costs the
suite about four seconds.

Its first run found what the manual pass had not:

- `ScoreTile` and the provenance confidence bar put `aria-label` on a bare
  `span`, which assistive technology ignores; both are `role="img"` now, and
  the bar says "Confidence: 3 of 4" rather than a raw 0.75.
- Three popovers -- the notification bell's and the two help popovers on the
  graph pages -- were unnamed dialogs; each is named after what opened it.
- The first connection step and the access tab jumped from the page's `h1`
  to `h3`s; their section headings are `h2`s.
- Two `dl`s were invalid: the risk breakdown held its capped note as a `p`
  inside the list (it sits after it now), and the permissions summary wrapped
  its pairs in `span`s (they are the `div`s a `dl` allows).
- The command palette's "nothing matches" sat inside the listbox, which may
  hold only options. It is above it now, in an always-mounted `role="status"`,
  so a search that stops matching is said aloud as well as drawn.

**`eslint-plugin-jsx-a11y`, strict.** It declares ESLint up to 9 and this
project runs 10, so `package.json` overrides its peer to the installed ESLint.
The plugin reads JSX, not ESLint's removed context API, and runs clean; the
alternative was `eslint-plugin-jsx-a11y-x`, a single-maintainer fork with a
five-hundredth of the upstream's users. Turned down, each with its reason in
`eslint.config.js`: the two interaction rules watch pointer handlers only,
because a key handler on a container is where the graph canvases hear arrow
keys bubbling from the focused box inside; and in the vendored `ui/**` the
rules that cannot see spread props. `no-autofocus` stays on, with an inline
exception where focus is placed on purpose -- the first field of a page that is
one form outside the shell, a dialog's one field, the answer that replaced the
button asking. It found one that was not on purpose: the first connection step
focused its name field, skipping the cloud choice drawn above it, and no longer
does.

## 156. A page size is validated where it is declared, and every page order ends on the id

A pass over the API against FastAPI's own practices. Most of it already held:
one lifespan, typed settings validated at import, dependencies that derive the
tenant rather than accept it, one error envelope, middleware ordered so every
error still carries CORS. Three things did not.

**`limit` and `offset` had no floor.** Every list declared a ceiling and no
floor, `/scans` declared neither and clamped in the handler, and `offset` was a
bare `int`. PostgreSQL refuses a negative `LIMIT` or `OFFSET`, so `?limit=-1`
reached the database and came back a 500; where the page is sliced in Python,
the attack-path list and map, `paths[:-1]` quietly dropped the last route.
Every `limit` is now `ge=1` with its ceiling, every `offset` `ge=0`, and
`/scans` answers 422 above 100 instead of clamping, like every other list.
`tests/unit/test_pagination_bounds.py` reads the bounds off the published
schema, so a list added without them fails the build.

**Paged orderings could tie.** `/findings` ordered by score and detection time,
`/risks` by score, `/changes` by time -- and one scan writes every finding it
raises with the same `now`, every change event with the scan's observed time,
and many rows share a score. PostgreSQL orders ties however the plan falls, so
the same offset could return a different row on the next request and a page
could repeat one finding and skip another. Each now ends on the id, as `/assets`
already did.

**The pools outlived the process.** The lifespan opened the engines and never
closed them, so a redeploy left its connections for the Session pooler to
notice were gone. It now awaits `dispose_engines()` after `yield`.

**Not done, and why.** FastAPI's usual advice is a `response_model` on every
route. Here the handlers return the `{data, error, meta}` envelope as a `dict`
built from `*Out` schemas, so the published schema says nothing about what a
response holds. Typing all of them is a change to eighty-odd routes and the
generated `openapi.json`, and is worth doing as its own piece -- a generic
`Envelope[T]` model, one router at a time -- rather than folded into this (§157).

## 157. Responses are typed envelopes, one router at a time, starting with findings

§156 left this undone: every route returned the `{data, error, meta}` envelope
as a `dict`, so the published schema said "an object" for every success and
FastAPI's own `HTTPValidationError` for every 422 -- a shape the API never
sends, since the validation handler answers with the envelope.

**`Envelope[DataT, MetaT]`** (`app/schemas/common.py`) is the success shape,
with `error` fixed to null. A route declares it as its return type and FastAPI
takes that as the response model, so the body is validated on the way out and
the schema names what `data` and `meta` hold. `meta` is a parameter of its own
rather than an open dict because it is where a list says how big the set is --
`PageMeta` is `total`, `limit`, `offset` -- and a client should not have to
guess that. A response with nothing beside its data says `NoMeta`, which is
`{}`. Two parameters rather than a default for the second: pydantic 2.10
refuses a `TypeVar` default when parametrizing, so `Envelope[X]` alone cannot
mean `Envelope[X, NoMeta]`.

**Handlers build the models, not dicts.** A response model given a dict drops
every key it does not declare, so a field added to a payload and forgotten in
the schema would vanish from the API without an error. Built as models,
pydantic refuses the missing field at construction instead. The `envelope()`
helper stays for the routers not yet moved.

**Errors are documented, not modelled per route.** They are written by the
exception handlers outside the route, so `ErrorEnvelope` is published through
`responses=`: every route behind the tenant can answer 401, 404 and 422
(`ERROR_RESPONSES`, on the router), a write adds 403, and the rescan adds 409.

**Findings first**, all seven routes. What they send is unchanged, checked by
calling every route with the old handlers and the new against the same faked
session and diffing the bodies, with two exceptions. `accepted_until` is
written `Z` like every other time on the finding, rather than `+00:00` -- the
same instant, which it was the only field to spell differently. And a finding
whose rule has left the registry sends the registry's fields as `null` (and
`compliance_mappings` as `{}`) rather than leaving them out; the web types say
so. `remediation_spec` and `prowler` are typed with the rules routes, which
publish the same objects. An attack path is
typed as `AttackPathOut` (`app/schemas/attack_path.py`), which the attack-path
routes reuse.

**Risks second**, all four routes, unchanged but for `observed_at`, which is
written `Z` for the same reason as `accepted_until`. A risk's `path` is not
`AttackPathOut`: it is the list of hops the correlation stage stored at scan
time (`services/scan/correlation.py`), six keys since the column was first
written and never the `facts` and `detail` a live route computes -- which the
web types claimed it had, and nothing read. It is `RiskPathStepOut`, every
field a plain string rather than an enum, because it is read back from JSONB
and a value renamed since would otherwise turn a stored route into a 500. The
web types split the same way: `RouteStep` is the stored hop, and
`AttackPathStep` extends it. `score_breakdown` stays open for the same reason
-- it is stored as scored, in two shapes. A queue row is `RiskListItemOut`, the
risk with its `finding_count` and `route_count`; the detail is `RiskDetailOut`,
with `observed_at` and the member findings.

**Attack paths third**, all nine routes, and here the serializers change rather
than the routes: every `serialize_*` in `services/graph.py` returns its model --
`AttackPathOut`, `RouteMapOut`, `NeighborhoodOut`, `EstateOut`, `AccessOut`,
`SimulationOut`, `ChokePointOut`, `DeadEndOut` -- so a drawing is typed where it
is built, and the finding page's routes and the route map's are the same
`serialize_path` model rather than a dict each spread and extended. Unlike a
risk's stored route, all of this is computed from the graph on the request, so
relationships, resource types, levels and kinds are the enums themselves. An
estate box carries different fields by what it holds, and is a union
discriminated on `kind` -- `ScopeBoxOut`, `GroupBoxOut`, `AssetBoxOut`,
`FoldBoxOut` -- rather than one model of optional fields, which would have sent
an asset's fields as `null` on every scope. Diffed over the demo estate (thirty
responses, including an opened fold, a route pattern, a plan that closes only
together, and the three 404s), one thing changed: the list's `meta` carries
`dead_ends` and `dead_ends_total` as `null` when there are routes, rather than
leaving them out. They are worked out only when there is none, and a schema
that has the key sometimes is harder to read than one whose value says "not
asked"; the page reads both with `??`.

**Rules fourth**, both routes, and with them the two objects a finding's detail
had left open. `remediation_detail` returns `RemediationSpecOut` and
`prowler_detail` returns `ProwlerCheckOut` or `ProwlerCrossCheckOut`
(`app/schemas/rule.py`), so the rules page and the finding page publish one
type each. An expected state is a union discriminated on `comparison`:
`equals` and `also_accepts` exist only on an equality, because a collection
expectation with `equals: null` reads as "this must be null". The Prowler
detail is a union with no discriminator -- its two shapes share no key and each
has keys the other lacks -- and changing the payload to add one was not worth
it. `azure_policy` stays `dict[str, Any]`: it is Azure's policy document, and
restating Azure's schema here would be a second copy to keep true. The mirror's
own columns are plain strings, severity aside, because a rule removed from the
registry stays in the table disabled and a renamed value would otherwise fail
the whole list. Over all 804 rules, one thing changed: an expected state with no
example sends `example: null` rather than leaving the key out, which nothing
reads. Validating on the way out has a price here that the smaller routes do
not show: the full list costs about 106 ms rather than 85 through the test
client. That was taken as the cost of a list that cannot drift from its schema;
if it ever matters, the list is the route to cache, not to untype.

**Remediation fifth**, all three routes. The queue is `RemediationOut` with
`on_routes` set on the model rather than spread into a copy of it, and an
update answers `RemediationUpdatedOut`, whose `note` -- what happens after a
task is marked done -- is `null` on any other change rather than missing. The
page reads it with `??`, as it did the missing key. Nothing else in the three
responses changed.

**Changes, notifications, compliance and the dashboard sixth**, together, and
here the rule above -- build models, not dicts -- has an exception it needed a
tool for. The dashboard and the compliance frameworks are built as dicts by
their services because other readers take the same dicts: the PDF report, the
compliance export (which pops keys from the detail to reshape it), and a dozen
pipeline tests. Rewriting the services to build models would move every one of
those readers onto attributes for no gain to them. So the route validates the
finished dict instead, against models that are `ClosedModel`s
(`app/schemas/common.py`): `extra="forbid"`, so a key the service adds and the
schema does not declare fails the request rather than being dropped from it --
the silent loss that made "models, not dicts" the rule. A unit test holds that
refusal in place. Changes and notifications build their models directly, as
before. The compliance export stays a file, not an envelope, declared with its
two media types; the guard test lists it in `FILES` rather than exempting file
routes by shape, so a new one is a decision somebody writes down. The dashboard
was compared by answering its eighteen queries in order, for an estate with a
scan and one without; compliance through its real resolution over the whole
registry, every framework. The only change across them is time: every
timestamp these four wrote with `isoformat()` is now written `Z`, as the rest
of the API already did.

**Scans seventh**, all eleven routes. The detail and the event stream were one
builder so that a pushed state and a polled one are the same document (§88);
they still are, and now the builder returns `ScanDetailOut`, which the stream
dumps to JSON for each tick and the detail route returns as its envelope's
data. The scope, the stages and the collection status stay dicts in
`services/scans.py`, which the pipeline tests read, and are validated at the
route as `ClosedModel`s. The stream is not an envelope: it is declared as
`text/event-stream`, with its four events described, and joins the export in
the guard test's list of routes that answer with something else, now named
`NOT_ENVELOPED`. Compared across twenty cases -- every refusal, a broker that
would not take the message, each of the worker probe's three answers, and the
stream read to its end -- the stream's text is unchanged, and the only change
elsewhere is a collection task's `collected_at` written `Z`.

**Cloud connections eighth**, sixteen of eighteen routes. `CloudConnectionOut`
now declares the four fields `_serialize` had been adding beside it
(`role_required_version`, `degraded_categories`, `change_events_enabled`,
`last_change_event_at`), and `_serialize` sets them on the model. The unit tests
caught one thing the comparison did not: a connection built in memory has not
had its column defaults applied, so `change_events_enabled` is `None`, which the
old code coerced after dumping and the model now refuses on the way in -- it is
coerced by a validator on the model, as `provider_ref` already was. The
provider onboardings' dicts -- the app registration, the revocation steps, the
revocation check -- and the change-event setup stay dicts and are validated at
the route as `ClosedModel`s. The revocation is one model for both clouds: AWS
adds `external_id_note`, `account_id` and `managed_policies`, which Azure now
sends as `null` rather than omitting, and nothing on the page reads them. The
ARM template and the consent callback are not envelopes -- the portal fetches
one from any origin and Entra redirects to the other -- and are hidden from the
schema as before; the guard lists them and skips hidden routes when checking
documented errors. Compared over twenty-four cases, both clouds, with an
administrator's and a viewer's view of the consent link: the times are written
`Z`, and Azure's revocation carries the three `null`s.

**Cloud accounts, organizations and the engine audit ninth; reports and the
event webhook declared rather than typed; `/health` typed.** Cloud accounts
documents its errors per route rather than on the router, because the Azure
permissions list is public and would otherwise claim a 401 it never sends; a
declaration that has been cleared is `data: null`, typed as such.
Organizations documents 401 and 422 for all, and 404 only where a route looks a
membership up -- most of them act on the caller, not inside an organization. The
engine audit is built as a dict and validated as `ClosedModel`s, with the
scanner's kinds, outcomes and states left as strings: a separate service on its
own release writes them, and a value it adds should reach the page rather than
fail the audit. A report is a PDF or an HTML page, declared with both media
types; the change-event webhook answers the provider in the provider's terms
and stays out of the schema. Compared over eighteen cases, the one change is
the audit's scan time written `Z`.

The guard test stopped naming the converted routers and now walks every route
in the app, with two lists beside it: `NOT_ENVELOPED`, six routes answered with
something else, each checked to still exist so a stale entry cannot exempt
whatever lands at that path next; and, for one commit, `UNCONVERTED`, which
held `/api/v1/assets`. That router had been left off every list of what
remained, and the first run over the whole app is what found it. The error
check now asks the stronger question -- every documented 4xx or 5xx is
`ErrorEnvelope`, and `HTTPValidationError` is nowhere in the schema -- rather
than looking for three codes, because not every route can answer 401 or 404.

**Assets last**, all four routes, and with them `UNCONVERTED` is gone: the
guard walks every route in the app with no exemption but the six that answer
with something else. The list is `AssetRowOut` under `AssetsMeta` (the page
plus `unchecked` and the facets); the hierarchy, accumulated as dicts by scope,
is validated as `ClosedModel`s; the detail is `AssetDetailOut`, with each
context value's provenance as `ContextFactOut`. `resource_type` is the enum,
because the column already is one -- a value it did not know would fail on load
before it reached a response. Compared over nine cases -- the list filtered and
empty, the hierarchy with a directory bucket, a subscription asset and a
directory one, and the 404s -- the only change is the asset times written `Z`.
The published schema now has a typed success for every JSON route; the three
without one are the compliance export, the reports and the scan's event
stream, each declared with its own media type.

`tests/unit/test_typed_responses.py` walks every route under the converted
prefixes and fails on one that returns anything but an `Envelope`, or that
publishes FastAPI's 422 instead of `ErrorEnvelope`. Its `TYPED` list grows a
router at a time until it covers `/api/v1`, and then goes.

## 158. Nothing a stranger or a download can trigger holds the event loop or the pool

A review of the whole API against FastAPI's practices found five problems
that a single request could cause. Three of them stall the process, one
answers 500 where it should answer something else, and one leaves a scan
queued that nothing will ever run.

**The JWKS fetch ran on the loop, once for every unknown key id.**
`PyJWKClient` fetches synchronously, with a 30-second default timeout, from
inside an async dependency. It also fetches again for every `kid` it does not
recognise, and the `kid` comes from the token's unverified header. A stranger
sending tokens with random key ids could make every request on the process wait
for a round trip to Supabase, health checks included. `SigningKeys`
(`core/security.py`) replaces it:

- The fetch is awaited through httpx, bounded at 5 seconds.
- It happens at most once per 30 seconds however many unknown ids arrive.
- A fetched set is trusted for five minutes, so a key Supabase revokes stops
  verifying within that time.
- Concurrent first requests share one fetch.
- A failed fetch keeps the last set, so an unreachable Supabase does not sign
  out everybody whose token it has already vouched for.

`decode_token` is now async, and so is `get_current_user`.

**Reports rendered on the loop.** WeasyPrint is synchronous and CPU-bound, so
one technical PDF blocked every other request, scan streams included, for as
long as the render took. HTML and PDF now render in a worker thread. PDFs pass
through a `CapacityLimiter(1)`, which bounds the CPU a burst of downloads can
take and means WeasyPrint's native libraries are never entered from two threads
at once.

The limiter created a second problem, and it is fixed in the same change. The
request's `rls_session` holds a pooled connection until the handler returns, so
every download waiting for the render slot held one. The app pool is ten plus
five, so fifteen queued downloads would exhaust it and every other request would
wait out the pool timeout. The route now closes the session once `build_report`
has read everything. The transaction only read, so the rollback that close
performs loses nothing.

**A report for "Łódź" or "東京" was a 500.** The filename slug keeps any letter
`isalnum` accepts, and a header value is Latin-1 on the wire. The name now
travels in `filename*` as percent-encoded UTF-8 (RFC 6266). `filename` beside it
keeps the ASCII remainder for clients that read nothing else.

**A scan the broker refused was left queued, and the request answered 500.**
`POST /scans` and `/replay` commit the scan before sending its message, so a
worker never picks up an id it cannot read yet. On a send failure they set the
scan `FAILED` and committed again. That second commit ran on `rls_session`,
whose transaction had already ended and cannot begin again inside
`session.begin()`, so it raised "Can't operate on closed transaction inside
context manager". The customer got a 500 and the scan sat queued: the one
outcome the branch existed to prevent. No test covered the branch.

`scans.enqueue_or_fail` now records the failure in a fresh `rls_session` for the
same user, so the write is held to the same tenant as the insert. It writes the
in-memory row as committed values so the caller's session has nothing to flush.
The message no longer carries the broker's exception, which is written for an
operator and can include a connection string; the exception is logged instead.
`GET /scans/worker-status` quoted the same exception to any member when the
broker could not be pinged. It now returns a fixed sentence naming what to check
(the Redis service and `REDIS_URL`), and the exception goes to the log.
`POST /findings/{id}/rescan` never guarded its send at all. It now goes through
the same helper and answers 503 `QUEUE_UNAVAILABLE`, because nothing on the
finding's page shows a scan record where the failure could be read.

**Found and deliberately not fixed here.** Graph construction and `simulate`
still run on the loop. The graph is cached per data version, so the cost is the
first request after each scan and each simulated plan, and it stays until an
estate is large enough to measure. (Section 161 moves both off the loop and
pins `anyio`.) `anyio` is not pinned directly; the
import-time `CapacityLimiter` needs a 4.x release that allows one outside a
running loop. FastAPI 0.118 moves the teardown of a `yield` dependency to after
the response is sent, which would keep `/scans/{id}/events`' request session
open for the whole stream. That route must stop depending on `DbSession` before
FastAPI is upgraded past 0.117.

## 159. Remediation work is assigned only to members of the organization

`assigned_to` on a remediation task was any UUID. Nothing checked it against
the organization, so a mistyped id, a colleague who had left, or a user of
another tenant was stored as the owner of work they could never see. That leaks
nothing, because the other tenant's user cannot read the row. But the task is
owned by nobody who can act on it, and the audit row records an assignment that
never happened.

`POST /remediation` and `PATCH /remediation/{id}` now refuse an assignee who is
not a member, with 422 `VALIDATION_FAILED`, before reading the finding or the
task. The check (`organizations.is_member`) runs under the caller's row-level
security, which already shows a member everyone else in their own
organizations. A user of another tenant therefore reads as absent, which is the
right answer for them. The demo shows a visitor only themselves, but nothing is
written there, so the check is never reached in it.

Any member may be assigned, a VIEWER included. The field records who is
expected to do the work, not whether they may change the task in CloudGuard,
and the fix itself usually happens in the customer's cloud. Clearing an
assignee is still not possible, because `null` in the PATCH means "unchanged";
that is a separate change to the update contract.

## 160. The consent callback shows Entra's words only under a state it signed

`/cloud-connections/azure/consent/callback` is unauthenticated by necessity:
Entra sends the browser there. When the `state` failed to verify, the callback
still redirected to `/connections?consent_error=` carrying the request's
`error_description`, or failing that its `error`, and the Connect page printed
it. Nothing in such a request shows that Entra sent it, since anyone can build
the URL. So a link on CloudGuard's own domain could put any sentence on
CloudGuard's own page, for example "Your tenant is compromised, call this
number". React escapes it, so this is text rather than script, but the text
reads as the product's, and phishing needs nothing more.

An unverified request now shows only CloudGuard's own reason
(`_consent_link_problem`): that the link expired or was issued for something
else, or that it is not valid. Entra's `error_description` is still passed
through where it matters, on the setup step. That branch runs only for a state
this API signed within the last half hour. The state names one connection, and
its setup page opens only for a member of that connection's organization, so a
stranger's link leads nowhere they could use. A denial whose link has also expired loses Entra's
reason,
and the customer is asked for a fresh link. They would be asked for one anyway.

## 161. Graph work runs off the loop, limits count people, and every request has an id

A second pass over the backend against FastAPI's practices, checked against
the three reviews of 2026-09-20. Five changes, all small, each closing a
failure that one request or one deploy could cause. Three candidates were
examined and deliberately not built; they are listed at the end with why.

**Graph work runs in a thread.** Section 158 left graph construction and
`simulate` on the loop until an estate was large enough to measure. The case
for waiting was weaker than it looked: the API runs as one uvicorn process with
no `--workers`, so while one tenant's cold graph was being built, or a plan
simulated, every other tenant's request waited, `/health` included, and
Railway restarts a service whose health probe stops answering. The fix costs
one thread hop per call.

- `services/graph.off_loop` runs a callable in a worker thread through a
  `CapacityLimiter(2)`. Two rather than one, so a short what-if on a warm graph
  does not queue behind somebody else's cold build. The limit keeps a burst of
  cold graphs from taking every thread in the pool that the rest of the API
  shares.
- `load_graph` reads the rows on the loop and hands them to `_assemble`, which
  builds the graph and walks its routes in the thread. The routes are memoized
  on the graph and almost every reader asks for them first, so the first reader
  finds them done.
- The attack-path routes run their own analysis through `off_loop`: the route
  map (which reads link severance), choke points, blast radius, access, the
  neighbourhood, the estate map, what-if, simulate and dead ends.

Nothing holding a database session crosses into the thread; the session
belongs to the loop. The graph's memo fields are filled by
check-compute-assign on plain dicts. Two threads computing the same entry at
once both produce the same deterministic value, and the dict assignment is
atomic, so a race costs duplicated work rather than a wrong answer. A lock was
not added for that reason. `anyio` is now pinned in `pyproject.toml`, because
two limiters are created at import time.

**The fair-use rate limit counts people, not addresses.** API_REVIEW Finding 9.
`RateLimitMiddleware` runs before any token is verified, so it can only count by
address, and a customer's office is one address: fifty people behind it shared
300 requests a minute, six each. The middleware's ceiling for credentialed
requests becomes a flood guard (1,200 per address per minute). The fair-use
limit moves to `get_current_user`, which counts 300 per verified user per
minute after `decode_token` succeeds. A token that fails to verify is never
counted, so nobody can spend a colleague's allowance by naming them in a forged
token.

A second, smaller allowance (`limit_costly`, 20 per user per minute) guards the
requests that cost far more than a read: starting or replaying a scan, a report
render, what-if and simulate, and the connection checks that call the provider
(discover, recheck, check-revoked). A route opts in with
`dependencies=[Costly]`. Both answer 429 `RATE_LIMITED` with `Retry-After`, and
both fail open when Redis is unreachable, as the middleware does.
`AppError` now carries headers through to the response for this. The counter
itself (`middleware.over_limit`) is shared, so there is one implementation of
fixed-window counting.

**Every request has an id.** The scan pipeline has bound its ids into log lines
since `log_context`. The request path had nothing, so lines from concurrent
requests could only be matched by timestamp. `RequestContextMiddleware` is now
the outermost layer:

- It mints a UUID per request and binds it into structlog's context, so every
  line the request logs carries it.
- It returns the id in `X-Request-ID`, exposed through CORS so the frontend can
  read it.
- The envelope of an unhandled 500 carries it in `meta.request_id`, so the one
  string a customer can quote finds the failure in the logs.

The id is always minted by the server and never taken from the caller's own
`X-Request-ID`, because it is written into the audit trail, and an id a client
could choose is one it could make collide with somebody else's entries. The
middleware also records the caller's address as the rate limit sees it
(`client_address`, validated as an IP). Both values live in context variables
(`core/request_context.py`), so service code reads them without being handed
the request, and reads `None` in the worker, where there is no request.

**Two migrations cannot run at once.** Every API instance runs
`alembic upgrade head` as it boots. Two instances booting together, from a
scaled service or a restart that overlaps a deploy, would both read the same
version and both apply the next migration. The second fails on a table that now
exists, and its instance crash-loops. `database/migrations/env.py` now takes
`pg_advisory_xact_lock` inside the migration transaction before Alembic reads
the version. The second runner waits, then finds nothing left to do. The lock
is transaction-scoped rather than session-scoped, so it holds through
Supabase's transaction pooler and is released by the commit however the run
ends.

**Celery no longer stores results nobody reads.** Nothing in the API or the
scanner reads a task's return value. A scan's state is its rows, written
fenced on the attempt. Every task still wrote a result to Redis, kept for a day:
four sweeps a minute plus every step. Both apps now set `task_ignore_result`,
which also retires `task_track_started`.

**Examined and not built.**

- _A graph version counter in place of the aggregate check._ `graph_version`
  takes `max()` and `count()` over the tenant's assets and edges on every read.
  A counter bumped by ANALYZE would be one indexed lookup. But it is correct
  only if every write path bumps it, and a path that missed would serve routes
  through an estate that has moved, which is the one failure the cache was
  designed never to have. The aggregate catches every writer by construction.
- _A separate beat service._ Running the scheduler inside the worker would
  double every sweep if the worker were ever scaled past one replica. Every
  sweep is already idempotent, though: notifications have a unique index,
  scan starts take the per-target advisory lock (section 65), and reaping and
  expiry are conditional updates. Doubling costs queries, not correctness, and
  a new Railway service is an operational change without a failure behind it.
- _Trigram indexes and cursor paging for findings._ The search is an `OR` across
  a finding and its joined resource, which a trigram index on each table cannot
  serve as one scan. Nothing measured says the current plan is slow. This waits
  for an `EXPLAIN` on a production-sized estate.

## 162. Colleagues join by invitation, and members are managed in Settings

An organization had exactly one way to gain a member: be created by them. The
membership policies were right to refuse everything else. Only an OWNER or
ADMIN may insert an `organization_members` row, which is what stops anybody
writing themselves into another tenant. But nothing had been built on top of
those policies, so the person who connected the cloud was the only person who
could ever see it. The 2026-09-20 product review ranked this first: the buyer
of a CSPM is rarely the person who fixes what it finds.

**An invitation is a link, and it works only for the invited address.**
`POST /invitations` (owners and admins) stores an address, a role and the
SHA-256 of a 32-byte random token, and returns the link once. Cleave sends no
email, because it has no mail provider and adding one is its own decision; the
inviter passes the link on however their team talks. Acceptance runs through
`app.accept_invitation(token_hash)`, a SECURITY DEFINER function, because the
invitee is not a member yet and no membership policy may let them insert
themselves. Inside it, three checks: the invitation is neither used nor
withdrawn, it has not expired (seven days), and it names the address on the
caller's own verified token. That address is read from the request's claims
(`app.user_email()`), not passed as an argument. `rls_session` now carries the
token's `email` claim, as Supabase's own PostgREST does, so the function reads
what Supabase signed. A forwarded link joins nobody. `app.peek_invitation`
lets the acceptance page say which organization and role the link offers, and
whether the signed-in account is the invited one, before the click.

The binding is only as strong as the token's `email` claim. That claim proves
ownership of the address only because Supabase gives no session to an
unconfirmed address, so the project's **Confirm email** setting is now a
security control, and `docs/DEPLOYMENT.md` says so. With confirmation off,
anybody could sign up as an invited address and accept its link.

Several smaller choices follow from treating the token as a credential:

- **Only the hash is stored**, so a read of the invitations table joins nobody
  to anything.
- **The token travels in the URL fragment** (`/invite#<token>`), never in a path
  or query, so it is not sent to any server, kept in an access log or leaked in
  a Referer. The page removes it from the address bar once read, and sends it
  to the API in a POST body.
- **Inviting an address again replaces its open invitation.** The old link stops
  working. A partial unique index allows one open invitation per address.
- **An accepted or withdrawn invitation is kept as history.** Nothing deletes
  one through the API, and the table has no DELETE policy.
- **Nobody is invited straight into ownership.** The schema refuses `OWNER` and
  the table has a CHECK against it. Ownership is granted by an owner to
  somebody already inside.
- **Accepting never changes an existing member's role.** An address that is
  already a member is refused at invite time rather than offered a role it
  would not get.

A link opened while signed out is held in `localStorage` for a day
(`lib/pendingInvite.ts`). Every way of signing in lands back on the site's
root, and the shell sends a signed-in reader holding one to `/invite` before
anything else. Without that, an invitee with no organization would be walked
into creating one.

**Members are listed to everyone and managed by owners and admins.**
`GET /members`, `PATCH /members/{id}` and `DELETE /members/{id}`. The
membership policies already allow owners and admins to update and delete.
Two rules they cannot express are enforced in `services/team.py`, in a pure
function tested as a matrix:

- **Only an owner makes, changes or removes an owner.**
- **The last owner stays.** Owners are counted with their rows locked
  (`FOR UPDATE`), so two owners demoting each other at once cannot both see the
  other still standing.

A member's address is now on their membership (`organization_members.email`),
because the address itself lives in Supabase's `auth` schema, which the
application role cannot read. It is copied from the verified token: at
acceptance from the invitation, and by `app.record_member_email()`, which
`get_tenant` calls only when the token's address differs from what is stored.
The function touches the caller's own rows and nothing else. Rows that existed
before this change show "address shown after their next sign-in" until then.

Every change is audited through the one writer (`services/audit.py`, section
163): `invitation.created`, `invitation.revoked`, `invitation.accepted`,
`member.role_changed` and `member.removed`.

**Not built here.** A member other than an owner or admin cannot leave an
organization on their own, because `member_delete` needs OWNER or ADMIN; that
wants its own SECURITY DEFINER door, as leaving the demo has. Scoping a member
to some subscriptions only, which the product review also asked for, is a
change to every tenant policy and is not attempted. Remediation tasks assigned
to a removed member stay assigned (section 159 checks membership at assignment
time only).

## 163. The audit trail is append-only, complete, and readable

`audit_logs` has existed since the first migration, and `docs/SECURITY.md` has
promised since then that accepted risks "remain auditable via `audit_logs`".
Four things made that promise weaker than it read.

**Any member could rewrite it.** The table was created as one more tenant table
and inherited the uniform policy set, so any member could UPDATE and DELETE any
row of their organization: a VIEWER as readily as an OWNER. The API never
offered an edit, but the database would have accepted one, and an audit trail
that its subjects can rewrite is not evidence of anything. Migration 0045
revokes UPDATE and DELETE from `authenticated` and from `cloudguard_worker` and
drops their policies. Rows still go when their organization is deleted,
because a foreign-key cascade runs as the table's owner. SELECT narrows to
owners and admins, plus a member's own entries. The second arm matters as well
as being fair: an INSERT that returns its row must pass the SELECT policy, and
a member writing their own entry must be able to.

**Several changes were never recorded.** Findings, risks, remediation, context
declarations, schedules, change detection and acceptances wrote entries. These
did not, and now do:

- connection created, deleted, scope changed, setup cancelled or resumed
- scan started, replayed, cancelled or deleted
- organization edited
- everything in section 162: invitations and members

A deleted connection's entry is written before the cascade, while there is
still a name to record. The provider checks (discover, recheck, check-revoked)
are not recorded, because they change what CloudGuard knows rather than
anything a person decided.

**Entries said what but not whence.** `ip_address` was never filled. There is
now one writer, `services/audit.record` (`findings.record_audit` is an alias for
its existing callers). It stamps the caller's address and the request's id
(section 161) on every entry, from context variables, so no call site has to
remember to. The id finds the request's log lines. In the worker both are
`None`, which is the true answer there.

**Nobody could read it.** `GET /audit-log` (owners and admins) returns the
trail newest first, paged, with the actor's current address joined from their
membership. The query filters by one action (`member.removed`), by an action
family (`member.`, the trailing dot is the signal), by actor, or by resource
type. Settings shows it as **Activity** to owners and admins. An entry by
somebody since removed shows "a former member", because their id stays on the
entry while their address no longer has a membership to be read from.

## 164. Notifications reach Slack, Teams and signed webhooks, and a customer's URL cannot reach inside

The bell was the only place a notification arrived. The notification sweep
already decides carefully what is worth interrupting somebody for: three kinds,
a reachable finding, a verified fix and a reading that stopped arriving
(`NotificationKind`). But nobody sits watching a CSPM tab, so that
judgement reached no one. The 2026-09-20 product review ranked outbound alerts
second, after invitations.

**An endpoint is a URL, a format and the kinds it wants.** Owners and admins
manage them in Settings under **Integrations** (`/webhooks`), at most twenty per
organization. There are three formats:

- **Slack**: an incoming webhook, sent `{"text": ...}` with mrkdwn's three
  control characters escaped and a link back into Cleave.
- **Teams**: a workflow webhook, sent a message carrying an Adaptive Card 1.4
  with an "Open in Cleave" action.
- **Generic**: signed JSON for anything the customer runs. Each request carries
  `X-Cleave-Event`, `X-Cleave-Delivery`, `X-Cleave-Timestamp` and
  `X-Cleave-Signature`, which is `sha256=` followed by the HMAC of
  `<timestamp>.<body>` under the endpoint's 32-byte secret. The timestamp is
  inside what is signed, so a captured delivery cannot be replayed with a fresh
  one.

Two values in this feature are credentials, so each is handled as one:

- **The generic endpoint's secret** is returned once, on the answer that
  created it.
- **A Slack or Teams URL is itself the credential.** The API never hands a
  stored URL back whole, only its host and last four characters.

**A delivery is owed once and retried until it lands or is given up on.**
`webhook_deliveries` holds one row per endpoint and notification, unique on the
pair. The notification sweep enqueues in the same transaction that writes the
notifications, with one `INSERT ... SELECT ... ON CONFLICT DO NOTHING`, so a
notification never exists without its deliveries and a sweep that runs twice
owes nothing twice. An endpoint is owed only notifications written after it was
created, and none older than a day, so a new channel is not flooded with last
week.

A separate beat task (`deliver-webhooks`, every minute) sends what is due. It
claims up to fifty deliveries with `FOR UPDATE SKIP LOCKED`, pushes their next
attempt five minutes out as a lease, and commits before sending anything, so
no transaction is open while somebody else's server takes its time, and an
overlapping sweep skips what this one holds. Sends run five at a time with a
five-second timeout. A failure is retried after 1 minute, 5 minutes,
30 minutes, 2 hours and 6 hours, and after the sixth attempt it is marked
`FAILED` and kept, so an admin can see what was lost. Each endpoint records its
last success and last failure with the receiver's answer (the first 300
characters), and Settings shows both. **Send test** posts a message that says
it is a test and reports what came back. It releases the request's database
connection before sending and records the result in a fresh session, following
section 158.

**A customer's URL cannot reach anything inside.** This is the first place a
customer chooses where this service sends a request, and the worker sits in
Railway's private network beside Redis, the database pooler and the cloud
metadata address. `core/outbound.py` is the only way these requests are made,
and it enforces four rules:

1. **HTTPS on port 443 only.** No userinfo, and no `localhost`, `.local` or
   `.internal` names.
2. **Every address the name resolves to must be public.** Private, loopback,
   link-local (the metadata address), shared (100.64/10), reserved and
   multicast ranges are refused for IPv4 and IPv6, and an IPv4-mapped IPv6
   address is judged as the IPv4 it carries. One bad answer refuses the URL,
   because the connection could land on any of them.
3. **The connection is pinned to the address that was checked.** The request
   goes to the IP, with the real name in `Host` and in TLS's server name
   (httpx's `sni_hostname` extension). A name that resolves somewhere public
   when checked and somewhere private a moment later (DNS rebinding) therefore
   cannot move the connection, and the certificate is still verified against
   the name the customer gave.
4. **No redirects are followed, and no proxy from the environment is used.** A
   3xx is recorded as a failure like any other answer.

A URL is checked when it is typed, and a refusal is a 422 to the person typing
it, then checked again at every send.

**The tables** (migration 0046): owners and admins read and write endpoints and
read deliveries. `cloudguard_worker` reads endpoints and records outcomes on
them, and inserts and advances deliveries, each held to the organization it
declared. `deliver_due` is the one service function allowed to commit
directly, because it runs only under `scan_session` and has to commit between
claiming and sending (`tests/unit/test_request_transaction.py`).

**Corrected after review, the same day it shipped.** A FastAPI review of the
backend found two faults in this section's code, and both are fixed:

- **Every delivery owed in one sweep shared one id.** `insert().from_select()`
  keeps the model's defaults by default, and SQLAlchemy computes a Python-side
  default (`uuid.uuid4`) once per statement, not once per row. The second row
  owed in a sweep collided with the first on the primary key, and because
  enqueueing shares the notification sweep's transaction, the organization's
  bell notifications rolled back with it, every five minutes, logged as a
  derivation failure. Only an organization with a webhook and two or more
  deliveries owed at once was affected, and none was yet. `enqueue` now passes
  `include_defaults=False`, so the table's own defaults give each row its id,
  and it runs in a savepoint, so a fault in the webhooks can never again take
  the bell down with it. Every earlier test owed exactly one delivery, which is
  why none caught it; a test now owes four.
- **A receiver could stall the sweep.** httpx's timeouts are per phase and its
  read timeout restarts with every chunk, so a receiver answering one byte
  every few seconds was never cut off. It held the sweep until Celery's limit,
  and when the five-minute claim lease ran out the next sweep sent the same
  deliveries again. `post_json` now runs the whole call, from lookup to answer,
  under a ten-second deadline (`outbound.DEADLINE`). It reads a refusal's body
  as a raw stream only as far as 4 KiB, so an endless or compressed body costs
  a few kilobytes. An attempt is now counted when it is claimed rather than
  when it returns, so a delivery that keeps killing its sweep is given up on
  after its last attempt instead of retried for ever. A sweep also stops
  starting new organizations after ten minutes and leaves the rest for the
  next one.

**Not verified live.** The Slack body is the documented incoming-webhook shape.
The Teams body is the documented workflow-webhook shape, but it has not been
tried against a live Teams workflow, and **Send test** is how a customer finds
out. PagerDuty, per-severity routing and an automatic pause after repeated
failures were left out: each is a decision about paging people, and should wait
until somebody is using the three formats above.

## 165. A pressed button keeps focus, a filtered list says its count, and every raw control draws a solid focus line

A second accessibility pass, against the checklist §155 did not walk: what a
screen reader hears after something changes, and where focus is left when a
control changes under it. Three gaps, each across the app rather than in one
place.

**A button that disables itself kept focus nowhere (2.4.3, 2.1.1).** Forty-one
buttons disable themselves while their mutation runs -- invite, revoke, save,
accept, rescan, send test -- and more disable themselves as a result of what
they did: a form whose success clears its fields leaves its submit button with
nothing to send, and a pager's Next is disabled on the last page it just
reached. A natively `disabled` button that holds focus loses it to `<body>`, so
the next Tab started again at the skip link and the navigation, and a screen
reader said nothing at all about the press. The vendored `Button` now passes
Base UI's `focusableWhenDisabled` by default: an unavailable button is marked
`aria-disabled` rather than `disabled`, stays in the tab order, and Base UI
refuses the press itself -- the click, Enter and Space, and a form's implicit
submission, whose synthetic click it cancels. The styles follow it with
`aria-disabled:` beside `disabled:`. A caller that wants the native behaviour
passes `focusableWhenDisabled={false}`; none does. The cost is that a button
unavailable because a precondition is unmet (a delete waiting for the
organization's name) is now a tab stop that says "dimmed" -- which is also how
a reader finds out the control exists and why it will not act. The three raw
`<button>`s outside the primitive that disabled themselves -- the sign-in and
set-password submits and the onboarding demo card -- carry `aria-disabled` and
refuse the press in their own handlers. Tests assert `aria-disabled`, not
`toBeDisabled()`, which reads only the native attribute.

**Filtering a list said nothing (4.1.3).** On Findings, Risks, Assets, Rules and
the attack-path route list, a filter or a search redraws the table and the
count beneath it while focus stays in the search box or on the segmented
filter. A sighted reader sees "1–4 of 4 findings matching these filters" or an
empty state; a screen reader heard neither, so could not tell that the filter
applied or that it left nothing. `LiveStatus` (`components/common`) is a polite
`role="status"` region mounted with the page -- a region that arrives already
holding its text is not reliably read -- which takes the same count line the
page draws, or the empty state's title, once it has held for 400 ms. The delay
is so that a search filtering on every key says the count the reader stopped
on, not one per letter. With `quietFirst`, the first count is the starting point
rather than news: on arrival the page's heading has focus and is being read,
and the count would talk over it. While the list is loading or failed the
message is `null`, and the region keeps what it last said. Each page builds its
count line once and draws the same string it speaks, so the two cannot drift.
The invitation form and the webhook form use the same region, without
`quietFirst`, for the panel their success draws below them -- "the link is
ready", "the secret is ready" -- which focus, still on the submit button, would
otherwise never reach.

**Nineteen raw controls had only the browser's ring at half strength (2.4.7,
1.4.11).** §155 gave `focus-ring` to controls that drew a halo with
`outline-none`. Controls that drew no focus style at all were left with the
user agent's outline, and the base layer's `outline-ring/50` recolours that to
the same half-strength ring §155 measured at 1.9:1. They are the account menu's
trigger and rows, the error boundary's reload, the scan indicator, the route
list's rows and group members, the filter chips' clear buttons on Findings and
Assets, the coverage panel's expander, the dashboard's quiet actions, the
set-password submit, and the sign-in page's text links and show-password
toggle. Each takes `focus-ring`, or `focus-ring-inset` where the row fills a
container that would clip an outline drawn outside it.

**Smaller.** The set-password form's "passwords don't match" is about the
confirmation field, so that field is `aria-invalid` and described by the
message while it shows. The sign-in button's spinner is `aria-hidden`; the
label beside it already says "Signing in…".

**Not changed.** Field-level `aria-invalid` elsewhere: the other forms'
errors come back from the API about the request as a whole, and a field
marked invalid by a guess is worse than a form-level alert that is right. A
page change in the pager leaves focus on the pager rather than moving it to the
table; the count line is spoken instead, which says what moved without taking
the reader away from the control they are paging with.

## 166. One line of copy, one type scale, and the rest a question mark away

The interface had become a document. The English catalogue (`i18n/en.ts`) held
about 5,970 words across 886 strings; 134 of them ran past 80 characters and
51 past 150, and several components carried more prose inline. Most of it was
true and some of it was important -- what Cleave can and cannot do in a
customer's tenant, why UNKNOWN is not a pass -- but it was printed on every
visit to a screen whose reader had already read it, and it pushed the numbers
and actions below the fold. Beside it the type had drifted: eighteen
hand-typed pixel sizes (`text-[11.5px]`, `text-[13.5px]`, `text-[12.5px]`...)
used 240 times, and page titles drawn nine different ways. This is the first
of a series of passes toward a quieter interface; this one lays the rules the
later ones are held to, and changes little a reader will notice.

**A type scale of nine steps.** `index.css` declares `--text-micro` (10px),
`caption` (11), `meta` (12), `body` (13), `title` (15), `heading` (18), `page`
(22), `stat` (28) and `display` (32), in rem so a reader's browser font size
still scales the page. Every pixel size was mapped onto the nearest step --
half pixels down, 14 and 14.5 up to `title`, 17 and 19 to `heading`, 26 to
`stat`, 36 to `display` -- so a few figures moved by a pixel or two, and the
two 36px scores on the finding and risk pages are now 32. No step carries a
line height: Tailwind emits `font-size` alone, the element inherits its
leading exactly as it did under `text-[13px]`, and a caller that wants its own
says `leading-*`. `tailwind-merge` knew none of the names and reads an unknown
`text-*` as a colour, so `cn("text-body", "text-muted-foreground")` would have
dropped the size; `lib/utils.ts` extends it with the scale (`TYPE_SCALE`), and
`lib/format.ts`, which had its own `cn`, re-exports that one. A test
(`lib/__tests__/designBudget.test.ts`) fails on any `text-[Npx]` outside the
vendored primitives and the tests. It is a test rather than an ESLint rule
because the development environment's configuration guard refuses edits to
`eslint.config.js`; the check is the same and runs in CI with the rest.

**One page title.** `PAGE_TITLE_CLASS` (`components/common/states.tsx`) is the
h1 of every page that draws its own header block -- a detail page's name among
its badges, the sign-in card -- and `PageHeader` uses it too. The dashboard's
empty state uses `PageHeader` instead of its own copy of it. The error fallbacks
(`ConfigError`, `ErrorBoundary`) keep their smaller heading: they render when
the app has failed, inside a card, and are not pages.

**The copy budget.** A string in `en.ts` is at most 90 characters -- about one
line of a panel at the reading size -- unless its key ends `Explain`. An
`Explain` string is rendered only through `InfoTip` (`components/common`), a
question-mark button that opens a popover: reached by Tab and by touch as well
as by pointer, named for what it explains, and scaling out of the button that
opened it. `PageHeader` takes `explain` and `explainLabel` and puts the
question mark beside the title, so a page says what it is in one line and how
it is measured on request. The graph legend's "how to read" (§136) and the
attack-path page's note on groups (§143) were the two places this was already
done by hand; both now use `InfoTip`, and the question mark is `EXPLAIN_ICON`
in `lib/icons.ts`. The 123 strings over the budget when it was set are listed in
`i18n/overBudget.ts`. That list is a ratchet: the test fails on a new string
over the budget, and also on a listed string that is no longer over it, so a
shortened string leaves the list in the same change and the list only
shrinks. Shortening one means cutting it to a line and moving what was cut to
an `Explain` sibling -- not deleting it. The claims that keep the product honest
(UNKNOWN is never a pass, a gap in coverage is said, nothing is claimed that
was not read) stay on the page; what moves behind the question mark is how and
why.

## 167. Motion follows a changed value

The app already moves: panels arrive in reading order, numbers count up, the
route map closes routes in hop order, and a link into the graph grows into
the next page (§140, §149). What it lacked was movement for the changes that
matter most -- a finding proved fixed, a filter that reorders a list, a tab
changing -- and the passes after §166 add it. The rules they are held to are
written here once, with the pieces they share in `lib/motion.ts`.

Something moves because a value it shows changed: never because a component
mounted again, and never because the dashboard's twenty-second poll came back
with the same numbers. That is the rule `useCountUp` already kept, and
`useValueChange` makes it available to anything else: it returns how many
times a value has changed since mount (zero on mount and on every render with
the same value) and what the value was before, computed in the render that
carries the change rather than one frame later. It compares with `Object.is`,
so a caller passes the number or string shown rather than the object it came
from. A live scan moves only as the API reports (§87). Only `transform` and
`opacity` animate, with timings from `DURATION`. A row or an indicator that
moves to a new place (`layout`, a shared `layoutId`) uses `layoutSpring`, a
spring with no bounce timed like a page, because a row that overshoots its
place reads as uncertainty; past `LAYOUT_ROW_LIMIT` (100) rows a list does not
animate its layout at all, since measuring every row costs more than the
movement says. A stroke that draws itself -- a proved fix's check, a sparkline
arriving -- uses `drawPath`. Reduced motion is still answered once, by
`MotionConfig` and the one media query, and still means the final state
immediately. There are no ambient loops, no decorative motion and no
progress without data behind it: in a security product, movement that means
nothing teaches the reader to ignore movement.

## 168. One engine: Prowler is removed, and what it brought is kept as data and a backlog

§150 ran Prowler as a second engine beside the native rules: over eight hundred
checks for breadth, six frameworks, and an audit of the native rules wherever
the two answered the same question. Weighed after running it, it cost more
than the breadth was worth, and it could never do the part of the product that
is the product.

**What it cost.** A second service with its own image, queue and pinned
dependency tree, because Prowler's pins cannot share a process with the API's;
one step per process, because Prowler keeps its clients in module globals; a
fourth step kind with its own lease rules (§151); a database role with column
grants; a log-scraping layer, because Prowler reports a refused listing as
silence and silence is never a pass; the built-in Reader assigned in every
customer's subscription, and a redeploy prompt for connections without it
(§153); and third-party code holding every customer's credentials in memory,
the open item §151 carried forward. Its captures could only be re-interpreted,
never re-evaluated, because its checks ran against the cloud rather than
against anything Cleave stored. And none of its verdicts reached the graph: a
public AKS API it found was a finding, never an entry point on a route.

**What is kept.** The six frameworks it brought -- CIS Azure 6.0, CIS AWS 7.0,
AWS FSBP, NIS2, HIPAA and ATT&CK -- are frozen from the last generated
catalogue into `app/compliance/data/frameworks.json` and loaded by
`app/compliance/catalog.py` like the frameworks written there by hand. They are
now offered whether or not anything runs Prowler, because they no longer depend
on it: coverage comes from the native rules mapped to them, and a requirement no
rule reaches reads not covered, as everywhere else.

The controls native rules had inherited from the checks they covered are kept
too, in `app/compliance/data/crosswalk.json`: seventy-one rules, 749 control
links, exactly the output `inherited_mappings()` produced -- including its two
limits, that a framework a rule maps itself keeps its hand-written mapping and a
pair recorded as disagreeing by design passed nothing on.
`app/compliance/crosswalk.py` merges it under the rule's own mappings for the
rules mirror and a finding's detail. Both files are hand-edited from now on;
nothing regenerates them. The CIS licensing question §150 raised about control
titles is unchanged by this and still open.

What Prowler checked that no native rule answers is
`docs/NATIVE_COVERAGE_BACKLOG.md`: 130 Azure checks in three tiers and 575 AWS
checks, with the CIS control each maps to. Tier 1 is new exposure and identity
surface -- AKS, Cosmos DB, Container Registry, Databricks, AI Search, MySQL,
Function apps, Entra's authorization policy -- the part that feeds the graph.
Tier 2 is configuration hygiene on resources Cleave already reads. Tier 3 is
deferred with a reason: a latest-runtime-version check needs a table that
changes without a release, which breaks the rule contract's determinism, and
availability settings are not posture. AWS is not ported for breadth while it
has never run against a live account. An entry leaves the file when a native
rule answers it.

**What is removed.** `apps/scanner`, `tools/prowler`, `app/prowler`, the
scanner Dockerfile and Railway file, the CI job; `ScanStepKind.ASSESS`, the
`assess` queue and `ASSESS_ENABLED`; the engine audit route, service and page;
the `engine` and `prowler` fields on rules and findings; retention's pruning of
Prowler captures; and the every-read machinery of §153 with the Reader
assignment in the ARM template. The custom role is unchanged, so no role
version moves. Connections deployed while the template assigned Reader keep the
assignment until the customer removes it; nothing reads through it. The
`$filter=atScope()` on the assignment listing stays: it was a correctness fix
for the grant-version probe in its own right.

Migration 0047 deletes what the engine wrote -- findings under `PRW-` rule ids
and the risks they leave with no member (deleted, not resolved, as §124 says),
their rule results, gaps and verifications, and the mirrored rule rows -- and
drops ASSESS steps, both tables, the `rules.engine` columns and
`app.scan_owner`. It revokes every grant and policy `cloudguard_scanner` held
and drops the role where it may; where an operator's grant it cannot revoke
keeps it alive, it is left NOLOGIN with a notice in the deploy log rather than
failing the API's start command. Rule id columns stay 128 wide.

**What is given up.** The breadth, until the backlog is worked down; the audit
of native rules against a second opinion; and following new benchmark releases
by bumping a pin. The audit was the most useful of the three, and the cheap
way to keep it is offline: run Prowler by hand against a sandbox tenant and
compare, never as a production dependency. Anything that reintroduces a second
engine needs a new entry here first.

## 169. Six more types are read and modelled, each through its own listing under role v9

§168 left a backlog whose first tier is exposure and identity surface the native
engine could not see: AKS, Container Registry, Cosmos DB, MySQL, Databricks and
AI Search appeared in the inventory only as unchecked rows of type UNKNOWN, with
no configuration, no exposure and no place in the graph. This is the collection
half of closing it. No rule judges them yet; that is the next step.

**Per-type ARM listings, not Resource Graph properties.** The plan in §168 was
to add `properties` to the inventory query, on the hope that the trimmed role
would get configuration back without new reads. Whether Resource Graph returns
a resource's properties to a caller holding only
`Microsoft.Resources/subscriptions/resources/read` could not be settled without
a live tenant, and the design should not rest on it either way: `rbac.py`
requires every action to be exercised by a real call, and a per-type read that
only a Resource Graph query "used" would be an action nothing proves. So each
type is read the way every other is -- its subscription-wide ARM listing, one
evidence key each, so a refused listing costs only its own type's verdicts.

**Role v9: six reads, each verified.** `Microsoft.ContainerService/managedClusters/read`,
`Microsoft.ContainerRegistry/registries/read`, `Microsoft.DocumentDB/databaseAccounts/read`,
`Microsoft.DBforMySQL/flexibleServers/read`, `Microsoft.Databricks/workspaces/read`
and `Microsoft.Search/searchServices/read` were checked on 2026-09-29 against the
published operations reference (the provider pages of Azure permissions, and the
Search provider's own operations listing, since Microsoft.Search is not on a
provider page), and the api-versions -- 2024-02-01, 2023-07-01, 2024-11-15,
2023-12-30, 2024-05-01 and 2023-11-01 -- and the field names read against each
provider's REST or template reference. Every one is the resource's own `/read`:
a cluster's kubeconfig, a registry's login, a Cosmos DB account's keys and a
search service's admin keys are `/action` reads and are not requested. The
role's ceiling test went from thirty actions to thirty-five. A v8 connection
keeps every verdict and route it had and is prompted to redeploy, with Compute
and Databases named as affected -- category granularity, which is broader than
the six types, as it has been for every version.

**Six neutral types.** `KUBERNETES_CLUSTER`, `CONTAINER_REGISTRY`,
`DOCUMENT_DATABASE`, `MYSQL_SERVER`, `ANALYTICS_WORKSPACE` and `SEARCH_SERVICE`,
named so EKS, ECR and their kind fit them later (§74). Cosmos DB, MySQL and AI
Search join the data-holding floor; a registry does not, because it holds code
rather than customer data.

**Exposure is established the way it already was.** Public access disabled is
LOW, access narrowed to named networks MEDIUM, open to every network HIGH. A
cluster whose ARM record leaves out `apiServerAccessProfile` was created with
the defaults, which is a public API server, so absence reads as reachable -- the
precedent App Service set. A MySQL server with public access on is UNKNOWN,
because what decides it is its firewall rules, which are not read, and a public
server with none admits nobody; the PostgreSQL servers are held to the same
rule when their rules cannot be read. Private endpoint counts are None where
the listing did not carry the field, so a rule can tell "not stated" from none.

**A cluster runs as two identities.** Clusters join the graph's workloads beside
virtual machines and web apps, running as the control plane's identity and as
the kubelet identity under `identityProfile`, which is what a pod reaching its
node acts as. A public cluster whose kubelet identity holds Contributor is now a
route; before, the cluster was an unchecked row.

**What a role over each amounts to** (`connectors/azure/access.py`, strings
verified with the others): Contributor and Owner take EXECUTE on a cluster
(the admin kubeconfig, run command, or the write that re-enables local
accounts) and on a Databricks workspace (Databricks makes them its admins),
and READ_DATA on a registry (its admin login), a Cosmos DB account (its keys),
a MySQL server (as PostgreSQL) and a search service (its admin and query keys).
Reader reaches nothing in any of them. A registry pull reads images too, and is
not claimed: `pull/read` sits inside `*/read`, so claiming it would make every
Reader assignment reach and undo what §125 established.

**Nothing here has been read from a live tenant.** The tests are fixtures shaped
after the published reference. The first redeployed v9 connection is the check:
six listings in its snapshot, the six types as modelled assets rather than
UNKNOWN rows, and no new gap. Until a rule declares them the six keys are
baseline evidence, collected for the graph, and move out of the baseline one by
one as rules claim them.

## 170. Fourteen rules over the types role v9 reads

§169 made AKS, Container Registry, Cosmos DB, MySQL, Databricks and AI Search
assets and graph nodes; this judges them. Fourteen native rules close fifteen of
the backlog's Tier 1 checks (§168), each written in the house style -- its own
words, a remediation declared as data, UNKNOWN whenever its listing failed:

- **AKS** -- AZ-AKS-001 API server open to every address (no private cluster,
  public access on, no authorized ranges); AZ-AKS-002 local admin accounts kept;
  AZ-AKS-003 Kubernetes RBAC off; AZ-AKS-004 a node pool hands its nodes public
  IPs; AZ-AKS-005 no network policy engine.
- **Container Registry** -- AZ-ACR-001 the shared admin login is on; AZ-ACR-002
  the registry answers every network.
- **Cosmos DB** -- AZ-COS-001 open to every network (public access on, no IP rule,
  no virtual network filter); AZ-COS-002 account keys accepted; AZ-COS-003
  minimum TLS below 1.2.
- **Databricks** -- AZ-DBW-001 the workspace answers every network; AZ-DBW-002
  cluster nodes get public IPs; AZ-DBW-003 no VNet injection.
- **AI Search** -- AZ-SRCH-001 open to every network, stepping exploitability down
  where the service accepts only Entra tokens.

**What an absent setting means is decided per setting, and said.** Where the
service documents a default and the default is the unsafe one -- AKS local
accounts, Cosmos DB key access, Databricks and AI Search public access -- absence
reads as that default and fails, as a cluster with no `apiServerAccessProfile`
already reads as public (§169). Where absence could mean either -- Kubernetes
RBAC, a registry's admin user, Cosmos DB's minimum TLS -- the rule is UNKNOWN.
A Databricks workspace's custom parameters can be absent altogether (the
published sample lists `"parameters": null`), so the two rules reading them are
UNKNOWN then rather than assuming the service default; the normalizer now keeps
`custom_virtual_network` None in that case instead of False.

**No policy is generated.** Every setting has an Azure Policy alias somewhere,
and none has been verified from here; `remediation/spec.py` declines rather than
guesses, and each rule's notes say so. The CLI lines use `az resource update
--ids <resource-id> --set properties.<field>=<value>` wherever a service-specific
flag could not be confirmed, which is valid for any resource. Terraform hints
name the azurerm argument, inverted where it is (`public_network_access_enabled
= false` for a Disabled setting), and are left out where the argument takes a
value the expected state does not carry.

**Mappings.** Each rule maps its own ISO 27001, NIST CSF, GDPR, NIST 800-53,
SOC 2 and PCI DSS controls, as every rule must. The crosswalk gains entries for
the new rules from the compliance mappings of the Prowler checks each one
answers -- the same derivation §168 froze -- for NIS2, HIPAA, ATT&CK and the CIS
benchmarks, never overriding a framework the rule maps itself.

**Evidence.** The five keys these rules declare leave the baseline; the MySQL
listing stays in it, because no MySQL rule could be written from the listing
alone: its TLS questions are server parameters, which need
`Microsoft.DBforMySQL/flexibleServers/configurations/read` and a role version.
The backlog now holds twenty-two Tier 1 checks, and states why each group is
left.

## 171. The rest of Tier 1 that needs no new read: five rules, two already answered, one declined

§170 closed fifteen Tier 1 checks. Of the twenty-two left, eight needed nothing
the scanner does not already read. Each was weighed against what the native
engine already says before anything was written, and three turned out not to be
new questions.

**Five rules.**

- AZ-ACR-003 and AZ-COS-004: a registry or Cosmos DB account with no approved
  private endpoint. LOW with exploitability 1 -- whether the thing is reachable is
  the public-network rules' question (AZ-ACR-002, AZ-COS-001); this asks whether
  the private path exists that lets public access be switched off. UNKNOWN when
  the listing did not carry the connections, since the normalizer keeps None
  apart from zero (section 169). No expected state is declared: what is expected
  is a count, and the endpoint is a resource of its own.
- AZ-DBW-004: Databricks managed services encrypted with Microsoft's keys. LOW.
  Absent is the documented default, Microsoft-managed, so it fails.
- AZ-WEB-006: a function app that answers every network. Function apps only --
  a web app is usually meant to be public, and flagging every one would be the
  noise AZ-NET-003 was written to avoid. It needed one new reading of what was
  already collected: a site's access restrictions, from the configuration read
  since role v7 (`ipSecurityRestrictions`, and `ipSecurityRestrictionsDefaultAction`
  where the configuration has it, both confirmed in the 2022-09-01 reference).
  Unmatched traffic is denied when the default action is Deny, or -- without
  that field -- as soon as any restriction exists; a rule allowing `Any` undoes
  either. The normalizer now records `access_restricted` and, for any site,
  steps exposure from HIGH to MEDIUM when it is restricted: a web app admitting
  three office ranges is no longer an entry point, and nothing else about
  exposure changed.
- AZ-CMP-004: a Linux machine whose ARM record allows SSH password sign-in
  (`osProfile.linuxConfiguration.disablePasswordAuthentication`). UNKNOWN where
  the record has no `osProfile`, which a machine built from an attached disk does
  not. The setting is fixed at creation, so the remediation is honest that the
  interim fix -- `PasswordAuthentication no` in sshd -- closes the door without
  closing the finding; only a rebuild does. The demo's Linux build agent now
  carries an `osProfile` with keys only, added in `build_snapshot_demo.py`
  (section 102), so the demo gains no UNKNOWN.

**Two already answered.** `iam_role_user_access_admin_restricted` is AZ-IAM-003,
which flags any role that can write role assignments -- User Access Administrator,
Owner and custom roles alike -- by its actions rather than its name.
`app_function_identity_without_admin_privileges` is AZ-IAM-002 and AZ-IAM-003
together: full control of the subscription, or the power to grant any role, for
any workload identity rather than for function apps alone. Contributor over one
resource group is deliberately not flagged; narrowing to that is AZ-IAM-002's
own remediation. Both checks' mappings joined those rules' crosswalk entries.

**One declined.** `network_http_internet_access_restricted` would fail every web
server that serves the web. AZ-NET-003 already excludes ports 80 and 443 for that
reason, and the check moves to Tier 3 with it.

What is left in Tier 1 all needs a read that is not collected: MySQL's TLS server
parameters (a role version) and the Entra checks (Graph's authorization policy,
authentication-methods policy and a per-user join of MFA to VM access).

## 172. The reads the rest of Tier 1 needed: MySQL's TLS parameters and the tenant's authorization policy

After section 171, fourteen Tier 1 checks remained and every one needed a reading
not collected. This adds the two that could be verified from here, and the
eleven checks they close with nine rules.

**MySQL, under role v10.** `Microsoft.DBforMySQL/flexibleServers/configurations/read`
(checked on 2026-09-29 against the operations reference) reads two parameters by
name beneath each server -- `require_secure_transport` and `tls_version`, under
the 2023-12-30 configurations contract, value at `properties.value` -- in one
evidence key, `mysql_configurations`, as PostgreSQL's one parameter is read.
`_per_resource_task` gained `also` so one task can declare both endpoints. A v9
role keeps every verdict and is prompted to redeploy with Databases named.
AZ-MYS-001 fails a server that accepts connections without TLS; AZ-MYS-002 one
whose `tls_version` lists anything below TLS 1.2. Each is UNKNOWN where the
parameter was not read. The MySQL listing leaves the baseline: these rules
declare it.

**The authorization policy, under consent already given.** Graph's
`/policies/authorizationPolicy` is readable under `Policy.Read.All`, which every
connected tenant consented for Conditional Access -- so no customer is sent back
to a Global Administrator. Its shape and the three guest role ids were read from
the v1.0 reference. The normalizer keeps six settings in `controls`, each None
where Graph did not state it, and five AGGREGATE rules judge them:

- AZ-ID-015 users can consent to any application -- the legacy default consent
  policy is assigned. Consent limited to verified publishers asking for
  low-impact permissions (`microsoft-user-default-low`), Microsoft's own
  recommendation, passes; Prowler's stricter reading, that no user consent at all
  is allowed, is not adopted.
- AZ-ID-016 any user can register applications.
- AZ-ID-017 guest invitations open to every member, or to everyone.
- AZ-ID-018 guests not held to the Restricted Guest User role, stepping
  exploitability down for the Guest User default and keeping it for guests
  holding member access.
- AZ-ID-019 any user can create tenants or security groups, UNKNOWN only when
  neither was stated.

**Two Conditional Access checks from what is already read.** The normalizer
records, beside `mfa_policies`, `mfa_protected_apps`: every application an
enabled policy requires multi-factor for, of all users, skipping a policy whose
excluded groups were not read -- the same caution `mfa_policies` takes. AZ-ID-013
fails when neither security defaults nor such a policy covers Azure management
(the Windows Azure Service Management API, `797f4846-ba00-4fd7-ba43-dac1f8f63013`,
or `All`); AZ-ID-014 the same for `MicrosoftAdminPortals`. Security defaults pass
both: they challenge every administrator at every sign-in and every user reaching
Azure management.

All nine are tenant settings, so none has an expected state on an asset and none
generates a policy; each gives an `az rest` PATCH of the authorization policy or
the Conditional Access listing to start from.

**What is left in Tier 1:** the authentication methods policy and MFA
registration campaign, a join of per-user MFA registration to the Azure roles
that reach virtual machines, and the Group.Unified directory setting. Each is a
Graph read that has not been verified here yet.

## 173. Tier 1 closed: the authentication methods policy and the directory's group settings

The last three Tier 1 checks. Two needed Graph reads, both under consent every
tenant already gave, and one was already answered.

**Two reads, verified against the v1.0 reference.** `/policies/authenticationMethodsPolicy`
is readable under `Policy.Read.All` (a higher-privileged permission for it than
the least, and the one already held). `/groupSettings` is readable under
`Directory.Read.All` and `Group.Read.All`, both held. Each is its own evidence
key in the directory plan.

- AZ-ID-020 fails when none of Microsoft Authenticator, FIDO2 or X.509 certificate
  sign-in is enabled, or when the registration campaign is switched off. A
  campaign in state `default` -- Microsoft-managed, and on for users still
  relying on SMS and voice -- passes; only an explicit `disabled` fails.
- AZ-ID-021 fails when any user can create Microsoft 365 groups. `Group.Unified`
  exists only once somebody changed it from the defaults, and the default lets
  every user create groups, so a tenant without the setting fails rather than
  reads unknown -- the one place in these rules where an absent object is a
  finding, and it is because Microsoft documents what its absence means.

**One already answered.** `entra_user_with_vm_access_has_mfa` asks whether users
holding roles that reach virtual machines have MFA. AZ-ID-004 asks it of every
user, so it answers this and more; its crosswalk entry gains the check's
mappings. A narrower rule would repeat findings AZ-ID-004 already raises.

Tier 1 of the backlog is now empty. Tier 2 -- configuration hygiene on resources
already read -- is next.

## 174. Tier 2 is declared as property specs, starting with storage

Tier 2 of the backlog is about seventy checks, and nearly all are one setting
compared with the value that is safe. As hand-written classes each would repeat
the same forty lines -- evidence guard, absent case, evidence dict, remediation
declaration -- around one comparison, and that repetition is where a check's
guard and its declaration drift apart.

**`app/rules/property.py`.** A `PropertySpec` declares the check: the field the
normalizer produced, the safe value (or, where safety is not one value, a
`passes` test with a stated reason no expected state can express it), what an
absent field means, the remediation prose and CLI, the Terraform argument, and
the mappings. `property_rule` builds a `SecurityRule` subclass from it, so the
result is registered, mirrored, verified and mapped like every other rule.

Nothing the hand-written rules promise is given up:

- UNKNOWN whenever the rule's evidence failed.
- `absent` is stated per spec: `unknown`, or `fail` only where the service
  documents that its default is the unsafe value. A spec that states neither a
  safe value nor a test, or a test without a reason, fails at import.
- Where the safe value is one value it becomes an expected state, and
  `test_remediation_spec.py` holds the rule to it in both directions.
- No policy is generated until the aliases are verified (section 170).

**First batch: storage, needing no new read.** Four fields join the storage
normalizer from the listing already collected -- the key source, the portal's
default authorization, the network bypass and the private endpoint count -- and
six specs judge them, with the infrastructure-encryption and blob-versioning
fields that were already there:

- AZ-STO-006 blob versioning off (UNKNOWN when the blob service was not read).
- AZ-STO-007 infrastructure encryption off (absent fails: ARM leaves it out unless
  requested at creation).
- AZ-STO-008 encrypted with Microsoft's keys.
- AZ-STO-009 the portal defaults to the access keys (absent fails: the documented
  default is false).
- AZ-STO-010 trusted Azure services cannot bypass the network rules.
- AZ-STO-011 no approved private endpoint.

The crosswalk carries each counterpart's mappings. The storage checks that need
the file service (file-share soft delete, SMB) or a key-rotation reading are
left for a batch that adds those reads.

## 175. The rest of Tier 2 that needs no new permission

Fourteen more property specs (section 174), each reading a field the scanner
already collects or a server parameter under a configuration read the role
already holds. `PropertySpec` gained `applies_when`, a metadata condition matched
as a case-blind substring, so a check can apply to function apps alone; it feeds
the remediation declaration too, so the remediation tests build an asset the
check applies to.

**Server parameters by name.** Five PostgreSQL parameters -- `log_checkpoints`,
`log_connections`, `log_disconnections`, `connection_throttle.enable` and
`logfiles.retention_days` -- are read by name per server into a new evidence key,
`postgresql_logging`, under `Microsoft.DBforPostgreSQL/flexibleServers/configurations/read`,
held since v7. The names are Flexible Server's own, confirmed on Microsoft Learn;
the catalogue's `connection_throttling` and `log_retention_days` are the retired
Single Server's. A name a server does not have fails that server's read, which
is UNKNOWN. MySQL's read gains `audit_log_enabled` and `audit_log_events` under
the v10 action. `get_postgresql_parameter` and `get_mysql_parameter` take the
name, and each declares one endpoint ending in `/configurations/{name}`. No role
version changes.

**The rules:**

- AKS: AZ-AKS-006 no automatic upgrade channel (absent fails -- the default is
  none); AZ-AKS-007 neither Container insights nor managed Prometheus.
- Function apps: AZ-WEB-007 no virtual network integration.
- PostgreSQL: AZ-DB-010 to AZ-DB-013 the four logging and throttling parameters;
  AZ-DB-014 logs kept three days or less; AZ-DB-015 no Entra authentication
  (`authConfig.activeDirectoryAuth`).
- MySQL: AZ-MYS-003 no audit log; AZ-MYS-004 the audit log leaves out CONNECTION.
- SQL: AZ-DB-016 audit records kept under 90 days (zero, kept indefinitely,
  passes).
- Virtual machines: AZ-CMP-005 not Trusted Launch with secure boot and vTPM;
  AZ-CMP-006 an attached managed disk without a disk encryption set (UNKNOWN for
  a machine with no managed disk).

Hardening checks map PCI 6.3.3, not 2.2.1: one setting is not a configuration
standard, and the PCI test that keeps 2.2.1 uncovered said so.

**Two moved to Tier 3.** Client certificates (mutual TLS) are how an application
authenticates its callers, a design choice rather than hygiene every app should
have; and a custom role for administering resource locks is an organizational
arrangement whose absence says nothing about how locks are managed.

Everything left in Tier 2 needs a read that is not collected: Key Vault keys and
secrets, SQL encryption protectors and vulnerability assessment, Defender
settings and contacts, activity-log alerts, network watchers and flow logs, VM
backup and just-in-time access, file services, and diagnostic settings on web
apps.

## 176. Tier 2 closed: twenty-one reads under role v11, forty-eight rules

Section 175 left fifty-two Tier 2 checks, every one needing a reading the scanner
did not take. This adds the reads, answers fifty checks with forty-eight native
rules, and moves two to Tier 3. The backlog's Azure section is now Tier 3 alone.

**Role v11: twenty-one reads, each verified.** Every action string was checked on
2026-09-30 against the published operations reference -- the Azure permissions
pages for Security, Databases, Storage, Compute, Monitor, Networking, and
Management and governance -- and every response shape and api-version against
the provider's own REST specification (`Azure/azure-rest-api-specs`), because
`rbac.py`'s rule stands: one string that is not a real operation fails the whole
role deployment. The reads are Defender for SQL's server setting, the TDE
protector and both forms of vulnerability assessment beneath each SQL server;
the file service beneath each storage account; the keys and secrets in each
vault; Defender for Cloud's security contacts, settings, IoT solutions and
just-in-time policies; Recovery Services vaults and their protected items;
managed disks; activity-log alerts; policy assignments; and virtual networks,
Network Watchers, flow logs and Bastion hosts. Both just-in-time reads are
requested: the subscription-wide listing returns policies that live under a
location, and the reference does not say which of the two ARM checks for it --
the trade section 14 made for Resource Graph, made the same way. The reference
prints the activity-log alert action as `ActivityLogAlerts/Read`; the role
spells it `activityLogAlerts/read`, because ARM compares actions case-blind and
the test holding every action to `/read` should not need an exception. The
ceiling test goes from thirty-five actions to fifty-five; the role holds
fifty-four. A v10 connection keeps every verdict and route it had and is
prompted to redeploy, with seven categories named -- everything but resources,
authorization and identity -- and the checks on the new reads report UNKNOWN
until then. Two more readings need no new permission: web apps join the
diagnostic settings task (the read held since v1), and Entra's named locations
are read from Graph under `Policy.Read.All`, already consented.

**Vault contents, through the management plane only.** "The role asks for no
data-plane permission" was tested as "no `/secrets/read` in the role", which
was a proxy for the claim rather than the claim. `Microsoft.KeyVault/vaults/secrets/read`
is described by the reference as "View the properties of a secret, but not its
value", and ARM's contract for a secret says its value "will never be returned";
reading a value is `secrets/getSecret/action`, a data action. So the test now
asserts the claim itself -- no `getSecret`, no `readMetadata` data action, no
data action at all, and the only Key Vault actions are the vault read and the
two management-plane listings -- and CloudGuard can say which secrets never
expire without being able to read one. The same goes for disks: they are
described, and `beginGetAccess/action`, the export, is asserted absent.

**Two new asset types in use.** Managed disks become `ResourceType.DISK`, with
LOW exposure because no network endpoint answers for a disk; virtual networks,
a type declared long ago and never produced, become assets with their watcher
and the flow logs that cover them. Both were unchecked inventory rows before.
Disks are not added to the data-holding floor: that would change the score of
every estate for a rule that judges only unattached ones, and deserves its own
decision. The web app shows a disk with its own icon and fills `<disk>` in a
remediation command.

**What each reading means when it says nothing** is decided per field, as in
section 174, and where the service documents the unset value the normalizer
writes it in rather than leaving each rule to remember it: SMB versions and
channel ciphers nobody chose allow all of them; a disk with no encryption type
uses the platform key; an assignment with no enforcement mode enforces; a
classic vulnerability assessment with no `emailSubscriptionAdmins` notifies
administrators. The new readings live in `connectors/azure/settings.py`, small
pure reductions the normalizer calls where each asset is built.

**The rules, and where they part from the catalogue:**

- Defender for Cloud (subscription): AZ-DEF-002 no contact email, AZ-DEF-003 no
  alert email at High or lower, AZ-DEF-004 Owners not emailed, AZ-DEF-005 attack
  path email off or Critical only, AZ-DEF-006 Defender for Endpoint integration
  off, AZ-DEF-007 Defender for Cloud Apps integration off, AZ-DEF-008 container
  images not scanned (the Containers plan and its
  `ContainerRegistriesVulnerabilityAssessments` extension), AZ-DEF-010 the
  Microsoft cloud security benchmark unassigned or not enforced. A disabled
  security contact is read as no contact.
- AZ-DEF-009 IoT hubs no Defender for IoT solution watches. Not applicable to a
  subscription with no hub, where the catalogue failed every subscription. IoT
  hubs are not modelled, so it is the first rule to declare the inventory as
  evidence; `test_evidence_keys.py` now names it as the one exception.
- AZ-VULN-002 a machine Defender says has no vulnerability assessment solution,
  matched on the assessment's stable name (`ffff0522-...`, the one the built-in
  policy reads) rather than its wording. AZ-VULN-001 matched that assessment on
  the word "vulnerab" and would have called an unscanned internet-facing
  machine one with unpatched vulnerabilities; it now skips it.
- Activity-log alerts: AZ-LOG-005 to AZ-LOG-014, one per operation CIS names
  (policy assignment, network security group, security solution, SQL firewall
  rule and public IP, each written and deleted), and AZ-LOG-015 Service Health.
  An alert counts only when enabled and scoped to the subscription: one scoped
  to a resource group watches nothing created beside it.
- AZ-LOG-016 the activity log export leaves out Administrative, Security, Alert
  or Policy; AZ-LOG-017 and AZ-LOG-018 the storage account the activity log is
  exported to uses Microsoft's keys, or allows public blob access. Those two
  apply to that account alone: the normalizer marks it `holds_activity_log`.
- Networks: AZ-NET-010 no enabled flow log sends the network's traffic to a
  workspace (a flow log covers a network through the network, one of its
  subnets, or a network security group on one of its subnets -- the retiring
  NSG flow logs record the same traffic); AZ-NET-011 a covering flow log keeps
  under 90 days (zero keeps for ever); AZ-NET-012 no Network Watcher in the
  network's region; AZ-NET-013 no DDoS Network Protection, LOW because it is
  priced per plan and is availability rather than exposure; AZ-NET-014 no
  Bastion host, not applicable where there is no virtual machine.
- Vaults: AZ-KV-004 enabled keys with no expiry, AZ-KV-005 enabled secrets with
  no expiry, AZ-KV-006 enabled keys that never rotate. One rule each, not one per
  access model as the catalogue had: an expiry date means the same thing under
  RBAC and access policies. The finding names the keys and secrets. A key whose
  record states no rotation policy is not judged either way; whether ARM's
  listing carries `rotationPolicy` is the first thing a live v11 read will show,
  and until it does the rule may be UNKNOWN rather than guess.
- SQL: AZ-DB-017 a service-managed TDE protector; AZ-DB-018 no Defender for SQL,
  passing on either the server's own setting or the subscription's
  `SqlServers` plan -- the catalogue read only the first and failed every server
  a subscription plan protects; AZ-DB-019 no vulnerability assessment, in which
  the express configuration (the default since 2022, weekly scans, no storage
  account) passes as the classic one does; AZ-DB-020 to AZ-DB-022 classic scans
  not recurring, sent to nobody, or not sent to administrators, not applicable
  to an express server, which the catalogue failed on all three.
- Storage: AZ-STO-012 file share soft delete off, AZ-STO-013 SMB versions below
  3.1.1, AZ-STO-014 SMB channel ciphers below AES-256-GCM, each not applicable
  to a blob-only account (and the collector does not ask one for a file service);
  AZ-STO-015 no access key expiry of 90 days or less, read from `keyPolicy` on
  the listing already collected.
- Machines and disks: AZ-CMP-008 no just-in-time access, AZ-CMP-009 not backed up
  -- UNKNOWN, not failed, while any vault's protected items could not be read --
  and AZ-CMP-010 an unattached disk on a platform key.
- Web apps: AZ-WEB-008 App Service Authentication off, LOW, since an app that
  authenticates in its own code is not wrong and may dismiss it; AZ-WEB-009 HTTP
  logs sent nowhere, for web apps only.
- AZ-ID-022 no trusted named location with IP ranges.

Most are property specs. `PropertySpec.applies_when` now reads a stated `False`
as "false" rather than as blank, which is what lets a check apply to web apps
(`is_function_app` false) and not to a site whose kind was never stated. A
per-resource read that is a listing -- a vault's keys, a watcher's flow logs --
now reports itself partial when the listing ran past what one scan reads,
rather than passing on a short list.

Mappings follow the house rule: each rule maps its own ISO 27001, NIST CSF,
GDPR, NIST 800-53, SOC 2 and PCI DSS controls, and the crosswalk gains an entry
per rule from the compliance mappings of the checks it answers, never
overriding a framework the rule maps itself (section 168). No policy is
generated for any of them until the aliases are verified (section 170).

**Two moved to Tier 3.** Whether a function app sends to Application Insights is
written only in its application settings, behind `config/list`, the action that
also returns connection strings and keys and that the role never requests.
Auto-provisioning of the Log Analytics agent asks about an agent Microsoft
retired in August 2024, through a read (`autoProvisioningSettings`) that is not
in the published operations reference -- the string that once failed a role
deployment outright.

**The demo** gains the payments vault's contents, attributes only: a signing key
that expires and rotates, a connection string that expires, and a payment
provider's API key that never does -- AZ-KV-005's finding. It gains no check
that cannot reach a verdict.

**Nothing here has been read from a live tenant.** The fixtures are shaped after
the REST specifications' own examples. The first redeployed v11 connection is
the check: twenty-one new readings in its snapshot, disks and virtual networks
as assets, and no new gap.

## 177. Six misfiled checks, and Tier 3 ported but for seven

Two follow-ups to section 176, asked for together.

**Six checks were misfiled as never to be ported.** The list section 168 kept of
checks the second engine excluded carried Prowler's own reasons, and one reason,
"reads activity records rather than configuration", covered six checks that
read configuration: the AKS Defender security profile, the Defender CSPM plan,
and four Cognito user pool settings. None was ever run here -- the second engine
had all thirty-seven switched off -- so porting them is new coverage, not a
replacement.

- AZ-AKS-008 no Defender security profile on a cluster, from the cluster listing
  (absent fails: no profile is no sensor). AZ-DEF-011 Defender CSPM off, from the
  plan listing.
- AWS policy v5 reads Cognito user pools: `cognito-idp:ListUserPools`,
  `DescribeUserPool` and `DescribeRiskConfiguration`, and
  `wafv2:GetWebACLForResource`, in three regional keys so a refused risk or WAF
  read costs only its rules. Pools become `ResourceType.USER_POOL`, HIGH exposure
  because their sign-in faces the internet by design. AWS-COG-001 threat
  protection not enforced; AWS-COG-002 compromised credentials not blocked;
  AWS-COG-003 a risk level lets a sign-in through without BLOCK or MFA_REQUIRED
  (the catalogue asked for BLOCK at every level; requiring MFA stops the
  attacker and not the user, so it passes); AWS-COG-004 no web ACL. The two risk
  rules are not applicable unless protection is enforced, which AWS-COG-001
  reports -- three findings for one fix otherwise. The dependent regional
  tasks read their region's pools out of the collected payload, which is the
  first regional task in the connector to depend on another. Nothing here has
  been run against AWS; the inline policy's ceiling test goes from thirty to
  thirty-five.

**Tier 3: seventeen ported, seven not.** The four checks earlier sections
declined on purpose stay declined (HTTP 80, client certificates, the lock-admin
role, container image vulnerabilities as a finding), and three cannot be asked: a function app's
host runtime version and its Application
Insights connection live only in application settings behind `config/list`,
and the Log Analytics agent is retired.

- Role v12 adds `Microsoft.RecoveryServices/Vaults/backupPolicies/read` and
  `Microsoft.Compute/virtualMachineScaleSets/read`, both checked against the
  published operations reference and their contracts against the REST
  specification. Recovery Services vaults become `BACKUP_VAULT` assets and scale
  sets `SCALE_SET` assets. The protected-items read drops its machine-only
  filter, so a vault protecting file shares is not reported empty; the backup
  task keeps each vault's record rather than its id. The role's ceiling test
  goes to sixty; it holds fifty-six.
- **Runtime versions, without breaking determinism.** Tier 3 deferred these
  because a table of current versions changes without a release. The table is
  of _end-of-support dates_ instead (`connectors/azure/settings.py`,
  `END_OF_SUPPORT`, from the language communities' published timelines, which
  App Service follows), and the normalizer judges a site against it as of the
  snapshot's own collection time. A version passing its date needs no release,
  and a replayed capture answers as of when it was taken. A version newer than
  every entry is supported, one older than every entry is not, and one between
  two entries is UNKNOWN rather than guessed. AZ-WEB-011 Python, AZ-WEB-012 PHP,
  AZ-WEB-013 Java including Tomcat 8.5 and 10.0, which App Service still offers
  unpatched; MEDIUM, since an unpatched runtime keeps every vulnerability found
  in it. The table needs a new row only when a language ships a new version.
- LOW, exploitability 0, because each is resilience rather than a door:
  AZ-WEB-010 no HTTP/2; AZ-LOG-019 apps and no Application Insights resource
  (from the inventory, not applicable without apps -- the second rule to declare
  the inventory, and `test_evidence_keys.py` names it); AZ-COS-005 no automatic
  failover, AZ-COS-006 no continuous backup; AZ-MYS-005 and AZ-DB-023 backups not
  geo-redundant, AZ-MYS-006 and AZ-DB-024 no high availability; AZ-STO-016 not
  geo-redundant; AZ-BKP-001 a vault protecting nothing, AZ-BKP-002 a policy
  keeping daily points under 30 days; AZ-CMP-011 a machine's backups kept under 7
  days (not applicable when it has no backup, AZ-CMP-009's finding); AZ-CMP-012 a
  scale set behind no load balancer or application gateway, AZ-CMP-013 an empty
  one.

**`PropertySpec` changes.** A spec now names its provider, so the AWS rules are
specs too, with a remediation note that speaks of AWS rather than Azure Policy.
And a check whose `applies_when` field was never stated -- which languages a
site runs, when its configuration was not read -- is UNKNOWN rather than not
applicable, since whether it applies is itself unknown; evidence failures are
checked before `applies_when` for the same reason.

The web app draws the three new types with their own icons. The crosswalk gains
entries for the fifteen of the twenty-three new rules whose catalogue checks
carried mappings. The backlog's Azure section is seven checks, all deliberate;
the never-to-port list is thirty-one.

## 178. The overview in three zones, with its figures leading and its explanations a question mark away

The overview stacked nine panels in one column, each opening with a sentence
or two about itself, and the headline -- "7 risks. 3 routes run from something
exposed to something sensitive. One link closes 2 of 3." -- was a sentence too.
A reader who came for the numbers scrolled past prose they had read on every
visit before reaching the ranked risks. This pass applies §166 and §167 to the
one page everybody opens first.

**Three zones.** Where the posture stands: the score ring with its band and
delta, beside three figures (`TodayStats`) -- open risks, attack routes, and the
share of checks that reached a verdict -- then the severity strip. What to do
next: the ranked risks and the link to cut, side by side as before. The detail
behind both: coverage, fixes proved, what moved this week and compliance as a
two-by-two grid, with the region map keeping a full row because it needs the
width. The gap between zones is larger than the gap inside one, so the grouping
is read from the spacing rather than from headings that would add words.

**Coverage is stated twice, on purpose.** As a figure beside the score, which
it qualifies -- a score formed over half the checks is half a reading -- and in
full in the coverage panel, which still lists incomplete categories, the
unclassified-risk note with its link to Settings, and every collection gap with
the provider's own words. Nothing about what could not be read moved behind a
question mark: the gaps, UNKNOWN never being a pass, and "not a security score"
are still printed. What moved behind the question marks (`InfoTip`, with the
text under `dashboard.*Explain` in `en.ts`) is how each thing is measured: the
score's deduction by risk band, how risks are ranked, why a cut is simulated
whole, what coverage and compliance coverage count. The figures show a
dash for a figure the page does not have yet, never a zero. The compliance
panel lists five frameworks as rows with a bar each, the count of concluded
controls kept for a screen reader and on hover; the page is one click away.

**The checklist is one line once there is a scan.** Before the first scan it is
still the whole page, all five steps. After it, it is the progress bar, the one
step that is next and its action, and the button that puts it away -- the steps
already done and the ones waiting on it were a card of five that said little a
second time.

**Motion, under §167's rule.** The figures count up when they change. The
score ring's sweep and band colour are registered custom properties
(`@property --score-angle`, `--score-color` in `index.css`), so a new score
turns the ring and crossfades its colour instead of swapping in one frame; a
transition, not a keyframe, so nothing moves on mount. The delta's arrow
nudges once in its direction when a new delta arrives -- keyed on
`useValueChange`, so a refetch or a remount does not replay it. The trend
redraws when a new reading joins it: the sparkline draws itself when its
`<svg>` is inserted (by uncovering, because `pathLength` does not survive a
non-scaling stroke), so a new key is a new drawing. Compliance bars and the
checklist's progress grow by `scaleX` from the left, only when their value
changes. All of it is answered by the one reduced-motion media query and
`MotionConfig`, as before.

## 179. Lists move their rows, indicators slide, and a list page says what it is in a line

The second pass of §166 and §167, over the list pages -- Findings, Risks,
Assets, Rules -- and the navigation around them.

**Rows slide when the list changes, and only then.** A filter, a sort or a
search used to redraw a table in one frame: the rows that stayed jumped to new
places and the eye lost them. Each row is now a motion element carrying
`listLayout(ids)` (`lib/motion.ts`): `layout="position"`, the `layoutSpring`,
and a `layoutDependency` that is the list's order joined into a string. So a
row measures itself and moves only when the rows themselves changed -- never
because a banner above pushed the table down, a hover re-rendered it, or the
keyboard's current row moved. A row new to the list rises as it did (the CSS
`cg-rise`, capped stagger); one that left is gone; the ones that stayed slide.
Past `LAYOUT_ROW_LIMIT` (100) rows the helper returns nothing and the list does
not animate its layout at all, which is why the rule catalogue only moves once
a search has narrowed it. Table rows use `MotionTableRow`, an `m.tr` added
beside the vendored `TableRow` with the same classes, because a `tr` cannot be
wrapped. The rise on Findings and Assets rows changed its fill from `both` to
`backwards`: a fill that outlived the animation pinned the row's `transform`
to `none` and would have overridden the slide. Asset group headings are rows
too and are part of the order, so they move with the rows under them.

**Indicators slide.** The selected option of a `SegmentedFilter` and the
current row of the navigation are each one element with a shared `layoutId`
that moves from the option or row left to the one arrived at, instead of one
fill disappearing and another appearing. A filter's `layoutId` comes from
`useId`, so two filters on a page never trade theirs; the navigation's is one
name, because there is one current page. Both keep their look -- the soft fill,
the rule along a segment's foot, the ring around a nav row -- as the moving
element under the label.

**The engine is `domMax`.** Layout animation is not in `domAnimation`, which
§149 chose because nothing animated layout. `lib/motionFeatures.ts` now loads
`domMax`. It is still a separate chunk loaded after the first paint, so no page
waits on it; the cost is a larger chunk (28 kB gzipped) arriving a moment later.

**The bell rings when news arrives.** When the unread count rises while
somebody is on the page, the bell icon swings once (`cg-ring`). It compares
against the first count that loaded, never against nothing, so a page opened
with three unread does not ring. It uses `useValueChange` like everything else
under §167.

**A list page says what it is in one line.** Findings, Assets and Rules each
had a description of a sentence and a half; each is now a line ("Misconfigurations
Cleave observed, worst first."), with how the list is ranked or how rules work
behind the question mark beside the title (`pageExplain` in `en.ts`). The empty
states lost the sentence under "No findings match" that said to widen the
filters, because the "Clear filters" button under it says the same. The
unfiltered empty states keep one line.

**Two things from the plan were not done.** The count line under each list does
not tick: §165 has each page draw the exact string it speaks through
`LiveStatus`, and a number counting up inside it would be a second, moving
version of that string. Navigable rows did not get a chevron on hover. Every
row already opens its subject from anywhere on it and fills on hover, and a
chevron would have needed a column in each table to sit in.

## 180. Detail pages: facts in one rail, the rest in tabs, every tab strip slides, and a proved fix draws its check

The third pass of §166 and §167, over the finding, risk and asset pages, and
the one moment the product exists for.

**A finding's evidence, provenance and routes are tabs.** The finding page
stacked seven cards in its main column. What was seen (the evidence), where it
came from (the provenance, "How we know") and what it is part of (the attack
paths) are now one card of tabs under the fix, rather than three cards to
scroll past. The page opens on Attack paths when the asset is on a route --
that is what changes how urgent a finding is, and a medium misconfiguration on
a jump box between the internet and customer data is not a medium problem --
and on Evidence otherwise; the reader's choice replaces the page's once they
make one. The route count is on the tab. Every panel stays mounted
(`keepMounted`), so the browser's find still reaches text in a tab not shown. A
tab whose request failed is not offered, as the provenance panel already
rendered nothing then: an empty tab would say "no citation" out of a network
error. The explanation of why, the fix, the verification and the compensating
controls stay above as they were.

**The facts are one card.** On the finding page the score and its working,
the asset and its factors, the dates it was seen, and the controls it is
evidence toward were four cards; on the risk page the arithmetic, the factors
weighed and the note that a decision closes nothing were three. Each is now one
card of sections divided by a hairline, each section named by a small muted
`RailHeading` (`components/common/states.tsx`) so the figures lead. "Evidence
toward these controls -- not a compliance claim" moved behind a question mark;
"Nothing resolves without proof" stays printed, shortened to two sentences,
because it is said where the decision is made.

**Every tab strip slides.** The vendored `TabsList` now renders Base UI's
`Tabs.Indicator` before its tabs: the default variant's raised fill and the
line variant's underline are one element that moves to the tab chosen,
positioned from the `--active-tab-*` variables Base UI writes, with the
per-tab fill and `::after` underline kept only for a vertical strip, which
CloudGuard has none of. Base UI keeps the indicator `hidden` until the layout
has settled, so it appears in place and moves only on a change. It is a CSS
`translate` and `width` transition on one small absolute element rather than a
`layoutId`: the primitive already knows where the tab is, and every tab strip
in the app -- the asset page, the attack-path panel, the scan wizard, the
remediation panel -- gets it without a change at the call site.

**A proved fix draws its check.** When a verification comes back fixed, the
check in `FixVerification` is Lucide's check path stroked on with `drawPath`
over the chart duration, and its circle crossfades to the pass colour. It is
drawn because it arrived: the panel exists only after somebody asked for the
check. A finding that was already fixed when the page opened gets the "Verified
fixed" alert, which does not move. The plan's second half -- the resolved row
collapsing out of the open list -- was not done as an exit animation: a table
row cannot collapse its height cleanly, and the list refetch already removes
it, with the rows that stay sliding up under §179.

## 181. Connecting a cloud: one line a step, the copy nobody reads deleted, and a step that finishes draws its check

The fourth pass of §166 and §167, over connecting a cloud and managing the
connection -- the flows that held the most words (`connection` and `setup`
were about 2,370 of the catalogue's 5,970) and 58 of the strings over the copy
budget.

**What was read on every visit is one line.** The setup intro, each rail step's
line, the consent, deploy, review and hand-off bodies, the two "who you need"
notes, the paused and nothing-in-scope notes, the connections page's intro and
empty state, the read-only promise, the schedule notes, the scope footnote and
the discard and remove confirmations were each cut to one line of at most 90
characters. Where the cut part carried something a reader may want -- why admin
consent scans nothing, what unticking a subscription does to findings already
held, what change detection reacts to and how a burst of changes becomes one
scan -- it is an `Explain` string behind a question mark: `StepHeader` takes
`explain` beside its title, and the change-detection panel's title carries the
reaction and the timing. The read-only promise stays printed at the foot of
the connect screen with its icon, as one line: it is the claim somebody deciding
whether to grant anything reads.

**Copy nobody could read is deleted.** The whole `connect` namespace -- an
earlier connect page's twelve strings -- had no reader left in the code, and
six more over-budget strings under `connection` and `setup` (`noGuidsNeeded`,
`noWriteActions`, `scheduleHelp`, `scheduleNotReady`, `whoYouNeedDetail`,
`doneBody`) were read by no component. They are removed rather than shortened.

**What is left over the budget is left on purpose.** The strings still in
`overBudget.ts` under `connection` and `setup` are the ones shown when something
has gone wrong or is about to be destroyed: why a deployment stalled (Contributor
instead of Owner, the wrong scope, propagation), consent that did not grant a
permission, a role upgrade, the change-detection wiring Cleave cannot do for
the customer, and how to revoke in Azure what removing a connection here does
not. Each appears only in that situation, and there its detail is the help;
hiding it behind a question mark would make a stuck person hunt for the fix.
The AWS strings are untouched: AWS is gated out of the UI and every string about
it is unverified (CLAUDE.md). The baseline went from 123 to 90.

**A step that finishes draws its check.** Each row of the setup rail is its
own component (`RailStep`) so it can hold `useValueChange` on whether it is
done: a step that finishes while the reader watches -- consent landing, the
role verified -- turns its number into a check that draws itself, and the line
down to the next step fills from the top (`scaleY`). A step already done when
the page opened is drawn done and still. The check is `DrawnCheck`
(`components/common`), now shared with the proved fix of §180, which draws
only when told the check is news.

## 182. Attack paths and scans: empty states in a line, how-to-read behind the question marks, and finishing said by the mark that replaces the spinner

The fifth pass of §166 and §167, over the attack-path page, the simulation
panel, and the scan cards and pipeline.

**Copy.** The attack-path empty states (no scan, no entry point, nothing
sensitive, no route) each had a paragraph under their title; each is now one
line. The map's how-to-read and the note on route groups were already behind
question marks and are now `mapHelpExplain` and `patternsHelpExplain`, which
the copy budget lets run long. The simulation panel's intro is a line ("Press a
line on the drawing, or start from a change below"), with why a plan is checked
as a whole behind a question mark beside its title. On the scans side the delete
dialog, the nothing-found notes, the replay results and the two collection
hints are one line each. `cutHereDetail` had no reader and is deleted. The
phrases that carry the product's rule stay word for word: a reading that
produced nothing leaves its checks "unknown, never passed", and an advisory
replay says "No finding was created, resolved or reopened". The stuck-worker
diagnostic keeps its detail, as §181's troubleshooting copy does. The baseline
went from 90 to 71.

**Motion.** The simulation's "N of M routes close" counts to its new answer when
the plan changes, and the bar under it grows by `scaleX` instead of animating
its width. The route map already closes routes in hop order (`closeDelay` in `RouteMapCanvas`), so
that part
of the plan needed nothing. In the scan pipeline, a phase that finishes while the
reader watches, or a subscription's collection that does, replaces its spinner
with a `DrawnCheck` that draws itself -- keyed on `useValueChange` seeing the
previous state as running -- and a phase or lane that was already done when the
scan was opened shows its check still. The pipeline's counters already counted
up (§87), so nothing else changed there. The phase marks carried a `layout`
prop that did nothing under `domAnimation`; since §179 loads `domMax`, it now
animates a mark's move when the phase row reflows, which it was written for.

## 183. One radius scale and one spacing grid, held by the design budget test; what the polish pass did not do

The last pass of the series §166 began. `--radius` (0.5rem) gives four corners
-- 4, 6, 8 and 12px as `rounded-sm`, `-md`, `-lg` and `-xl` -- and Tailwind's
spacing runs in 4px steps. Beside them, 19 corners had been typed as 9 or 10px
(inputs on sign-in and onboarding, the setup step boxes, the code block, the
segmented filter, the cut panel's callout) and 3 as 2px for legend swatches, and 13
margins and paddings as 7, 13, 18, 22 or 26px. The 9 and 10px corners are
`rounded-lg`, the 2px swatches `rounded-xs`; 22 and 26px are `mt-6`, 18 is
`mt-4` or `px-5` (so the severity strip and stat strips line up with every
other card's `px-5`), 13 is `px-3`, 7 is `py-2`, and the sign-in button's 42px
height is `h-10`, the height of the inputs above it. A navigation row is 2px
taller for it. `designBudget.test.ts` now also fails on a radius, margin,
padding or gap written in pixels outside the vendored primitives, as it does on
a pixel font size.

Three items of the plan were not done, on purpose. Replacing bordered cards
with section headers across the app, and restricting muted text to metadata,
are judgements a screen has to be looked at to make; the passes above already
removed the cards they could see a reason to (the dashboard's, and the detail
pages' rails and tabs), and a codemod would have made the rest blind. The
empty-state icon drawing its outline once is not done because it would be motion
on arrival rather than on a change, which §167 rules out -- an empty list is the
state of things, not news. The before-and-after screenshots the plan asked for
were not taken: the development machine has no environment for the frontend
and no API to point it at, so they are for the deployed app.

## 184. A scan runs only the rules of the clouds it read

Found by walking the app against the Azure demo: the Findings list carried
AWS-IAM-004, "The account password policy is weak or absent", tenant-wide, in
an organization with no AWS account. The engine ran every enabled rule over
every scan. Per-resource rules were held to their cloud by `matches()` and
AGGREGATE rules by `for_provider()` (MULTI_CLOUD.md §6), but narrowing an Azure
context for an AWS rule only empties its resources -- `controls` is shared on
purpose -- and AWS-IAM-004 reads a missing `password_policy` as "no policy
set". The rest of the AWS aggregate rules found nothing and said UNKNOWN,
which cost less but was still wrong: fifty checks nobody could have asked for
counted against coverage, and "rules run" said 219 when 169 could run.

`RuleContext.providers` names the clouds a scan read, and `RuleEngine` does not
run a rule of any other: no verdict, no coverage entry, not counted in
`rules_run`. It is taken from the scan's accounts and its directory
connection, not from the resources that came back, because a subscription
whose every listing failed still owes its rules an UNKNOWN -- scoping by
resources would turn "could not look" into "nothing to look at". `None` runs
everything, which is what a context built by hand in a test means.

Compliance follows. A rule a scan does not run reads as "never ran", and
`resolve_control_status` makes that INCONCLUSIVE, so an ISO 27001 control
mapped to a passing Azure rule and an AWS one would have stayed inconclusive
for ever in an Azure-only organization. `_snapshot` now reads only the rules of
the organization's connected clouds, with the same no-connection exception as
`frameworks_for` (§74).

Migration 0048 deletes the findings already raised this way -- a rule's
provider with neither a connection nor an account of it in the organization --
and the risks they leave with no member, deleted rather than resolved for the
reason §124 gives. An organization that uses AWS keeps every AWS finding; its
own AWS scans judge them.

## 185. Four places the app contradicted itself, from the same walk

The walk that found §184 ran every page against the demo recording, and four
things on it said one thing beside something that said the opposite.

**A framework card's figure is a count, not a percentage.** The ring's centre
was `coverage_ratio` as a percentage, captioned "assessable". It was never a
grade -- the page says so twice -- but HIPAA read "94%" over a ring almost all
red, with no control passing, and nobody reads the caption before the number.
The centre is now controls with a verdict out of all of them ("32/34"), under
"with a verdict", and the overview's compliance panel prints the same count
beside its bar. A fraction says what it counts; a percentage invites the
sentence the product must never produce. The framework page keeps its
"40% assessable coverage": there it heads a bar split by status and a paragraph
saying what it measures.

**"Read on a schedule" only when there is a schedule.** The Environments row
said it of every live connection that was not listening for changes, next to a
last-read line saying "only when asked". A connection with no interval now
says "Read when a scan is run".

**A subscription is named, not numbered, on the map and on a route.**
`load_placements` fell back from the account's display name straight to the
subscription id, so a subscription with no display name was drawn on the
estate map, listed under "Your subscriptions" and named where a traced route
enters it as `00000000-…`, while the asset page's breadcrumb, which falls back
through `account_name` first, called it "Production Subscription". Both now
take the same chain.

**An identity's kind is words.** `_identity_kind` lowercased Azure's
`principalType` whole, so a link's evidence reached the Risks page's top fixes
as "(serviceprincipal)". CamelCase is split into words: "service principal",
"foreign group".

## 186. Counts that say what they count, a catalogue of your clouds, reasons for the customer, and fixes that lead somewhere

Four more from the §184 walk.

**The overview's severity strip says what each figure counts.** "Critical 2"
sat under the score and above five critical _risks_ at 100, and nothing said
the strip counts findings. Each tile now carries a line: "open findings", or
"checks, not findings" under no verdict. The strip is otherwise as §178 left
it -- one measurement split four ways, with the unanswered beside it.

**On Findings, a severity count is the filter.** The four counts above the
list were figures only, with a severity dropdown beside the search doing the
same job out of sight of them. `StatStrip` takes an optional `onSelect`: the
cell gets a button stretched over it, `aria-pressed`, named "Show only critical
findings", and pressing the selected one again lets go. The cell stays a
`dt`/`dd` pair, the button inside the `dd`. No verdict is not a toggle: it
counts checks, which are not a slice of this list. Its hint -- and any
`StatStrip` hint -- moved inside the `dd`, because a paragraph beside the pair
is not valid in a `dl`, which axe caught the first time a strip used one.

**The rule catalogue opens on the clouds you use.** An Azure-only
organization's catalogue opened on fifty AWS checks, first in rule-id order,
that §184 now guarantees will never run for it. A cloud filter defaults to
"Your clouds" -- the providers of the organization's connections, or every
cloud before one is connected, as `frameworks_for` treats compliance -- and
offers "All clouds" and each cloud by name. It is drawn only when the
catalogue holds more than one cloud.

**An unavailable cloud's reason is written for the customer.**
`available_providers` returned one reason, and it was the operator's: "Set
AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_PRINCIPAL_ARN", printed on the
card a customer was choosing between, beside the environments page calling
the same thing "Coming soon". `unavailable_reason` is now the customer's
sentence -- "Coming soon" for AWS not yet verified or configured, and "Not set
up on this deployment yet" for anything else -- and `operator_detail` carries
the variable or the checklist. The wizard shows the second closed beneath the
picker, under "Notes for whoever runs this deployment", rather than on the
cards: still shown, since hiding it would leave the person running a
self-hosted deployment with nothing to go on.

**Top fixes lead to the fix.** The three links on the Risks page that close
the most routes were text. Each is now a `GraphLink` to the attack-path page's
Simulate tab with that cut in the plan, as the overview's "Simulate this cut"
already opened it.

## 187. The worst asset first, one way to prove a fix, somewhere to start, and a scan compared with its own last

Five more from the §184 walk; two of them were not what they looked like.

**Asset groups in queue order.** The list arrives worst first, and grouping by
resource group kept that within each group -- then sorted the groups by size.
Nineteen archive accounts with two findings each led the page, and the one
account with seven sat below them, under a subtitle saying "ranked by open
findings". Groups now keep the order the rows arrive in, so the group holding
the top of the queue comes first. Grouping stays the default (§112's reason
stands).

**Proving a fix is offered once.** A finding's header carried a filled "Rescan
to verify", and the end of its fix a filled "Verify it now", which does the
same. The header's appears only where the fix has none -- a finding on no
asset, or one already resolved.

**An empty queue says where to start.** "Assign a finding from its detail page"
greeted somebody with fifty-eight open findings. Under it now are the five
worst open ones -- the findings list's own first page -- each with "Track",
the same `POST /remediation` a finding's page sends. Not in the demo, where
the API refuses it. The line above says "track", as the button does.

**A scan is compared with the last scan of the same scope.** `useLiveScan`
looked for a previous scan of the same connection, so a scan of one
subscription -- a finding's rescan, and every scan the demo seed replays --
had no comparison, and the dialog subtitled "what it changed" said nothing
about change. A subscription's scan is now compared with the last of that
subscription, a connection's with the last of that connection; never one with
the other, which would be a difference in scope. "-1 findings" is "-1 finding".

**Opened on a scan, the dialog takes focus itself.** Focus went to the first
control in the footer, which on a finished scan is "Run another", so Enter
started a scan. `initialFocus` now focuses the popup, which its title names;
setup keeps the default.

Not changed, because the walk misread them. A traced route on the attack-path
canvas _is_ framed (`RouteMapCanvas` fits its boxes); a route from the first
column to the last spans the whole drawing, so framing it barely changes the
zoom. The asset page's neighbourhood looked drawn low, but it is centred in a
canvas taller than the part of it above the fold.

## 188. Smaller things from the same walk: settings in effect, a first scan's arrivals, one-page gaps, the palette, the last owner, a long settings page, equal counts, a short sidebar and a phone

**Reports keep their order and say their settings.** The options sit below
the two documents on purpose -- they refine one rather than gate it -- so
moving them above was not the fix. Each card now says what its document will
hold ("Last 30 days · every section", or "4 of 5 sections"), counted over the
sections that report takes, so a box unticked earlier is readable where the
download is.

**A scan's many arrivals are one row.** A first scan introduces every asset
at once, and forty "First seen" rows buried the two changes that day meant
something. Six or more arrivals from one scan fold into "N assets first seen"
where the first of them stood, with "Show them" opening the list.

**A one-page gap is that page.** The pager wrote "1 2 … 4": the ellipsis took
the room of the "3" it hid. A gap of exactly one page is drawn as its number.

**The palette searches findings, and matches a rule at a word.** It left out
findings because the endpoint once had no text search; it has one
(`GET /findings?search=`, which the findings page uses), so open findings are
a group now, worst risk first. Rules are filtered in the browser, and a bare
substring made "stg" -- the start of an asset's name -- match six PostgreSQL
rules. A rule now matches where one of its words starts; a query with a space
or a hyphen is a phrase or an id, and matches anywhere as before. The dialog
is wider, so a rule's name is not cut at thirty characters.

**The last owner is not offered removal.** The API refuses to remove or demote
an organization's only owner (§162); the members table offered both anyway.
That row now says "The last owner stays" in their place.

**Settings links to its sections.** The page is seven topics and 2,600 pixels
long; a row of links under the heading names what is on it -- only the
sections this reader is shown -- and jumps to each.

**Risks: an untriaged count equal to the whole says so, and the counts
filter.** "Live risks 77" beside "Needs triage 77" read as a mistake; they are
equal until someone decides about a risk. The triage cell says "none decided
yet" then. Critical, High and Needs triage are toggles for the list, as the
severity counts on Findings are (§186).

**A short screen shows the whole sidebar.** At a laptop's 640-odd pixels of
page, Environments and Settings sat below the sidebar's fold with nothing
saying it scrolled. Below 760 pixels of height the rows and the gaps between
the groups tighten until the twelve rows fit.

**A phone reads the findings list.** The table was held at 760 pixels and
scrolled sideways under titles cut to fifteen characters. Under the small
breakpoint it is three columns -- finding, severity, score -- with the title on
up to two lines and the asset under it. The overview's three "Today" figures
sit side by side at every width rather than one per row.

Left alone: the organization's country stays a two-letter box. A picker of two
hundred countries for a field read only on a report's cover is more control
than the field is worth.

## 189. The last of the walk: a labelled trend, context you can act on, rows that exist, frameworks by name, fixed findings last, readable tiles and an icon

**The overview's trend says what it is.** The "Today" panel drew the score's
history in the score's band colour with no axis, so a score of 1 becoming 3
was a red line climbing -- a warning, to anyone who did not know. Above it now:
"Security score", and where it went ("1 → 3"). The colour stays: it is the
band, and §84's ramp is authoritative.

**An asset's context says where it came from, and how to settle it.** The
criticality and data sensitivity tiles each held one row labelled "Value",
beside the tile's own name. The row is now labelled by origin -- "Declared",
"Inferred" or "Not declared" -- and anything not declared carries "Declare it
for the subscription", to `/settings#context`. Settings scrolls to a fragment
once its sections exist; the router does not do that on its own.

**A finding's asset lists only what it has.** A user has no region and no
environment, and two rows of "—" under a person's name said nothing. Each row
is drawn only when there is a value.

**A finding's frameworks are named as the compliance page names them.** The
rail spaced the id -- "MITRE ATTACK", "CIS AZURE 6.0" -- and listed frameworks
about a cloud the organization does not use. It now reads the compliance list
the page already caches: the catalogue's short name ("ATT&CK"), in the
catalogue's order, and only frameworks offered to this organization (§74).
Until the list arrives it falls back to the spaced id, as before.

**A risk lists its open findings first.** A route's verified fixes sat between
its open findings and read as more to do. Open ones come first, then the
fixed, under "N of M already fixed; the rest are open".

**Two tiles pass contrast.** The asset list's group count was faded with
`opacity-70`, and the environments page's "Coming soon" tiles with
`opacity-60`; both failed axe in both themes. The count is `text-muted-foreground`;
the tiles are dashed rather than faded.

**The tab has an icon.** With none declared, every load asked for a
`/favicon.ico` that does not exist. `public/favicon.svg` is the brand's cut
mark, in each theme's foreground and primary.

Not done from the walk's list: the overview's "link to cut" panel keeps its
height beside the priority risks -- it is one of a pair of panels sharing a
row, and shrinking it would leave the row ragged instead.

## 190. A fix is written into the customer's own Terraform only by changing one value that is already there

Fix-as-Code (`docs/FIX_AS_CODE.md`) turns a failing finding into an edit of the
customer's HCL: first as a diff of a file they upload, later as a pull request.
`terraform_hints` already refused to generate a resource block, because a block
is either missing the arguments Terraform requires and will not apply, or fills
them in and applies something nobody asked for. Writing into a real file raises
the cost of being wrong -- the customer runs `plan` on what CloudGuard wrote --
so the same refusal becomes the rule for the edit engine.

**One argument, in a block that exists, whose value is a literal.** The engine
replaces the byte range of one value and nothing else, so formatting and
comments survive; it re-parses afterwards and refuses unless the block reads
back with exactly the values asked for. Where the argument is absent -- the
usual shape of an insecure default, `https_only` left out and so `false` -- it
adds the one line to the block, after its last argument and at its indent, and
the diff shows it as added. That is an optional argument set, not a required
one filled in; the rule is about structure. It never creates a resource or a
nested block -- a missing `network_rules` block is a decline, because
`default_action = "Deny"` with no IP rules would cut off every client. It
declines, with a reason a machine can read, when the resource's `name` is
interpolated, when the value comes from a variable or a module input, when the
resource is under `count` or `for_each`, when more than one block matches, or
when the provider version is outside the releases the attribute was checked
against. A decline is an answer, not an error. Collection states
(`NONE_MATCHING`, `NOT_EMPTY`) are structural edits and are not attempted.

**In an upload, the only block of its kind is the asset's.** Matching on a
literal `name` alone edited 3 of 468 resource blocks in HashiCorp's azurerm
examples and Azure's quickstarts: public HCL builds names from variables and
`random_string`. But a file that holds a type holds one block of it 94% of the
time, and an upload is a person saying which file defines this asset. So where
no block carries the asset's name, exactly one block of the rule's types exists,
and its name is an expression, the upload flow takes it -- with `matched_by:
"sole_block"` in the answer and a line in the UI asking the reviewer to check
it is the asset. A sole block with a different _literal_ name is another
resource and is not taken. Measured again, 55% and 69% of the same blocks get a
diff; most of the rest are nested blocks the file does not have. It is opt-in
(`sole_block=True`) and only the upload route opts in: in a repository
CloudGuard searched, nobody chose the file, and "the only one here" means
nothing.

**Every attribute is held to the provider's own schema.** The azurerm schemas
of 3.117.1 and 4.81.0, dumped by `terraform providers schema -json` and trimmed
by `tools/iac/trim_azurerm_schema.py`, are test fixtures; each
`terraform_attribute` must be a settable argument of each declared
`terraform_resource_types` entry in both, of the type the hint writes. The
first run found three hints that would have failed a customer's `plan`:
AZ-STO-002 named `https_traffic_only`, which azurerm never had; AZ-DB-002 wrote
`"Disabled"` into a boolean; AZ-KV-001 wrote `true` into
`soft_delete_retention_days`, a number of days. All seventeen Azure attributes
now carry the same name in both releases, so no attribute needs a per-version
spelling yet, and one whose name differs between majors needs the file's
provider version before it is written. `azurerm_app_service`, which spells the
web TLS floor `min_tls_version`, is left out of the web rules' types rather than
given a second spelling.

**Parsing is tree-sitter.** The HCL and Bicep grammars ship as binary wheels
for macOS and manylinux on 3.12 (`tree-sitter`, `tree-sitter-hcl`,
`tree-sitter-bicep`) and give exact byte ranges; a literal name parses as
`literal_value` and an interpolated one as `template_expr`, which is the decline
test. python-hcl2 was ruled out because it cannot write a file back unchanged.
Repository and upload contents are untrusted input: parsed, never evaluated,
under size and depth caps.

**For pull requests, later: a GitHub App, no auto-merge.** Installation tokens
are scoped to the repositories the customer picks and expire in an hour; a
personal access token is neither. The App's key is an environment variable and
tokens are never stored. CloudGuard opens a PR on its own branch and never
pushes to a default branch or merges. A merged PR records a claimed fix; only
the next scan's PASS resolves the finding.

## 191. Standards are the checks that enforce them, run by one hook file on commit, on push and in CI

A rule the code is held to exists only as a check that fails. A guideline
written in prose and enforced by nobody drifts, and `npm run lint` pointing at
a missing config for months (eslint.config.js) is what that looks like here.
So each standard has exactly one tool and one config file, and
`docs/STANDARDS.md` says why, never restating the rules the configs hold.

**One tool per concern.** Ruff lints and formats Python (it replaces black,
isort, flake8 and most of bandit); mypy types it. ESLint lints TypeScript;
Prettier formats TypeScript, JavaScript, CSS and hand-written JSON, at default
settings but `printWidth: 100` to match Python. Biome was declined because it
does not carry the jsx-a11y strict set (§155). A second Python linter or
formatter needs an entry here first.

**One file, three places.** `.pre-commit-config.yaml` holds every check. It
runs on commit (fast, changed files only), on push (mypy and tsc, the
whole-program checks), and in CI's `repo` job on every file. Git cannot install
hooks from a clone, since that would let a repository run code on `git clone`,
so `tools/dev/setup.sh` installs them once per clone. The local hooks are
feedback; the CI job, made a required check on `main`, is the enforcement.
Anyone who never installs them still cannot merge what they refuse.

**The project's pins are the hooks' pins.** Prettier, ESLint, mypy and tsc
run through `tools/dev/web.sh` and `tools/dev/api.sh` at the versions in the
lockfile and `pyproject.toml`. Ruff runs from its own hook repository, so it
works in a clone with no virtualenv yet, and `tools/dev/check_hook_pins.py`
refuses a Ruff hook version different from the pyproject pin. Third-party hooks
and GitHub Actions are pinned to a commit with the tag beside it, because a tag
can be moved after review.

**CI's token reads and nothing more.** `permissions: contents: read` at the top
of the workflow. A job that needs more asks for it on its own.

**Formatting landed as one change.** Ruff 0.8.4 became 0.16.9 and formatted
240 Python files; Prettier formatted 162 web files. The commits that did only
that are listed in `.git-blame-ignore-revs`, so `git blame` skips them
(`git config blame.ignoreRevsFile .git-blame-ignore-revs`, which
`tools/dev/setup.sh` sets; GitHub reads the file on its own). Vendored shadcn
components, generated files and the design handoff are not formatted.

**Rules tighten by ratchet.** A new lint rule lands as an error. A file it
cannot yet pass is listed in a per-file ignore or a mypy override with its
reason, and the list only shrinks, as with `i18n/overBudget.ts` and the
pip-audit ignores. Ruff's security, async and pytest rules, mypy `strict`,
type-aware ESLint, markdownlint, yamllint, actionlint, zizmor, djLint and
CodeQL come next, in that order.

## 192. Markdown is held to markdownlint at 100 columns, checked and never auto-fixed

The documentation is most of what a reader meets first and much of what this
log is, and nothing checked it: list markers, emphasis, fences and line lengths
varied file to file, and one fence in `DEPLOYMENT.md` had text after its closing
backticks, so it never closed and the Railway section below it rendered as code.
`docs/MARKDOWN_GUIDELINES.md` condenses Google's, Microsoft's and IBM's guides;
`.markdownlint-cli2.jsonc` holds what a tool can see, run by the commit hook and
CI's `repo` job (§191).

**Every rule on, styles chosen.** `-` bullets, ATX headings, `_italic_` and
`**bold**`, fenced code with a language on every fence (`text` for output and
ASCII diagrams), no trailing spaces, 100 columns for prose with tables, code and
headings exempt. HTML is refused but for what Markdown has no form for:
`<details>`, `<summary>`, `<b>` inside it, and `<br>` in a table cell. Table
pipe spacing (MD060) is off: consistency within a table is enough.

**The existing docs were brought to zero, rendering unchanged.** Autofixes,
a reflow of 717 prose lines, and a language on 68 fences, verified by rendering
every file with markdown-it before and after and comparing the HTML. Three
changes are deliberate: the broken `DEPLOYMENT.md` fence now closes, README's
second heading is an H2, and two indented code blocks in this file are fenced.
Hard line breaks that were trailing spaces are now a trailing `\`. Two
formulas too long to wrap carry a one-line exception with its reason.
`RULE_CATALOG.md` is generated and excluded, as are the design handoff and
developers' local `.claude/*.local.md` rules.

**Checked, never fixed by the hook.** `markdownlint-cli2 --fix` inserted blank
lines inside a fence nested in a list, which is how the Railway section came to
render as code a second time. A fix is made in the editor, where the extension
shows it, and reviewed. Relative links across files are not yet checked; that is
the next step, with lychee in offline mode.

**Claude Code reads the guidelines.** `.claude/rules/markdown.md` and
`.claude/rules/python.md` are path-scoped rules, loaded when a matching file is
in play. The `@path` import does not expand inside a rule, so each says to read
its guideline in full and carries the rules most often missed.

## Open items carried forward

**Railway Config as Code ends on 2026-12-01 (§152).** The API and worker read
`infrastructure/railway/api.json` and `worker.json`. Both have to move to
`.railway/railway.ts` (`railway config
pull`, then edit, `railway config plan`, `railway config apply`) before that
date, or the API and worker lose their start commands.

**Data residency is not built (§113).** An organization setting for allowed
regions, a rule over `CloudResource.region` per provider (never one rule that
branches on provider, §74), and a mapping to the controls that ask for it. The
region map and `?region=` filter are what it would link into.

**Phase 9 (reports) is built, generated on request rather than stored.**
Jinja2 renders the report to HTML and WeasyPrint prints that HTML — the stack
`ARCHITECTURE.md` §1 already named. Three choices there are worth keeping:

- **No jobs table, no artifact store.** A report is a read of data that is
  already computed, and the technical report is bounded at
  `MAX_TECHNICAL_FINDINGS` so it cannot grow into something that needs a queue.
  Storing PDFs would additionally owe the customer an answer about which of
  five stored copies is current; regenerating is cheap and always truthful.
- **HTML is the artifact, PDF is the wrapper.** `render_html` is what the
  templates produce and what the tests assert against; `render_pdf` prints it.
  This is not only for testing: WeasyPrint needs native pango/cairo/harfbuzz
  that a developer machine may lack, so the import is lazy and a server without
  them answers 503 with one clear sentence instead of failing every import that
  transitively reaches the module.
- **The trend is drawn on a fixed 0–100 scale.** The report is asked whether
  posture is improving, and a sparkline fitted to its own observed range makes
  a wobble from 81 to 84 climb as steeply as a recovery from 20 to 84. Inline
  SVG, generated by a pure function, because a PDF has no JavaScript and
  nothing in a report may fetch anything. Fewer than two readings draws
  nothing: a line through one point shows a direction nobody measured.
- **The caveats are printed, not hovered.** A PDF outlives the screen it was
  taken from and gets forwarded to auditors and boards, so the cover carries
  when the evidence was collected, how many checks reached no verdict, what
  could not be read at all, and that compliance coverage is evidence rather than
  a verdict. UNKNOWN never renders as a pass, on paper as on screen, and an
  accepted risk is counted in its own right rather than absorbed into
  "not open" — it is a decision to live with a finding, not a fix.

**Compliance mappings drive a coverage view, still without framework logic.**
Every rule carries CIS Azure 2.0, ISO 27001, GDPR and NIST CSF control
references in `rules.compliance_mappings`. `app/compliance/catalog.py` supplies
the other half — what those identifiers mean — as data, and
`app/services/compliance.py` joins the two against the latest scan. Requirement
15 still holds: no rule imports the catalogue, and nothing anywhere branches on
a framework name.

Three choices there are worth keeping:

- **Control titles are CloudGuard's own wording.** CIS Benchmarks and ISO/IEC
  27001 are copyrighted under licences restricting redistribution of their text.
  The identifiers are reproduced; the prose is not. Every framework carries a
  link to its authoritative source.
- **The catalogue lists controls no rule covers.** A catalogue of only what
  CloudGuard checks would report full coverage forever. A test asserts each
  framework has at least one uncovered control, and another asserts every
  control a rule references actually exists — a typo in a mapping would
  otherwise produce evidence that silently goes nowhere.
- **Coverage counts conclusions, not passes.** `coverage_ratio` is the share of
  controls CloudGuard reached a verdict on. UNKNOWN resolves to INCONCLUSIVE and
  is excluded — the same reason UNKNOWN is never PASS in the rule engine, except
  that here the misreading would end up in front of an auditor.

**A connection is a tenant or management group; subscriptions are discovered.**
`cloud_accounts` used to _be_ the connection — one row per subscription, tenant
id typed in by hand. That had two problems.

The first was a blind spot. A subscription created after onboarding was invisible
to CloudGuard, because nobody had registered it. An environment that is never
scanned produces no findings, and no findings reads as safe. Everywhere else this
product refuses that trade — UNKNOWN is never PASS, gaps are recorded rather than
dropped — and the connection layer quietly violated it.

The second was a tenant-binding hole. `cloud_accounts.tenant_id` came from the
request body, and validation only checked whether Azure answered. But CloudGuard's
service principal exists in _every_ tenant that has ever consented, so naming one
of those tenants on a fresh connection and clicking verify succeeded — the probe
passes, because the access is genuinely there — and the caller was reading an
environment belonging to somebody else. This is the confused-deputy problem AWS
integrations use an ExternalId for.

Both are fixed by the same change. `cloud_connections.tenant_id` is nullable and
written in exactly one place: the consent callback, from the tenant Entra itself
reports. Validation refuses any connection whose own consent has not completed.
A per-connection nonce additionally rides in the deployment artifact and is read
back from the role assignment's description — defence in depth, not the primary
control, since it is consent that binds the tenant.

`scope_type` keeps the narrow option first-class: `SUBSCRIPTION` behaves exactly
as the old model did. The coverage-versus-least-privilege trade is the customer's
to make, and a tenant-wide grant is genuinely broader than they may want.

Everything below a cloud account — scans, resources, findings, risk, compliance —
is untouched by this. Discovered subscriptions are still `cloud_accounts` rows,
so the pipeline never learned that anything changed.

**Supabase connections go through the Session pooler, not the direct host.**
Current Supabase projects resolve `db.<ref>.supabase.co` to an IPv6-only
address, and Railway cannot route IPv6 -- the connection fails with `Network is
unreachable` before it leaves the container. The Session pooler
(`aws-0-<region>.pooler.supabase.com`, port 5432) is IPv4 and behaves like a
normal PostgreSQL connection, including the session-level `SET LOCAL ROLE` and
`request.jwt.claims` that RLS depends on. The Transaction pooler on port 6543
is not an option: it does not support prepared statements, which asyncpg
requires.

**Multi-subscription accounts.** `cloud_accounts` holds a single
`subscription_id`, matching `DATABASE.md` §2. The child-table alternative the
spec mentions is a migration away and no core logic assumes one subscription per
tenant.

**Identity reach beyond direct role assignments (§125, §126, §128, §130).**
Read PIM activation policies, so an eligible role that activates without MFA or
approval can be walked like a held one. Read service principal owners beside application owners.
Expand the
members of a role-assignable group that holds a directory role but no Azure
role, whose members are read today only when it also holds an Azure role
(§126). Delegated permissions (`oauth2PermissionGrants`) act only on a signed-in
user's behalf and are not drawn.

**What a finding's fix closes.** The remediation queue says how many routes
run through a task's asset (§127), not which routes its fix would close. Saying
that needs each rule to declare which links its fix removes: a role-assignment
rule removes its principal's assignment, while an exposure rule may or may not
stop an asset being a way in, depending on what else exposes it.
