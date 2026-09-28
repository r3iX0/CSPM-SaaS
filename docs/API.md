# CloudGuard — API Design

> 🔗 **Interactive API Documentation & Schema**:
>
> - [Interactive API Playground & Docs](api/index.html)
> - [OpenAPI 3.1.0 Specification (JSON)](api/openapi.json)
> - Spec generator script: [`apps/api/scripts/generate_openapi.py`](../apps/api/scripts/generate_openapi.py)

## 1. Endpoints

Every path below is prefixed `/api/v1`. This list is generated from the routers
under `app/api/routes/` — if it disagrees with them, they are right.

```
POST   /organizations                      GET    /organizations
GET    /organizations/{id}                 PATCH  /organizations
DELETE /organizations/{id}

POST   /cloud-connections                  GET    /cloud-connections
GET    /cloud-connections/{id}             DELETE /cloud-connections/{id}
POST   /cloud-connections/{id}/discover
POST   /cloud-connections/{id}/recheck
PATCH  /cloud-connections/{id}/subscriptions
PATCH  /cloud-connections/{id}/schedule
GET    /cloud-connections/{id}/change-events
PATCH  /cloud-connections/{id}/change-events
POST   /cloud-connections/{id}/cancel      POST   /cloud-connections/{id}/resume
GET    /cloud-connections/{id}/revocation
POST   /cloud-connections/{id}/check-revoked
GET    /cloud-connections/azure/app-registration
GET    /cloud-connections/{id}/template            (unauthenticated, CORS-open)
GET    /cloud-connections/azure/consent/callback   (unauthenticated, signed state)

POST   /events/azure/{connection_id}               (unauthenticated, signed token)

GET    /cloud-accounts                     GET    /cloud-accounts/{id}
GET    /cloud-accounts/azure/permissions
GET    /cloud-accounts/{id}/context
PUT    /cloud-accounts/{id}/context
DELETE /cloud-accounts/{id}/context

POST   /scans                              GET    /scans
GET    /scans/{id}                         DELETE /scans/{id}
GET    /scans/{id}/detail                  GET    /scans/{id}/coverage
GET    /scans/{id}/collection              GET    /scans/{id}/events  (text/event-stream)
POST   /scans/{id}/replay                  POST   /scans/{id}/cancel
GET    /scans/worker-status

GET    /assets                             GET    /assets/{id}
GET    /assets/hierarchy                   GET    /assets/resolve?provider_resource_id=
GET    /changes
GET    /findings                           GET    /findings/{id}
GET    /risks                              GET    /risks/{id}
POST   /risks/{id}/status                  POST   /risks/status

POST   /remediation                        GET    /remediation
PATCH  /remediation/{id}
POST   /findings/{id}/accept-risk          POST   /findings/{id}/status
POST   /findings/{id}/rescan
GET    /findings/{id}/attack-paths         GET    /findings/{id}/provenance

GET    /attack-paths                       GET    /attack-paths/choke-points
GET    /attack-paths/graph?limit=1..200
GET    /attack-paths/blast-radius/{resource_id}
GET    /attack-paths/access/{resource_id}
GET    /attack-paths/neighborhood/{resource_id}?depth=1..3&expand=<fold id>
GET    /attack-paths/estate?subscription_id=&resource_group=
GET    /attack-paths/what-if?source=&relationship=&target=
POST   /attack-paths/simulate            { cuts: [{source, relationship, target}] }  (1..10)

GET    /rules                              GET    /rules/{rule_id}
GET    /compliance                         GET    /compliance/{framework_id}
GET    /compliance/{framework_id}/export?format=csv|json

GET    /notifications                      POST   /notifications/read
DELETE /notifications                      DELETE /notifications/{id}

GET    /dashboard
GET    /reports/{kind}?format=pdf|html&days=30&sections=a,b
```

Three of the scan endpoints exist because a scan is resumable work rather than
one call. `/detail` is the run's steps; `/coverage` is what each rule reached a
verdict on and what it could not; `/collection` is which evidence key arrived and
which did not, which is the row that makes an UNKNOWN answerable rather than
merely reported. `/replay` re-runs today's rules against a capture already
stored — no Azure call — and `/worker-status` pings the broker, because "scans
stay queued" is otherwise indistinguishable from "the product is broken".

`POST /findings/{id}/status` is the general transition; `accept-risk` is its own
endpoint rather than a status value because it takes a reason and an approver.

`/cloud-connections/{id}/recheck` is a POST because it is a probe rather than a
read. The GET validates a connection only while it is *unverified* — that is
what the setup wizard polls — so on a working connection it re-read the same row
and repainted the same answer, including a role version that had not been looked
at since the connection was created. This asks Azure two questions: whether the
read still works, and which role it works through, resolved from the actions on
the definitions the scanner's principal is actually assigned. A failed probe
leaves the recorded state alone; proving access is *gone* is
`/check-revoked`'s job, where the customer has asked that question deliberately.

`/cloud-accounts` is **read-only** except for `/context`: an account is a
subscription discovered beneath a connection, so there is nothing to create,
consent to, or validate there. Scoping one in or out is a PATCH on its
connection, not a delete — a deleted row would return on the next discovery run.

`/context` is the exception, and a principled one: everything else about a cloud
account records what Azure said, while a declaration records what a *person*
said. A customer marking a subscription production beats any amount of tag
inference, and there was previously nowhere to put the answer. The PUT replaces
the whole declaration rather than patching it — a field left out is one the
customer is no longer claiming, and a body claiming nothing withdraws the
declaration entirely, exactly as DELETE does. `UNKNOWN` is rejected for either
level: it is CloudGuard's own answer for "nothing said anything", so declaring
it would be asserting an absence that leaving the field out already asserts.

A declaration is applied by the next evaluation of the subscription — the next
scan, or a replay of its latest capture — and never rescores stored findings on
the spot. A risk score is what a scan concluded, and rewriting one from an API
call would leave findings carrying numbers no observation ever produced. It is
also applied as a *floor*: it can raise an asset's criticality above what the
capture supported but never lower it, so the worst a mistaken declaration can
do is over-rank something. `GET /assets/{id}` returns a `context` block giving
each value's source and confidence alongside it.

`/compliance/{framework_id}/export` answers with a document rather than the
envelope, for the same reason `/reports/{kind}` does: the caller is saving a
file, and an envelope would make every consumer unwrap a shape that means
nothing on disk. CSV is what goes into the spreadsheet an audit is run from and
JSON is what a GRC platform ingests; both carry every control, its verdict, the
rules behind that verdict and the provider readings behind those. Every CSV row
repeats the framework, its version and when the assessment was read, because the
thing that happens to every export is that fifteen rows are copied into a larger
sheet — where a row that no longer says which reading it came from is a
compliance claim with no date on it.

Three endpoints are unauthenticated by necessity, all protected by an
HMAC-signed token rather than a session: `/cloud-connections/azure/consent/callback`,
which Entra's redirect reaches from the customer's browser;
`/cloud-connections/{id}/template`, which Azure Portal fetches *from the
customer's browser* for the Deploy to Azure button — the reason it is also the
one endpoint answering `Access-Control-Allow-Origin: *`; and
`/events/azure/{connection_id}`, which Azure Event Grid delivers to when their
environment changes. All three are `include_in_schema=False`: they are reached
by Azure and by browsers following a link, never by this product's client, and
listing them in the OpenAPI document would invite a consumer to call them.

The webhook is separated from the template token by the `purpose` claim, not by
the signature — both are signed with the same secret, so it checks the claim
rather than treating a valid signature as proof of intent.

`/cloud-connections/{id}/change-events` returns the commands the customer runs
to wire their subscriptions up. CloudGuard cannot create the Event Grid
subscription itself: that is a write in their tenant, and it holds no write
permission anywhere. An event does not start a scan directly — a burst marks the
connection, the scan waits for the environment to go quiet, and a floor stops an
afternoon of deployments becoming an afternoon of scans.

`/rules/{rule_id}` and `/findings/{id}` carry `remediation_spec` beside the
remediation prose: the settings that must be true for the finding to close, the
CLI commands that set them, the Terraform arguments for whoever manages this in
code, and — only where one can genuinely enforce the whole rule — a generated
Azure Policy definition. `enforceable: false` with `azure_policy: null` is a
fact about the check rather than missing work: whether an administrator has MFA
is a directory setting, and no `policyRule` can express it. A rule with no
declaration at all returns `remediation_spec: null`; every rule in the current
set has one, so that answer is reserved for a rule added without one.

Each expected state carries its `comparison` — `equals`, `none_matching` or
`not_empty` — because without it a collection expectation serializes as
`equals: null`, which reads as "this must be null" rather than "this must not be
empty". A collection expectation also carries an `example`: the rule shape that
must not exist, or an entry that satisfies. Two rules report an empty
`expected_state` with a `notes` field explaining why — one judges a ratio across
the directory, the other a relationship between two assets — rather than
inventing a per-asset setting to point at.

`/notifications` is deliberately not `/changes`. That answers "what moved in the
environment" and is a property of the estate; this answers "what happened since
you last looked" and is a property of a reader — the same scan gives everyone
the same changes and each person a different unread count. Three kinds only:
a new finding on an asset that stands on an attack path, a fix a scan verified,
and a reading that stopped arriving. Severity alone is not a reason: a CRITICAL
on an isolated sandbox is a rulebook event, and a bell that fired on every
finding would be a filter rule inside a fortnight.

`meta.unread` and the list come from one read of the same rows, so a badge
cannot say three above a panel showing two. `POST /notifications/read` moves the
caller's watermark to *now* rather than to the newest stored row — the sweep
runs on a timer, and reading to the newest row would mark something seen before
it was written.

The two `DELETE`s dismiss rather than delete, and the distinction is the whole
design. A notification belongs to the organization — what happened, happened —
so removing the row would be one reader deciding what their colleagues get told.
Both write a per-reader dismissal instead, and the listing excludes them before
its limit rather than after, so a reader who puts down five still gets a full
panel. Dismissing is also not marking read: the watermark is a boundary in time
that moves on its own when the panel opens, while this is somebody saying they
are done with one row, and it says nothing about what arrives next.

Coverage-drop notifications carry CloudGuard's own sentence and never the
provider's. The collector's explanation — the remedy, who can apply it, every
permission a tenant did not grant — is the right paragraph on `/scans`, which is
where the row links; in a bell it filled the panel with one item and pushed the
rest out of sight. Rows are derived by a periodic job from `finding_events`,
`evidence` and the graph, never written by the scanner: one source of truth
about what happened, and a replay generates nothing because it writes no finding
events.

`/dashboard` carries two figures that are easy to confuse and answer different
questions. `coverage` is the share of checks that reached a verdict;
`evidence_freshness` is how recently the provider was actually read, measured
over the newest reading of each scope and evidence key rather than from the last
scan's finish time — a scan may carry a reading forward instead of re-taking it,
and a carried reading keeps the time it was collected. The headline is the
*oldest* of those readings, because an average would let a hundred fresh
listings hide the one subscription nobody has managed to read since Tuesday.

`/assets` returns `provider_resource_id` on every row, not only on the detail.
It is the one field that says where an asset *sits*: an ARM id spells out its
own subscription and resource group, so a client can group an inventory by scope
without a request per row. The row `id` is a CloudGuard identifier and names
nothing in the customer's cloud — the ARM id is what they can search for in
their own portal.

`/findings` also takes `evidence_id` — the citation chain walked from the other
end. `/scans/{id}/collection` reports how many findings rest on each reading, and
this is what that count links to. Filtered on the reading rather than on its
evidence key, because a key spans every subscription and every scan that ever
read it: the number offered and the rows returned have to be the same set, or it
is a count that does not survive being clicked.

`/findings` takes `search` and `sort` (`risk` by default, or `severity` or
`recent`), and `/risks` takes `search`. Both are on the server rather than left
to the client for the same reason: these endpoints paginate, so a client that
searched or ordered the page it was handed would be searching a hundred rows of
an estate and reporting "nothing matches" for the rest. `sort=severity` ranks
CRITICAL first rather than alphabetically, and an unrecognised `sort` is
rejected with 422 rather than quietly falling back to a different order than the
one asked for. `search` matches a finding's title, its rule id, or the name of
the resource it was found on; for a risk, its title or description.

`/changes` answers "what moved while I was away": asset appearances,
disappearances, and changes to the three attributes the risk engine multiplies a
finding by. A feed of transitions rather than a diff of two scans, so a week in
which nothing changed returns nothing rather than restating the inventory. The
window defaults to seven days and is bounded at ninety. `GET /findings/{id}`
carries the matching per-finding view as `timeline`, which is where a
regression becomes visible: a finding raised, fixed and raised again is
indistinguishable from one raised and fixed once if all you have is
`first_detected_at` and `resolved_at`.

Marking a remediation task `DONE` opens a **verification**: CloudGuard records
what it now expects to see and checks the environment on a backoff (5m, 15m, 1h,
4h) until it can answer. `GET /findings/{id}` returns that answer under
`verification`, and its `detail` is written for a person, because "still
failing", "CloudGuard could not read enough to tell" and "too soon, checking
again" are the same open finding and three different pieces of news. Cancelling
the task, or accepting the risk, withdraws the question rather than leaving it
pending.

`/assets/hierarchy` is no longer read by the web app, whose hierarchy view is now
the estate map's contents list (DECISIONS.md §112). It stays for API clients.
It returns the estate as it is organised — subscriptions (and
the directory, which belongs to no subscription) each holding their resource
groups, with asset and open-finding counts at both levels, worst first. The
resource group is read out of the ARM id's fifth segment in the database rather
than stored: an id states its own subscription and group, and a stored copy is
one more thing to keep in step. Directory assets are named as such rather than
reported as assets whose subscription is unknown.

Counted over the whole estate and returned whole, unlike `/assets`, which pages.

`/attack-paths/estate` is the same estate drawn as a graph (DECISIONS.md §111).
It returns boxes and the reach between them: subscriptions and the directory
when nothing is opened, a subscription's groups when `subscription_id` is
given, and a group's assets when `resource_group` is given as well. Those are
the same two parameters the list filters by. Each box carries asset,
entry-point, sensitive, open-finding and attack-path counts. Each edge carries
its links counted by relationship, and whether an attack path runs along it. A
lens that names nothing this organization holds is a 404. At most 40 asset
boxes are drawn per lens, and the rest are counted in one fold box.
A tree built from one page of a paginated list would show a resource group once
per page its assets straddled, each time with a fraction of its findings.

`/assets` accordingly takes `subscription_id` and `resource_group` so the tree
can drill in — `subscription_id=directory` is the tenant-scoped set, and
`resource_group` compares case-insensitively because ARM treats `Prod` and
`prod` as the same place.

`/assets` also takes `entry_point`, `sensitive` and `on_attack_path` (booleans).
They filter to what the estate map marks: exposure HIGH or CRITICAL, data
sensitivity HIGH or CRITICAL, and membership of any attack path. The first two
are the graph's own predicates over two columns. The third is read from the
tenant's cached graph. Every row carries `on_attack_path`. An asset that a
later scan no longer found is never on one, because the graph holds only
present assets.

`GET /assets/{id}` also returns:

- `placement`: `{scope_id, scope_name, resource_group}`, the same lens the
  estate map and the list's scope filter take. `scope_id` is `directory` for a
  tenant-scoped asset.
- `tenant_id`: the directory the asset lives in, for a portal link that opens
  in the right tenant.
- `absent_since`: set once a later scan looked for the asset and did not find
  it.
- `open_findings`: OPEN and IN_PROGRESS findings, counted by the server.

`/attack-paths/blast-radius/{id}` rows carry `asset_id`, so each row can link to
the asset's page. It is null for a vertex with no row.

Access holders and grants carry `through_directory` when they come from the
directory rather than an Azure role assignment: a directory role that can take
over a subscription, or the ability to sign in as a service principal (kind
`act_as`), §128. A grant's `via` is then the principal signed in as.

Holders and grants carry `eligible` for a role that could be activated under
Privileged Identity Management rather than held (§130): `kinds` says what
activating would give, and `controls` is false.

`/remediation` is ordered on the server (DECISIONS.md §127): open work first,
then priority, then `on_routes` -- how many attack paths run through the
finding's asset, carried on each row -- then the finding's risk score. Removing
a role assignment is one link to severance: an escalation line drawn beside a
role line is keyed as the role line, on the choke points, the what-if and the
route map.

`/attack-paths/access/{id}` answers who holds access to an asset and what an
identity holds (DECISIONS.md §125). `data.holders` lists every role assigned on
the asset or on a container above it, each as `{principal, role, at,
inherited_from, kinds, controls, conditional, resolved, runs_on}`: `kinds` are
the `AccessKind` values the role grants over this asset (empty for a
subscription or resource group), `controls` says whether the holder holds what
the asset holds, `resolved` is false when the role's definition was not read,
`runs_on` names the workloads that run as the principal, and for a group
`members` lists the members read as accounts, `unlisted_members` those read only
by name, and `members_total` counts both (all three null or empty for anything
that is not a group, and `members` null for a group whose membership was not
read, §126). `data.grants` lists
every role the asset itself holds when it is an identity: `{role, at, scope,
inherited_from, conditional, resolved, grants_access, access, controlled,
controlled_total, via}`, where `via` names the group the role is held through
when it is not the identity's own, and `controlled` is capped at `meta.controlled_limit` and
`controlled_total` the real count. Asset references carry `asset_id` for
linking, null where there is no row. `meta` also carries `holders_total`,
`grants_total`, `controlling` and `members_limit`. 404 for an id that is not a vertex.

`/assets` is ordered on the server — most open findings first, then name, then
id so that an offset always lands on the same row. It is a queue rather than a
directory, and a page cannot rank what it does not hold. `meta.facets` carries
the options the list's filters can offer, counted over the whole filtered set:
`{"resource_type": {type: count}, "environment": {name: count}, "region": {code: count}}`.
Each dimension is counted under every filter except its own, so filtering to one
type still offers the others. An asset with no environment is not listed as an
option.

`/assets` takes `region`, compared in one spelling (lower case, no spaces, so
`West Europe` finds `westeurope`). `region=none` finds the assets tied to no
region: the directory, and anything ARM calls `global`. The `region` facet lists
those under `none`, because the dashboard's region map links to them
(DECISIONS.md §113).

`/attack-paths/choke-points` answers a different question from the list: not
which routes exist but which single change closes the most of them. `severs` is
what actually closes, computed for *every* link in one forward pass per entry
point rather than by verifying a shortlist (DECISIONS.md §122); `on_routes` is
the larger count of routes the link merely sits on, carried beside it because
the gap is the point — a link on twenty routes that closes three is a link with
a way round, and promising twenty would be a number the customer can check and
find wrong. `closes` names the routes, because a count is a claim and those are
its working. Only removable links are candidates: a storage account has to live
somewhere, so containment is never offered, and a link that closes nothing is
not offered either.

`/attack-paths/graph` is every route as one drawable graph, and the page's only
request. `nodes` carry `column`, the fewest hops from any way in, which is the
axis the canvas lays out along. `edges` carry the hop's `facts` and `detail` —
the role held over the scope, the network two machines share (§121) — with
`severs`, the routes named in `closes`, `on_routes`, and `alternate` for the
case where those differ. `routes` are the serialized paths with the `key` the
browser and the risks queue both name a route by; `patterns` groups routes that
differ at one end only, and `loose` is the rest, so the two partition the list
exactly (§123). `meta.drawn` says how many of `meta.total` are in the payload —
a canvas silently stopping at 200 routes would be part of an estate presented
as the whole of it. Its `choke_points` are the rows `/choke-points` serves,
counted against every route rather than against the drawn ones: the risks queue
leads with those same rows under the small endpoint, because it wants three
rows and has no use for a route map, and one claim with two denominators is
worse than a second request. The attack-paths page fills that endpoint's cache
from this payload, so the two pages pay once between them.

`POST /attack-paths/simulate` answers for several links removed together, which
no sum of `severs` can: two links that are each other's way round close nothing
alone and everything together (DECISIONS.md §141). The plan is a body because
ten Azure ids three times over outgrow a URL; nothing is written, and a demo
visitor may ask it. `closed` names every route that no longer exists with the
plan made, against every route rather than the drawn ones, and `together` the
keys of those that no single cut closes alone. `remaining` is what still runs
and how many hops it now takes, which is longer where it goes round a cut. Each
entry in `cuts` carries `alone` (its own severance, the number on its line) and
`needed_for` (routes that reopen if it is taken out of the plan — zero means the
rest of the plan already covers it). A link not in the latest reading, or one
nobody can remove, is returned in `missing` and left out rather than failing
the plan, because a plan kept in a URL outlives the scan that drew it. `next`
is the choke points of the estate with the plan made, ranked against what is
left.

Every step of every route carries `facts` and `detail` beside `description`, on
this endpoint and on `/attack-paths`: "mi-app can act over sub-prod" names
nothing anybody can go and change, and "(Contributor)" does.

`/findings/{id}/provenance` answers "how do you know?" — the readings the
finding rests on, each with the listing it came from, when the *provider* was
read, the actions the read was made under, and the hash of the payload. The
finding's own `evidence` block is an excerpt of what the rule saw; this is the
citation for it, and the difference is whether a customer has to accept the
claim or can check it.

`evidence: null` means no citation was recorded — a finding raised before
CloudGuard tracked this. `[]` would mean the rule reads nothing, and answering
the first as the second would make a claim about the rule out of a gap in our
own history; `meta.recorded` says which. `age_seconds` is computed here rather
than left to the client, because a carried reading is older than the scan that
raised the finding and a client would measure it against its own clock.
`payload_available` is asked of the blob store rather than inferred from the
hash: retention prunes payloads on their own schedule, and a citation whose
bytes have aged out is still a true statement about what was read. Where the
scan itself has been deleted the reading's `outcome`, `item_count` and
`permissions` come back `null`/`[]` — "we no longer hold that", never `0`,
which would claim the listing came back empty.

Its own endpoint rather than a field on the finding, like `/attack-paths`: the
page answering "what is wrong" must not wait on a question most readers never
ask.

Each citation also carries `endpoints` — `[{path, api_version}]`, what the
reading actually called. The api-version is the half that settles an argument: a
field absent from a stored capture is a setting nobody set, or a contract too
old to return it, and a rule reading the second as the first raises a finding
out of CloudGuard's own staleness. Empty where the scan has been pruned, or
where the reading predates this being recorded — never a claim the task called
nothing. `/scans/{id}/collection` carries the same field per reading.

`/findings/{id}/attack-paths` answers whether this finding's asset stands on a
route from an internet-facing asset to a sensitive one, and where on it —
`asset_role` is `ENTRY`, `STEP` or `TARGET`, which is what decides the action:
an entry point is how somebody gets in, a target is what they came for, and a
hop in between is usually the cheapest link to cut. Membership is asked of the
whole route rather than of its endpoints.

It is a separate request rather than a field on the finding because it costs a
graph build, and the page that answers "what is wrong" must not wait on one. A
finding with no asset — tenant-wide — returns an empty list rather than a 404:
"on no route" is a true answer. An empty list is never an all-clear, and the UI
says so: what counts as sensitive is declared per subscription, so an estate
that has classified nothing produces no routes at all.

`/reports/{kind}` renders `executive` or `technical` from the evidence that
exists right now — nothing is queued and nothing is stored. It is the one
endpoint that does **not** return the response envelope: the body is a PDF or an
HTML document, because wrapping a document in `{ "data": ... }` would make every
consumer unwrap and re-encode it. Errors on this path still use the envelope.

`format=html` returns the same document the PDF is printed from, so a report can
be read without downloading one — and a deployment whose native PDF libraries
are missing still produces something useful while that is fixed. A server that
cannot render PDFs answers 503 `NOT_CONFIGURED` rather than 500.

`days` (1–365, default 30) is the **activity window**: how far back verified
fixes, completed remediation work and the trend line reach. It does not filter
the posture, which is a reading of now — a security score is not a thing that
has a date range.

`sections` is a comma-separated subset of `top_risks`, `attack_paths`,
`compliance`, `remediation`, `findings` (`findings` only means anything in the
technical report). Omit the parameter for all of them; pass it empty for none,
which is a posture-only report. An unknown name is refused with 422 rather than
ignored — a misspelling that silently produced a document without the section
somebody asked for is the one failure a report cannot afford. Whatever is left
out is *named on the cover as excluded*, so a reader downstream can tell a
choice from an absence of evidence. The posture block and the evidence caveats
are not optional either way.

`/dashboard` carries two things the screens could not otherwise show without a
second request each. `coverage.categories` is the last scan's evidence grouped
by category with an `incomplete` count — PARTIAL counts with FAILED, because a
truncated listing cannot support "none of them are public" — so a reader is told
*which* part of the estate could not be read rather than only how much.
`top_risks[]` carries `kind` and the three context levels the score was built
from (`internet_exposure`, `data_sensitivity`, `asset_criticality`), which are
already columns on the row and cost no extra query; they let a rank be read as a
reason rather than as an assertion. Each row also says where its graph opens
(DECISIONS.md §139): `asset_id` is the asset row a finding risk is about, when it
is about exactly one asset, and `route` is `{entry_id, target_id}`, the provider
ids an `ATTACK_PATH` route is keyed by on the attack-path page. Both are null
otherwise, and one query covers the whole list.

`regions[]` is where the estate runs, one row per provider and region code:
`{region, provider, assets, open_findings, by_severity, readings, unread}`,
ordered by what is open there, severity by severity from critical down. Every
asset and finding tied to no region is one row with `region` and `provider`
both null, and that row always comes last. `readings` and `unread` count only
the last scan's readings that were taken in a region, which no Azure reading
is. Coordinates are not in the payload; the web app holds them
(DECISIONS.md §113).

`remediation_activity` is eight weeks of findings raised, verified fixed and
reopened, grouped from the finding-event log rather than from the findings
themselves — `first_detected_at` and `resolved_at` are two points on a line, and
a finding raised, fixed, regressed and fixed again is indistinguishable from one
raised and fixed once. Reopenings are reported separately and never netted
against fixes.

Attack paths and changes stay on their own endpoints and are fetched separately
by the dashboard. A path costs a graph build and changes are a windowed feed, so
folding either into this payload would make the numbers everybody came for wait
on the two panels nobody scrolls to first.

`/risks` lists **live** risks unless a `status` is named: a finding risk while
its finding is open, a scenario until the route closes. A risk row outlives the
finding it was scored from, and listing every row ever raised made the page
disagree with the dashboard about the same estate on the same day. The rule is
settled rather than strict — a risk linked to no finding at all is still
listed, because the absence of a link is not evidence that a risk is over.

Each `/risks` row carries `finding_count` (open findings it covers) and, on a
finding risk, `route_count` (open routes and escalations sharing one of its
findings).

`POST /risks/{id}/status` and `POST /risks/status` (`risk_ids`, at most 100) take
`status` (`OPEN`, `IN_PROGRESS` or `ACCEPTED`), `reason` (required to accept) and
`expires_at`. `RESOLVED` is refused: a scan resolves a risk, never a person. A
finding risk writes the decision to each open, in-progress or accepted member
through the finding's own actions — events, audit rows and exceptions exactly as
on the finding page — and reads its status back from them, least-settled member
first. A route or escalation keeps a status of its own, and its end date on the
risk. `expires_at` is taken only with `ACCEPTED` and refused if already past;
accepting an accepted risk again replaces its end date. The bulk form checks
every risk before writing anything and applies to all or to none.

Once `expires_at` passes, the `expire-acceptances` sweep (every five minutes)
reopens the risk as `OPEN`, writing a timeline event and an audit row with no
user. `/risks` rows carry `accepted_until`: the earliest running end date among
a finding risk's accepted members, or a route's own. `GET /findings/{id}` carries
`accepted_until` too: the running acceptance's end date, `null` when the finding
is not accepted or has no end date.

`GET /risks/{id}` returns `observed_at` on a scenario: when the route was last
seen, resolved from the scan that saw it. `null` where that scan has been pruned
or the route predates this being tracked — both mean "we cannot say when", and
the page renders that rather than a date it cannot support. A finding risk
carries none, taking its reading from the finding it was scored from.

`/compliance` reads the rule catalogue's `compliance_mappings` against the
framework catalogue in `app/compliance/catalog.py` and this organization's
latest scan. Each control resolves to FAILING, INCONCLUSIVE, PASSING,
NOT_ASSESSED or NOT_COVERED — and `coverage_ratio` counts conclusions
(pass **or** fail), never passes, because a share-of-passing figure would be a
compliance score and this API does not issue those.

---

## 2. Response Envelope

Consistent shape for every response:

```json
{ "data": {}, "error": null, "meta": {} }
```

Errors:

```json
{
  "data": null,
  "error": { "code": "CLOUD_ACCOUNT_NOT_FOUND", "message": "Cloud account not found" },
  "meta": {}
}
```

---

## 3. Authentication

```
React → Supabase Auth → JWT → FastAPI → Validate JWT → Get user ID
      → Get organization membership → Check role → Perform operation
```

The frontend may use the Supabase publishable key. **Never** expose the Supabase service-role/secret key in the browser. See `SECURITY.md`.
