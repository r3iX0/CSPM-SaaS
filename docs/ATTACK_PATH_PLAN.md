# Attack paths: plan

Status: **being built, from 2026-10-11.** Built so far: Phase 0, the route ledger (`DECISIONS.md`
§244); item 1, the fix plan (§245); item 2, how to make a cut (§246); item 3, the route sentence
(§247); item 4, a readable drawing (§248); item 5, progress (§249); item 6, worst first (§250); item
7, say what matters (§251); item 8, hand it over (§252); E, the query bar (§253); I and F, the asset
card and inspector (§254); G, faster what-if (§255); J, motion (§256); H, a cut as a pull request
(§257, §258). Worked out on 2026-10-10 from a browser walk of `/attack-paths` on the local stack
(the demo organization, 17 routes) and a read of how Microsoft Defender for Cloud, Orca, Wiz and XM
Cyber present attack paths. Each item needs its own `DECISIONS.md` entry before it is built. The
route ledger (see "Foundations") is built first, as Phase 0. Items 1 to 4 are the first cut, planned
as phases A to D. Items E to J, an investigate depth for engineers, come after it.

## Who it is for

The client is not always a graph reader. Three people open this page:

- a security engineer, who wants the one change that closes the most;
- a cloud or platform engineer, handed a cut, who wants to know exactly what to change;
- a manager or auditor, who wants to know whether it is getting better.

Each asks a question the page should answer in that order:

1. Am I exposed? (how many routes, to what)
2. What is the one thing to do first?
3. How exactly do I do it?
4. Did it work, and is it getting better?

## What the page does today

The page is strong on question 1 and on analysis. It draws every route on one canvas,
weights each line by what cutting it closes (§122, §123), groups repeated routes (§123),
reads a route hop by hop in the panel (§142) and simulates a plan of up to ten cuts on
the server (§141).

From the walk, where it falls short:

- **No answer to "what first" on arrival.** The page opens on three counts, a canvas and
  a list of 17 routes sorted by hops. The best cut exists (the Simulate tab lists choke
  points, and the overview leads with one, §145), but the reader has to go looking.
- **A cut never says how to make it.** "Add to the plan" simulates a change. Neither the
  route navigator nor the Simulate tab links to a fix, a finding or a task. The loop
  from cut to work to verified stops at "what if".
- **The drawing is small.** Fitted to the whole estate, 17 routes draw boxes too small to
  read at the default frame height. Tracing a route highlights it but does not bring it
  into view.
- **No sense of progress.** Nothing says whether there are more or fewer routes than at
  the last scan, or which routes are new.
- **Order ignores impact.** The default sort is hops. A two-hop route to a High key vault
  sits above a three-hop route to a Critical ledger. Tracked routes already carry a risk
  score that the list does not show.
- **Sentences are built for analysts.** A hop reads "app-payments-api runs as
  app-payments-api (managed identity) (service principal)". It is accurate, but it is
  not a story a manager can repeat.

## What others do

- **Defender for Cloud** leads with an overview: attack paths over time, the top five
  choke points, top targets and entry points. Its list filters by risk level and
  remediation status. Each path has a Remediation tab that lists the recommendations
  that break it, separate from ones that only lower risk.
  ([Microsoft Learn](https://learn.microsoft.com/azure/defender-for-cloud/how-to-manage-attack-path))
- **Orca** scores each path from 0 to 99 for business impact and puts the top five on its
  risk dashboard. It also prioritizes the issues that sit on many paths, so that one fix
  breaks several.
  ([Orca blog](https://orca.security/resources/blog/cloud-attack-path-analysis/))
- **XM Cyber** ranks remediation by choke point: the exposures where many paths to
  critical assets converge. Its dashboard leads with choke points and critical assets
  by severity.
  ([XM Cyber brochure](https://xmcyber.com/wp-content/uploads/2026/02/XM-Company-Brochure.pdf))
- **Wiz** treats crown jewels as the endpoints, and traces confirmed paths to an owner
  and a fix, including a pull request.
  ([Wiz Academy](https://www.wiz.io/academy/detection-and-response/attack-path-analysis))

All four lead with **what to fix**, not with the graph. The graph is how a reader checks
the answer. Cleave already computes a better answer than most of them: exact severance
for every link (§122) and whole-plan simulation (§141). It does not yet put that answer
first.

## The idea that holds it together

**Lead with the plan, prove it with the drawing.** The page should open on the smallest
set of changes that closes every route, say how to make each one, and show that it
worked. The canvas, the list and the simulator stay as they are. They become the
evidence for that plan, not the first thing a client has to read.

## Foundations

Added on 2026-10-11 from the question "if we built attack paths from scratch today,
what would we do differently". The analysis stays as it is: exact severance (§122),
whole-plan simulation (§141), evidence read off the assets (§121) and a graph cached
against the data's version (`services/graph.py`, `load_graph`). What changes is what is
kept and what the page counts in. These four foundations sit under the items below,
and the route ledger is built first, as Phase 0.

### The route ledger (Phase 0)

Today a route has two sources of truth. The scan writes `ATTACK_PATH` risks from its
own graph (`services/scan/correlation.py`). The page rebuilds every route live from the
database graph and matches them to risks by their ends in the browser, after fetching
up to 500 risks (`AttackPaths.tsx`). Nothing records which routes existed at each scan,
so the page cannot say what is new, what closed, or whether things are getting better.

The ledger records it:

- **Written by ANALYZE**, from the graph the scan already builds. Every write goes
  through `ScanWriter.commit`, fenced on the step's attempt (§65, §108).
- **One row per episode of a route.** A route is keyed by its ends, as `route_key` keys
  it (§103). A row has the key, the route's steps and shape, the scan that first saw
  it, the scan that last saw it, and the scan that no longer saw it. A route that closes
  and comes back opens a new row, so a reopening is visible rather than overwritten.
- **Read by the page and the API.** Counts at each scan, routes new and closed since the
  last scan, and a route's history are reads of the ledger, not rebuilds. Live rebuild
  stays for what only it can answer: the what-if.
- **Tracked marks join on the server.** A route's risk is joined to the route by key in
  `GET /attack-paths/graph`, which removes the 500-risk match in the browser. The join
  does not wait for the ledger, which is empty until the first scan after release: a
  tracked mark that vanished until then would be a regression.
- **History starts at release.** No backfill is attempted: past scans did not keep
  their routes, and a reconstructed history would be a guess shown as fact.
- **Isolated like every tenant table**, under RLS with `organization_id`.

Phase 0 builds the table, its migration and policies, the fenced write in ANALYZE, and
one read (`GET /attack-paths/history`) that items 5 and 8, the receipt and the Rerouted
event build on.

### Cuts as the unit of work

Nobody fixes a route. Somebody removes a link, and one removal can close many routes.
Competitors list paths, and Cleave's risks queue tracks routes the same way.

A **cut** becomes its own record: the link, keyed as `AssetGraph.removal_key` keys it
(§127); its cost; its owner, derived from the ownership rules as a task's is (§236); its
status; its fix (item 2); and the routes it holds up. Its status runs from planned, to
made, to proved, where a scan shows the link gone and its routes closed. A link that is
gone while a route between the same ends remains is said as such (see "Rerouted
routes" below).

This starts beside the risks queue, as the cuts on the fix plan card (item 1) with an
owner and a status. Moving the queue itself onto cuts is a later decision.

### A cost on every link

Every removable link counts the same today, so a plan can only be ranked by how much
it closes. A cost per kind of change lets the plan be the cheapest set of changes that
closes every route:

- removing a role assignment costs least;
- a network change costs more, because it can break traffic;
- containment cannot be removed at all, as `removable` already says.

The costs are a table in code, deterministic and shown to the customer behind a
question mark, with their own decision. With costs, the plan can be found as a weighted
minimum cut, from a source on every way in to a sink on every sensitive asset. That
cut ignores the hop limit (`MAX_DEPTH`), so it closes every route but may not be the
smallest set. The page shows only what `simulate()` confirms, and says "these changes
close all 17", never "the fewest". Greedy (item 1) stays as the fallback.

### Rerouted routes

A route counts as closed only when nothing connects its ends (§103). That is right for
counting, but when a cut forces a route through another way round, nothing says so
today.

The ledger keeps each route's **shape**, the sequence of its links' removal keys. When
a route's key survives a scan with a different shape, the ledger records a **Rerouted**
event: the customer learns that their change moved the attacker rather than stopped
them, and which way round is left. A cut whose link is gone while its routes reroute
reads "made, but rerouted", never "proved".

## Proposed: first cut

### 1. A fix plan at the top

A card above the frame: **"3 changes close all 17 routes"**, then each change on one
line with the routes it closes, cumulatively ("then 5 more", "then the last 2").

- Computed on the server: a greedy pick over the severance already done for every
  link, re-ranked after each pick as `Simulation.next` already is (§141). The greedy
  pick is not guaranteed minimal; the card says "changes", never "the fewest".
- Capped at the plan limit (`MAX_SIMULATED_CUTS`, 10). Where ten do not close
  everything, it says how many remain.
- "Try this plan" loads it into the Simulate tab (`cut` in the URL), so the existing
  simulation is the proof.
- Replaces the three-count strip as the lead; the counts move into the card's sentence.

### 2. Every cut says how to make it

Wherever a cut is shown (the plan card, a hop in the navigator, a row in the Simulate
tab), a **"How to fix"** section:

- the change in one sentence ("Remove the Key Vault Secrets User role from
  app-payments-api's managed identity on kv-payments");
- the open findings on the link's two ends that this change resolves, each linking to
  its fix sheet (`/remediation?fix=`, §202) and offering Track through `useTrack`
  (§205);
- where the cut is a role assignment, the provider command to remove it. Commands are
  per provider (§74) and come from the API, never built in the browser.

This closes the loop: cut, then task, then a scan verifies (§18), then the route
disappears from the page.

### 3. A route says itself in one sentence

Each route gets a plain sentence, shown at the top of the navigator and as a second
line on its row: "From the internet, app-payments-api runs as its own identity, which
can read secrets in kv-payments." It is built from the hops' existing labels and facts,
and `vocabulary` keeps Azure words out of sentences (§78). The hop-by-hop navigator
stays below it, unchanged.

### 4. A drawing you can read

- When a route is traced, the canvas fits that route into view and dims the rest. Today
  it only highlights.
- The default view has a readable minimum zoom. It fits the busiest columns rather than
  shrinking the whole estate into one frame.
- The frame is taller on large screens.

## Proposed: next

### 5. Progress over time

"17 routes, 4 fewer than the last scan", with **New** and **Closed** marks on routes
since the previous scan, and a small trend across recent scans. It reads the route
ledger (Phase 0), and a route that reopened or rerouted is marked as such.

### 6. Worst first

Show each route's risk level and score where a risk tracks it, and add a "Worst first"
sort by that score as the default. Untracked routes sort after it by sensitivity, then
hops.

### 7. Say what matters

From a box's panel: "This holds sensitive data" or "This does not", saved as a context
declaration (§207). The "no sensitive targets" empty state gets the same action. Today
risk context is declared per subscription; per-asset needs its own decision.

### 8. Hand it over

"Track every fix in this plan" creates the tasks for all findings the plan resolves in
one step, and the plan goes into the PDF report beside `AttackPathRoute`.

## Proposed: an investigate depth for engineers

Items 1 to 8 serve the client who wants to know what to do. An engineer handed a cut
wants to check it. Added on 2026-10-11 from a design framework for engineer
investigations, and held to what Cleave already reads. These items follow the first cut
and do not replace it: the plan stays the default view, and the depth below sits on the
same page.

### E. A query bar with facets

- Search, sort and the place or box filter move out of the panel into a bar above the
  frame, so the panel holds only reading a route and simulating.
- Facets: target sensitivity, way in (internet or identity), link kind (role, network,
  identity), subscription, tracked or untracked, and at most N hops.
- Every facet is in the URL, like `trace`, `q` and `sort` (§138, §142). Routes that do
  not match fade on the canvas through `kept` in `flowChrome.ts`; they are not removed.
- "Copy investigation link" copies the page's URL with everything in it.
- Past a node threshold, the canvas folds each resource group into one box that opens
  on a click, as the estate map's boxes do (§111).
- The panel stays docked (§133, §137) but can be collapsed and widens while a hop is
  read. Only below the `lg` breakpoint does it become a sheet: on a wide screen, a
  slide-over would cover the nodes being inspected.

### F. The inspector reads deeper

When a hop or a box is selected, the panel adds three sections:

- **Effective permissions.** For a role hop, a grid of the principal against the
  resource and what the role controls there (read, write, secrets, assign roles). It is
  read from the `AccessKind`s that `graph/access.py` already evaluates (§125). A data
  action under an ABAC condition shows as "not claimed", never as granted.
- **Defined in code.** For an asset in the Terraform state index (§229), its address and
  the file that defines it, found by `find_resource_block`. Otherwise it says "Not in an
  indexed repository".
- **Recent activity.** The asset's recent change events, and an identity's last sign-in
  where the tenant's licence allows it. Where the licence rules it out, it says so
  (§196). It is named "Recent activity", not runtime context: Cleave reads configuration
  and runs no agent, so it has no process, traffic or exploit telemetry to show.

### G. Faster what-if

- **Instant pruning for a single cut.** Each line already carries the exact routes that
  it alone closes (`closes`, §122), so the canvas can prune at once when the plan holds
  one cut. From two cuts on, the drawing waits for the server and says it is checking:
  two cuts can close what neither closes alone (§141), so the browser never guesses.
- **"If this is compromised."** Any box can show its blast radius, from the existing
  blast-radius endpoint, drawn with the same fading as everything else on the canvas.

### H. A cut as a pull request

- Today, behind `FIX_PRS_ENABLED`, a rule's fix is previewed as a Terraform diff and
  opened as one pull request per repository (§232), checked by the plan guardrail
  (§234).
- A cut is a link, usually a role assignment, and removing one means **deleting an
  `azurerm_role_assignment` block**. The engine only edits arguments today, so this is a
  new kind of edit, with its own decision.
- A block with `count` or `for_each` can define many assignments. It is deleted only
  where every assignment it defines is in the plan, the same rule §232 applies to an
  edit.
- The pull request is opened in one click. Merging stays a person's review and is never
  applied by Cleave.
- Where the assignment is not in an indexed repository, the handoff falls back to the
  command from item 2.

### I. Boxes you can ask

Boxes are buttons already: a click picks one, the panel lists the routes through it,
and arrow keys move between boxes (`RouteMapCanvas.tsx`, `AssetNode`). But a click lands
on a list, not an answer. Added on 2026-10-11 so that a click on a box says three things:
what it is, what it holds up, and what can be done about it.

What each gesture does:

| Gesture | Today | Proposed |
| --- | --- | --- |
| Point at a box | Nothing on boxes; only list rows preview | Everything off its routes fades; the panel does not change |
| Click | Picks it; the panel lists its routes | Selects it; the panel opens its asset card |
| Double click or Enter | Nothing | Frames the box and its routes, and unfolds a folded group beside it |
| Esc | Back to the list | Clears the selection, then the framing |
| Click on empty canvas | Clears | Unchanged |

This keeps the rule every canvas follows: a click selects and the rest fades (`kept`,
§134). Nothing is draggable.

**The box at rest** keeps two lines and at most two badges: its name with an
open-findings badge in the worst severity, then its type and place with one role mark
(a way in, or sensitive data). Selected, it takes `focus-ring` and a raised surface
token, with no glow or scaling (§167). A box whose routes the plan closes greys after
its last route, as it does today (§146).

**The asset card** is what a click opens in the panel:

- its name, type and place, with a link to the asset's page;
- how many ways in reach it, what it reaches, how many routes run through it, and its
  sensitivity, counted from the routes on the page;
- **Best cut here:** of the links touching the box, the one that closes the most, read
  from the `severs` already on every line (§122), with "Add to the plan";
- its open findings, fetched only when the card opens (`/api/v1/findings?resource_id=`),
  each with a link to its fix sheet (`/remediation?fix=`, §202) and Track (`useTrack`,
  §205);
- **Trace worst route**, **If compromised** (item G) and **Copy link** (`?through=`,
  which already reopens the page on the box).

**Keyboard and access.** The canvas stays one tab stop, with the arrow keys moving
between boxes, Enter framing and Esc backing out. One-key shortcuts go through
`singleKeyShortcut`, so they can be turned off (§155): `t` traces the worst route, `c`
adds the best cut and `b` shows what a compromise reaches. A box keeps `aria-pressed`
and the summary it speaks today, and the card announces itself through `LiveStatus`.

**On a phone,** a tap selects and the card opens as a sheet.

**Not doing:** a menu or popover floating over the box, which would cover the
neighbours being read and fight label placement (§143), and hover tooltips, which do not
exist on touch. Actions live in the panel.

Everything but the findings is on the page already, so this is frontend work. The
findings come from an existing endpoint.

### J. Motion that explains what changed

Added on 2026-10-11. The canvas already moves in a few places: the camera frames a
traced route (`DURATION.quick`), the traced route's lines run as dashes, new boxes rise
(`cg-rise`), and a settled plan strikes its closed routes one after another and greys
each target after its last route (§146). This item extends that to every interaction
on the graph, so that each movement says what just changed and where.

**Rules.** These are the ones the product already keeps (§149, §167), applied to the
canvas:

- Something moves only when a value it shows changed, or the reader caused it
  (`useValueChange`). Nothing loops, except the one "checking" state below.
- Timings come from `DURATION` and the easings from `src/lib/motion.ts`: `instant`
  (120 ms) for pointing, `quick` (180 ms) for panels, `page` (240 ms) for the camera,
  `chart` (600 ms) for a line drawing itself.
- Only opacity, transforms and stroke offsets move. The layout never moves: boxes keep
  their place, and nothing is draggable.
- Lines are SVG drawn by React Flow, so they animate with CSS keyframes in `index.css`
  (stroke offset), not one `m.*` element per line. The panel and its cards use `m.*`
  under `<LazyMotion strict>`.
- At most a set number of lines (for example 30) animate at once. The rest take their
  end state, so a 200-route estate stays smooth.
- With reduced motion (`<MotionConfig reducedMotion="user">`,
  `usePrefersReducedMotion`), every state lands at once and "checking" is said in words.

**Pointing and selecting.**

- Pointing at a box or a list row fades everything off its routes in `instant`, and
  back when the pointer leaves.
- Selecting a box draws its ring in `instant`. The asset card (item I) arrives in the
  panel with `fadeUp` in `quick`, and its counts count up (`useCountUp`).
- Framing a box (Enter or double click) moves the camera in `page`. A group folded
  beside it unfolds: its boxes rise out of the group's box (`layoutSpring`).

**Tracing a route and stepping its hops.**

- Tracing a route frames it, as now, then draws it once from the way in to the target:
  each line strokes in turn, and each box on it lifts as its line reaches it, over
  `chart` in all. It plays once per route traced, never on a re-render.
- Stepping to a hop (up and down) sends a small pulse along that hop's line, from source
  to target, in `page`. The panel's marker for the hop slides to it (`layoutId`), and
  the camera pans only if the hop is out of view, as now.
- Moving to the next or previous route (left and right) fades the old route back into
  the drawing while the new one draws.

**Simulating.**

- Adding a cut marks its line at the middle with scissors, and the line's two halves
  draw back from the mark in `quick`.
- With one cut planned, the routes it alone closes fade at once (item G), because their
  answer is exact on the page.
- From two cuts on, the lines the plan touches run a slow dash while the server
  checks. This is the one loop, and it stops when the answer lands. With reduced motion,
  the banner says "Checking" instead.
- When the answer lands, the closed routes strike in list order and their targets grey,
  as §146 does now. The banner's count runs down ("17 → 12").
- Taking a cut out of the plan plays it backwards: the line draws itself back in and
  its reopened routes return in list order.
- "Try this plan" on the fix plan card (item 1) adds its cuts one after another in plan
  order, and the card's running count moves with each, so the plan is told as it is
  made.

**Blast radius and change over time.**

- "If compromised" (item G) spreads out from the box one hop at a time: each column it
  reaches lights a short stagger after the one before.
- A Rerouted route (see "Foundations") fades its old way out while its new way round
  draws in, so a reader sees where the attacker would go instead.

**Tests.** A test renders each interaction with reduced motion and checks that the end
state arrives at once. A test checks that re-rendering does not replay a drawing
(`useValueChange`), following `cutSequence.test.tsx`. A performance trace on the demo
checks that a trace and a settled plan keep to the frame budget.

### Not taken from the framework

- **Cinematic motion and glows.** Motion runs only when a value changes (§167), and the
  chrome keeps one brand hue (§144). Severity stays the only loud colour.
- **A second colour code on lines.** A line's weight already says what cutting it
  closes. Colour stays for state: traced, planned and closed.
- **Orthogonal routing, for now.** Right angles pile parallel lines into shared channels.
  React Flow's `smoothstep` edge is a cheap trial on the demo. A channel router such as
  ELK is a new library, which needs a `DECISIONS.md` entry first.
- **More than two badges a box.** Open findings, and a mark for sensitive data, are
  enough to read at estate zoom.

## Later, or not at all

- **ATT&CK technique per hop.** The framework is data already (§168). It adds a label
  analysts like, but it does not help the client act. Later.
- **A notification for a new route to sensitive data.** It is cheap on the existing
  notification sweep (§237), and it fits after item 5 exists.
- **Not doing: live exploit validation** (Wiz's Red Agent). It needs network calls into
  the customer's estate, which the rule engine forbids.
- **Not doing: a second graph library or a force layout.** The canvas stays React Flow,
  laid out by hop (§101).

## Open questions for planning

- Does the fix plan replace the stat strip, or sit beside it? This plan proposes it
  replaces it.
- Should the page open list-first on small screens, with the map behind a toggle? §137
  makes the drawing and routes one frame, so this would need its own decision.
- Which relationships have a deterministic "how to fix" today? Role assignments do.
  Network hops map to findings on the entry asset. "Runs as" (a managed identity)
  probably resolves through the role on the next hop, not by removing the identity.
- **Answered on 2026-10-11: what does one ANALYZE see?** Only its own scope. It builds
  its graph from the accounts it read, plus the directory (`correlate_paths` builds
  `AssetGraph` from `merged`), so a scan of one subscription sees only the routes that
  run wholly inside it and the directory. Correlation already refuses to resolve a
  route that touches an asset outside the scan's scope (`_outside_scope`, built on
  `asset_scope`), because a rescan of one subscription once closed every route in the
  others. The ledger closes by the same rule. Two consequences:
  - A route whose assets have no rows left counts as inside, so it closes. Its CLOSED
    event records why: the link was removed, or the asset is gone. A deleted connection
    must never read as a fix.
  - A route that crosses two connections is seen by no single scan, so the ledger has
    no row for it. The page then shows no New or Closed mark on it, rather than a
    wrong one.
- **Answered on 2026-10-11: which scan is "the last scan"?** None, for an organization:
  connections scan on their own schedules, and a scan may read part of one. So "new"
  and "closed" are said per scan and per route, never against an organization-wide
  "last scan". A route is New when its open episode began in the scan that last saw
  it. The page's summary names the scan it describes ("Since the scan of 9 October,
  Production: 2 new, 6 closed"), and the trend counts open routes per day from the
  episodes' times, not per scan.
