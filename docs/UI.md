# CloudGuard — Product UI

See `PRODUCT_SPEC.md` §4 for the underlying UX principle: don't overwhelm, prioritize, always answer WHAT/WHY/HOW BAD/HOW DO I FIX IT/DID THE FIX WORK.

---

## 1. Overview (Executive Dashboard)

One argument read top to bottom, not a wall of cards. Each step is the
precondition for the next:

```
Overview                            ✓ Assessed 31 Aug 01:51  [Scan now] [Reports]

┌───────────────────────┬────────────────────────────────────┐
│ SECURITY SCORE        │ POSTURE TREND                      │
│   72 / 100            │        ╭────                       │
│   Needs attention     │   ─────╯                           │
│   ↑ +7 · assessed …   │                                    │
└───────────────────────┴────────────────────────────────────┘

 Critical 0 │ High 1 │ Medium 1 │ Low 0 │ No verdict 3

 ASSESSMENT COVERAGE                       75%  · oldest reading 22h
 ✓ Network  ✓ Storage  ⚠ Identity

 WHERE IT RUNS
 ░░░░●░░░░░░░●◌░░░░░░░    ● East US       Virginia · 3 assets     4 open
 ░░░░░░░░░░░░░░░░░░░░░    ● West Europe   Netherlands · 9 assets  7 open
                          ● North Europe  Ireland · 16 assets     nothing open
                          ─ 5 assets not tied to a region, 2 open

┌────────────────────────┬────────────────────────────────────┐
│ PRIORITY RISKS         │ SHORTEST ATTACK PATH               │
│ ▣ Public database      │ vm-jump-01 → prodstorage           │
│   Internet-facing      │ ① runs as mi-jump                  │
│   Sensitive data       │ ✂ can act over prodstorage         │
│                94 CRIT │                                    │
└────────────────────────┴────────────────────────────────────┘

┌────────────────────────┬────────────────────────────────────┐
│ REMEDIATION            │ RECENT CHANGES                     │
│ 34% verified fixed     │  2h ●─ storage-prod — exposure ↑   │
│                        │  1d ●─ vm-jump-01 — appeared       │
└────────────────────────┴────────────────────────────────────┘
```

**The order is the argument.** Where the posture stands and which way it moves;
what that number is made of; how much of the estate the opinion was formed from;
what to deal with and what those faults form *together*; whether any of it is
getting fixed; what moved while you were away.

Coverage sits third on purpose — a score computed over half an environment is a
different claim from the same number over all of it, and a reader who has
already acted on the risks below has been told too late. It is never phrased as
a security percentage: 75% coverage is the share of checks that reached a
verdict, not 75% secure.

**Where it runs follows coverage**, because the two finish one sentence: how
much was seen, and where (DECISIONS.md §113). A dot-grid world map (hand-drawn
SVG, no map library) places each region at its metro. The dot is coloured by
the worst open severity there and sized gently by asset count, and a region
with nothing open is drawn muted, so the largest clean estate is never the
loudest mark. The ranked list beside it is the content: every row links to
the asset list filtered to that region, and the map is hidden from assistive
technology. What has no region is a line under the list, never a point. A
region the last scan could not fully read is ringed and marked unread. The
panel is absent until something is tied to a region.

**UNKNOWN sits in the severity strip**, at the end and labelled "no verdict". It
is not a fifth severity and it is never a pass, but a reader tallying what is
wrong has to see what could not be answered in the same glance.

**A ranked risk carries the terms it was ranked by** — internet-facing,
sensitive data, business-critical — so a rank reads as a reason rather than as
an assertion. A scenario is marked as a route, because it groups findings that
are already counted individually. The row leads with a severity-tinted mark
rather than an ordinal: the list is already in rank order, so a number column
would restate the reading direction, and the tint is what a reader actually
scans a list of five for. Score and severity badge sit together at the trailing
edge, where the eye lands after the title.

**Recent changes is drawn as a timeline** — date gutter, spine, entry — because
the question it answers is temporal: one bad afternoon and a steady drift are
the same five rows in a flat list and visibly different on a spine. The spine
stops at the first and last mark rather than running off the ends, which would
imply rows that are not there. A movement keeps its shape as well as its colour,
so a regression stays distinguishable from an arrival, and an attribute that
moved into UNKNOWN renders neutral in both.

**The charts follow the question, not the variety.** Rings only where the data
is a whole divided in two or three (coverage; finding status); severity as one
stacked bar; risk bands and framework coverage as bars from a common baseline;
the trend as an area on a fixed 0–100 scale with the score bands painted behind
it. The Assets hierarchy's treemap went with the hierarchy (§112): the map's boxes carry the same counts.
Sparklines under each severity count and beside the attack-path panel come from
posture history the payload already carried. No dual axes anywhere. Everything
with axes or a tooltip sits inside shadcn's `ChartContainer`, which is what
themes the tooltip; the contrast-tuned neutral ramp and the severity scale in
`index.css` stay the only definitions of the colours it draws with
(DECISIONS.md §84).

Motion counts numbers up when they change, animates a chart once on mount,
brings the panels in one at a time in the order they are read, and honours
`prefers-reduced-motion` by arriving rather than crawling. Timings live in
`lib/motion.ts` rather than in components, so a panel and a bar cannot disagree
about how long an arrival takes. A row that was already on screen when a poll
returned does not animate: entry motion means something arrived, and the
dashboard refetches every twenty seconds.

**Inventory counts are not headline figures here.** Assets, subscriptions and
resources are true and answer a different question; every pixel one takes is a
pixel not spent on what is wrong.

**Nothing is scored before a scan exists.** The empty state offers the first
scan and shows no number at all — a score over no evidence is a number about
nothing, and a reassuring one is worse.

---

## 2. Technical Dashboard — Navigation

A left sidebar, grouped by the question each screen answers rather than by the
order the pages were built (`components/layout/nav.ts`):

```
Posture    Overview  Changes  Reports
Exposure   Findings  Risks  Attack paths  Assets
Response   Remediation  Compliance
Evidence   Scans  Rules  Cloud  Settings
```

It collapses to an icon rail, remembered per browser in `localStorage` —
CloudGuard sets no cookies — because sixty pixels of label per row is a good
trade on a wide monitor and a bad one on a small laptop. The rail keeps the
grouping and the order and gives up only the words; every icon still names
itself on hover and to a screen reader. The collapse toggle sits at the foot of
the sidebar, beside the connection status, so it stays under the pointer in both
widths (DECISIONS.md §85). On mobile the same navigation is a sheet behind a
toggle in the header, since a control inside a closed sheet could not open it.
The shell is shadcn's `Sidebar` primitive (DECISIONS.md §84); the toggle is
wrapped so that its accessible name says which way it will go rather than the
primitive's fixed "Toggle Sidebar".

Every page title repeats its sidebar icon. Across the product, icons carry
meaning rather than decoration, and each meaning has exactly one icon, defined
in `src/lib/icons.ts` (DECISIONS.md §86). Resource types, risk factors, detail
page facts and change kinds each have their own shape. A shape always sits
beside a word and never replaces one. Severity badges and status pills are the
exception: they stay text on a tone, with no icon, to keep dense rows simple.
Filters built on `SelectField` show the chosen option's icon where it has one,
and a dot while they are narrowing the list. Cloud providers are drawn by `ProviderMark`, a monochrome hand-drawn
glyph, because Lucide carries no brand logos.

One page replaces another rather than cutting to it: the outgoing page leaves in
120ms and the incoming one arrives in 240ms, which reads as a replacement rather
than as a crossfade of two dense screens. Filters and pagination live in the
query string and deliberately do not re-play it — what changed there is the
table, not the page.

Detail screens carry a breadcrumb rather than a lone back button — what this is
a detail *of*, then what it is called — so somebody arriving from a shared link
knows where they are, not only where to leave.

---

## 3. Key Pages

**Assets** — resource, type, environment, region, criticality, exposure, findings count, last seen; filterable by type/environment/exposure, by what the map marks (reachable from the internet, sensitive data, on an attack path), and by scope. Two readings of one inventory, switched in the header (DECISIONS.md §112). **List** is the queue: assets with open findings first across every page, ranked by the API, filterable, paged, groupable by resource group, type or environment. A row on an attack path carries a small route mark. The type and environment menus offer every value in the filtered set, counted by the API, not only what is on the page. **Map** is the estate's shape and its wiring (§111). Subscriptions and the directory are boxes, with the reach that crosses between them drawn as arrows and counted. A click selects a box or an arrow and the panel beside the canvas says what it is: for a box, what reaches it and what it reaches, each a row that selects that arrow, and — where attack paths run through it — one link to them on the attack-path page, narrowed to it (§138); a double click or Enter opens a subscription on its groups and a group on its assets (§133), and pointing at a box fades what it does not touch (§134). The lens is the list's own scope filter, so switching views keeps the same set. Reach runs left to right: each box sits one column past the furthest box that reaches it, an arrow runs back only where reach loops, and an arrow that crosses several columns passes through a slot kept empty for it (§134). Each box counts entry points, sensitive assets and open findings. The map is for connections: it draws no route, walks none, and draws a quiet box like any other (§138). A row of legend chips names the marks, and the rest of how to read the map sits behind a question mark. The panel's tabs are the map's text forms: the same boxes listed worst first (what the hierarchy view used to be), and the reach across boundaries written as sentences; picking one selects it on the map. Pressing an asset opens its page on the Connections tab with the graph already drawn. Past 40 assets a lens folds the rest into one dashed box that links to the list. The list's other filters do not apply to the map, and the map says so when any are set. An old `?view=tree` link opens the map, and an old link to walk a route on it (`walk`, `hop`) opens that route on the attack-path page.

**Asset** (one asset's page, §112) — the breadcrumb returns to the list or map exactly as it was left, then names the subscription and resource group, each linking to the map opened there. The header carries the type, region, environment, first seen and last scanned, a Copy ID button, and Open in Azure for ARM resources (the link names the tenant, so it opens in the right directory). A banner says so when the last scan no longer found the asset. A summary strip gives open findings by severity and the three factors every finding on the asset is multiplied by, each with where its value came from. Below it are four tabs, kept in `?tab=`: **Findings** (open by default, closed one press away, and two different empty states: "no open findings" for a modelled type, "no checks for this kind of resource yet" for an unmodelled one), **Connections** (the neighbourhood graph and blast radius, which load when the tab opens; a link with `?around=` or `?trace=` opens here. The graph selects as the map does: a click selects a box or an arrow and the panel beside it says what it is and which routes run through it, and a double click, Enter, or the panel's button re-centres on it (§134); a legend beside the depth buttons names its marks, the dashed box only when one is drawn (§136)), **Access** (who holds a role on the asset or above it, grouped as can take what it holds, can change its configuration, can read its configuration, and could not be read, each with the workloads that run as the holder and, for a group, its members, plus who is eligible to activate a role over it, in its own group, plus directory roles that can take the asset's subscription and, on a service principal, whoever can sign in as it, each marked as the directory's; on an identity, every role it holds, including through a group, through signing in as a service principal, and through a directory role, and how many assets each one controls, §125, §126, §128), and **Configuration** (the collected JSON).

**Findings** — finding, severity, asset, risk, status, first/last seen; filterable by severity/status/rule and free text, searched and ordered in the database rather than in the browser. Severity is a select like every other filter in the product; its trigger names the active severity, so which one is applied reads without opening anything (DECISIONS.md §85). Severity, risk score and last seen order from their own column headers, one direction each: worst risk, worst severity and most recent all mean descending, and an ascending security queue puts the least urgent row first. A finding's title previews in full on hover, because the column truncates and opening six rows to find the one you meant is not navigation.

Every paged list uses one pager (`common/Pager.tsx`) with real page numbers — first, last, and a window either side — so the end of a four-hundred-row list is one click rather than eight. The changes feed is windowed by date and has no total, so it gets Previous and Next and nothing that implies a length.

**Risks** — the triage queue: findings, attack paths and escalations ranked together by risk score, the kind as a segmented view (All / Findings / Attack paths / Escalations), each finding row described by what was found on that asset rather than by the rule's rationale, level, status (Needs triage / In progress / Accepted / Resolved) and search as refinements. A row says what deciding about it decides about — "40 findings" on a grouped risk, "On 2 routes" on a finding that routes run through. Rows are selected by checkbox or `x` on the row `j`/`k` has marked, and a bar over the list offers only the decisions that would change something: **Mark in progress**, **Accept…** (a reason, an optional end date after which the risk returns to Needs triage on its own, and a sentence saying how many findings and routes it reaches — offered on accepted rows too, to move the end date) and **Reopen**. An accepted row shows "Accepted until …" when it has an end date (DECISIONS.md §104). A decision on several rows applies to all or none. Nothing is resolved by hand, and the demo offers no decisions. The three links that close the most routes sit above the list as **Top fixes**, linking to the attack paths page (DECISIONS.md §103).

**Attack paths** — the analysis behind the routes, drawn and listed together (DECISIONS.md §123). Above everything, the changes that close the most routes, each with what actually closes named and a **Simulate the cut** that greys out what would go out of reach — on the drawing, from the same answer the number came from, with nothing sent to Azure. The map draws every route as one graph: columns are hops from the outside in, so left to right is an attacker's progress; a line's thickness is how many routes close if it is cut, checked for every link rather than a shortlist; pressing a line simulates that cut, pressing a box narrows the rail to the routes through it. A legend above the drawing names its marks — a way in, sensitive data, open findings, a line's weight, and while a cut is tried the dashed cut and the greyed boxes — with how to read it behind a question mark (§136). The drawing and its routes are one frame (§137): the panel on its side lists repeated routes first as one row each — "3 virtual machines reach customerdata the same way", opening into its members — then the routes belonging to no group, shortest first. Choosing one traces it on the map and turns the panel into it, hop by hop, with the link worth cutting marked, each hop naming its evidence (the role, the network), the places it runs through — each a link to the estate map opened there — and a button back to the list. A step bar across the top of the frame walks it one hop at a time (§138): the hop's sentence, the subscription and group it lands in, whether cutting it severs the route, arrow keys to step, Escape to stop; the drawing marks the hop and brings it into view. What is traced, the hop, the box picked and the place narrowed to are in the URL, so the estate map links here narrowed to one of its boxes, and the panel says so with a way to show routes everywhere. While a cut is tried, a strip across the top of the frame says nothing in Azure has changed. A traced route says whether the queue tracks it — "Tracked as a risk", linking there — or is reach with nothing misconfigured on it, which is never a row.

**Remediation** — the work queue, ordered on the server: open work first, by impact against effort, and of two equally urgent fixes the one on an attack path first; a row on a route says how many (`DECISIONS.md` §127). Work reaches it from a finding's recommended fix (`DECISIONS.md` §41). Each row names the finding and the asset it is on, joined in the browser because the endpoint returns only the task (`DECISIONS.md` §29). Marking work done does not close a finding — a scan does — and the answer says so where the button is.

**Finding detail** — title, severity, asset, why it matters, evidence, risk score, recommended fix, estimated effort, owner, and actions: **Assign / Rescan**, and **Decide on its risk**, a link to the risk it belongs to. The finding page makes no triage decision itself — marking in progress, accepting and reopening happen on the risk, the one place triage happens (DECISIONS.md §107). An accepted finding shows its end date beside its status (DECISIONS.md §104). It also says what the finding is *part of*: the attack paths its asset sits on, drawn as routes with the link worth cutting marked, and labelled by where the asset sits on each — the way in, a link in the middle, or the target. No route found is written as a fact about the graph rather than as reassurance, because what counts as sensitive is something the customer declares. Evidence is the raw capture, clipped past about two screens with the rest one click away and copyable whole.

**Finding detail — how we know.** Under the evidence excerpt, the readings that
excerpt came from: which listing, how long ago the *provider* was read, the
permission the read was made under, and whether the capture is still stored. The
excerpt says what the rule saw; this says where it came from, which is the
difference between a claim a customer accepts and one they check. Three answers
are kept apart that a careless rendering would flatten into one blank space —
"raised before CloudGuard recorded this" is a fact about the product, "this
check reads no collected evidence" is a fact about the rule, and a failed
request is neither, so the panel does not render at all. Age is the API's
number, not the browser's: a carried reading is older than the scan that raised
the finding, and a clock-side calculation would differ per machine.

**Scan — what rested on a reading.** Each listing in a scan's collection panel
says when the provider was read and how many findings rest on it, linking to
exactly those. The finding page asks where its evidence came from; this is the
same chain from the evidence end, which is the question somebody looking at a
failed or stale listing actually has. A reading that failed says *no findings
rest on this* and is not a link — the rules that needed it degraded to UNKNOWN
and never became findings, which is the engine working rather than a gap. The
link carries `status=all`, because a reading whose findings have since been
fixed would otherwise land on an empty table and read as "nothing rested on it".

**Notifications** — a bell in the header, between the scan indicator and the
theme toggle: what is happening now, then what happened, then how the app looks.
It answers "since you last looked", which is a different question from the
Changes page and must not become a second copy of it. A popover rather than a
dropdown menu, because the rows are content containing links and a screen reader
announcing "menu, 6 items" would be wrong about what they are. Rows link and
never act — resolving or accepting is a decision about a finding, and one taken
from a dropdown is one taken without the evidence in front of you. It is marked
read when the panel opens rather than when it closes, and by an effect rather
than the click handler, because the unread count can arrive after the click.
No polling: `ScanIndicator` beside it polls only while a scan is in flight and
refuses to poll a finished one overnight, and there is no "in flight" here.
Empty reads *"Nothing new"* plus what it would have told you about; a failed
request renders nothing at all, because a network error is not an all-clear.

**Rules** — the catalogue, filterable by severity and free text. It lists what CloudGuard *runs*: a rule withdrawn from the registry (`enabled: false`) is held back behind a toggle and named as withdrawn, because it no longer runs and compliance coverage no longer counts it. Each rule expands to its rationale and the fix in every form the backend holds — prose, CLI, Terraform, Azure Policy.

**Compliance — a framework, control by control.** Controls keep the framework's
own section order, because somebody arrives holding an auditor's spreadsheet in
that order. Each control carries its verdict, the rules mapped to it, why a rule
could not tell where that applies, and — the half a compliance screen usually
leaves out — the provider readings the verdict rests on: which listing, how long
ago it was taken, across how many subscriptions, under what permission, and
whether the payload is still stored. Those are shown for a *passing* control as
much as a failing one, which is the whole point: a finding cites the readings
behind it, so "how do you know this is wrong" was already answerable, while the
green row an auditor asks about first had nothing behind it at all. The evidence
collapses per control, and what opens by default is the argument: failing and
inconclusive controls arrive expanded, passing and not-covered closed — CIS
Azure is fifty-six controls, and rendering all of them open buries the dozen
that are wrong under the forty that are not. The verdict itself is always
visible, never inside the panel. The oldest
read and the worst outcome are what a control reports, never an average — a
control is only as current and as complete as the least of the things it rests
on. The page is dated by the scan it was assessed from, and says so when that
scan was PARTIAL. **Export** takes the same assessment away as CSV (the
spreadsheet an audit is run from) or JSON (a GRC platform), fetched with the
caller's token rather than linked, because the token lives in memory and a plain
anchor would arrive unauthenticated.

**Risk detail** — the decisions (**Mark in progress / Accept… / Reopen**, the same ones as the queue's bar, with the same accept dialog, and none on a resolved risk or in the demo; an accepted risk shows "until …" beside its status), the findings a risk was built from, each one openable, plus the arithmetic in the terms that score was actually built from: the six weighted components for a finding risk, or worst-member/amplifier/hops for a route. The two are never mixed — a scenario was not scored from criticality and exploitability, so it is not shown them.

**Risk detail — when a route was last confirmed.** A scenario says when
anything last looked, under the route it draws. A path is a claim about how an
environment is wired *as of a reading*, and without a date one that survived the
latest scan and one nothing has re-checked since Tuesday render identically —
with the second reading as current. Where the scan that found it has been
pruned, the page says CloudGuard cannot tell rather than showing a date it
cannot support.

**Settings** — the half of the evidence a person supplies. The organization profile (name, industry, country; the slug is shown and never editable, because a rename must not change an identifier already in stored references). Per-subscription **context declarations** — environment, criticality, data sensitivity, note — which are what the risk engine multiplies every finding by, and which beat anything inferred from a tag or a resource name. `UNKNOWN` is not offered: it is CloudGuard's word for "nothing said anything", so leaving a field unset withdraws a claim rather than declaring the value unknown. A declaration applies at the next evaluation, not retroactively. Deletion lives here too, gated on typing the organization name, and offered to owners only.

**Reports** — two generated documents, with an **activity window** (30/90/365 days, which moves the verified-fix and completed-work counts and the trend line but never the posture) and per-section tickboxes (top risks, attack paths, remediation progress, compliance coverage, and — technical only — the full findings list). Anything unticked is named on the report's cover as excluded, so a reader downstream can tell a choice from a gap; the posture and the evidence caveats cannot be switched off. The two documents: **Executive** (posture, a fixed-scale 0–100 score sparkline, top risks, compliance coverage — no findings list) and **Technical** (the same numbers, then every open finding worst first). Both are laid out as documents (DECISIONS.md §109): a cover with the organization, dates and the "Read this first" caveats, a numbered contents list with page numbers, running headers and page numbers, the score as a ring beside severity bars and headline cards, and a closing "How to read this report". Both offer a PDF download and an HTML preview of the same document. Nothing is stored: reports are generated on request, and the page says so. Fetched with the caller's token rather than linked, because the bearer token lives in memory and a plain anchor would arrive unauthenticated.

**Changes** — what moved in the environment, newest first, grouped by the day it was observed; filterable by window (24 hours / 7 / 30 / 90 days) and by kind. Rows say whether an attribute change went up or down; a move into UNKNOWN is neither. A `DISAPPEARED` row says whether the asset is missing *now*, which is what makes it a job rather than history.

**Scan** — **automatic scanning** per connection (an interval, off by default). It is set here rather than on the connection card: this page answers when the environment was last read and when it will be read next, and a schedule is the second half of that sentence. **Run scan** opens the scan wizard, a side sheet mounted in the shell (DECISIONS.md §87). Its three steps are **Environment** (pick a connection; a scan covers the whole connection), **Review** (what is in scope, an estimate from the last finished run, and which checks will be UNKNOWN because the role cannot serve them), and **Scan**. The Scan step is a live pipeline: Plan, Collect and Analyze on one track, and one lane per scope under a segmented bar, all driven only by the steps the API reports. While Analyze runs it shows the phase that step reported (Normalize, Evaluate rules, Score risk) and the resource and rule counts as they are committed. Findings are not counted live (DECISIONS.md §88). The state is pushed over `GET /scans/{id}/events` when the stream is available, and polled when it is not. It ends in a result card with counts, the change in findings since the last scan, the severity breakdown and any gaps. A partial scan ends amber. Closing the sheet minimises it, and the header's scan indicator reopens the live view from any page. Below that, each run's card keeps its own progress and a summary: resources, rules run, findings by severity. A finished run also offers **Re-evaluate**, which runs today's rules against the capture it already stored — no Azure call. A replay labels itself as one, and says which of the two things its counts mean: applied to the current picture (findings moved), or advisory (the capture has been superseded, so nothing was created, resolved or reopened).

**Connection card** — per connection: the grants (two on Azure, one on AWS — the panel is a function of the provider, because a permanently green "Consent: granted" row beside a single AWS grant would describe a step that never happened), discovered subscriptions and their scope, a line naming where automatic scanning is now set and what it is set to, and **React to changes** (opens CloudGuard's webhook and hands over the `az eventgrid` command per subscription). The change control has to say that turning it on wires nothing up: creating that subscription is a write in the customer's tenant, and CloudGuard holds no write permission anywhere.

**Removing a connection is a dialog, not a panel.** It is the one irreversible
action in the product, and the confirmation is long — the three `az` commands
that revoke access, why CloudGuard cannot run them itself, and a probe that asks
Azure whether they worked. Expanded inside the row it pushed the rest of the
connection off screen while somebody was deciding whether to delete an
environment. As a modal it takes focus, Escape and "Keep it" are the same safe
answer, and the revocation commands are fetched only once the dialog is open —
a page of six connections must not ask six times for commands nobody wanted to
see. The commands stay *inside* the removal flow because that is the only moment
the customer is thinking about ending this, and deleting the connection destroys
the principal id and scope needed to write them.

---

## 4. Colour

Two layers, and the separation is load-bearing. The **semantic tokens** —
`background`, `card`, `muted`, `border`, `ring`, `primary`, `destructive` — are
the product's chrome and may be re-themed. The **severity scale** —
`critical`, `high`, `medium`, `low`, `unknown`, `ok`, each with a `-bg` tint and
a `-border` — is what a colour *means* to somebody reading a security finding,
and must not drift when an accent changes. `destructive` means "this button
deletes something"; `critical` means "an attacker can reach your data".
Collapsing the two would paint a cancel button and a public storage account the
same colour.

Both live in `apps/web/src/index.css` as Tailwind 4 `@theme inline` (there is no
`tailwind.config.js`; `DECISIONS.md` §35 covers why v3 cannot be gone back to).
Components use the tokens, never a raw hex or a Tailwind palette class — a
`bg-stone-50` is a light-mode decision written into a component, and it does not
flip when the theme does.

**Every pair is contrast-checked in both modes.** Text clears 4.5:1 against the
surface it sits on; chart series and the focus ring clear 3:1. The theme is a
class on `<html>` set before React exists, so "system" is a real third choice
rather than a synonym for light.

Three things that follow from this and are easy to get wrong:

- **Each mode is lit from its own surface.** The dark severity backgrounds are
  tints of the dark surface, not of white — a light tint on a dark page glows,
  and a glowing badge reads as more urgent than the one beside it, which is a
  ranking the rules never made. The neutral chart ramp likewise runs light-to-
  dark on the light page and dark-to-light on the dark one; it used to be one
  ramp copied into both blocks, which left roughly half of it invisible in each.
- **Hue is reserved for severity.** The chart ramp is deliberately neutral: a
  chart that coloured its series would be making a claim the rules never made.
  For the same reason there is no saturated accent anywhere in the chrome.
- **UNKNOWN gets its own colour and a dashed border**, not a shade of LOW — a gap
  in knowledge is not a mild problem, and the dash keeps it distinguishable
  without relying on colour at all.

---

## 5. When the app itself fails

Three failures are the client's own rather than any page's, and each is a
production condition that does not exist in development — where modules are
served from a running dev server, nothing redeploys under an open tab, and the
API is on localhost and either answers or refuses at once.

**A thrown error must not become a blank page.** React unmounts the whole tree
when a render throws and nothing catches it. There is a boundary at the root and
a second around the router's outlet, so a page that fails leaves the reader with
the navigation they arrived by. It says, in as many words, that nothing about
their environment has changed — an error screen in a security product is read as
a statement about the cloud unless it says otherwise.

**A release under an open tab is not an error.** Every page is a dynamic import,
and a deploy replaces the hashed files an open tab was going to fetch. The
boundary recognises that failure and reloads once, guarded in session storage
against a loop.

**Nothing may spin for ever.** Requests carry a timeout (`lib/api.ts`), because
neither `fetch` nor TanStack Query has one, and a host that accepts a connection
then goes quiet would otherwise leave the query loading until the tab closes. A
401 clears the token so the router sends the reader to sign in; a 403 does not,
because a viewer refused a write is signed in and should stay signed in.

See `DECISIONS.md` §66.

---

## 6. Onboarding

See `AZURE_INTEGRATION.md` §3 for the full onboarding flow and the connection-screen copy.
