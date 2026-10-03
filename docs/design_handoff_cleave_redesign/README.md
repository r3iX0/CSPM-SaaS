# Handoff: Cleave — full product redesign

Target repo: `r3iX0/CSPM-SaaS` · app: `apps/web` (React 18, Vite, Tailwind v4, shadcn/Base UI, TanStack Query, lucide-react)

## Overview
This package redesigns the whole CSPM web app. It covers 18 screens plus the shell, in light and dark themes, and renames the product from CloudGuard to **Cleave**. The redesign keeps every behaviour and rule in the current code: nothing closes without a scan proving it, "unknown" is never shown as a pass, and severity stays separate from destructive. What changes is the visual hierarchy, the density, the chroma of the severity scale, a teal brand accent, and two signature interactions: **the cut** and **the verified close**.

## About the design files
`design/Cleave.dc.html` is a **design reference built in HTML**. It's a clickable prototype that shows the intended look and behaviour. It is **not production code** to paste in. The job is to recreate it inside `apps/web` using the code's existing patterns: the `components/ui/*` primitives, the Tailwind v4 tokens in `index.css`, `useT()` strings in `i18n/en.ts`, lucide icons, and the TanStack queries already on each page. All data in the prototype is sample data. Keep the real queries and wire the new UI to them.

To view it, open `design/Cleave.dc.html` in a browser (keep `support.js` next to it). The sidebar switches screens. The header has a Light/Dark toggle.

## Fidelity
**High fidelity.** Colours, type sizes, spacing, radii and copy are final. Match them using the existing primitives. Where a primitive's default spacing differs from the spec, change the primitive's props or classes, not the spec.

---

## Implementation plan (one PR each, in order)

1. **Tokens.** Apply `tokens.css` to `apps/web/src/index.css` and add `@fontsource-variable/geist-mono`. Check both themes. This one PR re-themes the whole app.
2. **Rename + nav.** Change `app.name` in `en.ts` from "CloudGuard" to "Cleave", along with every "CloudGuard" string. In `nav.ts`, rename the "Connections" label to **"Environments"**. Use the new nav groups: *Posture* (Overview, Changes, Reports) · *Exposure* (Findings, Risks, Attack paths, Assets) · *Response* (Remediation, Compliance) · *Evidence* (Scans, Rules, Environments, Settings). Replace `Brand.tsx` with the new wordmark (see Assets).
3. **Shared components.** Update `SeverityBadge`, `StatusPill`, `StatStrip`, `ScoreTile`, `charts/Donut`, `charts/Sparkline` and `ProviderMark`, then add `ResourceIcon` (spec below).
4. **Shell.** `Shell.tsx`, `layout/Sidebar.tsx` and the header.
5. **Screens.** Overview → Findings → Finding detail (the verified close) → Risks → Risk detail → Attack paths (the cut) → Assets → Remediation → Compliance → Scans → Rules → Environments → Connection setup → Settings → Reports → Changes → Sign in → First run.
6. **Copy sweep.** Go through `en.ts` against the voice rules below.

`github.md` (in this folder) maps every screen to the repo files it came from.

---

## Design tokens

### Colour
All values are in `tokens.css`, ready to paste. Summary:

| Token | Light | Dark | Use |
|---|---|---|---|
| `--primary` (brand teal) | `oklch(0.45 0.072 196)` ≈ #146b6e | `oklch(0.74 0.082 194)` ≈ #6fc3c4 | Primary buttons, selected nav, active tab underline, route selection |
| `--primary-foreground` | `oklch(0.99 0 0)` | `oklch(0.18 0.02 196)` | Text on brand |
| `--primary-soft` | brand 10% on bg | brand 22% on bg | Selected nav fill, highlight panels |
| `--primary-border` | brand 28% on bg | brand 45% on bg | Selected nav ring, highlight panel border |
| `--background` / `--card` | `oklch(1 0 0)` | `0.145` / `0.205` | unchanged |
| `--muted` / `--muted-foreground` | `0.97` / `0.52` | `0.269` / `0.708` | unchanged |
| `--border` | `oklch(0.89 0 0)` | `oklch(1 0 0 / 12%)` | dark raised from 10% |
| hairline | `ring-1 ring-foreground/10` (dark `/12`) | | Every card outline. Not a border. |
| `--sidebar` | `0.985` | `0.185` | dark lowered from 0.205 |

Severity scale (`--sev-*`: fg / bg / border for critical, high, medium, low, unknown, ok). The **same hues** as today, with **more chroma and contrast**. Every foreground still clears 4.5:1 on its own `-bg`. The values are in `tokens.css`.

**Unknown** always uses a **dashed** border (`border-dashed`), wherever it appears: pill, tile, stat, score. This is how it stays distinguishable without colour.

### Typography
- Sans: Geist Variable (already installed). Mono: **Geist Mono** (add `@fontsource-variable/geist-mono`). Base size **14px**.

| Role | Size / weight / tracking | Notes |
|---|---|---|
| Page title (h1) | 22px / 600 / -0.02em | Detail pages: 24px |
| Page intro | 13px / 400, muted, max-width ~70–78ch | 6px below h1 |
| Card title (h2) | 13.5px / 600 | |
| Card description | 12px, muted | 4px below title |
| Sub-heading (h3, in panels) | 12px / 500 | |
| Body | 13–13.5px, line-height 1.6–1.65 | |
| Table header | 11.5px, muted | |
| Row title | 13.5px / 500, truncate | |
| Row meta | 11.5px muted (or 11px mono for rule ids) | |
| Stat label / value | 11.5px muted / **22px 600 tabular-nums** | |
| Big numbers (score, risk) | 28–36px / 600, line-height 1, tabular | |
| Nav group eyebrow | 11px / 500, uppercase, 0.04em, muted | |
| Nav item | 13.5px | |
| Pill | 11px / 500 (small: 10.5px, line-height 16px) | |
| Mono (evidence, rule ids, links like `a —Reader→ b`) | 11.5–12.5px Geist Mono | |

Use `tabular-nums` for every count, score, duration and date.

### Radii
Set `--radius: 0.5rem`, then use `rounded-lg` = 8px for buttons and inputs, `rounded-xl` = 12px for cards and frames, 9–10px for inner cards and list items inside panels (`rounded-[9px]`), 6px (`rounded-md`) for icon tiles and count chips, and `rounded-full` for pills, the avatar and dots.

### Spacing
- Page: `max-w-[1240px] mx-auto px-6 pt-6 pb-16`. Vertical rhythm between page blocks is **16px** (`gap-4`). Settings and Setup use 28px.
- Card header `px-5 py-4` (20/16). List rows `px-5 py-3` (20/12). Stat cells `px-[18px] py-3.5`.
- Buttons: sm = 28px high, `px-2.5`, 12.5px text. Default = 32px, 13px.

### Surfaces & shadows
- Card: `bg-card rounded-xl ring-1 ring-foreground/10`. No drop shadow.
- **Stat strip**: one rounded-xl container with `bg-border gap-px overflow-hidden`, where each cell is `bg-card`. This gives 1px hairline dividers with no double borders.
- Popover: `ring-1 ring-foreground/10` + `0 10px 30px rgb(0 0 0 / .14)`.
- Header: sticky, `bg-background/88 backdrop-blur-md`, bottom border.

### Motion
- Page enter: `cg-rise 260ms ease-out both` (already in index.css).
- Hover and colour changes: 150–250ms ease.
- The cut: see below. Every animation must respect the existing `prefers-reduced-motion` block.

---

## Shared components

**SeverityBadge / pill.** Shape: `inline-flex rounded-full border px-2 py-px text-[11px] font-medium`, with colour `text-{sev} bg-{sev}-bg border-{sev}-border`. Size `sm` is `px-1.5 text-[10.5px] leading-4`. Unknown adds `border-dashed`. Labels: Critical, High, Medium, Low, Unknown (the column header says "No verdict").

**StatusPill.** Open, In progress and Risk accepted use neutral styling: `bg-muted text-muted-foreground border-border`. Verified fixed uses `ok` colours. A tracked fix's `WorkPill` follows the same rule: only a scan's verdict is coloured (DECISIONS.md §208).

**StatStrip.** Uses the hairline grid described above. Label is 11.5px muted, optionally with a 12px leading icon. Value is 22px/600 tabular. When a value is alarming, colour the value itself (e.g. `text-critical`), not the cell.

**Segmented filter** (Findings status, Assets List/Map). A container with `border rounded-[9px] bg-card`, with a 1px left border between segments. Segments are `px-3 py-1.5 text-[12.5px]` in muted text. The active segment gets `bg-primary-soft text-foreground font-medium` plus `box-shadow: inset 0 -2px 0 var(--primary)`.

**ResourceIcon (new).** A 22–24px tile, `rounded-md bg-muted text-muted-foreground`, holding a 12–13px line icon at stroke width 1.5. Mapping: virtual machine → monitor, storage → cylinder, identity/service principal → user, network → share-2, key vault → key-round, SQL → database, container → box. Map these through `lib/icons.ts`. Shown to the left of the resource name in the Findings, Assets and Remediation rows.

**ProviderMark.** Monochrome provider glyphs (Azure, AWS, GCP, Kubernetes, Docker, GitHub, GitLab) in a 28px tile. Used on Environments and in Setup step 1.

**ScoreTile** (Risks list, Priority risks). A 40px square, `rounded-lg`, 15px/600 tabular number, tinted by level (`bg-{lvl}-bg border-{lvl}-border text-{lvl}`). Unknown shows "?" with a dashed border.

**Score gauge** (Overview). A 128px ring filled by a conic gradient in the level colour, with the rest in `--muted`. The inner disc is inset 12px and `bg-card`. Inside it: the score at 32px/600, "of 100" at 11px muted, and a delta chip below (↑/↓ n since last scan, in `ok` or `critical`).

**Mini-donut** (Assessment coverage). 64px, inset 9px, with the % at 14.5px/600 in the middle and "of N checks verdicted" in 12px muted beside it.

**Sparkline** (Overview trend). A 1.5px stroke in the level colour, with a vertical gradient fill underneath from that colour at 18% down to 0%.

**Buttons.** Keep `ui/button.tsx`. Outline sm is the default secondary action everywhere ("All risks", "Mark done"). Filled `default` (brand) is reserved for **one** primary action per view (Run scan, Connect, Rescan to verify).

---

## Screens

The prototype holds every screen. To find one in `design/Cleave.dc.html`, search for `at.<key>` (e.g. `at.paths`).

### Shell (`Shell.tsx`, `Sidebar.tsx`)
- Sidebar: 232px wide, `bg-sidebar`, right border, sticky, full height. The top block is 56px high with the wordmark and a bottom border. Nav has `p-3`, with groups 14px apart and items 2px apart. Items are `px-2.5 py-[7px] rounded-lg text-[13.5px]`. **Active item** gets `bg-primary-soft` and `ring-1 ring-inset ring-primary-border`. Findings, Risks and Attack paths show a right-aligned count (11.5px muted, tabular). The footer has a 6px ok dot and "3 subscriptions monitored" (11.5px muted).
- Header: 56px, sticky, blurred. On the left, a search trigger with min-width 220px, border, rounded-lg, 12.5px muted text "Search findings, assets, rules" and a `⌘K` kbd in mono. On the right: an ok dot with "Last read 3 hours ago" (12px muted), then the theme toggle (outline sm), then a 28px avatar.

### Overview (`pages/Dashboard.tsx` + `dashboard/*`)
Top to bottom:
1. Header: h1 "Overview" with the intro "Your Azure posture, and what Cleave could see while forming it." Actions sit on the right.
2. **Score panel.** A hairline grid with columns `320px | 1fr`. The left cell has the gauge, the delta and the label "Security score". The right cell has "What that means today · 30 days", the sparkline, and a severity tile row of 5 buttons (Critical, High, Medium, Low, No verdict). Each tile has a pill on top and a 28px/600 count; No verdict uses a dashed pill.
3. A grid with columns `1.35fr | 1fr`:
   - **Priority risks.** Header ("Ranked by what each would cost this business, not by how many alerts fired.") with an "All risks" button. Each row: ScoreTile 40, title 13.5/500, factor line 11.5 muted (e.g. "Scenario · internet-facing · sensitive data"), SeverityBadge, then a **28px ghost graph button**. For a route risk the graph button's label is "Trace among attack paths" and it opens Attack paths with that route traced. For an asset risk it's "Open in the graph". This mirrors `PriorityRisks.tsx` / `RiskGraphLink` upstream.
   - **The link to cut.** Description: "The single change that closes the most routes from something exposed to something sensitive." A brand-soft box holds the mono link `vm-jumpbox —Reader→ storage-prod-01` and "Cutting this role assignment closes **3** of 4 routes." The button "Simulate this cut" (with a scissors icon) opens Attack paths → Simulate tab with that cut already in the plan (`?cut=…`).
4. **Assessment coverage.** Mini-donut, a row of category states (the incomplete one is in the medium colour), and a dashed-top footer in medium-bg that explains the collection gap, with a "View scan detail" button.
5. A 2-column grid: **Fixes proved** (3 cells, each with a 22px icon tile, a label and a 22px number; verified closed is `text-ok`) and **What moved this week** (rows with a pill: Worse = critical, Declared = neutral, New = brand).
6. **Compliance coverage.** 4 cells, each with the framework name, % at 19px/600, and "n of N controls assessable". Copy: "What Cleave can speak to, never a verdict."

### Findings (`pages/Findings.tsx`)
StatStrip with 5 cells (Critical, High, Medium, Low, No verdict), each value coloured by level. Then the segmented status filter (Open · In progress · Verified fixed · Risk accepted · All), a search field (min-width 260) and a severity select. The table is a card with `overflow-x-auto` and grid columns `minmax(170px,2.4fr) 90px minmax(130px,1.2fr) 80px 110px 100px`, min-width 760px: Finding (title + mono rule id), Severity pill, Asset (ResourceIcon + name + type), Risk (13px/600 right-aligned), Status pill, Last seen (right-aligned muted).

### Finding detail + **the verified close** (`pages/FindingDetail.tsx`, `security/FixVerification.tsx`)
Breadcrumb, pills, mono `rule · vN`, a 24px title and an intro paragraph. The main column has: Why it matters · How to fix it (steps plus "Rescan to verify") · Evidence (mono `pre` on muted, rounded-[10px]) · How we know (provenance: listing, read time, permission, sha256) · What it is part of (the route). The side column has: Risk score (36px) · Asset · Timeline.

**The verified close**, shown after "Rescan to verify":
1. A "Checking your fix" card with the copy "Cleave is re-reading the subscription this resource lives in. You can leave this page — the finding closes on its own if the fix took." Below it, a 4-step bar (Queued → Reading network rules → Checking the rule → Result). Each step is a 4px pill that fills `--primary` as its phase is reached. In the prototype the phases land at 0, 900, 2100 and 3400ms; in the product, drive them from the real scan events (`lib/scanEvents.ts`).
2. When the scan closes it: an ok-bg / ok-border card titled "Verified fixed". The body says which scan read what, and when. Below that, a mono evidence line: `evidence sha256 4c1f9ab77e02… · network.nsg_rules · read <ISO time>`. A "Verified fixed" ok pill also appears in the header.
Never offer a manual "close". The only way to close is the scan.

### Risks / Risk detail (`pages/Risks.tsx`, `pages/RiskDetail.tsx`)
The list has a "Top fixes" panel (brand-soft background, brand-border) with a link to "All routes and fixes", then rows built from ScoreTile + title + kind chip ("Scenario" / "Escalation") + factor icons. Risk detail has: The route (vertical stop list) · Built from (the member findings in a bordered list) · The arithmetic (a dl of worst member, route amplifier and cap) · "Nothing resolves without proof".

### Attack paths — **the cut** (`pages/AttackPaths.tsx`, `graph/*`), synced with upstream 26 Sep
Layout: header ("Routes from something exposed to something worth taking — and the one link that cuts each."), then a StatStrip (Routes to sensitive data (critical) · Exposed assets · Sensitive assets), then **one frame**:
- Title row: "Every route, drawn" plus a `GraphLegend`. Legend items: globe `text-high` "Reachable from the internet", target `text-high` "Sensitive data", a count chip "Open findings", a thin/thick line pair "Thicker: closes more routes if cut". When a plan exists, two more: an ok dashed line "In the simulated plan" and a greyed box "Out of reach with the plan made". Last comes a `?` popover with the map help text.
- Frame: `rounded-xl ring-1 bg-card`, min-height 560. When a plan exists, a banner sits on top: ok-bg with an ok-border bottom, a scissors icon, "Simulating N change(s) together — nothing in your cloud has changed.", and a ghost "Show the plan" button.
- Canvas (flex-1): an 18px dot-grid background (`radial-gradient(fg/9% 1px, transparent 1px)`). Boxes are 132×44, rounded-[9px], bg-card with a border. Sensitive targets are tinted with their level. Each box shows a glyph (globe = exposed, target = sensitive, square = in-between), the name at 11.5/500 and the type at 10px muted, with a findings chip at the top right. Line thickness is `1.5 + 1.5 × routes closed if cut`. Line colours: default foreground/40%; traced route foreground; selected hop `--primary`; planned hop `--ok` dashed `6 4`; dead hop `--border` dashed `3 4`.
- Side panel: 320px+ wide, max-height 600, separated by the border. A segmented tablist sits at the top: **Routes N · Simulate n**. The active tab gets bg-card with a small shadow.
  - **Routes tab.** Search ("Any asset on a route") and a sort select (Shortest first · Most sensitive target · Most exposed entry · Tracked risks first). Then a "The same route, repeated · n groups" group: its row expands to its member routes, and a `?` explains "Grouped only where the routes are identical apart from one end…". Then a "Routes" list. Each row reads `entry → target` at 12/500 with the hop count; below that sit the exposure pill, the **hop strip** (a 10×4px dash per hop, with the earliest cut in ok), the sensitivity pill, and on the right "Closed by the plan" (ok) and/or a radar icon with "Tracked". Hovering a row previews its route: everything else fades to 16–30%.
  - **Route navigator** (a route is traced). A "← Routes" back button, "Route n of N", and prev/next buttons. Then the title, the pills, "Tracked as a risk" and, when a plan has settled, a verdict line (ok if the plan closes this route). Under "Hops" there's a vertical list: stop (a 12px tinted square, name, type · n open findings), then link (mono relationship). The selected link is brand-soft with a brand-border and expands to show the detail, "Cutting it closes this route and N others.", and "Add to the plan" / "Take out of the plan". The first link is tagged "Earliest place to cut" (ok pill). Pressing a line or box on the traced route selects that hop.
  - **Simulate tab, empty.** "Try a change before you make it" + explainer. Then "The changes that close the most": choke-point cards with the mono detail, "Closes **n** of N", up to 3 named routes with pills, and a 28px outline `+` button.
  - **Simulate tab, with a plan.** An outcome header: "**n** of N routes close" (18px number), a 6px ok progress bar, "N still run. Checked over every route, not only those drawn." (or "No route is left from anything exposed to anything sensitive."), and the small print "A simulation. Nothing in your cloud has changed." Then "The plan n of 10" with a Clear button. Each item is an ok-border card: scissors, mono detail, ×, then "Closes n alone · m close only with it". When m = 0, add a medium-coloured line: "The rest of the plan already closes everything this would. You can leave it out." Then "Copy the plan", "Worth adding next", "Still open" (clickable, traces the route) and "Closed".
- **The cut (signature timing).** A plan change posts to `/attack-paths/simulate`. While it's pending, keep the previous answer on screen at 60% opacity with a 13px spinner. When the answer lands, each route that newly closed is struck through in list order, **260ms apart**: `text-decoration-color` transitions from transparent to muted and the colour to muted over 400ms. At the same moment, "Closed by the plan" rises in (cg-rise, 300ms) with the same delay. Target boxes whose every route is closed grey out (fill to `--muted`, text to muted) 180ms after their last route, over 500ms, and the hops that only served closed routes go dashed `--border`. Make the stagger switchable (the prototype prop is `sequencedCut`). Under reduced motion there's no stagger: everything lands at once.
- The URL state stays as upstream has it: `trace`, `hop`, `through`, `scope`, `group`, `q`, `sort`, `cut`.

### Assets (`pages/Assets.tsx`)
The header has a List/Map segmented control. StatStrip: Total · Critical · Internet-facing · Unmodeled type (medium). Filters: search, type, any asset, and "By resource group". The table (min-width 860px) groups rows by resource group under a muted header row (`rg-prod-app 3`). Columns: Resource (ResourceIcon + name + a "Path" chip if it sits on an attack path) · Type · Environment · Criticality pill · Exposure pill · Open (count chip, `rounded-md bg-muted ring-1 ring-border`) · Last seen.

### Remediation (`pages/Remediation.tsx`)
StatStrip: Open · In progress · Effort left · Overdue (critical). One divided card. Each row: severity pill (72px column), title 13.5/500, meta "asset · type" plus, from `task.on_routes`, **" · on N attack path(s)"** at `font-medium text-foreground`. Then effort (56px), due date (130px; overdue in critical/500 as "Overdue · Sep 19"), and an outline "Mark done". Done rows sit at 70% opacity with a strike-through title and a `WorkPill` saying what the checks have found ("Checking the fix", "Not fixed yet", "Still failing", "Fixed"); the badge is the finding's severity, never the task's priority (DECISIONS.md §208). The footer note is on muted: "Marked done does not close a finding. Cleave reads the environment again on the next scan and closes it then, or leaves it open."

### Compliance (`pages/Compliance.tsx`, `ComplianceFramework.tsx`)
Framework cards: a donut, the name, the version and one line of scope. Then "Coverage by domain" (horizontal bars per framework), then the controls table: "Each verdict carries the readings it rests on — for the controls that passed as much as the ones that failed." The rule throughout: **coverage, never a verdict**.

### Scans, Rules, Environments, Setup, Settings, Reports, Changes, Sign in, First run
These use the same vocabulary: h1 + intro, StatStrip where there are counts, one card per concern, and divided rows. Specifics:
- **Scans:** an "Automatic scanning" card (cadence + change events), then a History card of scan rows with the pipeline state and per-category collection outcomes (complete / partial / failed / skipped; partial and failed carry the "checks report unknown, never passed" hint).
- **Rules:** a list with expandable detail ("Show detail" / "Hide detail").
- **Environments** (renamed from Connections): one row per connection with a ProviderMark, account counts, last read and status.
- **Setup:** a 44px provider tile, "Connect an Azure directory", and meta chips "About 3 minutes · Read-only · No credential to hand over". Then a step rail.
- **Settings:** max-width 820, 28px gaps, intro "Everything else in Cleave is something it observed. This is the other half of the evidence: what you told it."
- **Sign in:** a split layout, with a 46% (max 660px) muted brand aside on the left and a form 360px wide on the right.
- **First run:** a stepper, then "Create your organization".
Take exact copy and layout from the prototype (`at.scans`, `at.rules`, `at.connections`, `at.setup`, `at.settings`, `at.reports`, `at.changes`, `at.signin`, `at.onboarding`).

---

## Interactions & behaviour
- Rows are whole-row buttons or links with hover `bg-muted/60` (or `bg-accent/50`) and a focus-visible ring (`ring-3 ring-ring/50`).
- A graph link sits **beside** a row, never inside it. The row opens the entity; the icon opens the graph.
- Tabs, filters and the Attack-paths state live in the URL (already true upstream).
- Loading: skeletons keep the row height so the list doesn't reflow. Errors use `ErrorState` with "Nothing about your environment has changed — this is a problem displaying it."
- Responsive: every multi-column grid uses `minmax(0,1fr)` tracks. Tables scroll horizontally inside their card. The Attack-paths panel wraps under the canvas below roughly 780px of content width.

## State (new or changed)
- Attack paths: `tab: "routes" | "simulate"`, `previewKey`, a plan from `cut` params, and the simulation query using `keepPreviousData`. To sequence the cut, track "routes newly closed since the last settled answer" and give each one an index-based delay.
- Finding detail: the verify phase comes from the scan's event stream.
- Theme: the existing `lib/theme.ts` (`.dark` class) stays.

## Voice rules (copy sweep)
- Never write "secure" as a state, and never "no issues" or "all clear". Say what was checked and what couldn't be.
- Unknown is never a pass. Write "No verdict" and "could not be read".
- Nothing closes by hand. "Mark done" records work; a scan closes the finding.
- Simulations always say "Nothing in your cloud has changed."
- Sentence case everywhere. Numbers in figures.

## Assets
- **Wordmark:** two stroke-width-2 round-cap lines, drawn as `<line x1=1.5 y1=17 x2=9 y2=9.5>` in foreground and `<line x1=15 y1=14.5 x2=22.5 y2=7>` in `--primary` on a 24×24 viewBox (a cut line). Next to it, "cleave" in lowercase at 16px/600, tracking -0.045em.
- Icons: lucide throughout, 1.5 stroke (globe, target, scissors, radar, route, network, monitor, database, cylinder, key-round, user, box, circle-help, copy, plus, x, arrow-left, chevron-*).
- No raster images.

## Files in this package
- `README.md`: this spec
- `tokens.css`: paste-ready token patch for `apps/web/src/index.css`
- `design/Cleave.dc.html` + `design/support.js`: the clickable hi-fi prototype, all screens, both themes
- `github.md`: the screen ↔ repo file map and the sync record
- `CLAUDE_CODE_PROMPT.md`: a kickoff prompt to paste into Claude Code
