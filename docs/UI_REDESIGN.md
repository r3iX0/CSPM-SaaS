# CloudGuard — UI redesign, direction B

Companion to `UI.md`, which stays the authority on *what each page argues*.
This document is the authority on *how it looks and how the argument is
staged*. Where the two disagree, UI.md wins on content and this wins on form.

Reference material lives in `docs/design/direction-b/`:

- `preview/*.html` — six static screens. Open them in a browser. They are
  self-contained (inline styles, one Google Fonts link) and are the source of
  truth for exact values: read the markup rather than eyeballing the render.
- `render/*.png` — the same six screens as images.

---

## 0. Why this exists

`UI.md` §1 already says the Overview should be "one argument read top to
bottom, not a wall of cards." The shipped Overview is ten equal-weight cards
stacked vertically. The spec did not drift; the implementation drifted from it.

Three concrete symptoms, all visible on the live app:

1. **Every section carries an epigram.** "What the rules judged, in the
   abstract." "Accepted risk is counted, never absorbed." Ten sections, ten
   aphorisms rendered as permanent body copy. The writing is good; its
   placement is the problem. It belongs in tooltips, in `?` popovers, and in
   these docs — not under every heading.
2. **The same number is drawn three times.** Severity mix (3/6/2/0), a donut
   for "where findings stand" (a one-segment donut is a circle), and risk
   bands (4/7/0/0) are three views of eleven findings, stacked.
3. **The chrome is stock.** `--background: oklch(0.145 0 0)` and the rest of
   the neutral layer are shadcn defaults, unchanged. The severity layer below
   them is not — it is carefully reasoned and it stays.

---

## 1. What does NOT change

**The severity scale in `apps/web/src/index.css` is kept verbatim.** Every
`--sev-*` token, its light and dark values, and the comments explaining the
contrast work. Also kept:

- The separation between `--destructive` (this button deletes something) and
  `--color-critical` (an attacker can reach your data).
- UNKNOWN as its own colour with a **dashed border**, so it stays legible
  without colour. The redesign leans on this harder, not less.
- `--radius: 0.625rem` as the base, and the `--radius-sm/md/lg/xl` ladder.
- The `cg-draw` / `cg-rise` keyframes and the `prefers-reduced-motion` block.
- `@theme inline` as the mechanism, and the two-layer split it encodes.

Do not "harmonise" the severity ramp with the new accent. They are different
layers on purpose and that comment in `index.css` is correct.

---

## 2. The visual system

### 2.1 Type

Two faces replace the single Geist:

| Role | Face | Fallback |
|---|---|---|
| UI, headings, body | **Space Grotesk** 400/500/600/700 | `ui-sans-serif, system-ui, sans-serif` |
| All numerals, IDs, resource names, CLI | **JetBrains Mono** 400/500 | `ui-monospace, monospace` |

Add `--font-mono` alongside `--font-sans` in `@theme inline`. Install via
`@fontsource-variable/space-grotesk` and `@fontsource/jetbrains-mono` — do not
add a Google Fonts `<link>` to `index.html`. Import the face packages from
`main.tsx`, **not** with an `@import` in `index.css` the way Geist was loaded:
Tailwind v4 inlines such an import without rebasing the `url()`s in it, so no
font file is emitted and the browser silently falls back to system-ui.
Geist was never actually loading (DECISIONS.md §84).

**Every number in the product is mono and tabular** (`font-variant-numeric:
tabular-nums`). Scores, counts, percentages, GUIDs, resource names, rule IDs.
This is the single highest-leverage change in the whole redesign: it is most of
what separates a console from a marketing page. `.font-mono` carries
`tabular-nums` in `index.css`, so `font-mono` is the whole instruction.

**Dates are the exception, and this sentence used to say otherwise.** The six
previews are unanimous — every date in them is proportional while every count
beside it is mono — so a date, and any relative-time phrase in a sentence
("3 days ago", "evidence 67 hours old"), stays in the sans face; a date sitting
in a column keeps `tabular-nums` so it still aligns. The rule that survives is
that mono marks a value the reader compares against another value
(DECISIONS.md §85).

A numeral inside a sentence is wrapped on its own — "28 checks · 19 with a
verdict" is mono on the digits and proportional on the words.

Heading scale: h1 28px/700/-0.028em, panel title 16px/600/-0.015em, section
label 11px/500/0.12em uppercase, body 13.5px, table cell 14px, meta 12.5px.

### 2.2 Colour — the neutral layer only

Replace the `.dark` block's neutral tokens with these. They are the same
near-black the app has now, rotated onto a cool hue and given a little chroma,
so the surface reads as deliberate rather than as an absence of choice.

```css
.dark {
  --background:  oklch(0.155 0.018 268.3);  /* #090c14 page          */
  --card:        oklch(0.192 0.026 266.6);  /* #0f1420 panel         */
  --popover:     oklch(0.192 0.026 266.6);
  --sidebar:     oklch(0.142 0.018 271.7);  /* #070911 sits darker   */
  --secondary:   oklch(0.219 0.031 264.7);  /* #131a29               */
  --muted:       oklch(0.219 0.031 264.7);
  --accent:      oklch(0.219 0.031 264.7);
  --border:      oklch(0.262 0.036 265.6);  /* #1c2436 hairline      */
  --input:       oklch(0.294 0.039 265.4);  /* #232c40               */
  --foreground:  oklch(0.946 0.014 268.5);  /* #e9edf7               */
  --muted-foreground: oklch(0.712 0.037 265.9); /* #97a2ba           */
  --primary:     oklch(0.778 0.138 178.1);  /* #22d3b7 teal          */
  --primary-foreground: oklch(0.192 0.026 266.6);
  --ring:        oklch(0.778 0.138 178.1);
}
```

Two supporting greys used constantly in the previews and worth naming as
tokens: `#6b7793` (`oklch(0.570 0.046 266.8)`) for dim meta, `#5b6680`
(`oklch(0.511 0.044 266.9)`) for the faintest text — footnotes, placeholder,
"nothing here". They ship as `--meta-foreground` and `--faint-foreground`, and
they measure **4.11:1 and 3.20:1** on the card, so neither may carry body copy:
they are for the 11–12.5px meta register only. Raising both to clear AA lands
them on the same colour (`#727e9b`), which is why the constraint is documented
rather than the values nudged.

**The accent means one thing: you can act here.** Buttons, links, the active
nav rail, focus rings, an enabled toggle. It never means "good" and never
means "bad" — severity owns that vocabulary entirely. A teal element that
isn't interactive is a bug.

Contrast: re-run the same checks the existing comments describe. `--ring`
against `--background` and `--muted-foreground` against `--card` are the two
that matter. Measured: **10.3:1** and **7.2:1**. Foreground on the page is
16.7:1, and `--primary-foreground` on `--primary` is 9.7:1.

~~**Light mode is not designed yet.**~~ **Derived** (DECISIONS.md §92), on the
same hue family and with every value measured: foreground 17.3:1 on the page,
`--muted-foreground` 5.5:1 on the card, `--primary` at `oklch(0.52 0.13 178.1)`
so white on it is 4.9:1. The toggle is not gated.

### 2.3 Surfaces

- Panel: `--card` fill, 1px `--border`, `border-radius: 14px`. In code this
  is `ring-1 ring-border` on `Card` — a ring rather than a border so the
  edge costs no layout, and the `--border` token rather than
  `foreground/10`, which sits about 9% lighter and made every panel read
  as more outlined than the mockup.
- **Floating overlays are the exception** — popover, dialog, dropdown and
  select keep `ring-foreground/10`. A brighter edge is what separates a
  thing above the page from a thing on it.
- Nothing has a drop shadow. Depth comes from the fill step between page,
  panel and row.
- Table rows separate with a 1px `#151c2b` rule, one step darker than
  `--border`, so the grid recedes behind the data.
- Selected row: `rgba(34,211,183,0.06)` fill plus `box-shadow: inset 2px 0 0`
  in the accent. Never a full border.
- The hero panel on the Overview is the one place a gradient appears — two
  large, very low-alpha radial washes. Do not spread this pattern.

---

## 3. The shell

**Done** (DECISIONS.md §86). This section opened by saying `Sidebar.tsx`
renders a hamburger and an overlay drawer; the persistent rail already existed
by the time the redesign was written, so what changed was the anatomy below,
not the existence of the rail. The rail is **236px** at `lg` and above, with the
drawer kept for narrow widths only. It also keeps its collapse-to-icons state,
which predates this document and is remembered per browser.

Anatomy, top to bottom: brand row; the four existing nav groups from
`nav.ts` unchanged (POSTURE / EXPOSURE / RESPONSE / EVIDENCE); the connection
badge pinned to the bottom with `margin-top: auto`.

**Not the account row.** This section put it at the foot of the rail and the
shipped shell keeps it in the top-right corner instead: an account menu in the
top-right is a convention older than this product, and a reader looking to
switch organization or sign out should not have to be taught where it went
(DECISIONS.md §86).

- Group labels use the 11px uppercase section-label style.
- Nav item: 8px/12px padding, 8px radius, 14px label, 16px stroked icon.
- Active item: `inset 2px 0 0` accent rail, a left-to-right accent wash at
  0.14 alpha fading to 0, and `--foreground` text. No filled pill.
- A count badge (open risks) sits right-aligned inside its nav item. It reads
  `meta.total` from the same unfiltered `/api/v1/risks` request the risks page
  makes, so the two numbers cannot disagree.

Top bar is 58px with a bottom hairline: the `⌘K` search affordance on the
left at 360px wide, then notifications, the theme toggle and `AccountMenu` on
the right — where it was, and where it stays.

**Page header pattern, identical on all six screens:**

```
h1 (28px)                                    [secondary] [primary]
one factual status line (13px, muted)
```

The status line is facts only — "Last scan 4 Sept, 00:39 · evidence 67 h old",
"11 open risks · none accepted or waived". A coloured dot may precede it when
something is stale. It is **never** an epigram, a definition, or a sentence
explaining what the page is for.

**This rule beats the previews.** Four of the six mockups render a definitional
sentence as the page subtitle; the shipped pages do not, because this paragraph
is right and the sentence has somewhere better to live — a `?` on the title
(DECISIONS.md §87). Where a page has no fact to state, it carries no line.

---

## 4. Per-page changes

### 4.1 Overview — `pages/Dashboard.tsx`

Ten sections become four. Preview: `preview/overview.html`.

| Was | Becomes |
|---|---|
| Security score card + Posture trend card | **One hero panel**, three columns: score arc / exposure map / — |
| Severity mix + findings donut + risk bands | **One "Distribution" panel** with an `On the asset` ↔ `As judged` toggle, a stacked bar for the mix and one row per band for its size (DECISIONS.md §96) |
| Assessment coverage + "1 category could not be collected" | **One amber blind-spot banner** with two actions, promoted above the risk list |
| Priority risks | Table, unchanged in intent |
| Shortest attack path (empty) | **One line** inside the hero, not a section |
| Remediation 0% chart | **One stat tile** |
| Compliance + Recent changes | Bottom row, unchanged |

The **exposure map** replaces the empty attack-path panel: the real asset
graph (internet → storage account → resource group → subscription →
identities), severity-ringed. It always has something to draw, which the
attack-path panel does not. Served by `GET /api/v1/attack-paths/exposure-map`,
bounded, and explicitly **not** an attack path — an edge says one asset can act
on another, and nothing here is scored (DECISIONS.md §91).

The score arc is a single SVG circle, `stroke-dasharray` over a 270° sweep,
rotated 135°. `ScoreRing.tsx` already exists — adapt it rather than adding a
second implementation.

### 4.2 Risks — `pages/Risks.tsx`

The biggest change in the redesign. Preview: `preview/risks.html`.

The page is a **card feed** today: eleven full-width cards, each with a
five-line paragraph, three of them byte-identical. It becomes a table.

- Columns: checkbox · Risk · Exposure (150px) · Score (56px, right) ·
  Status (84px). Gap 14px, row padding 14px/22px.
- Titles and subtitles are `overflow: hidden; text-overflow: ellipsis;
  white-space: nowrap`. A table row is one line, not a paragraph.
- **Grouping.** The three identical "Identity can grant itself any role" rows
  collapse into one parent row marked `×3`, expandable to the individual
  identities. A "Group duplicates" toggle in the filter bar controls it.
- ~~**Fix the identity labels.**~~ **Done, in the collector.** The directory
  read was not failing to resolve names — a principal seen only in an ARM role
  assignment has no name in that payload, and the node was being named after
  its `principalType`. It is now named by its object id (DECISIONS.md §88).
- **A detail drawer replaces navigation.** Selecting a row opens a 372px
  right-hand drawer — score breakdown (`worst finding on the route` +
  `added for the route itself`, terms your API already stores), why it
  matters, what raises it, the CLI fix, and the actions. Keep
  `/risks/:riskId` working as a deep link that opens the list with that
  drawer open. At `< lg` the drawer becomes a full page.
- The prose currently inside each card moves into the drawer, where there is
  room for it, and is shown for one risk at a time instead of eleven at once.

### 4.3 Findings — `pages/Findings.tsx`

Already a table; the work is presentation. Preview: `preview/findings.html`.

- Columns: Finding · Severity (96) · Asset (176) · Rule (178) · Risk (72) ·
  First seen (84) · Status (104). Ellipsis on all four text columns. No
  checkbox column until something can act on a selection; the risk score column
  is kept because it is the table's default ordering (DECISIONS.md §89).
- **UNKNOWN rows are the point of this page.** They sit in the same table,
  greyed, with a dashed `No verdict` severity chip and a dashed `Unevaluated`
  status. Never sorted away, never a filter default, never counted as passes.
  They come from `GET /api/v1/findings/unevaluated`, not from the findings
  list: a check with no verdict is not a finding and is not stored as one. A
  filter hides the rows and never the count, and they are listed under every
  unfiltered page rather than paginated with the findings (DECISIONS.md §89).
- One amber strip above the table states the count once: "9 checks reached no
  verdict. They are listed, never counted as passes." That single sentence
  replaces the per-section prose.
- The rule ID gets its own mono column, so a finding is traceable to the check
  that raised it without opening it.

### 4.4 Assets — `pages/Assets.tsx`

Preview: `preview/assets.html`.

- Grouped by resource group using the grouping select that already exists;
  group header rows are a darker fill with a disclosure chevron.
- Columns: Asset · Type (168) · Environment (132) · Exposure (116) ·
  Open findings (120, right) · Last seen (92).
- Unclassified environment and exposure render as **dashed `Unknown` chips**,
  not as blanks. The board is currently all-dashed, which is the honest
  picture and makes the "Classify assets" banner read as the fix.
- `i18n` `assets.unchecked` ("{count} with no checks yet") is right and stays.
  Per row, write "no checks yet" in words rather than showing `0`, so an
  unexamined asset never looks clean. **Limit:** this can only be said for a
  type CloudGuard has no rule for. Nothing stored distinguishes a modelled
  asset that passed from one no rule applied to (DECISIONS.md §89).
- Footer states the collection gap: "Directory listing is incomplete — 4
  identity collectors were refused", with a link to fix access.

### 4.5 Attack paths — `pages/AttackPaths.tsx`

Preview: `preview/attack-paths.html`. This page will be empty for most new
tenants, so **the empty state is the page**.

The four distinct empty states in `i18n/en.ts` (`emptyNoScan`,
`emptyNoEntry`, `emptyNoTargets`, `emptyNoPaths`) are a good product decision
and stay. What changes is that the reader is shown **which precondition is
missing** rather than being told in a paragraph:

```
✓ A scan has run          ✓ Entry points found      ✗ Sensitive targets
  4 Sept · 5 assets read    1 reachable from web      0 carry a classification
```

Below the strip: a three-node diagram with the missing end amber and dashed,
the matching `empty*Detail` sentence as the body, and one primary action.
Below that, one clearly-labelled example path — `example — not your estate` —
so the reader knows what the page becomes.

`attackPaths.intro` (three sentences) comes off the page. Its argument is now
carried by the diagram, and the sentence itself belongs in the "How paths are
built" popover.

### 4.6 Remediation — `pages/Remediation.tsx`

Preview: `preview/remediation.html`. The most opinionated screen.

Four stat tiles — Verified fixed · Still open · In progress · Came back —
then a **four-column board**:

```
To fix        In progress      Awaiting a scan      Verified fixed  🔒
```

- **"Verified fixed" is not a drop target.** It carries a padlock and nothing
  can be dragged into it. Only a scan moves a card there. As built, the board
  is moved with buttons rather than dragged — the app has no drag library — and
  the column simply has no control that reaches it (DECISIONS.md §90).
- "Awaiting a scan" is where a deployed fix waits for confirmation.
- This replaces the subtitle "Fixes a later scan observed — never work
  somebody marked done" with a column that simply will not let you. Each of
  the two right-hand columns carries one dashed note explaining itself; those
  are the only two explanatory sentences on the page.

The ageing strip — under a week / 1–4 weeks / over a month, plus oldest open —
is the one thing on the page the four tiles do not already say, and it is
measured from when the finding was first raised rather than from when somebody
added it to the board.

**Correction:** the raised/fixed/came-back chart this section says to remove is
not on this page. It is `ActivityBars` inside the overview's
`RemediationProgress` panel, which §4.1 turns into a single stat tile — so it
belongs to the overview's restructure, which **has no step in §5's build order**
(DECISIONS.md §90).

---

## 5. Build order

Do these in sequence; each is independently reviewable.

1. ~~**Tokens and type.**~~ **Done** — `index.css` neutral layer, `--font-mono`,
   font packages, and the two supporting greys as tokens. The `--sev-*` layer is
   byte-identical; light mode is untouched. DECISIONS.md §84.
2. ~~**Tabular numerals everywhere.**~~ **Done** — every score, count,
   percentage, GUID, resource name and rule id is on the mono face; dates are
   not, per §2.1 above. DECISIONS.md §85.
3. ~~**The shell.**~~ **Done** — the rail's anatomy, the 58px top bar with
   search at its head, the account row at the foot of the rail, and
   `PageHeader` on all twelve routes. DECISIONS.md §86.
4. ~~**Copy pass.**~~ **Done** — section epigrams deleted or moved behind a `?`
   (`components/common/HelpPopover.tsx`), and every page header line is now a
   fact the page knows. The mockups' definitional page subtitles were not kept:
   §3's own rule says the line is facts only, and the definitions live on the
   title's `?`. DECISIONS.md §87.
5. ~~**Risks table + drawer.**~~ **Done** — the table, duplicate grouping, the
   372px drawer, `/risks/:riskId` as a deep link into the ranking, and the
   collector fix behind the identity labels. No checkbox column: nothing has a
   bulk action yet. DECISIONS.md §88.
6. ~~**Findings, Assets** presentation.~~ **Done** — including the UNKNOWN
   rows, which needed a new endpoint: they are not findings and were not on the
   page at all. DECISIONS.md §89.
7. ~~**Attack paths** empty states, **Remediation** board.~~ **Done** — the
   precondition strip, the diagram and the labelled example; the four-column
   board with a locked "Verified fixed", the four tiles and the ageing strip.
   Moved with buttons, not dragged. DECISIONS.md §90.
8. ~~**The Overview** (§4.1).~~ **Done** — hero with the exposure map, four
   tiles, the blind-spot banner promoted above the ranking, and the
   distribution toggle. It had no step of its own in this list, which is the
   gap §90 named. Nine superseded components deleted; DECISIONS.md §91 lists
   what left the product and where it went.
9. ~~Remaining routes (Changes, Reports, Compliance, Scans, Rules, Cloud) by
   applying the same patterns.~~ **Done** — Rules becomes a table with a
   drawer, the last two hand-drawn panels move onto `Card`, and light mode is
   derived rather than left half-converted. The other five routes already
   carried the patterns after steps 2-4. DECISIONS.md §92.

## 6. Do not

- Do not change any `--sev-*` value, or merge severity into the accent.
- Do not add a drop shadow, a rounded-corner-plus-left-border-accent callout,
  or a gradient outside the Overview hero.
- Do not use teal for a non-interactive element.
- Do not restore per-section subtitle prose "for clarity". If a panel needs
  explaining, it needs a `?` popover or a better label.
- Do not hide, collapse or default-filter UNKNOWN rows.
- Do not let a table row wrap to two lines.

## 6.5 Below `lg`

The mockups are all 1440px wide, so this is written rather than drawn
(DECISIONS.md §93). Three breakpoints, and each one is a decision about what
the reader loses first.

**`lg` (1024px) — the two-column layouts collapse.** The sidebar becomes the
drawer it already was; the account menu is in the top bar at every width, so
nothing about it changes here. A page
with a drawer open — risks, rules — shows the drawer *instead of* the list
rather than beside it: the same component, so the narrow reading cannot drift
from the wide one. The overview hero stacks, arc above map.

**`sm` (640px) — the horizontal affordances go.** Search is its icon and
nothing else: a full-width search bar on a 375px screen leaves the
notifications and the account menu fighting for what is left. The stat tiles go
two-up, the remediation board goes two columns before it goes one.

**Tables scroll; the page never does.** Every table carries a `min-w-[...]`
floor — the sum of its fixed columns plus room for the flexible one — inside
the primitive's own `overflow-x-auto`. Without the floor a table does not
scroll, it *crushes*: the flexible first column collapses toward nothing and
the finding title disappears while the empty columns keep their width. Same for
the attack-path diagram and the exposure map, both of which are fixed-width
drawings inside a scrolling frame.

What is deliberately **not** responsive: nothing is hidden by width alone. No
column is dropped on a small screen and no row is summarised, because a
security table that quietly shows less on a phone is the same failure as one
that quietly shows less when a collector was refused.

## 7. Known gaps in the mockups

- The Findings rows other than the two identity ones use **invented rule IDs**
  (`storage.https_only`, `logging.diagnostics`, `authz.owner_direct`). Replace
  with real IDs from the rule registry.
- ~~No component sheet yet~~ — there is one at **`/design`**, rendered from the
  components themselves rather than drawn, so it cannot describe a product that
  no longer exists. Development only: the route and its chunk do not exist in a
  production build (DECISIONS.md §94).
- ~~`--meta-foreground` and `--faint-foreground` are below AA for body text
  with no lint rule enforcing it~~ — `cloudguard/meta-foreground-is-not-body`
  fails the build when either is paired with a size in the body register, and
  CI runs it. It cannot catch a size inherited from a parent, which is stated
  in the rule rather than left to be discovered (DECISIONS.md §95).
