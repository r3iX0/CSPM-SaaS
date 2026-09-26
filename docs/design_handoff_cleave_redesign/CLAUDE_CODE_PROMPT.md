# Kickoff prompt for Claude Code

Paste this into Claude Code from the root of `CSPM-SaaS`, with this folder copied to `docs/design_handoff_cleave_redesign/`.

---

You're implementing the Cleave redesign in `apps/web`. The spec is in `docs/design_handoff_cleave_redesign/README.md`, the token patch is in `tokens.css`, and the clickable reference is `design/Cleave.dc.html` (open it in a browser). The HTML is a reference, not code to copy. Rebuild it with our existing `components/ui` primitives, Tailwind v4 tokens, `useT()` strings and TanStack queries. Keep every behaviour and every DECISIONS.md rule the current code enforces.

Work in the README's PR order. Each PR must be self-contained, pass `pnpm test` and typecheck, and update the existing tests where copy or structure changed. Don't regress a11y: keep the aria labels and focus rings, and keep reduced motion working.

1. **Tokens.** Apply `tokens.css` to `src/index.css`, add `@fontsource-variable/geist-mono`, and set `--radius: 0.5rem`. Screenshot a few pages in light and dark mode and check the contrast of every `--sev-*` foreground on its `-bg` (≥ 4.5:1).
2. **Rename + nav.** CloudGuard → Cleave across `en.ts` and user-facing strings. Connections → Environments in `nav.ts`, with the new nav groups. New `Brand.tsx` wordmark.
3. **Shared components.** `SeverityBadge`, `StatusPill`, `StatStrip`, `ScoreTile`, `Donut`, `Sparkline`, `ProviderMark`, and the new `ResourceIcon` via `lib/icons.ts`.
4. **Shell.**
5. **Screens,** one per PR, in the README's order. For each one: read its "Screens" section, open the matching `at.<key>` section in the prototype, and read the repo files listed for it in `github.md`.
6. **Copy sweep** against the voice rules.

Before starting each PR, give me a short plan: the files you'll touch and anything in the spec that conflicts with the current code. Then implement.
