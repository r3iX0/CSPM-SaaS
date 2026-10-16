# One Adapter per Cloud Provider

## Problem

CloudGuard maintainers who add or change a cloud have to keep three separate provider registries
(connectors, onboarding, change feeds), a hard-coded availability check, and about eight frontend
provider branches in step by hand. The seam in DECISIONS.md §71 stops provider imports in neutral
code, but nothing keeps these pieces consistent with each other. As a result, adding a third cloud
touches about ten files, and the frontend works out again what onboarding already declares. Leaving
this as it is makes every future cloud, and every change to an existing one, slower and more likely
to drift.

## Evidence

Source: the architecture deepening review of 2026-10-14, item 03 ("Strong", ports & adapters).

- Three registries are kept consistent by hand: `CONNECTORS`, `ONBOARDING` and `CHANGE_FEEDS`.
- The change feed is untyped, so its callers cast results with `bool()` and `str()`.
- Five wrappers do nothing but pass defaults through.
- Neutral service code names Azure and AWS directly to decide which providers are available.
- About eight frontend branches compare `provider` against `azure` or `aws`. They work out again
  what `ProviderOnboarding` already declares.
- No drift bug or failed change has been observed. The cost of change ("a third cloud touches ~10
  files") is an **assumption — needs validation by counting the files touched in the AWS
  integration commits**.

## Users

- **Primary**: CloudGuard maintainers and future contributors who add a cloud provider or change
  how an existing one connects, onboards, streams change events or reports availability.
- **Not for**: customers or operators. The product they see must not change, and `AWS_ENABLED`
  gating keeps working as it does today.

## Hypothesis

We believe **one adapter per cloud that declares its connector, onboarding, change feed and
availability, with the web app reading those declared capabilities from the providers endpoint**,
will **remove the hand-synced registries and the provider branching** for **CloudGuard
maintainers**.

We'll know we're right when:

- the three registries and the five default-only wrappers no longer exist;
- no neutral backend module and no web component branches on a provider name;
- callers of the change feed need no type casts, and strict type checking passes;
- a stub third provider added in a test registers by adding one adapter and touching nothing else.

## Success Metrics

| Metric | Target | How measured |
|---|---|---|
| Provider registries | 3 → 1 | Code inspection |
| Default-only wrappers | 5 → 0 | Code inspection |
| Provider-name branches in neutral backend code | 0 | Existing provider seam test, extended |
| Provider-name branches in web components | ~8 → 0 | New automated frontend check |
| Casts on change-feed results | 0 | Code inspection; strict type check passes |
| Files touched to register a stub third provider | 1 adapter module | Test that adds a stub adapter |
| User-visible behaviour change | None | Existing API and web test suites pass unchanged |

## Scope

**MVP**:

- One adapter interface per provider, covering connector, onboarding, change feed and availability.
- Azure and AWS adapters that wrap the pieces each provider already has.
- The separate registries, the default-only wrappers and the hard-coded availability removed.
- The providers endpoint publishes each provider's declared capabilities.
- The web app reads those capabilities instead of branching on the provider name.

Responses stay the same apart from the added capability fields. The UI stays the same, and
`AWS_ENABLED` gating is kept.

**Out of scope**:

- A real third cloud such as GCP. The stub adapter only proves the seam.
- Running AWS against a live account (the `docs/AWS_INTEGRATION.md` §1 checklist), which is a
  separate effort.
- Changes inside connectors, rules or collection. Only how providers are registered and exposed
  changes.
- Renaming `provider_ref` (§70). It stays deferred, because stored captures use the old names.
- Moving vocabulary onto onboarding. §78 stays as it is.
- Changing what availability or `operator_detail` mean. §186 stays as it is.

## Delivery Milestones

| # | Milestone | Outcome | Status | Plan |
|---|---|---|---|---|
| 1 | One backend adapter per cloud | Registries and wrappers are gone, the feed is typed, availability is declared by each adapter, and the seam test covers it | complete | DECISIONS.md §263 |
| 2 | Capabilities published | The providers endpoint returns each provider's declared capabilities, with no other response changes | complete | DECISIONS.md §263 |
| 3 | Web reads capabilities | The web app has no provider-name branches, and a frontend check enforces that | pending | — |
| 4 | Seam proven | A test-only stub provider registers by adding one adapter | pending | — |

## Open Questions

- [ ] Should capabilities go into the existing providers endpoint's payload, or into a new field or
  version of it?
- [ ] Should provider-specific setup copy stay in web i18n keyed by provider, or come from the
  adapter's declared capabilities?
- [ ] Does this need a new DECISIONS.md entry that supersedes part of §71?
- [ ] Can a frontend lint rule or test reliably ban provider-name branches without false positives,
  for example on display-only provider marks?

## Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| AWS adapter changes go unverified, because AWS has never run live | Medium | Medium | Wrap existing AWS pieces without changing them; keep the `AWS_ENABLED` gate and fixture tests |
| Capability payload duplicates or contradicts §78 vocabulary and §186 availability rules | Medium | Medium | Publish declared facts only; vocabulary and `operator_detail` stay where they are |
| The frontend branch ban is too broad and blocks legitimate display code | Medium | Low | Scope the check to behaviour branches; allow display such as `ProviderMark` |
| The refactor silently changes an API response the SPA relies on | Low | High | Keep typed response tests (`test_typed_responses.py`) and the web suites green with no fixture edits |
| Interface designed for two providers fits a third poorly | Medium | Low | The stub third adapter in milestone 4 tests the interface's shape |

---
_Status: DRAFT — requirements only. Implementation planning pending via /plan._
