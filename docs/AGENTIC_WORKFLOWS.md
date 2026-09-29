# Agentic workflows — where they belong in Cleave, and where they never do

Status: **proposal**. Nothing here is built. The boundary in §1 is recorded as
a decision (DECISIONS.md §166); the use cases in §3 are candidates, ordered, and
each needs its own entry before it ships.

---

## 1. The boundary

The core — rules → findings → risk → graph → verification — is deterministic,
auditable and fenced. That is the product, and it is what an auditor, a
customer's security team and a compliance report rely on. `ROADMAP.md` already
drew the line and it stands:

```
Azure → Rules → Findings → Risk → Evidence → AI       (correct)
Azure → AI → security decision                         (never)
```

An agent may **read, explain, draft and triage** around the engine. It never
sits inside it: no verdict, severity, score, route or closure count is produced
by a model. Every number an agent says comes from a tool that read it from the
engine.

## 2. When an agent earns its place

An agent is worth building only when all three hold:

1. **The path is open-ended** — the next step depends on what the last one
   found. If the steps are known in advance it is a workflow, and a workflow is
   code.
2. **Something deterministic verifies the output** — a test suite, a
   re-evaluation over stored captures, the verification engine (§18), a human
   merge.
3. **A wrong answer is cheap, or caught** before it reaches a customer's
   decision.

Otherwise use a single prompt over a structured payload, or no model at all.

## 3. Candidates, ranked by value over risk

### 3.1 Engine divergence triage and rule authoring (internal — start here)

**Status: prototype built (DECISIONS.md §167)** — `app/prowler/triage.py`,
`apps/api/scripts/triage_divergences.py`, the `triage-divergences` skill, and
`tests/unit/test_divergence_triage.py`. Rule authoring is not built.

`engine_divergences` records every disagreement between a native rule and the
Prowler check it covers (§150), and raw provider JSON is stored verbatim. An
agent reads both verdicts, the capture and the rule source, decides which
engine is right, drafts the fix — a rule patch, a `tools/prowler/curation.json`
edit, a new fixture — and runs `pytest` until it passes.

The same loop authors rules: from a CIS control or a Prowler check's text, draft
the `SecurityRule`, its fixtures and its tests, and iterate until green.

- **No customer exposure.** It runs in the development loop as a Claude Code
  skill or subagent, and a person reviews the diff.
- **Verification is free.** The test suite and re-evaluation over stored
  captures judge every proposal.
- **Immediate return.** Divergences are triaged by hand today; the AWS pack and
  the remaining catalogued controls are rules still to write.

### 3.2 A grounded copilot over the estate (product — highest customer value)

Questions a customer actually asks: *why is this storage account critical? who
can reach the key vault? which single cut closes the most routes? what changed
since Tuesday?* They are open-ended, and the graph already answers each one
exactly (`access.py`, `severance.py`, `POST /attack-paths/simulate`,
`change_events`).

- **Tools are thin wrappers over services**, run under the caller's
  `rls_session`, so tenant isolation is the database's as it is everywhere
  else: list findings, get a finding, who holds access to an asset, what an
  identity holds, attack paths through an asset, simulate a plan of cuts,
  change events in a window. Six to eight tools; more and the model chooses
  badly.
- **Read-only.** No tool writes, and none fetches a URL.
- **Grounding is enforced, not requested.** Every tool result carries ids.
  Before an answer is sent, a validator checks that each finding, asset and
  route id the answer cites appeared in that turn's tool output; an answer
  that cites anything else is dropped, not softened.
- **Existing seams carry it.** `AI_ENABLED` plus a per-organization opt-in;
  the `Costly` rate-limit allowance (§161); answers streamed over the SSE the
  scan detail already uses (§88); each question and its tool calls written
  through `services/audit.record` (§163); graph work through
  `graph_service.off_loop`.
- **Evals are nearly free.** `snapshot_demo.json` is deterministic (§102), so
  a golden set of questions whose answers are asserted against the API runs in
  CI, the same way the rule tests do.
- **Behind `AIProvider`**, the interface `ROADMAP.md` already sketches, so the
  product works with AI off.

### 3.3 Remediation pull requests (the differentiator — later)

§21 already declares, per setting, the normalized field, the ARM alias, the
Terraform argument and the expected state, so *what* to set is solved
deterministically. What is hard is *where*: the resource's definition in the
customer's Terraform or Bicep, behind modules, variables and `for_each`. That
search is agent work.

The loop closes on deterministic ground: the agent opens a pull request, a
person merges it, and the verification engine (§18) confirms the cloud now
shows the expected state — or says `STILL_FAILING` or `INSUFFICIENT_EVIDENCE`.

It needs a GitHub App with repository-scoped write, which is real trust. Build
it when customers ask for repository integration, not before.

### 3.4 Narrative text — executive summary, Jira ticket text, compliance commentary

**Not agents.** One call over a payload the PDF report already builds; Haiku is
enough. Cheap and worth doing, but it does not justify agent infrastructure and
should not be the reason it gets built.

### 3.5 Change-event investigation (maybe)

Reconstructing what drifted, who did it and why a risk moved, from
`change_events` and scan diffs. Useful, but most of it is joins. Try SQL first;
reach for an agent only for the part SQL cannot express.

## 4. What an agent is never allowed to do

- **Evaluate a rule, set a severity or score a risk.** It breaks the
  determinism `rules/base.py` promises, the rule that an error is UNKNOWN and
  never PASS (§6), and the evidence behind every compliance claim.
- **Change a customer's cloud.** The read-only scanner role is part of what is
  sold; write access is a liability CloudGuard would carry.
- **Replace the orchestrator.** Steps are fenced to the worker that claimed
  them because a worker cannot be trusted to commit (§65, §108); a model loop
  is less trustworthy than a worker.
- **Run free SQL.** Every tool goes through the service layer under RLS, or
  tenant isolation leaks through the model.
- **Be a swarm.** One agent with good tools does every case above; several
  agents talking to each other add failure modes and cost, not capability.

## 5. Security conditions particular to this product

- **Prompt injection is in the data by design.** Resource names, tags and
  descriptions are written by the customer — or by whoever compromised them.
  Tool output is untrusted input, which is why tools are read-only, fetch no
  URL and write nothing without a person confirming.
- **Raw captures hold secrets.** App settings, connection strings and SAS URLs
  appear in ARM JSON. A model is sent normalized, redacted fields, never a
  `RawSnapshot`.
- **Customer configuration leaves the boundary.** That needs an
  organization-level opt-in, a DPA with the model provider, and an entry on the
  subprocessor list; EU customers will ask.
- **Cost is bounded per organization and per request.** A token budget, and
  tool results capped and paginated rather than returned whole.

## 6. Tool design rules

The model never sees the implementation, only the schema and the description.

- Descriptions say what the tool answers, what it does not, and what to call
  instead.
- Inputs are ids and enums, not free text, wherever the domain allows.
- Results return ids beside every name, so the grounding validator has
  something to check.
- Errors say how to recover — "asset not found; list assets by name first" —
  never an empty result that reads as "nothing there". Silence is never a pass
  here either.
- Results are capped (top N, with a total), so a large estate cannot fill the
  context.

## 7. Order and models

1. **Now:** divergence triage and rule authoring as a Claude Code skill (§3.1).
   No product risk, and it teaches tool design on this codebase.
2. **Next:** copilot v1 (§3.2), read-only, on the demo organization first, with
   the golden eval set in CI and a DECISIONS entry for the grounding contract.
3. **Later:** remediation pull requests (§3.3), once repository integrations
   exist.

Models: Sonnet 5.5 for the copilot, Haiku 4.5 for summaries and
classification, Opus 5.5 for offline rule authoring.
