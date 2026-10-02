# Fix-as-Code: IaC diffs and pull requests

Status: **Phase 0 done (2026-09-29), Phase 1 next.** The decision is DECISIONS
§190. Phase 0 settled:

- `RemediationSpec.terraform_resource_types` is declared on the 13 Azure rules
  with a Terraform attribute; `tests/unit/test_terraform_hints_schema.py` holds
  every attribute to the azurerm 3.117.1 and 4.81.0 schemas (fixtures from
  `tools/iac/trim_azurerm_schema.py`). It found three broken hints, now fixed:
  AZ-STO-002, AZ-DB-002, AZ-KV-001.
- All 17 attribute names are the same in v3 and v4, so the per-attribute
  provider range was not added; add it when a rule needs a name that differs.
- `bicep_property` was deferred to the Bicep phase: nothing reads it before then.
- tree-sitter HCL and Bicep grammars exist as binary wheels for macOS and
  manylinux on 3.12 and round-trip byte ranges exactly.
- `terraform_hints` surfaces through `GET /rules` and the finding's
  `RemediationPanel` Terraform tab. CLI fix commands already exist
  (`spec.cli` with placeholders filled by `lib/remediationFill.ts`).
- Customer secrets (webhook signing secrets) are plaintext columns under RLS;
  relevant for Phase 3 only.
- `python-multipart` is already a dependency, so the Phase 1 upload is multipart.

**Phase 1 built (2026-09-29), Terraform only:** `app/remediation/iac/terraform.py`
(`edit_terraform`), `app/services/iac.py`, `POST /findings/{id}/iac-diff`
(multipart `file` + optional `lockfile`), and `IacDiffCheck` in the finding's
Terraform tab. §190 was amended: an optional argument missing from an existing
block is added, since an omitted argument is the usual shape of an insecure
default.

**Hit rate, measured with `tools/iac/hit_rate.py`:**

| Corpus | Blocks tried | Patched | Declined `interpolated_name` |
|---|---|---|---|
| hashicorp/terraform-provider-azurerm `examples/` | 299 | 3 (1%) | 295 (99%) |
| Azure/terraform quickstarts | 169 | 0 | 169 (100%) |
| Azure Verified Module, storage account | 0 | -- | -- (no plain azurerm resources) |

Public samples are parameterised on purpose (`"${var.prefix}-sa"`,
`random_string`), so this likely understates customer repositories, but it
confirms the top risk: matching on a literal `name` alone almost never fires.
Where a file holds a type at all, it holds **one** block of that type 94% of the
time (118 of 125 files).

**Sole-block matching, uploads only (§190).** Where no block carries the name
and the upload holds exactly one interpolated block of the rule's types, it is
taken, and the answer says `matched_by: "sole_block"` so the reviewer checks it.
Measured with `hit_rate.py --sole-block`:

| Corpus | Patched | Already set | Nested block missing | Interpolated (several blocks) | Empty block |
|---|---|---|---|---|---|
| azurerm `examples/` (299) | 165 (55%) | 10 (3%) | 45 (15%) | 70 (23%) | 9 (3%) |
| Azure quickstarts (169) | 116 (69%) | 15 (9%) | 38 (22%) | 0 | 0 |

It does not carry over to Phase 2, where CloudGuard chooses the file and "the
only one here" means nothing. **Before Phase 2**, settle how a searched
repository is matched: a Terraform state address, or evaluating simple
interpolations against variable defaults and `.tfvars`. The next lever for
uploads is `nested_block_missing` -- mostly `network_rules` / `network_acls` /
`site_config` absent -- which stays a decline by design for `default_action`.

## What it is

For a failing finding, CloudGuard produces a real edit to the customer's own
Terraform or Bicep that makes the rule pass, delivered two ways:

- **Download IaC diff** -- no integration required.
- **Create pull request** -- GitHub first, then GitLab (maybe Azure Repos and Bitbucket also later
  on) CloudGuard locates the file and block that define the asset and opens a PR on a new branch. It
  never pushes to the default branch and never merges.

The commercial case: remediation time drops from weeks to hours, and the platform
engineers who review the PR become advocates for the tool.

## The constraint this must respect

`app/remediation/spec.py` deliberately refuses to generate code it cannot stand
behind. `terraform_hints` returns an attribute, not a resource block, because a
generated block is either missing required arguments and will not apply, or fills
them in and applies something nobody asked for. Fix-as-Code keeps that rule:

- **Edit only an attribute inside a block that already exists.** Never create a
  resource, never fill in required arguments.
- **Decline rather than guess**, and say why. Decline when:
  - the resource name is interpolated (`name = "${var.prefix}sa"`);
  - the value comes from a module input or a variable;
  - more than one block matches;
  - the provider version is unknown or outside the range the attribute was
    verified for.
- **Collection edits come last.** Removing `0.0.0.0/0` from an NSG means deleting
  part of a nested `security_rule` block or a separate
  `azurerm_network_security_rule` resource -- a structural edit, not setting an
  attribute. The first release covers `Comparison.EQUALS` only
  (`minimum_tls_version`, `public_network_access_enabled`, ...).
- **A merged PR never resolves a finding.** It records a claimed fix; the next
  scan decides.

## Phases

### Phase 0 -- Decision record and spec extension (small)

- Write DECISIONS §190: edit in place only, the decline rules, a GitHub App
  rather than personal access tokens, no auto-merge.
- Add `bicep_property: str | None` to `ExpectedState` (e.g.
  `properties.minimumTlsVersion`). Same "verified before written down" rule as
  `arm_alias`, and never derived from the alias: aliases and property paths do
  not always correspond.
- Add a Terraform provider version range to the spec. azurerm v4 renamed
  arguments (`enable_https_traffic_only` became `https_traffic_only_enabled`),
  so an attribute name is only correct for a known range.
- A coverage test: every `terraform_attribute` / `bicep_property` sits on an
  `EQUALS` state, and a per-rule report of which rules are editable.
- First, confirm what was not checked when this was written: where
  `terraform_hints` is surfaced today, how many rules declare
  `terraform_attribute`, and how secrets (e.g. webhook signing secrets) are
  stored.

### Phase 1 -- Edit engine and "Download IaC diff" (medium)

- `app/remediation/iac/`: `locate()` and `patch()` behind an `IacDialect`
  interface, with Terraform and Bicep implementations.
- Parse with tree-sitter (HCL and Bicep grammars) for exact byte ranges; the edit
  replaces only the value's range, so formatting and comments survive.
  python-hcl2 is unsuitable because it cannot write a file back unchanged.
- After every edit, re-parse and check that exactly one attribute changed and
  nothing else did; otherwise refuse.
- Provider version from `required_providers` or `.terraform.lock.hcl`; unknown
  or out of range means decline.
- `POST /findings/{id}/iac-diff`: the customer uploads a `.tf` / `.bicep` file
  and receives a unified diff. Nothing is stored. Returns `Envelope[...]`,
  documents `ErrorEnvelope`, marked `dependencies=[Costly]`. A decline is data
  with a machine-readable reason, not a 4xx.
- Fixture tests per case: plain, interpolated name, module, `for_each`, `count`,
  multiple matches, azurerm v3 vs v4, Bicep `existing`, Bicep loops.
- Measure the locate hit rate on real-world samples here, before committing to
  Phase 2.
- Besides Bicep and Terraform, should be included also azure cli or aws cli fix command (to be
  copied easily) - cli based on cloud provider (gcloud, kubectl later on...)

### Phase 2 -- GitHub App and pull requests (large)

- **GitHub App, not PATs.** Installation tokens are scoped to repositories the
  customer selects and expire in an hour. Permissions: `contents:write`,
  `pull_requests:write`. The App private key is a server environment variable;
  installation tokens are never persisted.
- **Schema**, all with RLS policies and grants for `cloudguard_app`:
  - `code_integrations` -- organization, provider, installation id;
  - `repo_mappings` -- repository and path glob, mapped to a subscription or
    resource group;
  - `fix_pull_requests` -- finding, repository, branch, PR URL, state, attempt.
- **Locating the file:** mappings narrow the candidate repositories; the tree is
  read through the Git Data API (no clone); `locate()` runs over `*.tf` and
  `*.bicep` matching the literal `name` and the resource type. Size and
  file-count caps. A Terraform state resource address, where the customer
  provides one, is a possible later improvement.
- **Opening the PR** is a Celery task, claimed under a lease, with provider calls
  made outside any transaction and a refused enqueue recorded in a fresh
  `rls_session` (the §158 / §164 pattern). Blob, tree, commit, branch
  `cloudguard/fix-<rule>-<short>`, PR. The body carries the rule, the expected
  state in its `describes` wording, and a link to the finding. Idempotent: at
  most one open PR per finding and file.
- **Audit and roles:** every action through `services/audit.record`. Owners and
  admins connect integrations; members and above open PRs. Every write refused
  in the demo organization (§99).
- **Closing the loop:** a PR merge event creates the existing "fix claimed"
  verification; the next scan's PASS resolves the finding.
- **Frontend:**
  - Settings > Integrations: GitHub card and a repo-mapping editor.
  - Finding remediation panel: "Download IaC diff" and "Open pull request"; a
    decline reason spoken through `LiveStatus`; the unavailable button stays
    focusable as `aria-disabled` (§165).
  - PR status read through TanStack Query.

### Phase 3 -- GitLab (medium)

- Project or group access token, stored the way other customer secrets are.
- Self-hosted GitLab is a URL the customer typed, so every call goes through
  `core/outbound` (§164). That module is POST-only today; it needs GET and PUT
  with the same address pinning.

### Phase 4 -- Collection edits (large, open-ended)

- `NONE_MATCHING` removals: `security_rule` blocks (static and dynamic),
  separate NSG rule resources, Bicep arrays.
- Removing a rule can break legitimate traffic, so the PR body must state exactly
  what access is removed.

## Risks

| Risk | Level | Mitigation |
|---|---|---|
| Real-world HCL is mostly modules and variables, so few PRs can be generated | High | Decline with a reason; measure the hit rate in Phase 1 before building Phase 2 |
| An unverified `terraform_attribute` / `bicep_property` breaks the customer's `plan` | High | Provider-range gating; verify against azurerm v3 and v4 schemas (`terraform providers schema -json` as a test fixture) |
| Repository contents are untrusted input (parser DoS, path tricks) | Medium | Size, depth and time caps; parse only, never evaluate; grammars pinned |
| GitHub App private key and token handling | Medium | Environment variable only; short-lived installation tokens, never stored |
| Editing the wrong block when a name repeats across workspaces or environments | Medium | Multiple matches means decline; mappings scoped by path glob |
| Scope creep toward AWS / CloudFormation | Low | Azure only; AWS stays gated behind `AWS_ENABLED` |

## Dependencies

- `tree-sitter` with HCL and Bicep grammars -- new Python dependencies; whether a
  maintained Bicep grammar package exists is unchecked.
- A registered GitHub App: name, webhook URL for PR merge events, permissions.
- Optionally, the azurerm provider schema JSON as a test fixture.

## Open decisions

1. **First release scope.** Phase 1 alone, to prove the edit engine
   and the locate hit rate with no integration.
2. **GitHub App or personal access token.** GitHub App
3. **Bicep in the first release, or Terraform first.** Terraform first.

## Estimate

High complexity overall. Phases 0-1: about 3-4 days. Phase 2: about 1.5-2 weeks.
Phases 3-4: another 1-2 weeks.
