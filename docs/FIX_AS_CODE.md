# Fix-as-Code: IaC diffs and pull requests

Status: **Phases 0 and 1 done (2026-09-29); Phase 2 built behind `FIX_PRS_ENABLED`
(§227, §229, §231 to §234): the GitHub App linked, the state index uploaded, one pull request
per rule per repository, claimed on merge, a value passed into a module written on the module
call, and each pull request's plan judged as a check run.** GitLab (Phase 3) is next. The
decisions are DECISIONS §190 and §227 to §234.
As of 2026-10-08, 35 Azure rules carry a Terraform hint, and no edit is made to an argument that
replaces the resource (§228). Phase 0 settled:

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
only one here" means nothing. Phase 2 matches a searched repository by the
customer's own state addresses (§227). The next lever for uploads is
`nested_block_missing` -- mostly `network_rules` / `network_acls` /
`site_config` absent -- which stays a decline by design for `default_action`.

## What it is

For a failing finding, CloudGuard produces a real edit to the customer's own
Terraform or Bicep that makes the rule pass, delivered two ways:

- **An uploaded file's diff** -- no integration required.
- **A pull request** -- GitHub first, then GitLab (maybe Azure Repos and Bitbucket also later
  on). The customer's CI says which block defines the asset, and CloudGuard opens a PR on a new
  branch. It never pushes to the default branch and never merges.

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

### Phase 2 -- The repository index and pull requests (large)

Decided in DECISIONS §227, which settles how a searched repository is matched. Ermir's design of
2026-10-04 (`docs/superpowers/specs/2026-10-04-fix-as-code-pull-requests-design.md`) is adopted
for the GitHub App, the tables, the edit engine, the lease and the flow. Three of its decisions are
replaced: the customer's CI locates blocks instead of a model, a pull request covers a rule in a
repository instead of one finding, and the upload stays until pull requests ship.

**Locating: the customer's CI says where each asset is defined.** A GitHub Action, run in the
customer's pipeline where state access already exists, reads `terraform show -json` and uploads,
for each managed resource, its `address`, `type`, `index` and the `id` from `values`. For an
azurerm resource that `id` is the Azure Resource Manager id, which is the asset's own id, so the
match is exact through variables, `random_string`, `count`, `for_each` and modules. The block is
then found from the address: `module.storage.azurerm_storage_account.main` leads to the root
module's `module "storage"` call, its local `source`, and `resource "azurerm_storage_account"
"main"` there, read with tree-sitter. A literal-name search stays as a fallback for a repository
with no index.

- **Nothing else leaves the runner.** State and plan JSON carry secrets in plaintext (`values`
  holds every attribute; `sensitive_values` only marks which). The Action keeps the four fields
  above and drops the rest before upload. It never uploads state.
- **No stored credential.** The Action authenticates with its GitHub OIDC token (issuer
  `https://token.actions.githubusercontent.com`, audience Cleave's API, permission `id-token:
  write`). Cleave checks the signature against GitHub's published keys, takes `repository_id` and
  `ref`, and accepts an index only for a repository the organization's GitHub App installation
  covers and only from its default branch.
- **One index per repository, working directory and workspace**, replaced whole on each upload.
- **The index also marks an asset IaC-managed.** Its fix sheet then leads with "Open pull request",
  and the CLI fix moves behind "Emergency fix: will drift until the code changes", because the next
  `terraform apply` reverts a change made outside the code.

The edit rule of §190 does not change: one literal value, or one optional argument added, in a
block that exists. The index finds the block; it does not make a variable's value editable. A
module's input is the exception (§233): where the argument is exactly `var.<name>` and the module
uses that variable for nothing else, the module call that sets it is edited instead.

**Declines added by the index:**

- `module_external`: the address passes through a module whose `source` is a registry or git
  address, so the block is not in this repository.
- `partial_instances`: a block under `count` or `for_each`, or shared by several workspaces,
  defines every instance at once. It is edited only where every instance in the index fails the
  rule, and declined otherwise.
- `index_stale`: the indexed address no longer parses to a block in the default branch's tree.
- `variable_shared` and `unindexed_caller` (§233): the module uses the input variable elsewhere
  too, or code no index covers calls the module an edit would change.

**One pull request per rule per repository.** It edits every failing asset of the rule that the
repository defines and the engine can edit, and says in its body which assets it declined and why.
This matches the Jira sync's one issue per rule group (`docs/TICKETING.md`), and the pull request
is linked from that issue's status comment. `fix_pull_requests` is keyed by organization, rule and
repository, unique while open, with the findings it covers in `fix_pull_request_findings`. A second
request for the same rule and repository answers the open pull request. The branch is
`cloudguard/fix-<rule>`.

**The rest is the 2026-10-04 design, unchanged:**

- **GitHub App, not personal access tokens.** Installation tokens are scoped to repositories the
  customer selects and expire in an hour, minted per task and never stored. Permissions:
  `contents:write`, `pull_requests:write`, and `checks:write` for the guardrail (§234). The
  App's private key is a server environment variable.
- **Schema**, with RLS policies and grants for `cloudguard_app`: `code_integrations`,
  `repo_mappings`, `fix_pull_requests`, `fix_pull_request_findings`, and `iac_indexes` with their
  entries.
- **Opening the pull request** is a Celery task claimed under a lease, with provider calls outside
  any transaction and a refused enqueue recorded in a fresh `rls_session` (§158, §164). The route
  `POST /remediation/pull-requests` takes a rule, is `Costly`, answers `202`, and is refused in the
  demo organization (§99).
- **Closing the loop:** the App's merge event claims the fix for every finding in the pull request,
  through the existing verification. The next scan decides.
- **Audit and roles:** every action through `services/audit.record`. Owners and admins connect;
  members and above open pull requests.
- **Interface:** Settings > Integrations gains the GitHub card, the mapping editor and the Action's
  workflow file to copy. The fix sheet and the rule sheet gain "Open pull request", unavailable
  with its reason spoken through `LiveStatus` (§165).
- **Rollout** behind `FIX_PRS_ENABLED`, off by default. Every request logs how the block was found
  (`index` or `name`) and every decline reason, from the first day.

**The upload stays** (`POST /findings/{id}/iac-diff`, `IacDiffCheck`, `sole_block`). It is the only
code fix for a customer without GitHub. Whether it goes is decided once pull requests are live and
both can be measured.

**Not in this phase:** a model that locates blocks. It is not needed while the index is exact, and
it would need a model provider, key custody and data-processing terms first. If repositories
without an index turn out to be common, it can return behind the same locator output.

**Order.** Widen the editable rules first; it improves today's upload at once. Then the Action in
index mode with the IaC-managed flag, which needs no GitHub App. Then the Jira sync. Then the App
and pull requests. Module input edits (§233) and the pull-request guardrail (§234) followed, each
with its own entry.

**The guardrail** (§234). `tools/iac/github/cleave-guardrail.sh` runs in the customer's pull
request job after `terraform plan`, keeps only the allowlisted arguments of each azurerm resource
the plan creates or updates, and posts them with the job's OIDC token. Cleave judges them against
the rules' Terraform hints and posts a check run on the pull request. A failure fails the check
only where the change brings it. The App needs `checks: write` for the check run.

### A cut as a pull request (built, DECISIONS.md §257, §258)

Beside a rule's fix, the attack-path page can ask for a cut -- a role assignment that routes to
sensitive data cross -- as a pull request. The same index, sweep, lease and GitHub App open it;
the edit is deleting the `azurerm_role_assignment` blocks the assignment ids map to, all or
nothing for a block under `count` or `for_each`. A merge marks the cut made; the next scan's route
ledger shows whether its routes closed.

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
| Real-world HCL is mostly modules and variables, so few PRs can be generated | High | Locate by state address (§227); a variable's value still declines, and each decline is logged |
| Customers do not add the Action, so nothing is indexed | Medium | A literal-name fallback; the workflow file is offered to copy; the IaC-managed flag gives the Action value before any PR |
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
3. **Bicep in the first release, or Terraform first.** Terraform first. Bicep has no state
   file, so the index does not reach it; its locator is an open question for its own phase.
4. **How a searched repository is matched.** By the customer's state addresses, uploaded by
   their CI (§227).

## Estimate

High complexity overall. Phases 0-1: about 3-4 days. Phase 2: about 1.5-2 weeks.
Phases 3-4: another 1-2 weeks.
