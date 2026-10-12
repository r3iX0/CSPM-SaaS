# Remediation: plan

Status: **brainstorm; Parts 1 and 2 are not built or decided.** Part 3's first item,
accountability, is built without its Jira half: due dates by severity and progress numbers
(`DECISIONS.md` §225), owner routing (§236), and the weekly digest and overdue escalation
(§237). Part 4's audits and the
audit's faults 1, 3, 4, 5 and 7 are fixed (§221, §222, §224). Worked out on
2026-10-04 from a browser
audit of `/remediation` in production and a discussion of who works the queue. Part 4 was
added on 2026-10-05 from a read of 68 Reddit threads on what practitioners want from a
cloud security posture management (CSPM) tool. Each
part below still needs its own `DECISIONS.md` entry before it is built, and two specs
are to be written from it: `docs/TICKETING.md` (new) and `docs/FIX_AS_CODE.md`
(extended). `PRODUCT_REVIEW_2026-09-20.md` §C proposed the Jira sync first; this plan
settles its shape.

## Who it is for

Three kinds of user work the queue, often in one organization:

- a solo security engineer who finds and fixes, and wants speed;
- a security team that triages and hands fixes to cloud or platform teams, and wants
  owners, due dates and tickets;
- a compliance lead who fixes to pass a framework, and wants deadlines, exceptions and
  evidence.

Target customers already track work in **Jira or GitHub Issues**. The next features
should win all four goals: show progress, cut more risk per hour, get fixes done, and
fix faster.

## The idea that holds it together

**Cleave is the referee; Jira and GitHub are where the work happens.** The queue must
not become a second backlog nobody reads. What Cleave has that a tracker does not is
the verdict: whether a fix actually took (§18). Every feature either carries work out
to the tracker or the repository, or carries a verified verdict back.

Already built, so not on this list: risk acceptance with an expiry (§103, §104), and
Slack, Teams and signed webhook notifications (§164).

## What the audit found

Seen in production on 2026-10-04, at 1440 and 390 pixels wide.

### Faults

Faults 1, 3, 4, 5 and 7 are fixed by `DECISIONS.md` §224. Fault 1 was most likely a cancelled
task beside a new one on the same finding, the cause behind fault 3 too. Fault 7 also covered
the acceptance end date in `RiskTriage.tsx`.

1. The rule sheet listed `ServicePrincipal a2005e68 · Service principal` twice, once
   "In progress" and once "Not tracked". Probably two findings on one asset, with a
   label that cannot tell them apart. Not confirmed.
2. Users are still named service principals (`User 837a0b67 · Service principal`),
   on three of six rows. Known and deferred in §212.
3. The rule sheet said "6 assets, 5 still to do" and offered "Mark all 5 done", with
   no way to track the sixth, untracked asset from the sheet.
4. On a phone, a queue row's chevron and effort fall to their own line, the button is
   centred, and the critical row's "3 on an attack path" is cut off.
5. "Marked done does not close a finding…" is said three times: on the page and twice
   in the fix sheet.
6. Six `GET /findings/{id}` requests on every load. By design (§29), and grouping
   waits on all of them (§203), so it grows with the queue.
7. The due date is the browser's native `dd.mm.yyyy` input, which matches nothing
   else in the design system.

### Gaps

- Finished work disappears: nothing shows what was fixed. Closed by §225.
- "Overdue 0" means nothing while nobody sets due dates. Closed by §225.
- `notes` is drawn (`pages/Remediation.tsx`) but nothing lets anyone write it.
- No filters: owner, subscription, severity, or "assigned to me".
- A row says it is on attack paths, not how many routes fixing it closes.

## Part 1: Jira sync, closed by verification

Decided:

- **Jira Cloud first**, behind a `TicketProvider` seam so GitHub Issues and Linear can
  follow.
- **One issue per rule group** (the §203 grouping), keyed by organization, rule and
  Jira project. A rule whose assets map to two projects gets one issue in each.
- **Status and assignee sync back** into Cleave. Comments stay in the tracker.
- **Created manually**, by "Send to Jira" on a group or a task, and optionally by an
  organization rule (for example, every Critical and High, or only what is on an
  attack path).
- **A new failing asset** on the same rule joins the open issue's checklist with a
  comment. If the issue is already done, a new issue is opened that links the old one.
- **Routing by subscription**, with an organization default. Directory findings have
  no subscription and use the default.

How it behaves:

- **Out.** The issue carries the fix's steps, the rule's one script (§203), a
  checklist of assets with their state, and a link back to `?rule=`.
- **Back.** Moving the issue to in progress moves the tasks to IN_PROGRESS. Moving it
  to done marks the tasks DONE, which opens the §18 verification.
- **The verdict.** Each asset is ticked as its verification passes. When the last one
  passes, Cleave comments with the evidence. When one fails, Cleave moves the issue
  back with the assets still failing. INSUFFICIENT_EVIDENCE comments and does not
  reopen, because it is Cleave failing to look, not the fix failing.
- **Setup** in Settings > Integrations: OAuth 2.0 (3LO), a default project and issue
  type, per-subscription overrides, and a mapping of Jira statuses to to-do, in
  progress and done, plus the reopen transition. Jira workflows differ per project,
  so nothing is assumed.

What it needs, and where it meets existing decisions:

- A table of ticket links (organization, rule, project, issue key) and their tasks,
  and OAuth tokens stored encrypted. A rule group has no server identity today; §203
  groups in the browser only.
- Assignees: §159 assigns work only to members. A Jira assignee is matched to a member
  by email; with no match the name is shown and `assigned_to` is left alone.
- A webhook receiver, a job to refresh dynamic webhooks before they expire, and a poll
  as a fallback. Outbound calls are claimed under a lease and made outside any
  transaction (§164).
- Refused in the demo organization, as every write is (§99).
- **To verify against Atlassian's documentation before building:** how dynamic
  webhook deliveries to an OAuth 2.0 app are authenticated, how long the webhooks
  live (believed about 30 days), and the scopes needed.

## Part 2: Fix-as-Code

Where it stands (`docs/FIX_AS_CODE.md`, §190): Phases 0 and 1 are built. An uploaded
`.tf` file gets a diff from `POST /findings/{id}/iac-diff`, for 13 Azure rules,
Terraform only. Phase 2, pull requests, is blocked on locating an asset's block in a
repository: literal-name matching patched 1% of public samples, and sole-block
matching (55 to 69%) is valid only for an upload.

Decided:

- **Locate by the customer's own CI.** A GitHub Action, run in the customer's pipeline
  where state access already exists, reads `terraform show -json` and uploads a map of
  resource address, type and ARM resource id. The ARM id equals the asset's id, so the
  match is exact through variables, `random_string`, `count` and `for_each`. Cleave
  never holds state credentials. The block is then found from the address itself:
  `module.storage.azurerm_storage_account.main` leads to the module's source and to
  `resource "azurerm_storage_account" "main"`, read with tree-sitter. State JSON does
  not carry file paths or line numbers.
- **Security requirement.** State and plan JSON carry secrets in plaintext. The Action
  must never upload either. It extracts on the runner only what Cleave needs: address,
  type and id for the index, and for the guardrail only the attributes the rules read,
  from an allowlist Cleave publishes.
- **One Action, two modes.** On a push to the default branch it uploads the index; on
  a pull request it uploads the filtered plan for the guardrail.
- **Jira first, then pull requests.** The pull request plugs into the ticket.

In scope for the first release after Phase 1, in this order:

1. **Widen the editable rules.** More `terraform_attribute` hints, each held to the
   azurerm schemas (§190). Independent, and improves today's upload diff at once.
2. **The Action in index mode, and an IaC-managed flag.** An asset Terraform manages
   leads with "Open pull request"; the CLI fix moves behind "Emergency fix: will drift
   until the code changes", because the next `terraform apply` reverts it.
3. **The Jira sync** (Part 1).
4. **The GitHub App and one pull request per rule group.** Blocks located by address,
   the pull request linked in the Jira issue's checklist, a merge claims the fix, and
   the verdict closes the issue and the checklist. Open: a block under `count` or
   `for_each` changes every instance, so edit it only where every instance fails the
   rule, and decline otherwise.
5. **Module input edits.** Edit the module call's input where it passes straight
   through to the attribute.
6. **The pull request guardrail.** The Action's plan mode; the same rules evaluated
   against planned values, reported through the Checks API. The plan becomes a second
   kind of input to the rule engine, which needs its own entry; rules stay
   deterministic.

Step 2 needs no GitHub App. Steps 4 and 6 share it.

## Part 3: afterwards

Ranked by how much each builds on Parts 1 and 2.

1. **Accountability.**
   - Due dates by severity: an organization policy, optionally tied to the framework
     deadline a control maps to, synced to the Jira due date.
   - Owner routing by subscription, resource group or Azure tag (for example
     `owner=platform-team`), which also picks the Jira project and assignee.
   - Overdue escalation: a weekly digest per owner, and overdue work sent to the
     security lead through Slack or Teams (§164).
2. **Proof of progress.**
   - Fixed in the last 30 days, median time to fix by severity, the share of work done
     by its due date, and time from a guardrail failure to its fix.
   - Fix evidence into the audit package (§208): which ticket, which pull request, and
     when the verification passed, for each control.
   - A second approver on an exception (§104), and reminders through Jira before an
     exception expires.
3. **Risk per hour.**
   - An attack-path plan of cuts (§141) becomes one Jira epic with an issue per cut,
     each row saying how many routes it closes.
   - Campaigns: a goal such as "no standing Owner assignments by Q1" over several rule
     groups, with a burn-down.
4. **Reach.** GitHub Issues and Linear adapters, GitLab (Fix-as-Code Phase 3), Bicep,
   and AWS only once `docs/AWS_INTEGRATION.md` §1 passes.

**Deliberately last: Cleave applying a fix itself.** The scanner role is read-only,
and customers trust it partly for that. Writing to a customer's cloud needs a
separate, opt-in role, approval for each fix, and a rollback story. It changes what
the product promises and needs its own entry before any code. Pull requests give most
of the speed without it.

## Part 4: gaps from practitioner research

On 2026-10-05, 68 Reddit threads were read from r/cybersecurity, r/AZURE, r/aws,
r/devsecops, r/sysadmin, r/msp and r/CloudSecurityPros. They asked most for the two
things Parts 1 and 2 already plan: a ticket that closes when the fix is verified, and a
fix delivered as code or policy rather than applied by the tool. They asked for four
more things this plan did not have. Nothing here is decided.

1. **Blast radius before the fix.** Practitioners say the slow part is not writing the
   fix but knowing it will not break production: "whether that 'overly permissive' rule
   is keeping production alive". The fix sheet (§202, §203) would show what reaches the
   asset on the graph and which identities hold access to it (§125), before the
   commands. Cleave reads configuration, not traffic, so the sheet can name who could
   depend on a setting, not who does, and must say so.
2. **A score that explains its own movement.** The dashboard reports `score_delta` and
   a history (`services/dashboard.py`), but not why the score moved. Defender for Cloud
   users describe a score that fell from 72% to 50% with no visible cause, while their
   CFO watches the number. The delta would be split into its causes, each linking to its
   findings:
   - new failures;
   - fixes verified;
   - rules added or changed;
   - assets that appeared or disappeared;
   - acceptances that expired (§104).
3. **Exceptions at scale.** An acceptance covers one finding (`exceptions.finding_id`).
   Practitioners call per-resource exemptions "beyond impossible to manage well at a
   larger scale", and some keep them as a file their pipeline applies. Two questions to
   settle:
   - Can one acceptance cover a rule group or a scope, such as a subscription or a tag,
     with one reason, approver and expiry? That would be one record over a scope, not a
     batch endpoint, but §203's reasons for refusing batches must still be weighed.
   - Does any rule fail a resource that a setting at a higher scope already makes safe?
     Security Hub's per-bucket public access check, which ignores the account-level
     block, is the example practitioners cite.
4. **Platform-owned identities.** Defender for Cloud's most-resented findings flag
   managed identities that Microsoft's own recommended Azure Policy assignments create,
   driving subscription scores to 2 to 4%. `AZ-ID-003` judges users only, so it cannot
   do this. Audit the rules that judge service principals and managed identities for
   the same fault.

### Audit results

Both audits were run on 2026-10-05 by reading the Azure rules and running each suspect
rule against a synthetic resource. Every case below returned FAIL where Azure blocks the
access, or where the identity belongs to Azure Policy.

A setting elsewhere already makes the resource safe. All four are fixed by `DECISIONS.md` §221:

1. **`AZ-STO-001`** (HIGH) fails a storage account whose public network access is
   Disabled when its network rules still default to Allow. Azure ignores the network
   rules when public access is Disabled. `test_private_blob_with_open_network_still_fails`
   in `tests/unit/test_storage_rules.py` asserts this FAIL, because its fixture has
   public access Disabled.
2. **`AZ-DB-001`** (CRITICAL) and **`AZ-DB-025`** (MEDIUM) fail a SQL or PostgreSQL
   server whose public network access is Disabled when an old 0.0.0.0 firewall rule
   remains. Azure applies no firewall rule while public access is Disabled.
   `AZ-DB-001`'s message says the server "is reachable from the internet".
3. **`AZ-CMP-001`** (HIGH) fails a virtual machine if any one network security group
   (NSG) guarding it opens an administrative port. Inbound traffic must pass both the
   subnet's NSG and the network interface's, so a subnet NSG that denies the port makes
   the machine unreachable.
4. **NSG precedence.** `_inbound_allow_rules` in `rules/azure/network/exposure.py`
   drops every Deny rule before matching, so an Allow rule that a higher-priority Deny
   shadows still fails. This affects `AZ-NET-001` to `AZ-NET-005`, `AZ-NET-008`,
   `AZ-NET-009`, `AZ-NET-017` and `AZ-CMP-001`.

Clean: the delete-lock rules (`AZ-LCK-001`, `AZ-STO-019`) count locks on the resource
group and subscription, `AZ-DB-018` accepts the subscription's Defender for SQL plan,
`AZ-DB-020` to `AZ-DB-022` judge only the classic assessment, the internet-exposure rules
for key vaults, registries, clusters, Cosmos DB and AI Search accept public access
Disabled, and `AZ-NET-016` leaves out the reserved subnets.

Identities the platform creates. Settled by `DECISIONS.md` §222:

1. `AZ-ID-003` is clean, since it judges users only.
2. **`AZ-IAM-002`** (HIGH), **`AZ-IAM-003`** (CRITICAL) and **`AZ-IAM-008`** (HIGH)
   cannot tell an Azure Policy assignment's managed identity from any other service
   principal. A landing zone's DeployIfNotExists assignments hold Owner or Contributor
   by design, so the advice to narrow the role breaks the policy. `AZ-IAM-005` and
   `AZ-IAM-012` count these identities as Owners too.
3. The data to tell them apart is already read. Each subscription's policy assignments
   are listed with `$filter=atScope()`, which includes those inherited from management
   groups, and each assignment names its identity's principal id. The normalizer does
   not use it yet. What the rules should then say about such an identity is a decision:
   its privilege is real, but whoever can edit the policy holds it, not a workload.

The research also found gaps outside remediation: per-workload pricing that breaks at
renewal, no affordable multi-tenant view for managed service providers, and a stated
data region. Those belong in `docs/ROADMAP.md`, not here.

## Not proposed

A batch endpoint for marking or tracking work, and a group rescan. Both were rejected
in §203, and the reasons still hold.

## Next

1. Done: Part 3's first two items, by §225. The Jira sync carries `due_on` out as the
   issue's due date. Still open from them: tying a deadline to a framework's, and the share of
   work done by its due date over time rather than per window.
2. Done: `docs/TICKETING.md` from Part 1 (§226), with the three Atlassian questions answered,
   and `docs/FIX_AS_CODE.md` Phase 2 from Part 2 (§227). §227 settles Part 2 against Ermir's
   2026-10-04 design: the CI index locates blocks (no model), one pull request per rule and
   repository, and the upload stays until pull requests ship.
3. Closed: the audit's faults 1, 3, 4, 5 and 7 by §224, and Part 4's audits by §221 (the
   four faults) and §222 (Azure Policy's identities). Faults 2 and 6 wait on §212 and §203.
4. Build, in Part 2's order. Done: widening the editable rules (§228), which found three hints
   that would have recreated the resource, now guarded. Done: the Action in index mode with the
   IaC-managed flag (§229, §231), with the GitHub App linked. Done: one pull request per
   rule and repository, claimed on merge (§232). Then the Jira sync's first step, which waits
   on a registered Atlassian OAuth app.
5. Done: Part 3's accountability item without Jira: owner routing (§236), and the weekly
   digest and overdue escalation through the notifications (§237). Done: fix evidence in the
   audit package, without the ticket (§238). Done: a second approver on an acceptance (§239).
   Next from Part 3 without Jira: campaigns with a burn-down.
