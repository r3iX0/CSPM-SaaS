# Ticketing: the Jira sync

Status: **designed, not built.** This is the build specification for syncing the remediation
queue with Jira Cloud, for whoever builds it. `DECISIONS.md` §226 records what was chosen and why:
Jira Cloud first, one issue per rule group per project, status and assignee synced back, manual
sending with an opt-in rule, and routing by subscription. This document says how, and records what
was checked against Atlassian's documentation on 8 October 2026.

## Contents

- [The rule it follows](#the-rule-it-follows)
- [Verified against Atlassian](#verified-against-atlassian)
- [Connecting a Jira site](#connecting-a-jira-site)
- [Routing](#routing)
- [Data model](#data-model)
- [Out: sending a rule group](#out-sending-a-rule-group)
- [Back: what Jira tells Cleave](#back-what-jira-tells-cleave)
- [The verdict](#the-verdict)
- [Delivery and failure](#delivery-and-failure)
- [Security](#security)
- [API](#api)
- [Interface](#interface)
- [Build order](#build-order)
- [To confirm while building](#to-confirm-while-building)

## The rule it follows

Cleave is the referee, and Jira is where the work happens. Cleave never lets Jira close a finding:
moving an issue to done marks its tasks done, which opens the verification (§18), and only a scan
closes the finding. Every behaviour below either carries work out to Jira or carries a verified
verdict back.

## Verified against Atlassian

Checked on 8 October 2026 against the
[webhooks guide](https://developer.atlassian.com/cloud/jira/platform/webhooks/), the
[OAuth 2.0 (3LO) guide](https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/) and
Atlassian's published OpenAPI document for the REST API v3
(`https://developer.atlassian.com/cloud/jira/platform/swagger-v3.v3.json`).

| Question | Answer | Consequence here |
|---|---|---|
| Scopes to register webhooks | `read:jira-work`, `manage:jira-webhook` | Asked for at connect |
| Scopes to create, comment, transition | `write:jira-work` | Asked for at connect |
| Refresh token | `offline_access`; rotating, old token disabled on use; expires after 90 days unused | Store the new one on every refresh |
| Webhook lifetime | 30 days from creation or last refresh; expired ones kept 3 months | Daily refresh job |
| Refresh call | `PUT /rest/api/3/webhook/refresh` with `webhookIds` | One call per connection |
| Webhooks per OAuth app | 5 per app, per user, per site | One webhook per connection, filtered by project |
| Registration body | `url` and `webhooks` (`events`, `jqlFilter`, `fieldIdsFilter`); **no secret** | The HMAC `X-Hub-Signature` scheme does not apply |
| Delivery authentication | `Authorization` bearer token signed with the app's client secret | Verify it, then treat the event as a hint only |
| Webhook JQL | `project`, `issueKey`, `status` and a few more, with `=`, `!=`, `IN`, `NOT IN` | `project IN (...)` |
| Retries | Up to 5, every 5 to 15 minutes, on 408, 409, 425, 429, 5xx | Deduplicate on `X-Atlassian-Webhook-Identifier` |
| Missed deliveries | `GET /rest/api/3/webhook/failed` | Read by the poll |
| A user's email | `emailAddress` "may be returned as null" by the user's privacy setting | Assignee matching is best effort |
| API base | `https://api.atlassian.com/ex/jira/{cloudid}/rest/api/3/...` | The site is a `cloudid` from `accessible-resources` |

Scopes are the classic ones. The granular equivalents are marked Beta in the OpenAPI document.

## Connecting a Jira site

An owner or an admin connects one Jira Cloud site per organization, from Settings > Integrations.

1. `POST /integrations/jira/connect` answers the authorization URL:
   `https://auth.atlassian.com/authorize` with `audience=api.atlassian.com`, `prompt=consent`,
   the scopes `read:jira-work write:jira-work manage:jira-webhook read:jira-user offline_access`,
   and a `state` that is a signed token naming its purpose (`jira-connect`), the organization and a
   nonce (§147).
2. Atlassian redirects to `GET /integrations/jira/callback` with `code` and `state`. The route
   checks the signature and purpose, spends the nonce once under a row lock, then exchanges the code
   at `https://auth.atlassian.com/oauth/token`.
3. `GET https://api.atlassian.com/oauth/token/accessible-resources` lists the sites the user
   granted. One site is used directly; with several, the settings page asks which one.
4. The connection records the Atlassian account that connected. The webhook and the tokens belong
   to that account, so the settings page says "Connected as" and recommends a service account. When
   that person leaves, the connection breaks, and Cleave says so (see
   [Delivery and failure](#delivery-and-failure)).

Disconnecting deletes the webhook (`DELETE /rest/api/3/webhook`), then the tokens. Existing issue
links stay, read-only, so history still shows which issue a fix went through.

## Routing

- **A default project and issue type**, required to send anything.
- **Per-subscription overrides**: a cloud account to a project and issue type. Directory findings
  have no subscription and use the default.
- **Routes are one statement**, replaced whole (`PUT`), as risk context is (§207).
- The settings page reads projects and their issue types from Jira
  (`GET /rest/api/3/project/search`, then the project's issue types), so nobody types a key.

**Status mapping uses Jira's status categories.** Every Jira status belongs to one of three
categories: `new`, `indeterminate` or `done`. They map to `TODO`, `IN_PROGRESS` and `DONE`. The plan
asked for a per-project mapping because workflows differ. Categories already absorb that difference,
so a mapping is only an override, offered per project when a team's categories are wrong. Reopening
picks the first available transition into a `new` or `indeterminate` status, and closing picks the
first into `done`. Both can be overridden per project with a transition id.

## Data model

All tables are tenant-owned under row-level security (RLS), like every other.

- `ticket_connections`: one per organization. Provider (`JIRA`), `cloud_id`, site URL, the
  connecting `account_id` and display name, granted scopes, the encrypted access and refresh tokens
  with their key id, `access_expires_at`, `status` (`ACTIVE`, `BROKEN`, `DISCONNECTED`), the reason
  when broken, the webhook ids, `webhook_expires_at` and `last_polled_at`.
- `ticket_routes`: `cloud_account_id` (null for the default), `project_key`, `issue_type_id`, and
  optional reopen and close transition ids.
- `ticket_links`: one Jira issue for one rule in one project. `rule_id`, `project_key`,
  `issue_id`, `issue_key`, the last seen status category, `status_comment_id`, `created_at`,
  `closed_at`, and `follows_link_id` for an issue opened after an earlier one was done. Unique on
  organization, rule and project while `closed_at` is null. This row is the rule group's server
  identity, which §203 left to the browser.
- `ticket_link_tasks`: which tasks an issue carries. A task is in at most one open link.
- `ticket_outbox`: work owed to Jira (create, update the status comment, comment a verdict,
  transition, refresh the webhook). Claimed under a lease and sent outside any transaction, as
  webhook deliveries are (§164), with attempts and the next attempt time.
- `ticket_events_seen`: delivery identifiers already handled, kept 7 days.

Organizations also gain an auto-create rule: the severities to send, and whether to send only what
is on an attack path. Off by default.

## Out: sending a rule group

A group is sent manually by "Send to Jira" on a queue row or a rule sheet. A task's button sends its
rule group. The auto-create rule sends a group the first time a scan raises a finding it matches.
Sending one group is one action on one thing, not the batch endpoint §203 rejected.

What one send does:

1. Splits the group's open tasks by route, so each project gets its own issue.
2. Creates any task that does not exist yet, for an untracked finding of the rule on a routed
   asset, through `create_task`. An issue then never names an asset the queue does not have.
3. Creates the issue with `POST /rest/api/3/issue`:
   - **Summary**: the rule's title and the asset count ("Storage accounts allow public blob access
     (4 assets)").
   - **Description**, in Atlassian Document Format: the fix's steps, the rule's one script over
     every asset (§203), and a link back to `/remediation?rule=`. Written once. Cleave never
     rewrites the description, so nobody's edits are lost.
   - **Due date**: the earliest `due_on` among the tasks (§225).
   - **Labels**: `cleave` and the rule id.
   - Priority is not set, because priority schemes differ per site.
4. Posts the **status comment**: one Cleave-owned comment listing each asset and its state, and
   the rule's pull request once Fix-as-Code opens one (§227), edited in place (`PUT` on the
   comment) as states change. A checklist kept in the description would
   overwrite human edits; a stream of comments would bury the discussion.

**A new failing asset** on a rule with an open issue joins that issue: a task is created and linked,
the status comment is updated, and a short comment says the asset was added. If the rule's issue is
already done, a new issue is opened that links the old one (`follows_link_id`, and a Jira issue
link of type "Relates").

Assignees are not sent. The plan syncs assignees back only.

## Back: what Jira tells Cleave

**A webhook is a hint, never a fact.** One webhook per connection listens for `jira:issue_updated`
and `jira:issue_deleted`, with `jqlFilter` set to `project IN (...)` over the routed projects. A
delivery is checked, then the issue is read again with Cleave's own token, and only that reading
changes anything. A forged or replayed delivery can at worst cause one read.

The receiver, `POST /integrations/jira/events`:

1. Verifies the bearer token against the app's client secret, and refuses without it.
2. Ignores a delivery whose `X-Atlassian-Webhook-Identifier` it has seen.
3. Finds the connection from `matchedWebhookIds`, and the link from the issue id. An issue no link
   names is ignored.
4. Queues a re-read and answers `200` at once. Answering slowly invites Jira's retries.

**The poll is the floor.** Every 15 minutes, each active connection reads its open links' issues
with `GET /rest/api/3/search/jql` (`issue in (...) AND updated >= <last poll>`) and the failed
webhooks list. A missed or expired webhook then delays an update rather than losing it.

What a re-read changes:

- **Status category** `new`, `indeterminate` or `done` moves the link's open tasks to `TODO`,
  `IN_PROGRESS` or `DONE`, through `_change_status`, so done opens the verification. The mapping is
  idempotent, so Cleave's own transitions echoing back change nothing.
- **Assignee**: matched to a member by email when Jira returns one. With no match, the link shows
  the Jira name and `assigned_to` is left alone, since only members are assigned (§159).
- **Deleted issue**: the link closes, and its tasks stay as they are, untracked in Jira.

## The verdict

Cleave's verification (§18) settles each task, and the link reacts:

- **Every task verified fixed**: Cleave comments with the evidence (the scan, when, and what it
  saw) and moves the issue to done if it is not there already. A fix observed before anyone touched
  the ticket closes the ticket.
- **A task still failing** after its issue was done: Cleave transitions the issue back with the
  reopen transition and comments with the assets still failing. The status change comes back and
  moves the tasks to `TODO`, which withdraws their claim, as a reopen in the queue does (§212).
- **Insufficient evidence**: Cleave comments and does not reopen. It is Cleave failing to look,
  not the fix failing.

## Delivery and failure

- **Outbox.** A request never calls Jira. It writes outbox rows and commits. A worker claims them
  under a lease, calls Jira outside any transaction, and records the result in a fresh session
  (§158, §164). On a `429` it waits for `Retry-After`. Other failures back off up to five
  attempts, after which the row is left failed and the queue row says "Not sent".
- **Tokens.** The access token is refreshed shortly before `access_expires_at`. The rotated refresh
  token is stored in the same transaction as the access token. A refresh refused with
  `invalid_grant` marks the connection `BROKEN`.
- **A broken connection** stops the outbox and the poll for that organization, notifies owners and
  admins through the existing notifications (§164), and asks for a reconnect in Settings.
  Reconnecting as the same site keeps every link.
- **Webhook refresh.** A daily job refreshes webhooks expiring within 7 days, and re-registers one
  that has gone. Changing the routes re-registers the webhook with the new project list.

## Security

- **Tokens are encrypted** at the application layer with AES-GCM from `cryptography`, under a key
  from the environment (`TICKETING_TOKEN_KEY`) with a key id stored beside each value, so the key
  can rotate. A refresh token writes to a customer's Jira, so a database copy alone must not hand
  it over. Webhook secrets stay plaintext under RLS: they reach only the customer's own endpoint.
- **The request role cannot read tokens.** Column privileges let `cloudguard_app` write the token
  columns at the callback and never select them; only the worker role reads them.
- **The callback and the receiver are open routes**, listed with the other open routes in
  `tests/unit/test_openapi_contract.py`. The callback's credential is its signed, single-use
  `state`. The receiver's credential is the bearer token, and the receiver reads nothing from the
  body it does not confirm with its own call.
- **Outbound calls go only to `api.atlassian.com` and `auth.atlassian.com`**, fixed hosts rather
  than a URL a customer typed, so they need not go through `core/outbound.post_json`.
- **Roles.** Connecting, routing and the auto-create rule are owner and admin actions. Sending a
  group needs write (`require_write`). The demo organization and guests are refused, as every write
  is (§99, §219).
- **What leaves Cleave**: rule text, asset names, resource ids in the script, and evidence
  summaries, into the customer's own Jira. The settings page says so before connecting.

## API

Planned, all under `/api/v1`:

| Method and path | Purpose | Who |
|---|---|---|
| `GET /integrations/jira` | The connection, its status, account and routes | Members |
| `POST /integrations/jira/connect` | The authorization URL | Owner, admin |
| `GET /integrations/jira/callback` | OAuth redirect; open route | Signed `state` |
| `DELETE /integrations/jira` | Disconnect | Owner, admin |
| `GET /integrations/jira/projects` | Projects and their issue types | Owner, admin |
| `PUT /integrations/jira/routes` | The routes, whole | Owner, admin |
| `POST /integrations/jira/events` | Webhook receiver; open route | Bearer token |
| `POST /remediation/tickets` | Send a rule group (`rule_id`); `202` | Write |

Each task in `GET /remediation` gains `ticket`: the issue key, its URL and its status category, or
null.

## Interface

- **Settings > Integrations** gains a Jira card: connect, "Connected as", the site, routes, the
  auto-create rule, and a broken connection's reason with a reconnect button.
- **The queue** shows an issue key on a row that has one, linking to Jira, and "Send to Jira" in a
  group's row and its rule sheet when a connection exists. "Not sent" appears when the outbox gave
  up.
- **The rule sheet** names the issue, its status and its assignee as Jira has them.

## Build order

1. Connection, routes, manual send, the outbox and the status comment. Nothing comes back yet.
2. Back: the receiver, the poll, status categories and assignees.
3. The verdict comments and transitions, and new assets joining an issue.
4. The auto-create rule.

Each step ships with its own `DECISIONS.md` entry. The `TicketProvider` seam (create, comment,
transition, read issue, register and refresh webhooks) is cut in step 1, so GitHub Issues and Linear
can follow without touching the outbox.

## To confirm while building

- **The bearer token's algorithm.** The webhooks guide says it is signed with the client secret but
  not how. Log the header of the first real delivery on a test site, then pin the algorithm.
- **"Only a single URL per app."** The OpenAPI document says this of the registration URL. Confirm
  that one receiver URL serves every organization's connection.
- **The status comment's rendering**, as Atlassian Document Format, in Jira's issue view.
- **What happens to a webhook** when its account loses access to the site, so the poll can detect
  it.
