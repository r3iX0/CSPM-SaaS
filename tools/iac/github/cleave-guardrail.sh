#!/usr/bin/env bash
# Have Cleave judge this pull request's Terraform plan before it is applied (DECISIONS.md §234).
#
# Run it from the directory Terraform runs in, after `terraform plan -out=<file>`, in a
# GitHub Actions job on `pull_request` with `permissions: id-token: write`. Pass the plan
# file as the first argument. It reads the plan with `terraform show -json`, and for each
# azurerm resource the plan creates or updates keeps only the arguments Cleave's rules
# read, from the allowlist Cleave publishes: their planned and prior values, and which
# are known only after apply. Nothing else leaves the runner. A plan holds every
# attribute in plain text, secrets included; a value Terraform marks sensitive is
# dropped even where it is allowlisted.
#
# Cleave reports the verdict as a check run on the pull request, and this script exits
# non-zero where the change brings a misconfiguration, so the job fails with it.
#
# The upload is authenticated by the job's own GitHub OIDC token, so there is no Cleave
# secret to store. Cleave accepts it only for a pull request of a repository its GitHub
# App is installed on.
#
# Needs: terraform, jq, curl. Set CLEAVE_API to Cleave's API origin.
# Optional: CLEAVE_WORKING_DIRECTORY, if this is not run from the Terraform root.
set -euo pipefail

: "${CLEAVE_API:?Set CLEAVE_API to Cleave's API origin}"
: "${ACTIONS_ID_TOKEN_REQUEST_URL:?The job needs permissions: id-token: write}"
plan_file="${1:?Pass the file written by terraform plan -out}"

working_directory="${CLEAVE_WORKING_DIRECTORY:-$(realpath --relative-to="${GITHUB_WORKSPACE}" .)}"
workspace="$(terraform workspace show)"

allowlist="$(curl -sSf "${CLEAVE_API}/api/v1/iac-guardrail/allowlist" | jq -c .data.attributes)"

resources="$(terraform show -json "${plan_file}" | jq -c --argjson allow "${allowlist}" '
  # "a.b" is a nested block: the path ["a", 0, "b"], read only where the block is one.
  def steps($path): ($path | split(".")) as $s
    | reduce range(1; $s | length) as $i ([$s[0]]; . + [0, $s[$i]]);
  def at($v; $s):
    if ($s | length) == 0 then $v
    elif ($s[0] | type) == "number" then
      (if ($v | type) == "array" and ($v | length) == 1 then at($v[0]; $s[1:]) else null end)
    elif ($v | type) == "object" then at($v[$s[0]]; $s[1:])
    else null end;
  # after_unknown and *_sensitive mark a value, or a whole block, with true.
  def marked($v; $s):
    if $v == true then true
    elif ($s | length) == 0 then false
    elif ($s[0] | type) == "number" then
      (if ($v | type) == "array" and ($v | length) >= 1 then marked($v[0]; $s[1:]) else false end)
    elif ($v | type) == "object" then marked($v[$s[0]]; $s[1:])
    else false end;
  def scalar: if type == "object" or type == "array" then null else . end;
  def kept($values; $sensitive; $unknown; $paths):
    [ $paths[] as $p | steps($p) as $s
      | select((marked($unknown; $s) | not) and (marked($sensitive; $s) | not))
      | {key: $p, value: (at($values; $s) | scalar)}
      | select(.value != null) ] | from_entries;
  [ .resource_changes[]?
    | select(.mode == "managed")
    | select(.provider_name | endswith("/hashicorp/azurerm"))
    | select(any(.change.actions[]; . == "create" or . == "update"))
    | ($allow[.type] // []) as $paths
    | select($paths | length > 0)
    | .change as $c
    | { address, type, actions: $c.actions,
        after: kept($c.after; $c.after_sensitive; $c.after_unknown; $paths),
        before: kept($c.before; $c.before_sensitive; false; $paths),
        unknown: [ $paths[] | select(marked($c.after_unknown; steps(.))) ] } ]')"

token="$(curl -sSf -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${CLEAVE_API}" | jq -r .value)"

# The repository and the pull request are not sent: Cleave reads both from the token.
answer="$(jq -n \
  --arg working_directory "${working_directory}" \
  --arg workspace "${workspace}" \
  --argjson resources "${resources}" \
  '{working_directory: $working_directory, workspace: $workspace, resources: $resources}' |
  curl -sSf -X POST \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    --data-binary @- \
    "${CLEAVE_API}/api/v1/iac-guardrail/plans")"

jq -r '.data | (.verdicts[] | select(.verdict == "FAIL")
  | "\(if .introduced then "brought by this change" else "already failing" end): "
    + "\(.rule_id) \(.address) \(.attribute) = \(.planned), expected \(.expected)"),
  "Check run: \(.check_run_url // .check_run_detail)"' <<<"${answer}"
[ "$(jq -r .data.conclusion <<<"${answer}")" = "success" ]
