#!/usr/bin/env bash
# Tell Cleave where each Azure resource is defined in this Terraform root (DECISIONS.md §229).
#
# Run it from the directory Terraform runs in, after `terraform init`, in a GitHub
# Actions job on the default branch with `permissions: id-token: write`. It reads
# the state with `terraform show -json` and sends, per managed azurerm resource whose
# id is an Azure Resource Manager id, four fields: address, type, index and id.
# Nothing else leaves the runner. State holds every attribute in plain text,
# secrets included, and this keeps only those four.
#
# The upload is authenticated by the job's own GitHub OIDC token, so there is no
# Cleave secret to store. Cleave accepts it only from the default branch of a
# repository its GitHub App is installed on.
#
# Needs: terraform, jq, curl. Set CLEAVE_API to Cleave's API origin.
# Optional: CLEAVE_WORKING_DIRECTORY, if this is not run from the Terraform root.
set -euo pipefail

: "${CLEAVE_API:?Set CLEAVE_API to Cleave's API origin}"
: "${ACTIONS_ID_TOKEN_REQUEST_URL:?The job needs permissions: id-token: write}"

working_directory="${CLEAVE_WORKING_DIRECTORY:-$(realpath --relative-to="${GITHUB_WORKSPACE}" .)}"
workspace="$(terraform workspace show)"

entries="$(terraform show -json | jq -c '
  [ (.values.root_module // {}) | recurse(.child_modules[]?) | .resources[]?
    | select(.mode == "managed")
    | select(.provider_name | endswith("/hashicorp/azurerm"))
    | select((.values.id | type) == "string")
    | select(.values.id | startswith("/subscriptions/"))
    | {address, type, index, id: .values.id} ]')"

token="$(curl -sSf -H "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
  "${ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${CLEAVE_API}" | jq -r .value)"

jq -n \
  --arg working_directory "${working_directory}" \
  --arg workspace "${workspace}" \
  --arg commit_sha "${GITHUB_SHA}" \
  --argjson entries "${entries}" \
  '{working_directory: $working_directory, workspace: $workspace,
    commit_sha: $commit_sha, entries: $entries}' |
  curl -sSf -X PUT \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    --data-binary @- \
    "${CLEAVE_API}/api/v1/iac-indexes"
