/**
 * A Terraform argument azurerm sets only by recreating the resource (DECISIONS.md §228).
 *
 * The tab still says what new code should set, and says the cost; it never
 * offers to write the change into an existing file, because the apply would
 * destroy the resource -- for a storage account, with its data.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import type { RemediationSpec } from "@/lib/types";
import { RemediationPanel } from "@/components/security/RemediationPanel";

function spec(replaces: boolean): RemediationSpec {
  return {
    expected_state: [],
    cli: [],
    terraform: [
      {
        attribute: "infrastructure_encryption_enabled",
        value: "true",
        describes: "Data is encrypted twice at rest",
        replaces,
      },
    ],
    azure_policy: null,
    enforceable: false,
    notes: "",
  };
}

async function openTerraform(replaces: boolean) {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <RemediationPanel
        remediation="Recreate the account with infrastructure encryption."
        spec={spec(replaces)}
        fill={{ values: {}, resourceName: "prodlogs" }}
        findingId="finding-1"
      />
    </QueryClientProvider>,
  );
  await userEvent.setup().click(screen.getByRole("tab", { name: "Terraform" }));
}

describe("a Terraform argument that replaces the resource", () => {
  it("says so, and offers no edit of existing code", async () => {
    await openTerraform(true);

    expect(screen.getByText(/makes Terraform destroy this resource/)).toBeInTheDocument();
    expect(screen.queryByLabelText(/Terraform file/)).not.toBeInTheDocument();
  });

  it("offers the edit where the argument changes in place", async () => {
    await openTerraform(false);

    expect(screen.queryByText(/makes Terraform destroy this resource/)).not.toBeInTheDocument();
    expect(screen.getByLabelText(/Terraform file/)).toBeInTheDocument();
  });
});

describe("an asset the customer's state index places in code (DECISIONS.md §229)", () => {
  it("leads with the code, and calls the CLI an emergency fix", () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <RemediationPanel
          remediation="Raise the minimum TLS version."
          spec={{
            ...spec(false),
            cli: ["az storage account update --name <account> --min-tls-version TLS1_2"],
          }}
          managedInCode={[
            {
              repository: "contoso/infra",
              working_directory: "envs/prod",
              workspace: "default",
              address: "module.storage.azurerm_storage_account.main",
              commit_sha: "a1b2c3",
              uploaded_at: "2026-10-08T09:00:00Z",
            },
          ]}
        />
      </QueryClientProvider>,
    );

    expect(
      screen.getByText(/Managed in code: module\.storage\.azurerm_storage_account\.main/),
    ).toHaveTextContent("contoso/infra/envs/prod");
    expect(screen.getByRole("tab", { name: "Terraform" })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tab", { name: "Emergency fix" })).toBeInTheDocument();
  });
});
