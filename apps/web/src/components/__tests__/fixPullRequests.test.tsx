/**
 * A rule's fix as pull requests (DECISIONS.md §232).
 *
 * Offered only with a linked GitHub installation; each request says where it has
 * got to, links its pull request once there is one, and how many assets it edited.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "@/lib/api";
import type { FixPullRequest, GitHubStatus } from "@/lib/types";
import { FixPullRequests } from "@/components/security/FixPullRequests";

const LINKED: GitHubStatus = {
  available: true,
  installations: [
    {
      installation_id: 7,
      account_login: "contoso",
      account_type: "Organization",
      connected_at: "2026-10-08T09:00:00Z",
    },
  ],
};

const OPEN: FixPullRequest = {
  id: "pr-1",
  rule_id: "AZ-STO-002",
  repository: "contoso/infra",
  state: "OPEN",
  pr_number: 17,
  pr_url: "https://github.com/contoso/infra/pull/17",
  decline_reason: null,
  detail: null,
  created_at: "2026-10-09T09:00:00Z",
  findings: [
    {
      finding_id: "f-1",
      address: "azurerm_storage_account.logs",
      outcome: "EDITED",
      reason: null,
      path: "infra/main.tf",
      line: 3,
    },
    {
      finding_id: "f-2",
      address: "module.vendored.azurerm_storage_account.this",
      outcome: "DECLINED",
      reason: "module_external",
      path: null,
      line: null,
    },
  ],
};

function mount(github: GitHubStatus, pulls: FixPullRequest[] = []) {
  vi.spyOn(api, "get").mockImplementation((path: string) =>
    Promise.resolve({ data: path.includes("pull-requests") ? pulls : github, meta: {} }),
  );
  render(
    <QueryClientProvider client={new QueryClient()}>
      <FixPullRequests ruleId="AZ-STO-002" />
    </QueryClientProvider>,
  );
}

afterEach(() => vi.restoreAllMocks());

describe("a rule's fix as pull requests", () => {
  it("is not offered without a linked GitHub installation", async () => {
    mount({ available: true, installations: [] });
    await vi.waitFor(() => expect(api.get).toHaveBeenCalled());
    expect(screen.queryByRole("button", { name: /Open pull request/ })).not.toBeInTheDocument();
  });

  it("links each pull request and says how much of it was edited", async () => {
    mount(LINKED, [OPEN]);

    expect(await screen.findByRole("link", { name: "#17" })).toHaveAttribute(
      "href",
      "https://github.com/contoso/infra/pull/17",
    );
    expect(screen.getByText("1 of 2 assets edited")).toBeInTheDocument();
  });

  it("asks for the rule's pull requests", async () => {
    mount(LINKED);
    const post = vi
      .spyOn(api, "post")
      .mockResolvedValue({ data: { pull_requests: [OPEN], not_indexed: 1 }, meta: {} });

    await userEvent.setup().click(await screen.findByRole("button", { name: /Open pull request/ }));

    expect(post).toHaveBeenCalledWith("/api/v1/remediation/pull-requests", {
      rule_id: "AZ-STO-002",
    });
  });
});
