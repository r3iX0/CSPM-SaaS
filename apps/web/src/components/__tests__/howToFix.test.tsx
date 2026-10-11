/**
 * Every cut says how to make it (DECISIONS.md §246).
 *
 * The change in one sentence, the provider's commands where one command does
 * it, and the open findings on the link's two ends, each trackable. Asked for
 * only when somebody opens it.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { HowToFix } from "@/components/graph/HowToFix";
import { api } from "@/lib/api";
import type { CutFix } from "@/lib/types";

const LINK = { source: "mi", relationship: "grants_role", target: "rg" };

function fix(overrides: Partial<CutFix> = {}): CutFix {
  return {
    sentence: "Remove the Owner role from mi-payments on rg-data.",
    description: "mi-payments can act over rg-data",
    detail: "mi-payments can act over rg-data (Owner)",
    relationship: "grants_role",
    source: { id: "mi", name: "mi-payments", resource_type: "service_principal", asset_id: null },
    target: { id: "rg", name: "rg-data", resource_type: "resource_group", asset_id: "row-rg" },
    provider: "AZURE",
    cost: 1,
    severs: 3,
    commands: ["az role assignment delete --assignee p --role Owner --scope /s/rg"],
    findings: [
      {
        id: "finding-1",
        rule_id: "AZ-IAM-001",
        title: "Owner held by a workload identity",
        severity: "HIGH",
        status: "OPEN",
        asset_name: "rg-data",
        asset_id: "row-rg",
        tracked: false,
      },
    ],
    code: [],
    pull_request_offered: false,
    pull_requests: [],
    ...overrides,
  };
}

function mount(answer: CutFix) {
  const get = vi.spyOn(api, "get").mockResolvedValue({ data: answer, meta: {} });
  const post = vi.spyOn(api, "post").mockResolvedValue({ data: { id: "task-1" }, meta: {} });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <HowToFix link={LINK} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { get, post };
}

describe("HowToFix", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("asks for nothing until opened", () => {
    const { get } = mount(fix());
    expect(screen.getByRole("button", { name: "How to fix" })).toHaveAttribute(
      "aria-expanded",
      "false",
    );
    expect(get).not.toHaveBeenCalled();
  });

  it("says the change, gives its command and lists the findings on its ends", async () => {
    const { get } = mount(fix());
    await userEvent.click(screen.getByRole("button", { name: "How to fix" }));

    expect(
      await screen.findByText("Remove the Owner role from mi-payments on rg-data."),
    ).toBeVisible();
    expect(get).toHaveBeenCalledWith(
      "/api/v1/attack-paths/fix?source=mi&relationship=grants_role&target=rg",
    );
    expect(screen.getByText(/az role assignment delete/)).toBeVisible();
    expect(screen.getByRole("link", { name: /Owner held by a workload identity/ })).toHaveAttribute(
      "href",
      "/remediation?fix=finding-1",
    );
  });

  it("tracks a finding from the cut", async () => {
    const { post } = mount(fix());
    await userEvent.click(screen.getByRole("button", { name: "How to fix" }));
    await userEvent.click(await screen.findByRole("button", { name: "Track" }));

    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/v1/remediation", { finding_id: "finding-1" }),
    );
    expect(await screen.findByText("Tracked")).toBeVisible();
  });

  it("says when no single command makes the change", async () => {
    mount(fix({ commands: [], findings: [] }));
    await userEvent.click(screen.getByRole("button", { name: "How to fix" }));

    expect(await screen.findByText(/No single command makes this change/)).toBeVisible();
    expect(screen.getByText("No open findings on these two assets.")).toBeVisible();
  });

  it("asks for the cut as a pull request where its block is in code (§258)", async () => {
    const { post } = mount(
      fix({
        pull_request_offered: true,
        code: [
          {
            assignment_id: "ra",
            repository: "contoso/infra",
            working_directory: "infra",
            address: "azurerm_role_assignment.app",
          },
        ],
      }),
    );
    await userEvent.click(screen.getByRole("button", { name: "How to fix" }));
    await userEvent.click(await screen.findByRole("button", { name: "Open a pull request" }));

    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/v1/attack-paths/pull-requests", LINK),
    );
  });

  it("shows a pull request in flight instead of offering another", async () => {
    mount(
      fix({
        pull_request_offered: true,
        code: [
          {
            assignment_id: "ra",
            repository: "contoso/infra",
            working_directory: "infra",
            address: "azurerm_role_assignment.app",
          },
        ],
        pull_requests: [
          {
            id: "pr-1",
            cut_key: "mi|grants_role|rg",
            repository: "contoso/infra",
            state: "OPEN",
            pr_number: 31,
            pr_url: "https://github.com/contoso/infra/pull/31",
            decline_reason: null,
            detail: null,
            created_at: "2026-10-11T09:00:00Z",
            assignments: [],
          },
        ],
      }),
    );
    await userEvent.click(screen.getByRole("button", { name: "How to fix" }));

    expect(await screen.findByRole("link", { name: "#31" })).toHaveAttribute(
      "href",
      "https://github.com/contoso/infra/pull/31",
    );
    expect(screen.queryByRole("button", { name: "Open a pull request" })).toBeNull();
  });
});
