import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { RulesPage } from "@/pages/Rules";
import { api } from "@/lib/api";
import type { Rule } from "@/lib/types";
import { wholeText } from "@/test/text";
import { MemoryRouter } from "react-router-dom";

function rule(overrides: Partial<Rule> = {}): Rule {
  return {
    rule_id: "AZ-STO-001",
    name: "Storage account allows public blob access",
    description: "Anonymous readers can list and download blobs.",
    category: "storage",
    severity: "CRITICAL",
    version: "1.0",
    exploitability: 4,
    scope: "resource",
    applies_to: ["storage_account"],
    enabled: true,
    remediation: "",
    rationale: "",
    estimated_effort_minutes: 10,
    compliance_mappings: { ISO_27001: ["A.8.3"] },
    ...overrides,
  } as Rule;
}

function mount(rules: Rule[]) {
  vi.spyOn(api, "get").mockResolvedValue({ data: rules, meta: {} });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      {/* The drawer links out to the findings a rule raised, so the page needs
          a router around it. */}
      <MemoryRouter>
        <RulesPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("the rule catalogue", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("searches the whole catalogue, which arrives in one request", async () => {
    // Filtering in the browser is honest here and nowhere else in the product:
    // this list is the rulebook, not an estate, and it is all present.
    mount([
      rule(),
      rule({ rule_id: "AZ-NET-002", name: "Network security group permits inbound SSH" }),
    ]);

    fireEvent.change(await screen.findByLabelText("Search rules"), {
      target: { value: "ssh" },
    });

    expect(screen.getByText("Network security group permits inbound SSH")).toBeInTheDocument();
    expect(
      screen.queryByText("Storage account allows public blob access"),
    ).not.toBeInTheDocument();
  });

  it("matches on the rule id, which is how a finding names its rule", async () => {
    mount([rule(), rule({ rule_id: "AZ-NET-002", name: "Inbound SSH" })]);

    fireEvent.change(await screen.findByLabelText("Search rules"), {
      target: { value: "AZ-NET" },
    });

    expect(screen.getByText("Inbound SSH")).toBeInTheDocument();
  });

  it("says how much of the catalogue is showing", async () => {
    mount([rule(), rule({ rule_id: "AZ-NET-002", name: "Inbound SSH" })]);

    // Counted against what CloudGuard runs, not against every row the API
    // returned -- a withdrawn rule is in that response and is not a check.
    expect(await screen.findByText(wholeText("2 of 2 rules CloudGuard runs"))).toBeInTheDocument();
  });

  it("marks a tenant-wide rule, which belongs to no asset", async () => {
    mount([rule({ scope: "aggregate" })]);

    expect(await screen.findByText("Tenant-wide")).toBeInTheDocument();
  });

  it("offers a way back when a filter matches nothing", async () => {
    mount([rule()]);

    fireEvent.change(await screen.findByLabelText("Search rules"), {
      target: { value: "nothing at all" },
    });

    expect(screen.getByText("No rules match")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Clear filters" })).toBeInTheDocument();
  });

  it("keeps a withdrawn rule out of the list of checks it runs", async () => {
    // The catalogue's heading claims these are the checks CloudGuard runs. A
    // rule taken out of the registry is not one, and it arrives in the same
    // response as the live ones.
    mount([rule(), rule({ rule_id: "AZ-OLD-001", name: "Retired check", enabled: false })]);

    expect(await screen.findByText(wholeText("1 of 1 rule CloudGuard runs, and 1 withdrawn"))).toBeInTheDocument();
    expect(screen.queryByText("Retired check")).not.toBeInTheDocument();
  });

  it("shows the withdrawn rules, and says they no longer run", async () => {
    mount([rule(), rule({ rule_id: "AZ-OLD-001", name: "Retired check", enabled: false })]);

    fireEvent.click(await screen.findByRole("button", { name: /Show withdrawn rules/ }));

    // Dashed and named in the row, not greyed away: a rule that has stopped
    // running is not a quieter rule.
    expect(screen.getByText("Retired check")).toBeInTheDocument();
    expect(screen.getByText("Withdrawn")).toBeInTheDocument();

    // What that means is a sentence, and a sentence belongs where there is
    // room for one.
    fireEvent.click(screen.getByRole("button", { name: "Retired check" }));
    expect(
      await screen.findByText(
        /no longer runs and compliance coverage no longer counts it/,
      ),
    ).toBeInTheDocument();
  });

  it("offers no withdrawn toggle when nothing is withdrawn", async () => {
    // A permanent toggle on a complete catalogue implies rules are missing.
    mount([rule()]);

    await screen.findByText("Storage account allows public blob access");
    expect(screen.queryByRole("button", { name: /withdrawn/i })).not.toBeInTheDocument();
  });

  it("shows the reasoning and the fix beside the catalogue, one rule at a time", async () => {
    // Ninety rules each carrying a rationale and four fix formats is a
    // document, not a list. The table compares them; the drawer reads one.
    mount([
      rule({
        rationale: "Anonymous blob access is the most common cause of cloud data loss.",
        remediation: "Set allowBlobPublicAccess to false.",
      }),
    ]);

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Storage account allows public blob access",
      }),
    );

    expect(
      await screen.findByText(
        "Anonymous blob access is the most common cause of cloud data loss.",
      ),
    ).toBeInTheDocument();
    expect(screen.getByText("Set allowBlobPublicAccess to false.")).toBeInTheDocument();
  });

  it("sends a rule to the findings it actually raised here", async () => {
    // The catalogue is CloudGuard's rulebook and says nothing about this
    // estate; the one link out of it is to what the check found.
    mount([rule()]);

    fireEvent.click(
      await screen.findByRole("button", {
        name: "Storage account allows public blob access",
      }),
    );

    expect(
      await screen.findByRole("link", { name: /See what this raised here/ }),
    ).toHaveAttribute("href", "/findings?rule_id=AZ-STO-001&status=all");
  });
});
