/**
 * The queue has to say what the work is, and what it is not.
 *
 * `GET /remediation` returns a task and nothing of the finding behind it, so
 * the page used to offer a severity badge, a status and a link reading "View
 * finding" — everything about the record and nothing about the problem. A
 * person deciding what to do next had to open every card to find out.
 *
 * The board adds the other half: a card reaches "Verified fixed" when a scan
 * stopped finding the problem, and by no other route. That used to be a
 * sentence under the title asking to be believed.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { RemediationPage } from "@/pages/Remediation";

const TASK = {
  id: "task-1",
  finding_id: "finding-1",
  risk_id: null,
  status: "TODO",
  priority: "CRITICAL",
  due_date: null,
  estimated_effort_minutes: 15,
  notes: null,
  completed_at: null,
  created_at: "2026-08-01T00:00:00Z",
};

const FINDING = {
  id: "finding-1",
  rule_id: "AZ-STORAGE-001",
  severity: "CRITICAL",
  status: "IN_PROGRESS",
  title: "Storage account allows public blob access",
  description: "",
  evidence: {},
  remediation: "",
  rule_version: "1.0",
  risk_score: 91,
  first_detected_at: "2026-08-01T00:00:00Z",
  last_detected_at: "2026-08-01T00:00:00Z",
  resolved_at: null,
  resolved_by_scan_id: null,
  resource: {
    id: "asset-1",
    name: "prodstorage",
    resource_type: "STORAGE_ACCOUNT",
    environment: "PRODUCTION",
    region: "westeurope",
    criticality: "HIGH",
    data_sensitivity: "HIGH",
    public_exposure: "HIGH",
  },
};

const DASHBOARD = {
  security_score: 58,
  score_delta: null,
  history: [],
  findings_by_severity: {},
  findings_by_status: {},
  risk_bands: {},
  open_finding_count: 11,
  asset_count: 5,
  verified_resolved_last_30_days: 0,
  remediation_rate: 0,
  remediation_activity: [{ week: "2026-08-01", detected: 3, resolved: 1, reopened: 2 }],
  top_risks: [],
  coverage: { ratio: 1, unknown: 0, conclusive: 3 },
};

let tasks: object[] = [TASK];
let finding: object = FINDING;

function renderPage() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/remediation"]}>
        <RemediationPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("the remediation queue", () => {
  beforeEach(() => {
    tasks = [TASK];
    finding = FINDING;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        const body = url.includes("/findings/")
          ? finding
          : url.includes("/dashboard")
            ? DASHBOARD
            : tasks;
        return {
          ok: true,
          status: 200,
          json: async () => ({ data: body, error: null, meta: {} }),
        } as Response;
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("names the finding and the asset the work is on", async () => {
    renderPage();

    const title = await screen.findByRole("link", {
      name: "Storage account allows public blob access",
    });
    expect(title).toHaveAttribute("href", "/findings/finding-1");
    expect(await screen.findByText(/prodstorage/)).toBeInTheDocument();
  });

  it("holds work somebody deployed in its own column, short of fixed", async () => {
    // The distinction the board exists to make: a claim that the work is done
    // is not an observation that the problem is gone.
    tasks = [{ ...TASK, status: "DONE", completed_at: "2026-08-02T00:00:00Z" }];
    renderPage();

    const awaiting = await screen.findByRole("region", {
      name: "Awaiting a scan",
    });
    expect(
      within(awaiting).getByText("Storage account allows public blob access"),
    ).toBeInTheDocument();

    const verified = screen.getByRole("region", { name: "Verified fixed" });
    expect(
      within(verified).queryByText("Storage account allows public blob access"),
    ).not.toBeInTheDocument();
  });

  it("moves a card to verified only when the finding itself resolved", async () => {
    tasks = [{ ...TASK, status: "DONE" }];
    finding = { ...FINDING, status: "RESOLVED", resolved_at: "2026-08-03T00:00:00Z" };
    renderPage();

    const verified = await screen.findByRole("region", { name: "Verified fixed" });
    expect(
      within(verified).getByText("Storage account allows public blob access"),
    ).toBeInTheDocument();
  });

  it("offers no way to put a card in the verified column", async () => {
    // Not a rule written under the board: there is no control that reaches it.
    renderPage();

    const verified = await screen.findByRole("region", { name: "Verified fixed" });
    expect(within(verified).queryAllByRole("button")).toHaveLength(0);
    expect(
      within(verified).getByText(/Only a scan puts a fix here/),
    ).toBeInTheDocument();
  });

  it("says how long the open work has sat, since it was first raised", async () => {
    // The one thing about this queue the tiles above do not already say.
    renderPage();

    expect(
      await screen.findByRole("region", { name: "How long they have sat" }),
    ).toBeInTheDocument();
  });

  it("counts what came back, and never nets it off against the fixes", async () => {
    renderPage();

    const cameBack = await screen.findByRole("link", { name: /Came back/ });
    expect(cameBack).toHaveTextContent("2");
  });
});
