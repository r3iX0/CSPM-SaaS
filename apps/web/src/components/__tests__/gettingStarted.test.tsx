/**
 * The getting-started checklist, which must be right without remembering
 * anything: every tick comes from state the server already holds.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { GettingStarted } from "@/components/dashboard/GettingStarted";
import { api } from "@/lib/api";
import type { CloudAccount, CloudConnection, Dashboard } from "@/lib/types";

function dashboard(overrides: Partial<Dashboard> = {}): Dashboard {
  return {
    security_score: 70,
    score_delta: null,
    history: [],
    findings_by_severity: {},
    findings_by_status: {},
    risk_bands: {},
    open_finding_count: 3,
    asset_count: 10,
    verified_resolved_last_30_days: 0,
    remediation_rate: 0,
    top_risks: [{ id: "risk-1", title: "Public storage", risk_score: 90, risk_level: "CRITICAL" }],
    coverage: { ratio: 1, unknown: 0, conclusive: 10, context: { unclassified: 0, classified: 10, ratio: 1 } },
    last_scan: {
      id: "s1",
      status: "COMPLETED",
      completed_at: "2026-09-01T00:00:00Z",
      resource_count: 10,
      rule_count: 5,
      finding_count: 3,
      collection_errors: {},
    },
    ...overrides,
  } as Dashboard;
}

const account = { id: "a-1", account_name: "Production" } as CloudAccount;

function connection(overrides: Partial<CloudConnection> = {}): CloudConnection {
  return {
    id: "c1",
    is_ready_to_scan: true,
    scan_interval_hours: null,
    ...overrides,
  } as CloudConnection;
}

function mount(
  data: Dashboard,
  {
    connections = [connection()],
    declared = false,
    variant = "compact" as const,
  }: { connections?: CloudConnection[]; declared?: boolean; variant?: "full" | "compact" } = {},
) {
  vi.spyOn(api, "get").mockImplementation((path: string) => {
    if (path.includes("/context")) {
      return Promise.resolve({ data: declared ? { cloud_account_id: "a-1" } : null, meta: {} }) as never;
    }
    return Promise.resolve({ data: connections, meta: {} }) as never;
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <GettingStarted dashboard={data} accounts={[account]} variant={variant} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("the getting-started checklist", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it("starts at connecting, and holds back what depends on it", async () => {
    mount(dashboard({ last_scan: null }), { connections: [], variant: "full" });

    expect(await screen.findByRole("link", { name: "Connect a cloud" })).toHaveAttribute(
      "href",
      "/connections/new",
    );
    // Scanning, fixing and declaring all wait on the step before them.
    expect(screen.getAllByText("After the step before").length).toBeGreaterThan(0);
    expect(screen.getByText("0 of 5 done")).toBeInTheDocument();
  });

  it("offers to finish a connection that was started and not completed", async () => {
    mount(dashboard({ last_scan: null }), {
      connections: [connection({ id: "c9", is_ready_to_scan: false })],
      variant: "full",
    });

    expect(await screen.findByRole("link", { name: "Continue setup" })).toHaveAttribute(
      "href",
      "/connections/c9/setup",
    );
  });

  it("sends the fix step to the top risk once there is a scan", async () => {
    mount(dashboard());

    expect(await screen.findByRole("link", { name: "Open the top risk" })).toHaveAttribute(
      "href",
      "/risks/risk-1",
    );
    expect(await screen.findByText("2 of 5 done")).toBeInTheDocument();
  });

  it("ticks a step from the server's state, not from a click", async () => {
    mount(dashboard({ findings_by_status: { RESOLVED: 1 } }), {
      connections: [connection({ scan_interval_hours: 24 })],
    });

    expect(await screen.findByText("4 of 5 done")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Declare in Settings" })).toBeInTheDocument();
  });

  it("goes away once everything is done", async () => {
    const { container } = mount(dashboard({ findings_by_status: { RESOLVED: 1 } }), {
      connections: [connection({ scan_interval_hours: 24 })],
      declared: true,
    });

    await vi.waitFor(() => expect(container).toBeEmptyDOMElement());
  });

  it("can be put away after the first scan, and stays away", async () => {
    mount(dashboard());

    fireEvent.click(await screen.findByRole("button", { name: "Hide this checklist" }));

    expect(screen.queryByText("Get CloudGuard working for you")).not.toBeInTheDocument();
    expect(Object.values({ ...localStorage })).toContain("1");
  });

  it("cannot be put away before the first scan, when it is the whole page", async () => {
    mount(dashboard({ last_scan: null }), { connections: [], variant: "full" });

    await screen.findByText("Get CloudGuard working for you");
    expect(screen.queryByRole("button", { name: "Hide this checklist" })).not.toBeInTheDocument();
  });
});
