/**
 * Starting a scan, and following it.
 *
 * The wizard's promises are the ones worth pinning: it starts a scan through
 * the connection's own subscription, it shows what the API reports and nothing
 * it does not, it ends a partial scan amber rather than green, and a refusal
 * because a scan is already running lands the reader on that scan instead of on
 * an error they can do nothing about.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  ScanWizardProvider,
  useScanWizard,
} from "@/components/scans/ScanWizardProvider";

const connection = {
  id: "conn-1",
  provider: "azure",
  name: "Production tenant",
  is_ready_to_scan: true,
  degraded_categories: [],
  subscriptions: [
    { id: "acct-1", subscription_id: "s-1", display_name: "Payments", in_scope: true, status: "ACTIVE", discovered_at: null, last_scan_at: null, is_scannable: true },
    { id: "acct-2", subscription_id: "s-2", display_name: "Data", in_scope: true, status: "ACTIVE", discovered_at: null, last_scan_at: null, is_scannable: true },
  ],
};

function detail(overrides: Record<string, unknown> = {}) {
  return {
    id: "scan-1",
    cloud_account_id: null,
    connection_id: "conn-1",
    status: "DISCOVERING",
    started_at: "2026-09-13T10:00:00Z",
    completed_at: null,
    created_at: "2026-09-13T10:00:00Z",
    resource_count: 0,
    rule_count: 0,
    finding_count: 0,
    error_message: null,
    collection_errors: {},
    findings_by_severity: {},
    purgeable_finding_count: 0,
    scope: {},
    stages: [
      { stage: "PLAN", scope: null, status: "SUCCEEDED", attempt: 1, duration_seconds: 2, error: null },
      { stage: "COLLECT", scope: "Payments", status: "RUNNING", attempt: 1, duration_seconds: 14, error: null },
      { stage: "COLLECT", scope: "Data", status: "FAILED", attempt: 2, duration_seconds: 9, error: "Reader role missing on Data." },
      { stage: "ANALYZE", scope: null, status: "PENDING", attempt: 1, duration_seconds: null, error: null },
    ],
    ...overrides,
  };
}

let posted: unknown[] = [];

function stubApi({
  scans = [] as unknown[],
  scanDetail = detail() as unknown,
  postStatus = 202,
} = {}) {
  posted = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = new URL(String(input), "https://api.test").pathname;
      const reply = (status: number, data: unknown, error: unknown = null) =>
        ({
          ok: status < 400,
          status,
          json: async () => ({ data, error, meta: {} }),
        }) as Response;

      if (path.endsWith("/cloud-connections")) return reply(200, [connection]);
      if (path.endsWith("/detail")) return reply(200, scanDetail);
      if (path.endsWith("/api/v1/scans") && init?.method === "POST") {
        posted.push(JSON.parse(String(init.body)));
        return postStatus === 409
          ? reply(409, null, { code: "CONFLICT", message: "A scan is already running for this connection" })
          : reply(202, detail({ status: "QUEUED", stages: [] }));
      }
      if (path.endsWith("/api/v1/scans")) return reply(200, scans);
      return reply(200, []);
    }),
  );
}

function Opener({ scanId }: { scanId?: string }) {
  const wizard = useScanWizard();
  return (
    <button type="button" onClick={() => (scanId ? wizard.watch(scanId) : wizard.start())}>
      open wizard
    </button>
  );
}

function mount(scanId?: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <ScanWizardProvider>
          <Opener scanId={scanId} />
        </ScanWizardProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  fireEvent.click(screen.getByRole("button", { name: "open wizard" }));
}

describe("the scan wizard", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("walks from an environment to a live scan of it", async () => {
    stubApi();
    mount();

    expect(await screen.findByText("Production tenant")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));

    // Review says what will be read before anything is.
    expect(await screen.findByText("Payments")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Start scan/ }));

    // Scoped through one of the connection's own subscriptions; the worker
    // resolves the rest.
    await waitFor(() => expect(posted).toEqual([{ cloud_account_id: "acct-1" }]));

    // The lanes are the API's steps, failure text included.
    expect(await screen.findByText("Reader role missing on Data.")).toBeInTheDocument();
    expect(screen.getByText(/0 of 2 scopes read/)).toBeInTheDocument();
    expect(screen.getByText("attempt 2")).toBeInTheDocument();
  });

  it("ends a partial scan amber, never as complete", async () => {
    stubApi({
      scanDetail: detail({
        status: "PARTIAL",
        resource_count: 40,
        rule_count: 120,
        finding_count: 6,
        collection_errors: { Data: "Reader role missing on Data." },
        stages: [
          { stage: "PLAN", scope: null, status: "SUCCEEDED", attempt: 1, duration_seconds: 2, error: null },
          { stage: "COLLECT", scope: "Payments", status: "SUCCEEDED", attempt: 1, duration_seconds: 30, error: null },
          { stage: "COLLECT", scope: "Data", status: "FAILED", attempt: 1, duration_seconds: 9, error: "Denied." },
          { stage: "ANALYZE", scope: null, status: "SUCCEEDED", attempt: 1, duration_seconds: 12, error: null },
        ],
      }),
    });
    mount("scan-1");

    expect(await screen.findByText("Completed with gaps")).toBeInTheDocument();
    expect(screen.queryByText("Scan complete")).not.toBeInTheDocument();
  });

  it("follows the scan already running rather than reporting the conflict", async () => {
    stubApi({
      postStatus: 409,
      scans: [detail()],
    });
    mount();

    await screen.findByText("Production tenant");
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    fireEvent.click(await screen.findByRole("button", { name: /Start scan/ }));

    expect(await screen.findByText("Reader role missing on Data.")).toBeInTheDocument();
    expect(screen.queryByText("Could not start the scan")).not.toBeInTheDocument();
  });

  it("shows where a running analysis is, from the phase the step reported", async () => {
    stubApi({
      scanDetail: detail({
        status: "EVALUATING",
        resource_count: 40,
        stages: [
          { stage: "PLAN", scope: null, status: "SUCCEEDED", attempt: 1, duration_seconds: 2, error: null },
          { stage: "COLLECT", scope: "Payments", status: "SUCCEEDED", attempt: 1, duration_seconds: 30, error: null },
          { stage: "ANALYZE", scope: null, status: "RUNNING", attempt: 1, duration_seconds: 5, error: null, phase: "EVALUATE" },
        ],
      }),
    });
    mount("scan-1");

    const current = await screen.findByText("Evaluate rules");
    expect(current.closest("li")).toHaveAttribute("aria-current", "step");
    expect(screen.getByText("Normalize").closest("li")).not.toHaveAttribute("aria-current");
    // Committed when normalizing persisted them; findings are not counted live.
    expect(await screen.findByText("Resources")).toBeInTheDocument();
    expect(screen.queryByText("Rules run")).not.toBeInTheDocument();
  });
});
