/**
 * Starting a scan, and following it.
 *
 * The wizard's promises are the ones worth pinning: it starts a scan through
 * the connection's own subscription, it shows what the API reports and nothing
 * it does not, it ends a partial scan amber rather than green, a refusal
 * because a scan is already running lands the reader on that scan instead of on
 * an error they can do nothing about, the scan it is open on is in the URL, and
 * a scan is not stopped by one stray click.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";
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

const second = {
  ...connection,
  id: "conn-2",
  name: "Staging tenant",
  subscriptions: [
    { id: "acct-3", subscription_id: "s-3", display_name: "Sandbox", in_scope: true, status: "ACTIVE", discovered_at: null, last_scan_at: null, is_scannable: true },
  ],
};

let posted: unknown[] = [];
let cancelled: string[] = [];

function stubApi({
  connections = [connection] as unknown[],
  scans = [] as unknown[],
  scanDetail = detail() as unknown,
  postStatus = 202,
} = {}) {
  posted = [];
  cancelled = [];
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

      if (path.endsWith("/cloud-connections")) return reply(200, connections);
      if (path.endsWith("/events")) return reply(404, null);
      if (path.endsWith("/cancel")) {
        cancelled.push(path);
        return reply(202, detail({ status: "CANCELLED" }));
      }
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

/** Where the router is, so a test can read what the wizard wrote into the URL. */
function Location() {
  const location = useLocation();
  return <output data-testid="location">{location.pathname + location.search}</output>;
}

function mount(scanId?: string, { at = "/" }: { at?: string } = {}) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[at]}>
        <ScanWizardProvider>
          <Opener scanId={scanId} />
          <Location />
        </ScanWizardProvider>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  if (at === "/") fireEvent.click(screen.getByRole("button", { name: "open wizard" }));
}

describe("the scan wizard", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("walks from an environment to a live scan of it", async () => {
    stubApi({ connections: [connection, second] });
    mount();

    expect(await screen.findByText("Staging tenant")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));

    // Review says what will be read before anything is.
    expect(await screen.findByText("Payments")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Start scan/ }));

    // Scoped through one of the connection's own subscriptions; the worker
    // resolves the rest.
    await waitFor(() => expect(posted).toEqual([{ cloud_account_id: "acct-1" }]));
    // The scan is now a link.
    await waitFor(() =>
      expect(screen.getByTestId("location")).toHaveTextContent("/?scan=scan-1"),
    );

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
    // Finishing is a step of its own, not only a body swapped in place.
    const steps = screen.getByRole("list", { name: "Scan steps" });
    expect(steps.querySelector("[aria-current=step]")?.closest("li")).toHaveTextContent("Result");
    // What the scan covered is one tab away, in the same dialog.
    expect(screen.getByRole("tab", { name: "Details" })).toBeInTheDocument();
  });

  it("skips choosing when only one environment can be scanned", async () => {
    stubApi();
    mount();

    // Straight to review; Back still reaches the list.
    expect(await screen.findByText("Payments")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Continue" })).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(await screen.findByText("Which environment?")).toBeInTheDocument();
  });

  it("opens on the scan a link names", async () => {
    stubApi();
    mount(undefined, { at: "/findings?scan=scan-1" });

    expect(await screen.findByText("Reader role missing on Data.")).toBeInTheDocument();
    // Running in the background is closing: the scan leaves the URL, the page stays.
    fireEvent.click(screen.getByRole("button", { name: "Run in background" }));
    await waitFor(() => expect(screen.getByTestId("location")).toHaveTextContent(/^\/findings$/));
  });

  it("asks once more before stopping a scan", async () => {
    stubApi();
    mount("scan-1");

    await screen.findByText("Reader role missing on Data.");
    fireEvent.click(screen.getByRole("button", { name: "Cancel scan" }));
    expect(cancelled).toEqual([]);

    fireEvent.click(screen.getByRole("button", { name: "Stop scan" }));
    await waitFor(() => expect(cancelled).toEqual(["/api/v1/scans/scan-1/cancel"]));
  });

  it("follows the scan already running rather than reporting the conflict", async () => {
    stubApi({
      postStatus: 409,
      scans: [detail()],
    });
    mount();

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
