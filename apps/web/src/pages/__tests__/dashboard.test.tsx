/**
 * The dashboard's two exits.
 *
 * The page is one argument read top to bottom, and it ends with the reader
 * deciding what to do about what they just read. There are two answers — read
 * the environment again, or write this down — and the header has to offer both.
 * Reports existed for a while with nothing anywhere pointing at them.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { DashboardPage } from "../Dashboard";
import { api } from "@/lib/api";
import type { CloudAccount, Dashboard } from "@/lib/types";

function dashboard(overrides: Partial<Dashboard> = {}): Dashboard {
  return {
    security_score: 84,
    score_delta: 7,
    history: [],
    findings_by_severity: { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4 },
    findings_by_status: { OPEN: 10 },
    risk_bands: {},
    open_finding_count: 10,
    asset_count: 42,
    verified_resolved_last_30_days: 3,
    remediation_rate: 0.3,
    top_risks: [],
    coverage: { ratio: 0.9, unknown: 1, conclusive: 19, context: { unclassified: 0, classified: 0, ratio: 1 } },
    evidence_freshness: null,
    last_scan: {
      id: "s-1",
      status: "COMPLETED",
      completed_at: "2026-08-31T09:00:00Z",
      resource_count: 42,
      rule_count: 30,
      finding_count: 10,
      collection_errors: {},
    },
    ...overrides,
  } as Dashboard;
}

function mount(data: Dashboard, accounts: CloudAccount[] = []) {
  vi.spyOn(api, "get").mockImplementation((path: string) => {
    if (path.includes("cloud-accounts")) {
      return Promise.resolve({ data: accounts, meta: {} }) as never;
    }
    // The panels the page asks for after its own payload. Answered as the
    // lists they really are, so a test about the dashboard is not quietly
    // testing what happens when an endpoint returns the wrong shape.
    // The exposure map is a graph, not a list: answered as one, so a test
    // about the dashboard is not quietly testing a malformed payload.
    if (path.includes("exposure-map")) {
      return Promise.resolve({
        data: { nodes: [], edges: [] },
        meta: { entry_points: 0, nodes: 0, omitted: 0 },
      }) as never;
    }
    if (
      path.includes("attack-paths") ||
      path.includes("changes") ||
      path.includes("scans")
    ) {
      return Promise.resolve({ data: [], meta: {} }) as never;
    }
    return Promise.resolve({ data, meta: {} }) as never;
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("DashboardPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("points at the reports, which is the other thing to do with a posture", async () => {
    mount(dashboard());

    await waitFor(() =>
      expect(screen.getByRole("link", { name: /Reports/ })).toHaveAttribute(
        "href",
        "/reports",
      ),
    );
  });

  it("still offers a rescan, which is the primary action", async () => {
    mount(dashboard());

    await waitFor(() =>
      expect(screen.getByRole("link", { name: /Scan now/ })).toHaveAttribute(
        "href",
        "/scans",
      ),
    );
  });

  it("offers neither before there is a posture to read or report on", async () => {
    // Nothing has been scanned: the only sensible action is the first scan,
    // and a report over no evidence would be a document about nothing.
    mount(dashboard({ last_scan: null }));

    await waitFor(() =>
      expect(screen.getByText("Connect your cloud environment")).toBeInTheDocument(),
    );
    expect(screen.queryByRole("link", { name: /Reports/ })).not.toBeInTheDocument();
  });

  it("sends a ranked risk to that risk, not back to the unfiltered list", async () => {
    // Every top risk used to link to /risks, so clicking the thing the page had
    // just ranked first made the reader find it again in a table.
    mount(
      dashboard({
        top_risks: [
          {
            id: "risk-1",
            title: "Production database reachable from the internet",
            risk_score: 94,
            risk_level: "CRITICAL",
          },
        ],
      }),
    );

    await waitFor(() =>
      expect(
        screen.getByRole("link", { name: /Production database reachable/ }),
      ).toHaveAttribute("href", "/risks/risk-1"),
    );
  });

  it("says what the score was not charged for, above the ranking", async () => {
    // A reader who acts on a ranked list without knowing part of the estate
    // was unreadable is acting on a ranking of the readable part — so the
    // caveat sits above the list rather than under it.
    mount(
      dashboard({
        coverage: {
          ratio: 0.68,
          unknown: 9,
          conclusive: 19,
          context: { unclassified: 11, classified: 0, ratio: 0 },
        },
        last_scan: {
          id: "s-1",
          status: "PARTIAL",
          completed_at: "2026-08-31T09:00:00Z",
          resource_count: 42,
          rule_count: 30,
          finding_count: 10,
          collection_errors: { identity: "users: Directory.Read.All was refused" },
        },
      }),
    );

    expect(
      await screen.findByText("The score is charged for 68% of your estate"),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Grant admin consent" }),
    ).toHaveAttribute("href", "/connections");
  });

  it("counts what could not be answered, never as a pass", async () => {
    // UNKNOWN is not a fifth severity and is not a pass. The tile says how
    // many checks concluded out of how many ran, so a reader tallying what is
    // wrong sees what could not be answered in the same glance.
    mount(
      dashboard({
        coverage: {
          ratio: 0.5,
          unknown: 7,
          conclusive: 7,
          context: { unclassified: 0, classified: 0, ratio: 1 },
        },
      }),
    );

    const assessed = await screen.findByRole("link", { name: /Assessed/ });
    expect(assessed).toHaveAttribute("href", "/scans");
    expect(assessed).toHaveTextContent("7 of 14 checks");
  });

  it("says why a risk outranks the one beneath it", async () => {
    mount(
      dashboard({
        top_risks: [
          {
            id: "risk-1",
            title: "Production database reachable from the internet",
            risk_score: 94,
            risk_level: "CRITICAL",
            kind: "FINDING",
            internet_exposure: "CRITICAL",
            data_sensitivity: "HIGH",
            asset_criticality: "LOW",
          },
        ],
      }),
    );

    expect(await screen.findByText("Internet-facing")).toBeInTheDocument();
    expect(screen.getByText("Sensitive data")).toBeInTheDocument();
    // LOW criticality is not a reason this ranked where it did, so it is not
    // given a line saying nothing.
    expect(screen.queryByText("Business-critical")).not.toBeInTheDocument();
  });

  it("never scores an environment it has not read", async () => {
    mount(dashboard({ last_scan: null }));

    expect(
      await screen.findByText("Connect your cloud environment"),
    ).toBeInTheDocument();
    expect(screen.queryByRole("meter", { name: "Security score" })).not.toBeInTheDocument();
    expect(screen.queryByText("84")).not.toBeInTheDocument();
  });
});
