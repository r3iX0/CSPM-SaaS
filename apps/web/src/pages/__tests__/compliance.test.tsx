/**
 * The frameworks overview: coverage, never a verdict -- on each card, and
 * domain by domain.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { CompliancePage } from "@/pages/Compliance";

const FRAMEWORK = {
  id: "cis-azure",
  name: "CIS Microsoft Azure Foundations Benchmark",
  short_name: "CIS Azure 2.0",
  version: "2.0.0",
  authority: "Center for Internet Security",
  url: "https://example.test",
  summary: "Configuration benchmarks.",
  scope_note: "",
  control_count: 4,
  status_counts: { PASSING: 1, FAILING: 1, INCONCLUSIVE: 1, NOT_ASSESSED: 0, NOT_COVERED: 1 },
  coverage_ratio: 0.5,
  open_finding_count: 2,
};

const control = (id: string, group: string, status: string) => ({
  id,
  title: id,
  group,
  technically_assessable: true,
  status,
  open_finding_count: 0,
  rules: [],
  readings: [],
});

const DETAIL = {
  ...FRAMEWORK,
  assessed: true,
  assessment: null,
  controls: [
    control("1.1", "Identity", "PASSING"),
    control("1.2", "Identity", "FAILING"),
    control("5.1", "Logging", "INCONCLUSIVE"),
    control("5.2", "Logging", "NOT_COVERED"),
  ],
};

describe("the compliance overview", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        const data = url.endsWith("/compliance") ? [FRAMEWORK] : DETAIL;
        return {
          ok: true,
          status: 200,
          json: async () => ({ data, error: null, meta: {} }),
        } as Response;
      }),
    );
  });

  afterEach(() => vi.unstubAllGlobals());

  function mount() {
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <MemoryRouter>
          <CompliancePage />
        </MemoryRouter>
      </QueryClientProvider>,
    );
  }

  it("counts each status in words, with no verdict kept apart from a pass", async () => {
    mount();
    expect(await screen.findByText("1 inconclusive")).toBeInTheDocument();
    expect(screen.getByText("1 passing")).toBeInTheDocument();
    expect(screen.getByText("1 not covered")).toBeInTheDocument();
  });

  it("heads each card with a count of verdicts, never a percentage", async () => {
    mount();
    // One pass and one fail reached a verdict, of four controls. A "50%" here
    // read as a grade (DECISIONS.md §185).
    expect(await screen.findByText("2/4")).toBeInTheDocument();
    expect(screen.getByLabelText("2 of 4 controls with a verdict")).toBeInTheDocument();
    expect(screen.queryByText("50%")).not.toBeInTheDocument();
  });

  it("measures each domain by what reached a conclusion, not by what passed", async () => {
    mount();
    const domains = await screen.findByRole("list", { name: /CIS Azure 2\.0: share of controls/ });
    // Identity: a pass and a fail both concluded. Logging: neither did.
    expect(domains).toHaveTextContent(/Identity\s*100/);
    expect(domains).toHaveTextContent(/Logging\s*0/);
  });
});
