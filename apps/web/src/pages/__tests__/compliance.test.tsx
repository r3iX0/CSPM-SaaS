/**
 * The frameworks overview: coverage, never a verdict -- on each card, and
 * domain by domain.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, within } from "@testing-library/react";
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

let frameworks: object[] = [FRAMEWORK];
let detail: typeof DETAIL = DETAIL;

describe("the compliance overview", () => {
  beforeEach(() => {
    frameworks = [FRAMEWORK];
    detail = DETAIL;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        const data = url.endsWith("/compliance") ? frameworks : detail;
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
      <QueryClientProvider
        client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
      >
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

  it("draws each domain as its controls by status, never one bar that reads as a grade", async () => {
    // Teal at 100% over a section whose every control failed read as a pass
    // (DECISIONS.md §206). The row says what concluded, and what failed.
    mount();
    const coverage = await screen.findByRole("region", { name: "Coverage by domain" });
    const identity = await within(coverage).findByRole("link", { name: /^Identity/ });
    expect(identity).toHaveTextContent("2/2 with a verdict · 1 failing");
    expect(identity).toHaveAttribute("href", "/compliance/cis-azure?section=Identity");
    const logging = within(coverage).getByRole("link", { name: /^Logging/ });
    expect(logging).toHaveTextContent("0/2 with a verdict");
    expect(logging).not.toHaveTextContent("failing");
  });

  it("says a section nothing checks in words, not as an empty bar", async () => {
    detail = {
      ...DETAIL,
      controls: [...DETAIL.controls, control("9.1", "People", "NOT_COVERED")],
    };
    mount();
    const coverage = await screen.findByRole("region", { name: "Coverage by domain" });
    expect(await within(coverage).findByRole("link", { name: /^People/ })).toHaveTextContent(
      "1 control, nothing checks",
    );
  });

  it("puts the worst section first when asked, and keeps the framework's order otherwise", async () => {
    detail = {
      ...DETAIL,
      controls: [
        ...DETAIL.controls,
        control("6.1", "Networking", "FAILING"),
        control("6.2", "Networking", "FAILING"),
      ],
    };
    mount();
    const coverage = await screen.findByRole("region", { name: "Coverage by domain" });
    await within(coverage).findByRole("link", { name: /^Networking/ });
    const names = () =>
      within(coverage)
        .getAllByRole("listitem")
        .map((row) => row.textContent?.split(/\d/)[0]);
    expect(names()).toEqual(["Identity", "Logging", "Networking"]);

    fireEvent.click(within(coverage).getByRole("button", { name: "Most failing" }));
    expect(names()).toEqual(["Networking", "Identity", "Logging"]);
  });

  it("shows one framework at a time, and switches between them", async () => {
    frameworks = [FRAMEWORK, { ...FRAMEWORK, id: "gdpr", short_name: "GDPR" }];
    mount();
    const coverage = await screen.findByRole("region", { name: "Coverage by domain" });
    expect(within(coverage).getByRole("tab", { name: "CIS Azure 2.0" })).toHaveAttribute(
      "aria-selected",
      "true",
    );

    fireEvent.click(within(coverage).getByRole("tab", { name: "GDPR" }));
    expect(
      await within(coverage).findByRole("link", { name: "Every GDPR control" }),
    ).toHaveAttribute("href", "/compliance/gdpr");
  });
});
