import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { FindingsPage } from "@/pages/Findings";
import { containingText } from "@/test/text";

/** 120 findings, so a single default page cannot be the whole set. */
const TOTAL = 120;

function finding(index: number) {
  return {
    id: `00000000-0000-0000-0000-${String(index).padStart(12, "0")}`,
    rule_id: `AZ-RULE-${index}`,
    severity: index === 0 ? "CRITICAL" : "LOW",
    status: "OPEN",
    title: `Finding number ${index}`,
    description: "",
    evidence: {},
    remediation: "",
    rule_version: "1.0",
    risk_score: 50,
    first_detected_at: "2026-01-01T00:00:00Z",
    last_detected_at: "2026-01-01T00:00:00Z",
    resolved_at: null,
    resolved_by_scan_id: null,
    resource: null,
  };
}

let requested: string[] = [];
let gaps: unknown[] = [];

/**
 * The list request, not the page's other one.
 *
 * The findings page also asks for the checks that reached no verdict, which is
 * a second request to a different path -- so "the last URL" stopped meaning
 * "the list I filtered".
 */
const lastListRequest = () =>
  requested.filter((url) => !url.includes("/unevaluated")).at(-1) ?? "";

function renderPage(entry = "/findings") {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[entry]}>
        <FindingsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("the findings list", () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    requested = [];
    gaps = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        requested.push(url);

        if (url.includes("/unevaluated")) {
          return {
            ok: true,
            status: 200,
            json: async () => ({ data: gaps, error: null, meta: {} }),
          } as Response;
        }

        const params = new URL(url, "https://example.test").searchParams;
        const limit = Number(params.get("limit") ?? 100);
        const offset = Number(params.get("offset") ?? 0);
        const page = Array.from({ length: Math.min(limit, TOTAL - offset) }, (_, i) =>
          finding(offset + i),
        );
        return {
          ok: true,
          status: 200,
          json: async () => ({ data: page, error: null, meta: { total: TOTAL } }),
        } as Response;
      }),
    );
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("reports the true total, not the size of the page it was given", async () => {
    renderPage();

    // The bug this replaces: a hundred rows rendered as though they were all
    // of them, with nothing on screen saying otherwise.
    expect(await screen.findByText(containingText(/of 120 findings/))).toBeInTheDocument();
  });

  it("asks the database for the ordering rather than sorting a page", async () => {
    renderPage();
    await screen.findByText(containingText(/of 120 findings/));

    expect(requested[0]).toContain("sort=risk");
    expect(requested[0]).toContain(`limit=50`);
  });

  it("sends a search to the API instead of filtering what it holds", async () => {
    renderPage();
    await screen.findByText(containingText(/of 120 findings/));

    fireEvent.change(screen.getByLabelText("Search findings"), {
      target: { value: "payroll" },
    });
    await vi.advanceTimersByTimeAsync(300);

    // Filtering in the browser would search 50 of 120 findings and report
    // "no findings match" for the other 70.
    await waitFor(() =>
      expect(requested.some((url) => url.includes("search=payroll"))).toBe(true),
    );
  });

  it("debounces, so typing a word is one request and not six", async () => {
    renderPage();
    await screen.findByText(containingText(/of 120 findings/));
    const before = requested.length;

    for (const value of ["p", "pa", "pay", "payr", "payro", "payroll"]) {
      fireEvent.change(screen.getByLabelText("Search findings"), { target: { value } });
    }
    await vi.advanceTimersByTimeAsync(300);
    await waitFor(() =>
      expect(requested.some((url) => url.includes("search=payroll"))).toBe(true),
    );

    expect(requested.length - before).toBe(1);
  });

  it("turns the page by offset, not by slicing in the browser", async () => {
    renderPage();
    await screen.findByText(containingText(/of 120 findings/));

    fireEvent.click(screen.getByRole("button", { name: "Next" }));

    await waitFor(() => expect(requested.some((url) => url.includes("offset=50"))).toBe(true));
    expect(await screen.findByText(containingText(/51–100 of 120 findings/))).toBeInTheDocument();
  });

  it("returns to the first page when a filter changes the set", async () => {
    renderPage();
    await screen.findByText(containingText(/of 120 findings/));
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await screen.findByText(containingText(/51–100 of 120 findings/));

    fireEvent.change(screen.getByLabelText("Search findings"), {
      target: { value: "storage" },
    });
    await vi.advanceTimersByTimeAsync(300);

    // Page two of the old result describes nothing in the new one.
    await waitFor(() =>
      expect(
        requested.some((url) => url.includes("search=storage") && url.includes("offset=0")),
      ).toBe(true),
    );
  });

  it("orders from the column header, and asks the database to do it", async () => {
    // Sorting used to live in a dropdown beside the filters, which left the
    // table's own headers inert: clicking "Risk score" did nothing.
    renderPage();
    await screen.findByText(containingText(/of 120 findings/));

    fireEvent.click(screen.getByRole("button", { name: "Sort by severity" }));

    await waitFor(() =>
      expect(
        requested.some((url) => url.includes("sort=severity") && url.includes("offset=0")),
      ).toBe(true),
    );
  });

  /**
   * Arriving from a reading on the scans page.
   *
   * Two halves, and both are load-bearing. The scope has to reach the request,
   * or the page shows every finding under a chip claiming otherwise. And the
   * status default has to give way, because a reading whose findings have since
   * been fixed would otherwise answer "what rested on this" with an empty table
   * -- the citation would be true and the screen would say nothing rested on it.
   */
  /**
   * The checks that reached no verdict.
   *
   * A findings page that lists only failures answers "everything wrong" while
   * looking like it answered "every check", and the omission always reads in
   * the flattering direction: nine checks that could not run look exactly like
   * nine that passed.
   */
  it("lists a check that reached no verdict, in the same table", async () => {
    gaps = [
      {
        rule_id: "AZ-IDN-004",
        title: "Conditional access policies",
        reason: "Directory read was refused, so no verdict was reached",
        resource: null,
      },
    ];
    renderPage();

    expect(await screen.findByText("Conditional access policies")).toBeInTheDocument();
    expect(screen.getByText("No verdict")).toBeInTheDocument();
    // Never a status of its own, and never a pass.
    expect(screen.getByText("Unevaluated")).toBeInTheDocument();
  });

  it("states the count of no-verdict checks once, above the table", async () => {
    gaps = [
      {
        rule_id: "AZ-IDN-004",
        title: "Conditional access policies",
        reason: "Directory read was refused",
        resource: null,
      },
      {
        rule_id: "AZ-IDN-005",
        title: "Security defaults",
        reason: "Directory read was refused",
        resource: null,
      },
    ];
    renderPage();

    expect(
      await screen.findByText(
        containingText(/2 checks reached no verdict/),
      ),
    ).toBeInTheDocument();
  });

  it("keeps no-verdict rows out of a filtered table, and says so anyway", async () => {
    // A reader who asked for CRITICAL findings did not ask for the checks that
    // reached none — but the count above the table is a fact about the scan
    // and holds whatever the table is showing.
    gaps = [
      {
        rule_id: "AZ-IDN-004",
        title: "Conditional access policies",
        reason: "Directory read was refused",
        resource: null,
      },
    ];
    renderPage("/findings?status=all");
    await screen.findByText(containingText(/of 120 findings/));

    fireEvent.click(screen.getByLabelText("Filter by severity"));
    fireEvent.click(await screen.findByRole("option", { name: "Critical" }));

    await waitFor(() =>
      expect(
        screen.queryByText("Conditional access policies"),
      ).not.toBeInTheDocument(),
    );
    expect(
      screen.getByText(containingText(/1 checks reached no verdict/)),
    ).toBeInTheDocument();
  });

  it("scopes to one reading and stops defaulting to open findings", async () => {
    renderPage("/findings?evidence_id=ev-1&status=all");

    await waitFor(() => expect(requested.length).toBeGreaterThan(0));
    const url = lastListRequest();
    expect(url).toContain("evidence_id=ev-1");
    expect(url).not.toContain("status=OPEN");
    expect(await screen.findByText("Resting on one reading")).toBeInTheDocument();
  });

  it("still defaults to open findings when nothing in the URL says otherwise", async () => {
    renderPage();

    await waitFor(() => expect(requested.length).toBeGreaterThan(0));
    expect(lastListRequest()).toContain("status=OPEN");
  });
});
