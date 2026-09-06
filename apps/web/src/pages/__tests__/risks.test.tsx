/**
 * The risks list, holding two kinds of thing.
 *
 * A scenario is not a louder finding. It is several of them seen as one route,
 * scored from a different formula — floored at its worst member and amplified
 * for being short — so rendering it with the six weighted components of a
 * finding risk would invite the reader to check numbers that were never used.
 *
 * Both kinds share one list on purpose: a route outranking the findings inside
 * it is only visible where they are ranked together.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { RisksPage } from "../Risks";
import { api } from "@/lib/api";
import type { Risk } from "@/lib/types";
import { containingText } from "@/test/text";

function findingRisk(overrides: Partial<Risk> = {}): Risk {
  return {
    id: "r-finding",
    kind: "FINDING",
    path: [],
    title: "Public blob access on customerdata",
    description: "The storage account allows anonymous blob reads.",
    risk_score: 84,
    risk_level: "CRITICAL",
    status: "OPEN",
    asset_criticality: "HIGH",
    data_sensitivity: "HIGH",
    internet_exposure: "HIGH",
    exploitability: 4,
    business_impact: 4.5,
    score_breakdown: { components: {}, total: 84 },
    ...overrides,
  } as Risk;
}

function scenarioRisk(overrides: Partial<Risk> = {}): Risk {
  return {
    id: "r-scenario",
    kind: "ATTACK_PATH",
    path: [
      {
        source: "jump-01",
        source_id: "vm",
        relationship: "has_identity",
        target: "mi-jump-01",
        target_id: "mi",
        description: "jump-01 runs as mi-jump-01",
      },
      {
        source: "mi-jump-01",
        source_id: "mi",
        relationship: "grants_role",
        target: "sub-1",
        target_id: "sub",
        description: "mi-jump-01 can act over sub-1",
      },
    ],
    title: "jump-01 can reach customerdata",
    description: "Reachable from the internet in 2 steps.",
    risk_score: 96,
    risk_level: "CRITICAL",
    status: "OPEN",
    asset_criticality: "UNKNOWN",
    data_sensitivity: "HIGH",
    internet_exposure: "CRITICAL",
    exploitability: 0,
    business_impact: 4,
    score_breakdown: {
      worst_member: 84,
      amplifier: 12,
      hops: 2,
      uncapped: 96,
      total: 96,
    },
    ...overrides,
  } as Risk;
}

function mount(risks: Risk[]) {
  vi.spyOn(api, "get").mockResolvedValue({ data: risks, meta: {} });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <RisksPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("the ranking, as a table", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("ranks both kinds in one list", async () => {
    // A route outranking the findings inside it is only visible where they are
    // ranked together; on a page of its own it is a second opinion nobody
    // compares.
    mount([scenarioRisk(), findingRisk()]);

    await waitFor(() =>
      expect(screen.getByText("jump-01 can reach customerdata")).toBeInTheDocument(),
    );
    expect(screen.getByText("Public blob access on customerdata")).toBeInTheDocument();
  });

  it("opens each ranked risk, whichever kind it is", async () => {
    // The ranking is an assertion until the findings behind a row can be read.
    mount([scenarioRisk(), findingRisk()]);

    await waitFor(() =>
      expect(
        screen.getByRole("link", { name: "jump-01 can reach customerdata" }),
      ).toHaveAttribute("href", "/risks/r-scenario"),
    );
    expect(
      screen.getByRole("link", { name: "Public blob access on customerdata" }),
    ).toHaveAttribute("href", "/risks/r-finding");
  });

  /**
   * The three identical rows this redesign exists for.
   *
   * Three identities failing one check is one mistake with one fix. Ranked as
   * three rows it reads as three problems, and the reader who fixes the first
   * one comes back to a list that looks unchanged.
   */
  it("collapses rows failing the same check into one, and names the count", async () => {
    mount([
      findingRisk({ id: "a", title: "Role assignment permits every action — id-a" }),
      findingRisk({ id: "b", title: "Role assignment permits every action — id-b" }),
      findingRisk({ id: "c", title: "Role assignment permits every action — id-c" }),
    ]);

    await waitFor(() => expect(screen.getByText("×3")).toBeInTheDocument());
    // The parent stands for all three, so the other two are not rows yet.
    expect(screen.queryByText("id-b")).not.toBeInTheDocument();
  });

  it("expands a group to the assets it stands for", async () => {
    mount([
      findingRisk({ id: "a", title: "Role assignment permits every action — id-a" }),
      findingRisk({ id: "b", title: "Role assignment permits every action — id-b" }),
    ]);

    await waitFor(() => expect(screen.getByText("×2")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: "Expand duplicates" }));

    // The asset is what differs between them, so the asset is what a child row
    // is labelled with.
    expect(await screen.findByText("id-b")).toBeInTheDocument();
  });

  it("never groups two routes, however alike they read", async () => {
    // Two routes with one name still start and end somewhere different, and
    // collapsing them would claim one problem where there are two.
    mount([
      scenarioRisk({ id: "s-1" }),
      scenarioRisk({ id: "s-2" }),
    ]);

    await waitFor(() =>
      expect(
        screen.getAllByText("jump-01 can reach customerdata"),
      ).toHaveLength(2),
    );
    expect(screen.queryByText("×2")).not.toBeInTheDocument();
  });

  it("stops grouping when the reader turns it off", async () => {
    mount([
      findingRisk({ id: "a", title: "Role assignment permits every action — id-a" }),
      findingRisk({ id: "b", title: "Role assignment permits every action — id-b" }),
    ]);

    await waitFor(() => expect(screen.getByText("×2")).toBeInTheDocument());
    fireEvent.click(screen.getByRole("button", { name: /Group duplicates/ }));

    // Ungrouped, each row is itself again — full title, asset and all.
    expect(
      await screen.findByText("Role assignment permits every action — id-b"),
    ).toBeInTheDocument();
    expect(screen.queryByText("×2")).not.toBeInTheDocument();
  });

  /**
   * What makes this worse than the same misconfiguration somewhere quiet.
   *
   * A blank cell would read as an all-clear. An asset nobody classified is not
   * an asset holding nothing.
   */
  it("says an exposure it does not know rather than leaving the cell empty", async () => {
    mount([
      findingRisk({
        internet_exposure: "UNKNOWN",
        data_sensitivity: "UNKNOWN",
        asset_criticality: "UNKNOWN",
      }),
    ]);

    expect(await screen.findByText("exposure unknown")).toBeInTheDocument();
  });

  it("names the exposure that raised a score", async () => {
    mount([findingRisk()]);

    expect(await screen.findByText("internet-facing")).toBeInTheDocument();
    expect(screen.getByText("sensitive data")).toBeInTheDocument();
  });
});

/**
 * The second half of this page: how much of the ranking it actually shows.
 *
 * Separate from the fixtures above because these tests are about the request,
 * not the card -- they stub `fetch` so the URL the page builds is the thing
 * under test.
 */
const TOTAL = 80;

function pagedRisk(index: number) {
  return {
    id: `00000000-0000-0000-0000-${String(index).padStart(12, "0")}`,
    kind: "FINDING",
    path: [],
    title: `Risk number ${index}`,
    description: "",
    risk_score: 90 - index,
    risk_level: "HIGH",
    status: "OPEN",
    asset_criticality: "HIGH",
    data_sensitivity: "HIGH",
    internet_exposure: "HIGH",
    exploitability: 4,
    business_impact: 4,
    score_breakdown: {},
  };
}

let requested: string[] = [];

function renderPagedPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <RisksPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("the risk ranking", () => {
  beforeEach(() => {
    // The fixtures above spy on `api.get`; left in place it would answer these
    // requests before they ever reached the URL under test.
    vi.restoreAllMocks();
    vi.useFakeTimers({ shouldAdvanceTime: true });
    requested = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        requested.push(url);
        const params = new URL(url, "https://example.test").searchParams;
        const limit = Number(params.get("limit") ?? 100);
        const offset = Number(params.get("offset") ?? 0);
        const page = Array.from({ length: Math.min(limit, TOTAL - offset) }, (_, i) =>
          pagedRisk(offset + i),
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

  it("says how many risks there are, not how many fitted on the page", async () => {
    renderPagedPage();

    // A page whose claim is "these are your worst problems in order" showing
    // the first hundred of four hundred is the wrong answer, not a display bug.
    expect(await screen.findByText(containingText(/of 80 risks/))).toBeInTheDocument();
  });

  it("pages rather than rendering everything the API returned", async () => {
    renderPagedPage();
    await screen.findByText(containingText(/of 80 risks/));

    fireEvent.click(screen.getByRole("button", { name: "Next" }));

    await waitFor(() => expect(requested.some((u) => u.includes("offset=25"))).toBe(true));
  });

  it("filters at the database, so a filter narrows the estate", async () => {
    renderPagedPage();
    await screen.findByText(containingText(/of 80 risks/));

    fireEvent.change(screen.getByLabelText("Search risks"), { target: { value: "payroll" } });
    await vi.advanceTimersByTimeAsync(300);

    await waitFor(() =>
      expect(requested.some((u) => u.includes("search=payroll"))).toBe(true),
    );
  });

  it("offers UNKNOWN as a level, because the engine really assigns it", async () => {
    renderPagedPage();
    await screen.findByText(containingText(/of 80 risks/));

    fireEvent.click(screen.getByLabelText("Filter by risk level"));

    // Leaving it out would hide the risks CloudGuard could not score, which
    // are the ones most worth looking at.
    expect(await screen.findByRole("option", { name: "Unknown" })).toBeInTheDocument();
  });

  it("keeps findings and routes in one ranking by default", async () => {
    renderPagedPage();
    await screen.findByText(containingText(/of 80 risks/));

    // A route outranking the findings inside it is only visible where they are
    // ranked together.
    expect(requested[0]).not.toContain("kind=");
  });

});
