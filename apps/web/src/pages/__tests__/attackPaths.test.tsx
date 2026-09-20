/**
 * The attack paths page.
 *
 * Three things are worth testing here and none of them is that a list renders.
 *
 * The first is that an empty answer says *which* nothing it found. "No attack
 * paths" reads as reassurance, and in two of the three cases it is the
 * opposite: nothing classified as sensitive means CloudGuard does not know what
 * would cost the customer anything, which is a gap in what it was told rather
 * than a clean environment.
 *
 * The second is that the route is shown rather than just its endpoints, with
 * the evidence on each hop. Naming the links — and the role behind one — is the
 * whole difference between an alarm and something somebody can go and cut.
 *
 * The third is that what a cut would close is never overstated: a link sitting
 * on more routes than it closes has to say so.
 *
 * The canvas itself is not mounted here. React Flow measures a viewport jsdom
 * does not have, and what it draws is `routeMapLayout`'s answer, which is
 * tested directly.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { MemoryRouter } from "react-router-dom";

import { AttackPathsPage } from "../AttackPaths";
import { api } from "@/lib/api";
import type { MappedRoute, Risk, RouteMap, RouteMapMeta } from "@/lib/types";

const ROUTE: MappedRoute = {
  key: "vm|storage",
  pattern: null,
  entry: {
    id: "vm",
    name: "jump-01",
    resource_type: "virtual_machine",
    public_exposure: "CRITICAL",
  },
  target: {
    id: "storage",
    name: "customerdata",
    resource_type: "storage_account",
    data_sensitivity: "HIGH",
  },
  hops: 4,
  steps: [
    {
      source: "jump-01",
      source_id: "vm",
      relationship: "has_identity",
      target: "mi-jump-01",
      target_id: "mi",
      description: "jump-01 runs as mi-jump-01",
      facts: ["managed identity"],
      detail: "jump-01 runs as mi-jump-01 (managed identity)",
    },
    {
      source: "mi-jump-01",
      source_id: "mi",
      relationship: "grants_role",
      target: "sub-1",
      target_id: "sub",
      description: "mi-jump-01 can act over sub-1",
      facts: ["Contributor"],
      detail: "mi-jump-01 can act over sub-1 (Contributor)",
    },
    {
      source: "sub-1",
      source_id: "sub",
      relationship: "contains",
      target: "prod",
      target_id: "rg",
      description: "sub-1 contains prod",
      facts: [],
      detail: "sub-1 contains prod",
    },
    {
      source: "prod",
      source_id: "rg",
      relationship: "contains",
      target: "customerdata",
      target_id: "storage",
      description: "prod contains customerdata",
      facts: [],
      detail: "prod contains customerdata",
    },
  ],
  cheapest_break: {
    description: "jump-01 runs as mi-jump-01",
    detail: "jump-01 runs as mi-jump-01 (managed identity)",
    relationship: "has_identity",
    source_id: "vm",
    target_id: "mi",
  },
};

const node = (id: string, name: string, column: number) => ({
  id,
  asset_id: null,
  name,
  resource_type: "virtual_machine",
  provider: "AZURE",
  column,
  public_exposure: "LOW" as const,
  data_sensitivity: "LOW" as const,
  entry: column === 0,
  sensitive: false,
  routes: 1,
  findings: { open: 0, worst: null },
});

function emptyMap(): RouteMap {
  return { nodes: [], edges: [], routes: [], patterns: [], loose: [], choke_points: [] };
}

/** One route, and the link that severs it, as the graph endpoint sends them. */
function oneRoute(): RouteMap {
  return {
    ...emptyMap(),
    nodes: [node("vm", "jump-01", 0), node("mi", "mi-jump-01", 1)],
    edges: [
      {
        source: "vm",
        relationship: "has_identity",
        target: "mi",
        label: "runs as",
        facts: ["managed identity"],
        detail: "jump-01 runs as mi-jump-01 (managed identity)",
        severs: 1,
        closes: ["vm|storage"],
        on_routes: 1,
        alternate: false,
      },
    ],
    routes: [ROUTE],
    loose: ["vm|storage"],
  };
}

const CHOKE = {
  description: "mi-jump-01 can act over sub-1",
  detail: "mi-jump-01 can act over sub-1 (Contributor)",
  facts: ["Contributor"],
  relationship: "grants_role",
  source: { id: "mi", name: "mi-jump-01", resource_type: "service_principal" },
  target: { id: "sub", name: "sub-1", resource_type: "subscription" },
  total_routes: 4,
};

function mount(
  map: RouteMap,
  meta: Partial<RouteMapMeta> & { total: number },
  risks: Partial<Risk>[] = [],
) {
  vi.spyOn(api, "get").mockImplementation((url: string) =>
    Promise.resolve(
      url.includes("/risks")
        ? { data: risks, meta: {} }
        : { data: map, meta: { drawn: map.routes.length, ...meta } },
    ) as never,
  );
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <AttackPathsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("AttackPathsPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("links a route to the risk that tracks it", async () => {
    // Matched by its ends, which name a route on both pages (DECISIONS.md §103).
    mount(oneRoute(), { total: 1, entry_points: 1, sensitive_targets: 1 }, [
      {
        id: "r-route",
        kind: "ATTACK_PATH",
        path: [
          { ...ROUTE.steps[0], source_id: ROUTE.entry.id },
          { ...ROUTE.steps[3], target_id: ROUTE.target.id },
        ],
      },
    ]);

    await userEvent.click(await screen.findByText(/jump-01/));

    expect(
      await screen.findByRole("link", { name: "Tracked as a risk" }),
    ).toHaveAttribute("href", "/risks/r-route");
  });

  it("says when a route is reach rather than a risk", async () => {
    mount(oneRoute(), { total: 1, entry_points: 1, sensitive_targets: 1 });

    await userEvent.click(await screen.findByText(/jump-01/));

    expect(
      await screen.findByText("Not a risk: nothing on this route fails a check"),
    ).toBeInTheDocument();
  });

  it("shows the route hop by hop once one is opened", async () => {
    mount(oneRoute(), { total: 1, entry_points: 1, sensitive_targets: 1 });

    // Nothing but the summary until a route is chosen: the rail ranks, and the
    // hops are what one route says.
    await waitFor(() => expect(screen.getByText(/jump-01/)).toBeInTheDocument());
    expect(screen.queryByText("mi-jump-01 can act over sub-1")).not.toBeInTheDocument();

    await userEvent.click(screen.getByText(/jump-01/));

    await waitFor(() =>
      expect(screen.getAllByText("jump-01 runs as mi-jump-01").length).toBeGreaterThan(0),
    );
    expect(screen.getByText("mi-jump-01 can act over sub-1")).toBeInTheDocument();
    expect(screen.getByText("sub-1 contains prod")).toBeInTheDocument();
    expect(screen.getByText("prod contains customerdata")).toBeInTheDocument();
  });

  it("distinguishes a clean environment from an unscanned one", async () => {
    mount(emptyMap(), { total: 0, entry_points: 0, sensitive_targets: 0 });

    await waitFor(() =>
      expect(screen.getByText("No scan has run yet")).toBeInTheDocument(),
    );
  });

  it("does not call an unclassified environment safe", async () => {
    // The case that matters most. CloudGuard found exposed assets and nothing
    // it could call sensitive, so it does not know what would cost the customer
    // anything — and saying "no attack paths" here would be reassurance it has
    // not earned.
    mount(emptyMap(), { total: 0, entry_points: 3, sensitive_targets: 0 });

    await waitFor(() =>
      expect(
        screen.getByText("Nothing has been classified as sensitive"),
      ).toBeInTheDocument(),
    );
  });

  it("says plainly when nothing is exposed", async () => {
    mount(emptyMap(), { total: 0, entry_points: 0, sensitive_targets: 4 });

    await waitFor(() =>
      expect(
        screen.getByText("Nothing is reachable from the internet"),
      ).toBeInTheDocument(),
    );
  });

  it("reports a genuinely clean result as clean", async () => {
    // Exposed assets exist, sensitive assets exist, and no route joins them.
    // This is the one case where an empty answer is good news.
    mount(emptyMap(), { total: 0, entry_points: 2, sensitive_targets: 3 });

    await waitFor(() =>
      expect(
        screen.getByText("Nothing exposed can reach anything sensitive"),
      ).toBeInTheDocument(),
    );
  });

  it("says where each way in stops, and which assets the counts are", async () => {
    // A tenant whose only sensitive assets are its administrators meets the
    // "nothing reaches anything sensitive" condition with no machine in it.
    // The page has to say that, and say why each open machine leads nowhere.
    mount(emptyMap(), {
      total: 0,
      entry_points: 3,
      sensitive_targets: 1,
      entry_point_types: { virtual_machine: 2, user: 1 },
      sensitive_target_types: { user: 1 },
      dead_ends: [
        {
          id: "/vm/web",
          asset_id: "a-1",
          name: "vm-web",
          resource_type: "virtual_machine",
          public_exposure: "HIGH",
          reason: "reaches_nothing",
          reached: 0,
        },
        {
          id: "/vm/api",
          asset_id: null,
          name: "vm-api",
          resource_type: "virtual_machine",
          public_exposure: "HIGH",
          reason: "identity_without_role",
          reached: 1,
        },
      ],
      dead_ends_total: 3,
    });

    await waitFor(() =>
      expect(screen.getByText("Where each way in stops")).toBeInTheDocument(),
    );
    expect(screen.getByRole("link", { name: "vm-web" })).toHaveAttribute(
      "href",
      "/assets/a-1",
    );
    expect(
      screen.getByText(
        "Runs as no identity, and no other machine on its network lets it in.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "Runs as an identity that holds no role over anything CloudGuard scanned.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/The only assets classified as sensitive are accounts/),
    ).toBeInTheDocument();
    expect(screen.getByText("and 1 more")).toBeInTheDocument();
  });

  it("leads with the change that closes the most routes, and names the role", async () => {
    // The rail ranks routes, which is the right order for reading them and the
    // wrong one for acting: fifty routes are fifty things to read, and one role
    // assignment holding them up is one thing to do. "can act over" names
    // nothing anybody can change; "Contributor" does.
    mount(
      {
        ...oneRoute(),
        choke_points: [
          {
            ...CHOKE,
            severs: 4,
            on_routes: 4,
            closes: [
              {
                entry: "jump-01",
                target: "customerdata",
                hops: 4,
                data_sensitivity: "HIGH",
              },
            ],
          },
        ],
      },
      { total: 4, entry_points: 2, sensitive_targets: 2 },
    );

    const panel = (await screen.findByText("The changes that close the most")).closest(
      "[data-slot='card']",
    ) as HTMLElement;

    expect(
      within(panel).getByText("mi-jump-01 can act over sub-1 (Contributor)"),
    ).toBeInTheDocument();
    expect(within(panel).getByText("4")).toBeInTheDocument();
    expect(within(panel).getByText(/of 4 routes close/)).toBeInTheDocument();
    // Named, not just counted: the count is a claim and these are its working.
    expect(within(panel).getByText("jump-01 → customerdata")).toBeInTheDocument();
  });

  it("says when a link sits on more routes than it closes", async () => {
    // A customer told four routes close who then sees two remain stops
    // believing the next number too.
    mount(
      {
        ...oneRoute(),
        choke_points: [
          {
            ...CHOKE,
            severs: 2,
            on_routes: 4,
            closes: [
              {
                entry: "web-02",
                target: "customerdata",
                hops: 3,
                data_sensitivity: "HIGH",
              },
            ],
          },
        ],
      },
      { total: 4, entry_points: 2, sensitive_targets: 2 },
    );

    await waitFor(() =>
      expect(screen.getByText(/another way round/)).toBeInTheDocument(),
    );
  });

  it("collapses routes that are the same route said many times", async () => {
    // Twelve machines reaching one storage account the same way is one
    // sentence, and the list printed it twelve times.
    mount(
      {
        ...oneRoute(),
        routes: [{ ...ROUTE, pattern: "pattern-1" }],
        loose: [],
        patterns: [
          {
            id: "pattern-1",
            kind: "many_entries",
            description: "3 virtual machines reach customerdata the same way",
            size: 3,
            hops: 4,
            exemplar: "vm|storage",
            routes: ["vm|storage"],
            varies: [{ id: "vm", name: "jump-01", route: "vm|storage" }],
          },
        ],
      },
      { total: 3, entry_points: 3, sensitive_targets: 1 },
    );

    const group = await screen.findByText(
      "3 virtual machines reach customerdata the same way",
    );
    // Scoped to the rail: the same asset is a box on the canvas beside it, and
    // the claim here is about the list.
    const rail = group.closest("[data-slot='card']") as HTMLElement;
    // Members stay behind the group until it is opened: the reader decides
    // about the shape, not about each repetition of it.
    expect(within(rail).queryByText("jump-01")).not.toBeInTheDocument();

    await userEvent.click(group);
    expect(await within(rail).findByText("jump-01")).toBeInTheDocument();
  });

  it("says nothing about cutting when there is nothing to cut", async () => {
    mount(emptyMap(), { total: 0, entry_points: 3, sensitive_targets: 0 });

    await waitFor(() =>
      expect(
        screen.getByText("Nothing has been classified as sensitive"),
      ).toBeInTheDocument(),
    );
    expect(screen.queryByText("The changes that close the most")).not.toBeInTheDocument();
  });
});
