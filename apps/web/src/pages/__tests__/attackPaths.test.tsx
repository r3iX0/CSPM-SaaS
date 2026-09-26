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
import {
  fireEvent,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, onTestFinished, vi } from "vitest";

import { MemoryRouter, useLocation } from "react-router-dom";

import { AttackPathsPage } from "../AttackPaths";
import { api } from "@/lib/api";
import type { MappedRoute, Risk, RouteMap, RouteMapMeta, Simulation } from "@/lib/types";

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
  scope_id: "sub-1",
  scope_name: "Production",
  group: "prod",
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

function Where() {
  const location = useLocation();
  return <output data-testid="where">{location.search}</output>;
}

/** The drawn link from jump-01 to its identity, as a plan names it. */
const RUNS_AS = { source: "vm", relationship: "has_identity", target: "mi" };

function closingAll(overrides: Partial<Simulation> = {}): Simulation {
  return {
    before: 1,
    after: 0,
    closed: [
      {
        key: "vm|storage",
        entry: "jump-01",
        target: "customerdata",
        hops: 4,
        data_sensitivity: "HIGH",
      },
    ],
    together: [],
    remaining: [],
    cuts: [
      {
        ...RUNS_AS,
        description: "jump-01 runs as mi-jump-01",
        detail: "jump-01 runs as mi-jump-01 (managed identity)",
        alone: 1,
        needed_for: 1,
      },
    ],
    missing: [],
    next: [],
    ...overrides,
  };
}

/** Answers every simulation with this, and records the plans asked about. */
function simulateWith(result: Simulation) {
  return vi
    .spyOn(api, "post")
    .mockImplementation(() => Promise.resolve({ data: result, meta: {} }) as never);
}

function mount(
  map: RouteMap,
  meta: Partial<RouteMapMeta> & { total: number },
  risks: Partial<Risk>[] = [],
  at = "/attack-paths",
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
      <MemoryRouter initialEntries={[at]}>
        <AttackPathsPage />
        <Where />
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

    // Every hop is a row to read; the one being read says what it is in full.
    const hops = await screen.findByRole("list", { name: "Hops" });
    expect(
      within(hops).getByRole("button", {
        name: "Hop 1 of 4: jump-01 runs as mi-jump-01 (managed identity)",
      }),
    ).toHaveAttribute("aria-current", "step");
    expect(within(hops).getByText("mi-jump-01 can act over sub-1")).toBeInTheDocument();
    expect(within(hops).getByText("sub-1 contains prod")).toBeInTheDocument();
    expect(within(hops).getByText("prod contains customerdata")).toBeInTheDocument();
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

  it("starts the simulation from the change that closes the most, and names the role", async () => {
    // The rail ranks routes, which is the right order for reading them and the
    // wrong one for acting: fifty routes are fifty things to read, and one role
    // assignment holding them up is one thing to do. "can act over" names
    // nothing anybody can change; "Contributor" does. These lead the simulate
    // tab rather than a card above the drawing (DECISIONS.md §141).
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

    await userEvent.click(await screen.findByRole("tab", { name: /simulate/i }));
    const panel = screen.getByRole("complementary", { name: "The routes" });

    expect(within(panel).getByText("The changes that close the most")).toBeInTheDocument();
    expect(
      within(panel).getByText("mi-jump-01 can act over sub-1 (Contributor)"),
    ).toBeInTheDocument();
    expect(within(panel).getByText("4")).toBeInTheDocument();
    expect(within(panel).getByText(/of 4$/)).toBeInTheDocument();
    // Named, not just counted: the count is a claim and these are its working.
    expect(within(panel).getByText("jump-01 → customerdata")).toBeInTheDocument();
  });

  it("names the drawing's marks, and the cut's only while a plan is tried", async () => {
    simulateWith(closingAll());
    mount(
      {
        ...oneRoute(),
        // The drawn link, so the cut can be tried on the drawing.
        choke_points: [
          {
            ...CHOKE,
            relationship: "has_identity",
            source: { id: "vm", name: "jump-01", resource_type: "virtual_machine" },
            target: { id: "mi", name: "mi-jump-01", resource_type: "service_principal" },
            severs: 1,
            on_routes: 1,
            closes: [
              { entry: "jump-01", target: "customerdata", hops: 4, data_sensitivity: "HIGH" },
            ],
          },
        ],
      },
      { total: 1, entry_points: 1, sensitive_targets: 1 },
    );

    expect(await screen.findByText("Thicker: closes more routes if cut")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "How to read the drawing" })).toBeInTheDocument();
    expect(screen.queryByText("In the simulated plan")).toBeNull();

    await userEvent.click(screen.getByRole("tab", { name: /simulate/i }));
    await userEvent.click(
      screen.getByRole("button", {
        name: "Add to the plan: mi-jump-01 can act over sub-1 (Contributor)",
      }),
    );
    expect(screen.getByText("In the simulated plan")).toBeInTheDocument();
    expect(screen.getByText("Out of reach with the plan made")).toBeInTheDocument();
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

    await userEvent.click(await screen.findByRole("tab", { name: /simulate/i }));
    expect(screen.getByText(/another way round/)).toBeInTheDocument();
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
    // Scoped to the panel: the same asset is a box on the canvas beside it, and
    // the claim here is about the list.
    const rail = screen.getByRole("complementary", { name: "The routes" });
    // Members stay behind the group until it is opened: the reader decides
    // about the shape, not about each repetition of it.
    expect(within(rail).queryByText("jump-01")).not.toBeInTheDocument();

    await userEvent.click(group);
    expect(await within(rail).findByText("jump-01")).toBeInTheDocument();
  });

  it("says what a group holds on its row, with its help a question mark away", async () => {
    // Thirty-two routes in eight groups filled the panel with a paragraph and
    // eight sentences before anything could be read (DECISIONS.md §143).
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
      [
        {
          id: "r-route",
          kind: "ATTACK_PATH",
          path: [
            { ...ROUTE.steps[0], source_id: ROUTE.entry.id },
            { ...ROUTE.steps[3], target_id: ROUTE.target.id },
          ],
        },
      ],
    );
    const rail = await screen.findByRole("complementary", { name: "The routes" });
    const row = (await within(rail).findByText(/3 virtual machines reach/)).closest("button")!;

    expect(within(rail).getByText("· 1 group")).toBeInTheDocument();
    // Only one of the three is among the routes drawn.
    expect(row).toHaveTextContent("1 of 3 here");
    await waitFor(() => expect(row).toHaveTextContent("1 tracked"));
    expect(within(rail).queryByText(/Grouped only where/)).toBeNull();

    await userEvent.click(within(rail).getByRole("button", { name: "What a group is" }));
    expect(await screen.findByText(/Grouped only where/)).toBeInTheDocument();
  });

  it("reads a traced route in the panel beside the drawing, with a way back", async () => {
    mount(oneRoute(), { total: 1, entry_points: 1, sensitive_targets: 1 });
    const panel = await screen.findByRole("complementary", { name: "The routes" });
    await userEvent.click(await within(panel).findByText(/jump-01/));

    expect(within(panel).getByText("The route")).toBeInTheDocument();
    expect(within(panel).getByText("mi-jump-01 can act over sub-1")).toBeInTheDocument();

    await userEvent.click(within(panel).getByRole("button", { name: "Show every route" }));
    expect(within(panel).queryByText("The route")).not.toBeInTheDocument();
    expect(within(panel).getByText(/jump-01/)).toBeInTheDocument();
  });

  it("walks a traced route one hop at a time in the panel, with the hop in the URL", async () => {
    mount(
      oneRoute(),
      { total: 1, entry_points: 1, sensitive_targets: 1 },
      [],
      "/attack-paths?trace=vm%7Cstorage",
    );

    // One navigator, in the panel; no step bar over the drawing (§142).
    const navigator = await screen.findByRole("group", {
      name: /attack path from jump-01 to customerdata/i,
    });
    expect(
      within(screen.getByRole("complementary", { name: "The routes" })).getByRole("group", {
        name: /attack path from/i,
      }),
    ).toBe(navigator);
    const hops = within(navigator).getByRole("list", { name: "Hops" });
    expect(
      within(hops).getByRole("button", { name: /^Hop 1 of 4/ }),
    ).toHaveAttribute("aria-current", "step");
    // The earliest place to cut is marked, and what cutting it closes is the
    // number on the line, for this route.
    expect(within(navigator).getByText("Earliest place to cut")).toBeInTheDocument();
    expect(within(navigator).getByText("Cutting it closes this route.")).toBeInTheDocument();
    expect(within(navigator).getByText("managed identity")).toBeInTheDocument();

    fireEvent.keyDown(navigator, { key: "ArrowDown" });
    expect(screen.getByTestId("where")).toHaveTextContent("hop=1");
    expect(
      within(hops).getByRole("button", { name: /^Hop 2 of 4/ }),
    ).toHaveAttribute("aria-current", "step");
    expect(
      within(hops).getByRole("button", { name: /^Hop 2 of 4/ }),
    ).toHaveTextContent("mi-jump-01 can act over sub-1 (Contributor)");

    await userEvent.click(within(hops).getByRole("button", { name: /^Hop 4 of 4/ }));
    expect(screen.getByTestId("where")).toHaveTextContent("hop=3");
    // Containment is where something lives: not offered as a cut.
    expect(within(navigator).getByText(/Containment cannot be removed/)).toBeInTheDocument();
    expect(within(navigator).queryByRole("button", { name: "Add to the plan" })).toBeNull();

    fireEvent.keyDown(navigator, { key: "Escape" });
    expect(screen.queryByRole("group", { name: /attack path from/i })).toBeNull();
    expect(screen.getByTestId("where")).not.toHaveTextContent("trace=");
  });

  it("names the link that closes the most when it is not the earliest cut", async () => {
    // The server's cut is the earliest removable link. A later one can close
    // far more of the estate, and a reader choosing between them needs both.
    const map = oneRoute();
    map.edges.push({
      source: "mi",
      relationship: "grants_role",
      target: "sub",
      label: "can act over",
      facts: ["Contributor"],
      detail: "mi-jump-01 can act over sub-1 (Contributor)",
      severs: 3,
      closes: ["vm|storage", "a|storage", "b|storage"],
      on_routes: 5,
      alternate: true,
    });
    mount(map, { total: 1, entry_points: 1, sensitive_targets: 1 }, [], "/attack-paths?trace=vm%7Cstorage&hop=1");

    const navigator = await screen.findByRole("group", { name: /attack path from/i });
    expect(
      within(navigator).getByText("Closes the most on this route: 3 routes"),
    ).toBeInTheDocument();
    expect(
      within(navigator).getByText(
        "Cutting it closes this route and 2 others. It sits on 5; the rest have another way round.",
      ),
    ).toBeInTheDocument();
  });

  it("steps between routes in the order the list shows them", async () => {
    const second: MappedRoute = {
      ...ROUTE,
      key: "web|storage",
      entry: { ...ROUTE.entry, id: "web", name: "web-02" },
      steps: [{ ...ROUTE.steps[0], source: "web-02", source_id: "web" }, ...ROUTE.steps.slice(1)],
    };
    mount(
      { ...oneRoute(), routes: [ROUTE, second], loose: [ROUTE.key, second.key] },
      { total: 2, entry_points: 2, sensitive_targets: 1 },
      [],
      "/attack-paths?trace=vm%7Cstorage&hop=2",
    );

    const panel = await screen.findByRole("complementary", { name: "The routes" });
    expect(await within(panel).findByText("Route 1 of 2")).toBeInTheDocument();
    expect(within(panel).getByRole("button", { name: "Previous route" })).toBeDisabled();

    await userEvent.click(within(panel).getByRole("button", { name: "Next route" }));
    expect(screen.getByTestId("where")).toHaveTextContent("trace=web%7Cstorage");
    // A new route is read from its first hop.
    expect(screen.getByTestId("where")).toHaveTextContent("hop=0");
    expect(within(panel).getByText("Route 2 of 2")).toBeInTheDocument();
    // Chosen here, so the focus follows it to its name.
    expect(within(panel).getByRole("heading", { name: /web-02/ })).toHaveFocus();

    fireEvent.keyDown(within(panel).getByRole("group", { name: /attack path from/i }), {
      key: "ArrowLeft",
    });
    expect(screen.getByTestId("where")).toHaveTextContent("trace=vm%7Cstorage");
  });

  it("puts a hop into the plan without leaving the route, and says what the plan does to it", async () => {
    const post = simulateWith(closingAll());
    mount(
      oneRoute(),
      { total: 1, entry_points: 1, sensitive_targets: 1 },
      [],
      "/attack-paths?trace=vm%7Cstorage",
    );

    const navigator = await screen.findByRole("group", { name: /attack path from/i });
    await userEvent.click(within(navigator).getByRole("button", { name: "Add to the plan" }));

    expect(screen.getByTestId("where")).toHaveTextContent("cut=vm%7Chas_identity%7Cmi");
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/v1/attack-paths/simulate", { cuts: [RUNS_AS] }),
    );
    // Still reading the route: the plan is a tab away, not where the reader went.
    expect(
      await within(navigator).findByText("The simulated plan closes this route"),
    ).toBeInTheDocument();
    expect(within(navigator).getByRole("button", { name: "Take out of the plan" })).toBeInTheDocument();
  });

  it("finds routes by any asset on them, and says when nothing is so named", async () => {
    mount(oneRoute(), { total: 1, entry_points: 1, sensitive_targets: 1 });
    const panel = await screen.findByRole("complementary", { name: "The routes" });
    const search = await within(panel).findByRole("searchbox", { name: "Search routes" });

    // An asset in the middle of the route, not only its ends.
    await userEvent.type(search, "sub-1");
    expect(within(panel).getByText(/jump-01/)).toBeInTheDocument();
    expect(screen.getByTestId("where")).toHaveTextContent("q=sub-1");

    await userEvent.clear(search);
    await userEvent.type(search, "nowhere");
    expect(
      within(panel).getByText("No route passes anything named \u201cnowhere\u201d."),
    ).toBeInTheDocument();
  });

  it("sorts by what a route reaches, and marks the ones a risk tracks", async () => {
    const critical: MappedRoute = {
      ...ROUTE,
      key: "web|vault",
      entry: { ...ROUTE.entry, id: "web", name: "web-02" },
      target: { ...ROUTE.target, id: "vault", name: "kv-prod", data_sensitivity: "CRITICAL" },
    };
    mount(
      { ...oneRoute(), routes: [ROUTE, critical], loose: [ROUTE.key, critical.key] },
      { total: 2, entry_points: 2, sensitive_targets: 2 },
      [
        {
          id: "r-route",
          kind: "ATTACK_PATH",
          path: [
            { ...ROUTE.steps[0], source_id: ROUTE.entry.id },
            { ...ROUTE.steps[3], target_id: ROUTE.target.id },
          ],
        },
      ],
      "/attack-paths?sort=sensitive",
    );
    const panel = await screen.findByRole("complementary", { name: "The routes" });
    await within(panel).findByText(/kv-prod/);
    const rows = within(panel)
      .getAllByRole("button")
      .filter((button) => /→/.test(button.textContent ?? ""));
    expect(rows.map((row) => row.textContent)).toEqual([
      expect.stringContaining("web-02 → kv-prod"),
      expect.stringContaining("jump-01 → customerdata"),
    ]);
    await waitFor(() => expect(rows[1]).toHaveTextContent("Tracked"));
    expect(rows[0]).not.toHaveTextContent("Tracked");
  });

  it("brings a route a link named into view on arrival, once", async () => {
    // jsdom has no layout, so no scrollIntoView to spy on; one is lent here.
    const scroll = vi.fn();
    Element.prototype.scrollIntoView = scroll;
    onTestFinished(() => {
      delete (Element.prototype as Partial<Element>).scrollIntoView;
    });
    mount(
      oneRoute(),
      { total: 1, entry_points: 1, sensitive_targets: 1 },
      [],
      "/attack-paths?trace=vm%7Cstorage",
    );

    await screen.findByRole("group", { name: /attack path from jump-01 to customerdata/i });
    await waitFor(() => expect(scroll).toHaveBeenCalledTimes(1));

    await userEvent.click(screen.getByRole("button", { name: /^Hop 2 of 4/ }));
    expect(scroll).toHaveBeenCalledTimes(1);
  });

  it("says so when a link names a route the latest reading does not have", async () => {
    mount(
      oneRoute(),
      { total: 1, entry_points: 1, sensitive_targets: 1 },
      [],
      "/attack-paths?trace=gone%7Cstorage",
    );

    expect(
      await screen.findByText(/not among the routes in the latest reading/),
    ).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Clear" }));
    expect(screen.queryByText(/not among the routes/)).not.toBeInTheDocument();
    expect(screen.getByTestId("where")).not.toHaveTextContent("trace=");
  });

  it("says where a traced route enters each place, each a link to the estate map", async () => {
    mount(
      oneRoute(),
      { total: 1, entry_points: 1, sensitive_targets: 1 },
      [],
      "/attack-paths?trace=vm%7Cstorage",
    );
    const panel = await screen.findByRole("complementary", {
      name: "The routes",
    });

    // Said once where the route arrives in a place, not at every stop in it:
    // jump-01 and its identity both sit in Production › prod.
    expect(
      await within(panel).findAllByRole("link", { name: "Production › prod" }),
    ).toHaveLength(1);
    expect(
      within(panel).getByRole("link", { name: "Production › prod" }),
    ).toHaveAttribute(
      "href",
      "/assets?view=graph&subscription_id=sub-1&resource_group=prod",
    );
  });

  it("narrows the routes to the place the estate map linked from", async () => {
    mount(
      oneRoute(),
      { total: 1, entry_points: 1, sensitive_targets: 1 },
      [],
      "/attack-paths?scope=sub-1",
    );
    const panel = await screen.findByRole("complementary", {
      name: "The routes",
    });
    expect(panel).toHaveTextContent("Through Production (1)");
    expect(within(panel).getByText(/jump-01/)).toBeInTheDocument();

    await userEvent.click(
      within(panel).getByRole("button", { name: "Show routes everywhere" }),
    );
    expect(screen.getByTestId("where")).not.toHaveTextContent("scope=");
  });

  it("says so when no route runs through the place asked for", async () => {
    mount(
      oneRoute(),
      { total: 1, entry_points: 1, sensitive_targets: 1 },
      [],
      "/attack-paths?scope=sub-1&group=elsewhere",
    );
    const panel = await screen.findByRole("complementary", {
      name: "The routes",
    });
    expect(panel).toHaveTextContent(
      "No route drawn here runs through Production › elsewhere.",
    );
  });

  it("offers the estate's choke points on an empty simulate tab", async () => {
    mount(
      { ...oneRoute(), choke_points: [{ ...CHOKE, severs: 1, on_routes: 1, closes: [] }] },
      { total: 1, entry_points: 1, sensitive_targets: 1 },
    );

    await userEvent.click(await screen.findByRole("tab", { name: /simulate/i }));
    const panel = screen.getByRole("complementary", { name: "The routes" });
    expect(within(panel).getByText("The changes that close the most")).toBeInTheDocument();
    expect(
      within(panel).getByRole("button", {
        name: "Add to the plan: mi-jump-01 can act over sub-1 (Contributor)",
      }),
    ).toBeInTheDocument();
  });

  it("asks the server about the plan as a whole and keeps it in the URL", async () => {
    // Never summed from the numbers on the lines: two links that are each
    // other's way round close nothing alone and everything together.
    const post = simulateWith(closingAll({ together: ["vm|storage"] }));
    mount(
      { ...oneRoute(), choke_points: [{ ...CHOKE, severs: 1, on_routes: 1, closes: [] }] },
      { total: 1, entry_points: 1, sensitive_targets: 1 },
    );

    await userEvent.click(await screen.findByRole("tab", { name: /simulate/i }));
    await userEvent.click(
      screen.getByRole("button", {
        name: "Add to the plan: mi-jump-01 can act over sub-1 (Contributor)",
      }),
    );

    expect(screen.getByTestId("where")).toHaveTextContent("cut=mi%7Cgrants_role%7Csub");
    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/v1/attack-paths/simulate", {
        cuts: [{ source: "mi", relationship: "grants_role", target: "sub" }],
      }),
    );
    const panel = screen.getByRole("complementary", { name: "The routes" });
    expect(await within(panel).findByText(/of 1 route closes/)).toBeInTheDocument();
    expect(panel).toHaveTextContent("only because these changes are made together");
    expect(within(panel).getByText("only together")).toBeInTheDocument();
  });

  it("opens on the simulation a link names, and marks a change the rest covers", async () => {
    simulateWith(
      closingAll({
        cuts: [
          { ...closingAll().cuts[0], alone: 1, needed_for: 1 },
          {
            source: "mi",
            relationship: "grants_role",
            target: "sub",
            description: "mi-jump-01 can act over sub-1",
            detail: "mi-jump-01 can act over sub-1 (Contributor)",
            alone: 0,
            needed_for: 0,
          },
        ],
      }),
    );
    mount(
      oneRoute(),
      { total: 1, entry_points: 1, sensitive_targets: 1 },
      [],
      "/attack-paths?cut=vm%7Chas_identity%7Cmi&cut=mi%7Cgrants_role%7Csub",
    );

    const panel = await screen.findByRole("complementary", { name: "The routes" });
    expect(await within(panel).findByText("You can leave it out.", { exact: false })).toBeInTheDocument();
    expect(within(panel).getByText(/2 of 10/)).toBeInTheDocument();
    expect(screen.getByText(/Simulating 2 changes together/)).toBeInTheDocument();

    await userEvent.click(within(panel).getByRole("button", { name: "Clear" }));
    expect(screen.getByTestId("where")).not.toHaveTextContent("cut=");
  });

  it("says a planned link the latest reading no longer has is left out", async () => {
    simulateWith(
      closingAll({
        closed: [],
        after: 1,
        remaining: [{ key: "vm|storage", hops: 4 }],
        cuts: [],
        missing: [{ source: "gone", relationship: "network_access", target: "vm" }],
      }),
    );
    mount(
      oneRoute(),
      { total: 1, entry_points: 1, sensitive_targets: 1 },
      [],
      "/attack-paths?cut=gone%7Cnetwork_access%7Cvm",
    );

    const panel = await screen.findByRole("complementary", { name: "The routes" });
    expect(
      await within(panel).findByText(/Not in the latest reading/),
    ).toBeInTheDocument();
    expect(within(panel).getByText("Still open")).toBeInTheDocument();
  });

  it("draws no card above the drawing for the changes that close the most", async () => {
    // They are the simulate tab's starting point, and a second list of the same
    // links above the drawing was one thing said twice.
    mount(
      { ...oneRoute(), choke_points: [{ ...CHOKE, severs: 1, on_routes: 1, closes: [] }] },
      { total: 1, entry_points: 1, sensitive_targets: 1 },
    );

    await screen.findByRole("tab", { name: /simulate/i });
    expect(screen.queryByText("The changes that close the most")).toBeNull();
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
