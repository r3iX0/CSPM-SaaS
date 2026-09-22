/**
 * The graph view on an asset's page.
 *
 * The layout is tested as a function because that is where the promise lives:
 * the same estate draws the same picture, whatever order the rows arrived in.
 * The card is tested for what it decides -- when it asks, what it says when
 * there is nothing to draw, and that a fold or a cap is admitted in words.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { toast } from "sonner";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AssetNeighborhood } from "@/components/graph/AssetNeighborhood";
import { OpenInGraph } from "@/components/graph/OpenInGraph";
import {
  COLUMN_GAP,
  layoutNeighborhood,
  stepFrom,
} from "@/components/graph/neighborhoodLayout";
import { api } from "@/lib/api";
import type { AttackPath, Neighborhood, NeighborhoodNode, WhatIf } from "@/lib/types";

function vertex(id: string, layer: number, type = "virtual_machine"): NeighborhoodNode {
  return {
    id,
    asset_id: `row-${id}`,
    name: id,
    resource_type: type,
    provider: "azure",
    layer,
    public_exposure: "LOW",
    data_sensitivity: "LOW",
    entry: false,
    sensitive: false,
    findings: { open: 0, worst: null },
  };
}

const edge = (source: string, target: string, relationship = "contains") => ({
  source,
  target,
  relationship,
  label: relationship === "has_identity" ? "runs as" : relationship,
});

const AROUND_VM: Neighborhood = {
  focus: "vm",
  nodes: [
    vertex("vm", 0),
    vertex("mi", 1, "service_principal"),
    vertex("sub", 2, "subscription"),
    vertex("rg", -1, "resource_group"),
  ],
  groups: [],
  edges: [
    edge("rg", "vm"),
    edge("vm", "mi", "has_identity"),
    edge("mi", "sub", "grants_role"),
  ],
  routes: [],
};

describe("the neighbourhood layout", () => {
  it("puts the focus at the origin, what reaches it left and what it reaches right", () => {
    const at = layoutNeighborhood(AROUND_VM);

    expect(at.get("vm")).toEqual({ x: 0, y: 0 });
    expect(at.get("rg")!.x).toBe(-COLUMN_GAP);
    expect(at.get("mi")!.x).toBe(COLUMN_GAP);
    expect(at.get("sub")!.x).toBe(2 * COLUMN_GAP);
  });

  it("draws the same picture whatever order the rows arrived in", () => {
    const expected = layoutNeighborhood(AROUND_VM);
    const reversed: Neighborhood = {
      ...AROUND_VM,
      nodes: [...AROUND_VM.nodes].reverse(),
      edges: [...AROUND_VM.edges].reverse(),
    };

    expect(layoutNeighborhood(reversed)).toEqual(expected);
  });

  it("keeps children beside their parents rather than in name order", () => {
    // "a-child" sorts first by name but belongs to z-parent, which sits
    // second: alphabetical order would cross the two edges.
    const at = layoutNeighborhood({
      focus: "f",
      nodes: [
        vertex("f", 0),
        vertex("a-parent", 1),
        vertex("z-parent", 1),
        vertex("a-child", 2),
        vertex("z-child", 2),
      ],
      groups: [],
      routes: [],
      edges: [
        edge("f", "a-parent"),
        edge("f", "z-parent"),
        edge("z-parent", "a-child"),
        edge("a-parent", "z-child"),
      ],
    });

    expect(at.get("a-parent")!.y).toBeLessThan(at.get("z-parent")!.y);
    expect(at.get("z-child")!.y).toBeLessThan(at.get("a-child")!.y);
  });

  it("moves across to the nearest box in the next column, and back", () => {
    const at = layoutNeighborhood(AROUND_VM);

    expect(stepFrom(at, "vm", "right")).toBe("mi");
    expect(stepFrom(at, "mi", "right")).toBe("sub");
    expect(stepFrom(at, "vm", "left")).toBe("rg");
    expect(stepFrom(at, "rg", "right")).toBe("vm");
    expect(stepFrom(at, "rg", "left")).toBeNull();
  });

  it("moves up and down only within a column", () => {
    const at = layoutNeighborhood({
      focus: "f",
      nodes: [vertex("f", 0), vertex("a", 1), vertex("b", 1)],
      groups: [],
      routes: [],
      edges: [edge("f", "a"), edge("f", "b")],
    });

    expect(stepFrom(at, "a", "down")).toBe("b");
    expect(stepFrom(at, "b", "up")).toBe("a");
    expect(stepFrom(at, "f", "down")).toBeNull();
  });

  it("centres each column on the focus", () => {
    const at = layoutNeighborhood({
      focus: "f",
      nodes: [vertex("f", 0), vertex("a", 1), vertex("b", 1), vertex("c", 1)],
      groups: [],
      routes: [],
      edges: [edge("f", "a"), edge("f", "b"), edge("f", "c")],
    });

    const heights = ["a", "b", "c"].map((id) => at.get(id)!.y);
    expect(heights.reduce((sum, y) => sum + y, 0)).toBe(0);
  });
});

/** A drawn box, by the id the canvas keys it on. */
function box(id: string): HTMLElement {
  const found = document.querySelector<HTMLElement>(`[data-graph-node="${id}"]`);
  if (!found) throw new Error(`no box for ${id}`);
  return found;
}

const WHAT_IF: WhatIf = {
  description: "vm runs as mi",
  relationship: "has_identity",
  source_id: "vm",
  target_id: "mi",
  closes: [
    {
      entry: { id: "vm", name: "vm" },
      target: { id: "data", name: "data", data_sensitivity: "HIGH" },
      hops: 3,
    },
  ],
  before: 4,
  after: 3,
};

function Where() {
  const location = useLocation();
  return <output data-testid="where">{location.search}</output>;
}

function mount(
  neighborhood: Neighborhood | ((url: string) => Neighborhood),
  meta: Record<string, unknown> = {},
  at = "/assets/row-vm",
  whatIf: (url: string) => WhatIf = () => WHAT_IF,
) {
  const get = vi.spyOn(api, "get").mockImplementation((url: string) =>
    Promise.resolve(
      url.includes("/what-if")
        ? { data: whatIf(url), meta: {} }
        : {
            data: typeof neighborhood === "function" ? neighborhood(url) : neighborhood,
            meta: { depth: 2, truncated: false, max_nodes: 150, fan_out: 12, ...meta },
          },
    ) as never,
  );
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[at]}>
        <AssetNeighborhood providerResourceId="vm" name="vm" />
        <Where />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return get;
}

describe("the neighbourhood card", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("asks for nothing until somebody wants the graph", async () => {
    const get = mount(AROUND_VM);

    expect(get).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: /draw the graph/i }));
    expect(get).toHaveBeenCalledWith(
      expect.stringContaining("/attack-paths/neighborhood/vm?depth=2"),
    );
  });

  it("asks again at the depth somebody chooses", async () => {
    const get = mount(AROUND_VM);

    await userEvent.click(screen.getByRole("button", { name: /draw the graph/i }));
    await userEvent.click(screen.getByRole("button", { name: "3" }));

    expect(get).toHaveBeenLastCalledWith(expect.stringContaining("depth=3"));
    expect(screen.getByRole("button", { name: "3" })).toHaveAttribute("aria-pressed", "true");
  });

  it("says so when there is nothing around the asset, rather than drawing one box", async () => {
    mount({ focus: "vm", nodes: [vertex("vm", 0)], groups: [], edges: [], routes: [] });

    await userEvent.click(screen.getByRole("button", { name: /draw the graph/i }));

    expect(await screen.findByText(/nothing reaches vm/i)).toBeInTheDocument();
  });

  it("selects a box on a press, and centres on it only on a double click", async () => {
    const get = mount(AROUND_VM);

    await userEvent.click(screen.getByRole("button", { name: /draw the graph/i }));
    // Found by text rather than role: React Flow keeps a node hidden until it
    // has measured it, and jsdom measures nothing.
    // fireEvent rather than userEvent for the same reason: a hidden node
    // refuses pointer events.
    await screen.findByText("mi");
    fireEvent.click(box("mi"));

    // Selected, and the panel says what it is; the graph has not moved.
    expect(box("mi")).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByTestId("where")).toBeEmptyDOMElement();
    const panel = screen.getByRole("complementary", { name: "About the graph" });
    expect(panel).toHaveTextContent("mi");
    expect(panel).toHaveTextContent("No attack path here runs through it.");
    // What is not beside it fades.
    expect(box("rg").className).toContain("opacity-30");
    expect(box("vm").className).not.toContain("opacity-30");

    fireEvent.doubleClick(box("mi"));
    expect(screen.getByTestId("where")).toHaveTextContent("?around=mi");
    await waitFor(() =>
      expect(get).toHaveBeenLastCalledWith(expect.stringContaining("/neighborhood/mi?")),
    );
  });

  it("centres on a box from the panel, and on Enter", async () => {
    mount(AROUND_VM);

    await userEvent.click(screen.getByRole("button", { name: /draw the graph/i }));
    await screen.findByText("sub");
    fireEvent.click(box("sub"));
    await userEvent.click(screen.getByRole("button", { name: /centre the graph here/i }));
    expect(screen.getByTestId("where")).toHaveTextContent("?around=sub");

    fireEvent.keyDown(await waitFor(() => box("rg")), { key: "Enter" });
    expect(screen.getByTestId("where")).toHaveTextContent("?around=rg");
  });

  it("fades around a box under the pointer without selecting it", async () => {
    mount(AROUND_VM);

    await userEvent.click(screen.getByRole("button", { name: /draw the graph/i }));
    await screen.findByText("mi");
    fireEvent.pointerEnter(box("sub"));

    expect(box("mi").className).not.toContain("opacity-30");
    expect(box("rg").className).toContain("opacity-30");
    expect(box("sub")).toHaveAttribute("aria-pressed", "false");

    fireEvent.pointerLeave(box("sub"));
    expect(box("rg").className).not.toContain("opacity-30");
  });

  it("opens drawn when the URL is already centred elsewhere, with a way back", async () => {
    mount({ ...AROUND_VM, focus: "mi" }, {}, "/assets/row-vm?around=mi");

    // No "draw" press needed: a link to a re-centred view is a request for it.
    await waitFor(() =>
      expect(screen.getByText(/centred on/i)).toHaveTextContent("Centred on mi"),
    );
    expect(screen.getByRole("link", { name: /open its page/i })).toHaveAttribute(
      "href",
      "/assets/row-mi",
    );

    await userEvent.click(screen.getByRole("button", { name: /back to vm/i }));
    expect(screen.getByTestId("where")).toBeEmptyDOMElement();
  });

  it("opens drawn when the link centres it on the page's own asset", async () => {
    // How the estate map's asset boxes link here: the reader was looking at a
    // graph, so the page they land on shows one without a second press.
    const get = mount(AROUND_VM, {}, "/assets/row-vm?around=vm");

    await waitFor(() =>
      expect(get).toHaveBeenCalledWith(expect.stringContaining("/neighborhood/vm?depth=2")),
    );
    expect(screen.queryByRole("button", { name: /draw the graph/i })).not.toBeInTheDocument();
    expect(screen.queryByText(/centred on/i)).not.toBeInTheDocument();
  });

  it("offers a re-centred centre's page, and none for the page's own asset", async () => {
    mount({ ...AROUND_VM, focus: "mi" }, {}, "/assets/row-vm?around=mi");

    fireEvent.click(await waitFor(() => box("mi")));
    const panel = screen.getByRole("complementary", { name: "About the graph" });
    expect(panel.querySelector('a[href="/assets/row-mi"]')).not.toBeNull();
    // Already the centre: nothing to centre on.
    expect(screen.queryByRole("button", { name: /centre the graph here/i })).toBeNull();

    // The page's own asset, drawn off-centre, is a box to centre on again.
    fireEvent.click(box("vm"));
    expect(screen.getByRole("button", { name: /centre the graph here/i })).toBeInTheDocument();
    expect(panel.querySelector('a[href="/assets/row-vm"]')).toBeNull();
  });

  it("gives the canvas one tab stop and moves it with the arrow keys", async () => {
    mount(AROUND_VM);

    await userEvent.click(screen.getByRole("button", { name: /draw the graph/i }));
    await screen.findByText("mi");
    const stops = () =>
      [...document.querySelectorAll<HTMLElement>("[data-graph-node]")].filter(
        (box) => box.tabIndex === 0,
      );
    expect(stops().map((box) => box.dataset.graphNode)).toEqual(["vm"]);

    fireEvent.keyDown(stops()[0], { key: "ArrowRight" });

    expect(stops().map((box) => box.dataset.graphNode)).toEqual(["mi"]);
    expect(document.activeElement).toBe(stops()[0]);
  });

  it("draws a fold's members when it is opened", async () => {
    const get = mount({
      ...AROUND_VM,
      groups: [
        {
          id: "group:3:contains:sub",
          parent: "sub",
          relationship: "contains",
          layer: 3,
          count: 40,
          by_type: { resource_group: 40 },
        },
      ],
    });

    await userEvent.click(screen.getByRole("button", { name: /draw the graph/i }));
    await screen.findByText(/40 more/);
    fireEvent.click(box("group:3:contains:sub"));
    expect(screen.getByRole("complementary", { name: "About the graph" })).toHaveTextContent(
      "40 more, counted rather than drawn",
    );
    await userEvent.click(screen.getByRole("button", { name: /show them/i }));

    await waitFor(() =>
      expect(get).toHaveBeenLastCalledWith(
        expect.stringContaining(`expand=${encodeURIComponent("group:3:contains:sub")}`),
      ),
    );
  });

  it("admits a fold and a cap in words", async () => {
    mount(
      {
        ...AROUND_VM,
        groups: [
          {
            id: "group:3:contains:sub",
            parent: "sub",
            relationship: "contains",
            layer: 3,
            count: 40,
            by_type: { resource_group: 40 },
          },
        ],
      },
      { truncated: true },
    );

    await userEvent.click(screen.getByRole("button", { name: /draw the graph/i }));

    expect(await screen.findByText(/dashed boxes are counted, not drawn/i)).toBeInTheDocument();
    expect(screen.getByText(/the graph stops at 150 assets/i)).toBeInTheDocument();
  });

  it("marks a way in, sensitive data and open findings in words as well as shapes", async () => {
    mount({
      ...AROUND_VM,
      nodes: [
        { ...vertex("vm", 0), public_exposure: "CRITICAL", entry: true },
        {
          ...vertex("mi", 1, "service_principal"),
          public_exposure: "UNKNOWN",
          findings: { open: 3, worst: "HIGH" },
        },
        { ...vertex("sub", 2, "subscription"), data_sensitivity: "HIGH", sensitive: true },
        vertex("rg", -1, "resource_group"),
      ],
    });

    await userEvent.click(screen.getByRole("button", { name: /draw the graph/i }));

    // Exact strings: the legend under the canvas uses the same words.
    expect(await screen.findAllByText(", reachable from the internet")).toHaveLength(1);
    expect(screen.getByText(", holds sensitive data")).toBeInTheDocument();
    expect(screen.getByText("open findings")).toBeInTheDocument();
    // Unknown exposure is its own answer, not a way in and not silence.
    expect(screen.getByText(", internet exposure unknown")).toBeInTheDocument();
  });
});

const ROUTE: AttackPath = {
  entry: { id: "vm", name: "vm", resource_type: "virtual_machine", public_exposure: "CRITICAL" },
  target: { id: "data", name: "data", resource_type: "storage_account", data_sensitivity: "HIGH" },
  hops: 3,
  steps: [
    {
      source: "vm",
      source_id: "vm",
      relationship: "has_identity",
      target: "mi",
      target_id: "mi",
      description: "vm runs as mi",
      facts: ["managed identity"],
      detail: "vm runs as mi (managed identity)",
    },
    {
      source: "mi",
      source_id: "mi",
      relationship: "grants_role",
      target: "sub",
      target_id: "sub",
      description: "mi can act over sub",
      facts: ["Contributor"],
      detail: "mi can act over sub (Contributor)",
    },
    {
      source: "sub",
      source_id: "sub",
      relationship: "contains",
      target: "data",
      target_id: "data",
      description: "sub contains data",
      facts: [],
      detail: "sub contains data",
    },
  ],
  cheapest_break: {
    description: "vm runs as mi",
    detail: "vm runs as mi (managed identity)",
    relationship: "has_identity",
    source_id: "vm",
    target_id: "mi",
  },
};

describe("the routes through an asset", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("says plainly when no attack path passes through", async () => {
    mount(AROUND_VM);

    await userEvent.click(screen.getByRole("button", { name: /draw the graph/i }));

    expect(await screen.findByText(/no attack path passes through vm/i)).toBeInTheDocument();
  });

  it("traces a route: the whole line, and the link to cut", async () => {
    mount({ ...AROUND_VM, routes: [ROUTE] }, { routes_total: 1 });

    await userEvent.click(screen.getByRole("button", { name: /draw the graph/i }));
    const pick = await screen.findByRole("button", { name: /vm → data/ });
    expect(pick).toHaveAttribute("aria-pressed", "false");

    await userEvent.click(pick);

    expect(pick).toHaveAttribute("aria-pressed", "true");
    // Once in the line, once as a link to try cutting.
    expect(screen.getAllByText("mi can act over sub")).toHaveLength(2);
    expect(screen.getByText("Cutting this link severs the route")).toBeInTheDocument();
  });

  it("admits when part of the traced route is off the canvas", async () => {
    // The last hop, sub → data, is three hops out and was not drawn.
    mount({ ...AROUND_VM, routes: [ROUTE] }, { routes_total: 1 });

    await userEvent.click(screen.getByRole("button", { name: /draw the graph/i }));
    await userEvent.click(await screen.findByRole("button", { name: /vm → data/ }));

    expect(screen.getByText(/the canvas shows only some of it/i)).toBeInTheDocument();
  });

  it("untraces on a second press", async () => {
    mount({ ...AROUND_VM, routes: [ROUTE] }, { routes_total: 1 });

    await userEvent.click(screen.getByRole("button", { name: /draw the graph/i }));
    const pick = await screen.findByRole("button", { name: /vm → data/ });
    await userEvent.click(pick);
    await userEvent.click(pick);

    expect(pick).toHaveAttribute("aria-pressed", "false");
    expect(screen.queryByText("Cutting this link severs the route")).not.toBeInTheDocument();
  });

  it("says how many it is not showing", async () => {
    mount({ ...AROUND_VM, routes: [ROUTE] }, { routes_total: 31 });

    await userEvent.click(screen.getByRole("button", { name: /draw the graph/i }));

    expect(await screen.findByText(/showing the 1 shortest of 31/i)).toBeInTheDocument();
  });

  it("says what cutting the route's cheapest break would close, across the organization", async () => {
    const get = mount({ ...AROUND_VM, routes: [ROUTE] }, { routes_total: 1 });

    await userEvent.click(screen.getByRole("button", { name: /draw the graph/i }));
    await userEvent.click(await screen.findByRole("button", { name: /vm → data/ }));

    expect(await screen.findByText(/attack paths in the organization/)).toHaveTextContent(
      "Closes 1 of 4 attack paths in the organization, leaving 3.",
    );
    expect(get).toHaveBeenCalledWith(
      expect.stringContaining("/what-if?source=vm&relationship=has_identity&target=mi"),
    );
    expect(screen.getByRole("button", { name: "vm runs as mi" })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
  });

  it("tries another link when picked, and says plainly when there is a way round", async () => {
    const get = mount({ ...AROUND_VM, routes: [ROUTE] }, { routes_total: 1 }, undefined, (url) =>
      url.includes("grants_role")
        ? {
            ...WHAT_IF,
            description: "mi can act over sub",
            relationship: "grants_role",
            source_id: "mi",
            target_id: "sub",
            closes: [],
            after: 4,
          }
        : WHAT_IF,
    );

    await userEvent.click(screen.getByRole("button", { name: /draw the graph/i }));
    await userEvent.click(await screen.findByRole("button", { name: /vm → data/ }));
    await userEvent.click(screen.getByRole("button", { name: "mi can act over sub" }));

    expect(await screen.findByText(/closes nothing/i)).toHaveTextContent(
      "Every route through this link has another way round",
    );
    expect(get).toHaveBeenLastCalledWith(expect.stringContaining("relationship=grants_role"));
    // Containment is where things live: never offered as a cut.
    expect(screen.queryByRole("button", { name: "sub contains data" })).not.toBeInTheDocument();
  });

  it("arrives with a route traced when sent from the attack paths page", async () => {
    mount(
      { ...AROUND_VM, routes: [ROUTE] },
      { routes_total: 1 },
      `/assets/row-vm?trace=${encodeURIComponent("vm|data")}`,
    );

    // No "draw" press, and the route already picked.
    expect(await screen.findByRole("button", { name: /vm → data/ })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
  });
});

describe("exploring a route in the graph", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  function mountButton() {
    render(
      <MemoryRouter initialEntries={["/attack-paths"]}>
        <Routes>
          <Route path="/attack-paths" element={<OpenInGraph entryId="/vm/jump" traceKey="a|b" />} />
          <Route path="/assets/:assetId" element={<Where />} />
        </Routes>
      </MemoryRouter>,
    );
  }

  it("opens the entry point's page with the route to trace", async () => {
    const get = vi
      .spyOn(api, "get")
      .mockResolvedValue({ data: { id: "row-7" }, meta: {} } as never);
    mountButton();

    await userEvent.click(screen.getByRole("button", { name: /explore in graph/i }));

    expect(get).toHaveBeenCalledWith(
      `/api/v1/assets/resolve?provider_resource_id=${encodeURIComponent("/vm/jump")}`,
    );
    expect(await screen.findByTestId("where")).toHaveTextContent(
      `?trace=${encodeURIComponent("a|b")}`,
    );
  });

  it("says so when the asset is no longer in the graph, and stays put", async () => {
    vi.spyOn(api, "get").mockRejectedValue(new Error("404"));
    const error = vi.spyOn(toast, "error").mockImplementation(() => "id");
    mountButton();

    await userEvent.click(screen.getByRole("button", { name: /explore in graph/i }));

    await waitFor(() => expect(error).toHaveBeenCalled());
    expect(screen.getByRole("button", { name: /explore in graph/i })).toBeEnabled();
  });
});
