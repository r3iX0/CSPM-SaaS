/**
 * The graph view on an asset's page.
 *
 * The layout is tested as a function because that is where the promise lives:
 * the same estate draws the same picture, whatever order the rows arrived in.
 * The card is tested for what it decides -- when it asks, what it says when
 * there is nothing to draw, and that a fold or a cap is admitted in words.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AssetNeighborhood } from "@/components/graph/AssetNeighborhood";
import { COLUMN_GAP, layoutNeighborhood } from "@/components/graph/neighborhoodLayout";
import { api } from "@/lib/api";
import type { AttackPath, Neighborhood, NeighborhoodNode } from "@/lib/types";

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

function mount(neighborhood: Neighborhood, meta: Record<string, unknown> = {}) {
  const get = vi.spyOn(api, "get").mockResolvedValue({
    data: neighborhood,
    meta: { depth: 2, truncated: false, max_nodes: 150, fan_out: 12, ...meta },
  } as never);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <AssetNeighborhood providerResourceId="/subscriptions/s/vm" name="jump-01" />
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
      expect.stringContaining("/attack-paths/neighborhood/%2Fsubscriptions%2Fs%2Fvm?depth=2"),
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

    expect(await screen.findByText(/nothing reaches jump-01/i)).toBeInTheDocument();
  });

  it("draws the assets, each one a link to its own page", async () => {
    mount(AROUND_VM);

    await userEvent.click(screen.getByRole("button", { name: /draw the graph/i }));

    // Found by text rather than role: React Flow keeps a node hidden until it
    // has measured it, and jsdom measures nothing.
    const identity = (await screen.findByText("mi")).closest("a");
    expect(identity).toHaveAttribute("href", "/assets/row-mi");
    // The focus is where the reader already is, so it is not a link.
    expect(screen.getByText("vm").closest("a")).toBeNull();
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
    },
    {
      source: "mi",
      source_id: "mi",
      relationship: "grants_role",
      target: "sub",
      target_id: "sub",
      description: "mi can act over sub",
    },
    {
      source: "sub",
      source_id: "sub",
      relationship: "contains",
      target: "data",
      target_id: "data",
      description: "sub contains data",
    },
  ],
  cheapest_break: {
    description: "vm runs as mi",
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

    expect(await screen.findByText(/no attack path passes through jump-01/i)).toBeInTheDocument();
  });

  it("traces a route: the whole line, and the link to cut", async () => {
    mount({ ...AROUND_VM, routes: [ROUTE] }, { routes_total: 1 });

    await userEvent.click(screen.getByRole("button", { name: /draw the graph/i }));
    const pick = await screen.findByRole("button", { name: /vm → data/ });
    expect(pick).toHaveAttribute("aria-pressed", "false");

    await userEvent.click(pick);

    expect(pick).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText("mi can act over sub")).toBeInTheDocument();
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
});
