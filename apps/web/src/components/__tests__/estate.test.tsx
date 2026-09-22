/**
 * The estate map on the assets page.
 *
 * The layout is tested as a function, because that is where its promises
 * live: reach reads left to right from where it starts, an arrow runs back
 * only where a loop leaves no other way, a long arrow passes through a slot
 * rather than over a box, a quiet box is never mistaken for part of a route,
 * and the same estate draws the same picture.
 * The view is tested for what it decides: the lens is the list's scope
 * filter, opening a box is a step Back can retrace, a lens on nothing offers
 * the way back rather than a blank frame, and attack paths are read on their
 * own page -- a box links there, and an old link to walk one is sent there.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { EstateGraph } from "@/components/assets/EstateGraph";
import { ESTATE_COLUMN_GAP, QUIET_ROWS, layoutEstate } from "@/components/graph/estateLayout";
import { boxHref, boxLabel, edgeLabel, edgeLabelShort } from "@/components/graph/estateNames";
import { api, ApiError } from "@/lib/api";
import type { EstateBox, EstateEdge, EstateMap } from "@/lib/types";

function scope(id: string, extra: Partial<EstateBox> = {}): EstateBox {
  return {
    id: `scope:${id}`,
    kind: "scope",
    inside: true,
    scope_id: id,
    scope_name: id === "directory" ? "Directory" : `Sub ${id}`,
    provider: "AZURE",
    group: null,
    name: id === "directory" ? "Directory" : `Sub ${id}`,
    assets: 3,
    entry: 0,
    sensitive: 0,
    findings: { open: 0, worst: null },
    routes: 0,
    ...extra,
  };
}

const link = (
  source: string,
  target: string,
  relationship = "grants_role",
  count = 1,
): EstateEdge => ({
  source: `scope:${source}`,
  target: `scope:${target}`,
  links: [
    {
      relationship,
      count,
      label: relationship === "has_identity" ? "runs as" : "can act over",
    },
  ],
});

const ESTATE: EstateMap = {
  lens: { scope_id: null, group: null },
  boxes: [
    scope("directory"),
    scope("prod", { sensitive: 2, routes: 1 }),
    scope("web", { entry: 1, routes: 1, findings: { open: 4, worst: "HIGH" } }),
    scope("quiet"),
  ],
  edges: [
    link("web", "directory", "has_identity", 1),
    link("directory", "prod", "grants_role", 3),
  ],
};

describe("the estate layout", () => {
  it("reads left to right from the box holding a way in", () => {
    const { at } = layoutEstate(ESTATE);

    expect(at.get("scope:web")!.x).toBe(0);
    expect(at.get("scope:directory")!.x).toBe(ESTATE_COLUMN_GAP);
    expect(at.get("scope:prod")!.x).toBe(2 * ESTATE_COLUMN_GAP);
  });

  it("puts boxes with no reach after the route rather than on it", () => {
    const { at } = layoutEstate(ESTATE);
    expect(at.get("scope:quiet")!.x).toBe(3 * ESTATE_COLUMN_GAP);
  });

  it("stacks a quiet estate into a grid rather than one tall column", () => {
    const boxes = Array.from({ length: QUIET_ROWS + 2 }, (_, i) =>
      scope(`s${i}`),
    );
    const { at } = layoutEstate({ lens: ESTATE.lens, boxes, edges: [] });
    const columns = new Set([...at.values()].map((p) => p.x));
    expect(columns.size).toBe(2);
  });

  it("draws a cycle nothing leads into rather than losing it", () => {
    const { at } = layoutEstate({
      lens: ESTATE.lens,
      boxes: [scope("a"), scope("b")],
      edges: [link("a", "b"), link("b", "a")],
    });
    expect(at.get("scope:a")!.x).toBe(0);
    expect(at.get("scope:b")!.x).toBe(ESTATE_COLUMN_GAP);
  });

  it("enters a loop at its way in, so the arrow drawn back is the one into it", () => {
    const { at } = layoutEstate({
      lens: ESTATE.lens,
      boxes: [scope("a"), scope("b", { entry: 1 })],
      edges: [link("a", "b"), link("b", "a")],
    });
    expect(at.get("scope:b")!.x).toBe(0);
    expect(at.get("scope:a")!.x).toBe(ESTATE_COLUMN_GAP);
  });

  it("puts a way in that another way in reaches after it, rather than drawing reach back", () => {
    // Both hold a way in. Stacked in the first column, as they once were, the
    // arrow between them ran back round every box.
    const { at } = layoutEstate({
      lens: ESTATE.lens,
      boxes: [scope("a", { entry: 1 }), scope("b", { entry: 1 }), scope("c")],
      edges: [link("a", "b"), link("b", "c")],
    });
    expect(at.get("scope:a")!.x).toBe(0);
    expect(at.get("scope:b")!.x).toBe(ESTATE_COLUMN_GAP);
    expect(at.get("scope:c")!.x).toBe(2 * ESTATE_COLUMN_GAP);
  });

  it("keeps a slot for an arrow that crosses more than one gap, clear of the boxes", () => {
    const { at, bends } = layoutEstate({
      lens: ESTATE.lens,
      boxes: [scope("a"), scope("b"), scope("c")],
      edges: [link("a", "b"), link("b", "c"), link("a", "c")],
    });
    expect(at.get("scope:c")!.x).toBe(2 * ESTATE_COLUMN_GAP);
    const through = bends.get("scope:a|scope:c")!;
    expect(through).toHaveLength(1);
    expect(through[0].x).toBe(ESTATE_COLUMN_GAP);
    expect(through[0].y).not.toBe(at.get("scope:b")!.y);
    // A one-gap arrow has nowhere to bend.
    expect(bends.has("scope:a|scope:b")).toBe(false);
  });

  it("orders a column to uncross the arrows into it", () => {
    // In name order y sits above z, and a -> z, b -> y would cross.
    const { at } = layoutEstate({
      lens: ESTATE.lens,
      boxes: [scope("a"), scope("b"), scope("y"), scope("z")],
      edges: [link("a", "z"), link("b", "y")],
    });
    expect(at.get("scope:a")!.y).toBeLessThan(at.get("scope:b")!.y);
    expect(at.get("scope:z")!.y).toBeLessThan(at.get("scope:y")!.y);
  });

  it("draws the same picture whatever order the rows arrived in", () => {
    const expected = layoutEstate(ESTATE);
    const reversed = {
      ...ESTATE,
      boxes: [...ESTATE.boxes].reverse(),
      edges: [...ESTATE.edges].reverse(),
    };
    expect(layoutEstate(reversed)).toEqual(expected);
  });
});

describe("what a box and a link are called", () => {
  it("names what sits directly in a subscription as that", () => {
    const direct = { ...scope("prod"), id: "group:prod:", kind: "group" as const, name: null };
    expect(boxLabel(direct).title).toBe("Directly in Sub prod");
  });

  it("counts a link only when there is more than one", () => {
    expect(edgeLabel(link("a", "b", "grants_role", 3).links)).toBe("can act over ×3");
    expect(edgeLabel(link("a", "b", "has_identity", 1).links)).toBe("runs as");
    expect(edgeLabel(link("a", "b", "contains").links)).toBeUndefined();
  });

  it("shortens several kinds of reach on one arrow to the commonest and a count", () => {
    const links = [
      { relationship: "can_grant_roles", count: 1, label: "can grant itself any role over" },
      { relationship: "grants_role", count: 3, label: "can act over" },
      { relationship: "can_take_over", count: 2, label: "can take ownership of" },
    ];
    expect(edgeLabelShort(links)).toBe("can act over ×3 +2 more");
    expect(edgeLabelShort(links.slice(1, 2))).toBe("can act over ×3");
  });

  it("sends an asset to its page with its graph drawn, and the fold to the list", () => {
    const asset: EstateBox = {
      ...scope("prod"),
      id: "asset:/subscriptions/prod/vm",
      kind: "asset",
      asset_id: "row-1",
      provider_resource_id: "/subscriptions/prod/vm",
    };
    expect(boxHref(asset)).toBe(
      `/assets/row-1?around=${encodeURIComponent("/subscriptions/prod/vm")}`,
    );
    const fold: EstateBox = { ...scope("prod"), id: "fold", kind: "fold", group: "Data" };
    expect(boxHref(fold)).toBe("/assets?subscription_id=prod&resource_group=Data");
    expect(boxHref(scope("prod"))).toBeNull();
  });
});

function Where() {
  const location = useLocation();
  return (
    <output data-testid="where">
      {location.pathname}
      {location.search}
    </output>
  );
}

/** A drawn box, by the id the canvas keys it on. */
function box(id: string): HTMLElement {
  const found = document.querySelector<HTMLElement>(`[data-graph-node="${id}"]`);
  if (!found) throw new Error(`no box for ${id}`);
  return found;
}

function mount(
  answer: (url: string) => EstateMap | Error,
  at = "/assets?view=graph",
  lens: { scopeId: string; group: string } = { scopeId: "", group: "" },
) {
  const get = vi.spyOn(api, "get").mockImplementation((url: string) => {
    const found = answer(url);
    return (
      found instanceof Error
        ? Promise.reject(found)
        : Promise.resolve({
            data: found,
            meta: { routes_total: 1, max_assets: 40, folded_with_reach: 0 },
          })
    ) as never;
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[at]}>
        <EstateGraph scopeId={lens.scopeId} group={lens.group} />
        <Where />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return get;
}

describe("the estate map", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("draws the estate and lists the reach across it in words", async () => {
    const get = mount(() => ESTATE);

    await userEvent.click(await screen.findByRole("tab", { name: /links/i }));
    expect(get).toHaveBeenCalledWith("/api/v1/attack-paths/estate?");
    // The text form of the arrows.
    const items = [...screen.getByRole("tabpanel").querySelectorAll("li")].map(
      (row) => row.textContent ?? "",
    );
    expect(items[0]).toContain("Sub web");
    expect(items[0]).toContain("runs as");
    expect(items.some((text) => text.includes("can act over ×3"))).toBe(true);
  });

  it("selects a box on a click, and opens it only on Enter or a double click", async () => {
    mount(() => ESTATE);

    // The canvas is a lazy chunk: wait for the box itself, not its name,
    // which the panel beside the canvas carries first.
    fireEvent.click(await waitFor(() => box("scope:prod")));
    expect(box("scope:prod")).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByTestId("where")).not.toHaveTextContent(
      "subscription_id",
    );
    // The panel answers for it: what it is, and the reach on either side.
    const panel = screen.getByRole("complementary", { name: "About the map" });
    expect(panel).toHaveTextContent("Sub prod");
    expect(panel).toHaveTextContent("What reaches itDirectorycan act over");
    expect(panel).toHaveTextContent("It reaches nothing else on this map.");

    fireEvent.keyDown(box("scope:prod"), { key: "Enter" });
    expect(screen.getByTestId("where")).toHaveTextContent("subscription_id=prod");
  });

  it("fades around a box under the pointer without selecting it", async () => {
    mount(() => ESTATE);
    fireEvent.pointerEnter(await waitFor(() => box("scope:prod")));

    // Prod's neighbour stays; web, two hops away, fades.
    expect(box("scope:directory").className).not.toContain("opacity-30");
    expect(box("scope:web").className).toContain("opacity-30");
    expect(box("scope:prod")).toHaveAttribute("aria-pressed", "false");

    fireEvent.pointerLeave(box("scope:prod"));
    expect(box("scope:web").className).not.toContain("opacity-30");
  });

  it("opens a selected box from the panel, as a double click would", async () => {
    mount(() => ESTATE);
    fireEvent.doubleClick(await waitFor(() => box("scope:web")));
    expect(screen.getByTestId("where")).toHaveTextContent("subscription_id=web");
  });

  it("asks for the lens it is given", async () => {
    const get = mount(
      () => ({ ...ESTATE, lens: { scope_id: "prod", group: "Data" } }),
      "/assets?view=graph&subscription_id=prod&resource_group=Data",
      { scopeId: "prod", group: "Data" },
    );

    await waitFor(() =>
      expect(get).toHaveBeenCalledWith(
        "/api/v1/attack-paths/estate?subscription_id=prod&resource_group=Data",
      ),
    );
  });

  it("offers the whole estate when the lens names nothing", async () => {
    mount(() => new ApiError("NOT_FOUND", "gone", 404), "/assets?view=graph&subscription_id=gone", {
      scopeId: "gone",
      group: "",
    });

    await userEvent.click(await screen.findByRole("button", { name: /draw the whole estate/i }));
    expect(screen.getByTestId("where")).not.toHaveTextContent("subscription_id");
  });

  it("says so when nothing has been discovered", async () => {
    mount(() => ({ ...ESTATE, boxes: [], edges: [] }));
    expect(await screen.findByText(/nothing discovered yet/i)).toBeInTheDocument();
  });

  it("gives the canvas one tab stop, starting where reach starts", async () => {
    mount(() => ESTATE);

    await waitFor(() => box("scope:web"));
    const stops = () =>
      [...document.querySelectorAll<HTMLElement>("[data-graph-node]")].filter(
        (b) => b.tabIndex === 0,
      );
    expect(stops().map((b) => b.dataset.graphNode)).toEqual(["scope:web"]);

    fireEvent.keyDown(stops()[0], { key: "ArrowRight" });
    expect(stops().map((b) => b.dataset.graphNode)).toEqual(["scope:directory"]);
  });

  it("says CloudGuard failed, not that the estate is empty, when the API does", async () => {
    // Only a 404 means the scope is not there. A 500 read as "nothing is
    // there" would present an outage as a fact about the estate.
    mount(() => new ApiError("INTERNAL", "boom", 500));

    expect(await screen.findByText("Could not draw your estate")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /draw the whole estate/i })).toBeNull();
  });

  it("lists what the map holds worst first, and selects a row as the box would", async () => {
    // The hierarchy view, folded into the map: the same boxes as rows.
    mount(() => ESTATE);
    await waitFor(() => box("scope:web"));
    await userEvent.click(screen.getByRole("tab", { name: /contents/i }));

    const rows = [...screen.getByRole("tabpanel").querySelectorAll("li")].map(
      (li) => li.textContent ?? "",
    );
    expect(rows[0]).toContain("Sub web");

    await userEvent.click(
      screen.getAllByRole("button").find((b) => b.textContent?.startsWith("Sub prod"))!,
    );
    expect(box("scope:prod")).toHaveAttribute("aria-pressed", "true");
    await userEvent.click(screen.getByRole("button", { name: /open on the map/i }));
    expect(screen.getByTestId("where")).toHaveTextContent("subscription_id=prod");
  });

  it("draws every box, a quiet one too: it is a map of connections, not of routes", async () => {
    mount(() => ESTATE);
    await waitFor(() => box("scope:quiet"));
    expect(screen.queryByRole("switch")).toBeNull();
    expect(screen.queryByRole("tab", { name: /paths/i })).toBeNull();
  });

  it("picks an arrow out on the map from its sentence", async () => {
    mount(() => ESTATE);
    await waitFor(() => box("scope:quiet"));
    await userEvent.click(screen.getByRole("tab", { name: /links/i }));

    const row = screen
      .getAllByRole("button")
      .find((b) => b.textContent?.includes("runs as"))!;
    await userEvent.click(row);

    // The panel says what the arrow carries; its two ends stay, the rest fade.
    expect(screen.getByRole("complementary", { name: "About the map" })).toHaveTextContent(
      "Sub web → Directory",
    );
    expect(box("scope:quiet").className).toContain("opacity-30");
    expect(box("scope:web").className).not.toContain("opacity-30");
  });

  it("links a box's attack paths to their page, narrowed to it", async () => {
    mount(() => ESTATE);
    fireEvent.click(await waitFor(() => box("scope:prod")));

    const link = screen.getByRole("link", { name: /on 1 attack path/i });
    expect(link).toHaveAttribute("href", "/attack-paths?scope=prod");
  });

  it("says nothing about attack paths on a box none runs through", async () => {
    mount(() => ESTATE);
    fireEvent.click(await waitFor(() => box("scope:quiet")));
    expect(screen.queryByRole("link", { name: /attack path/i })).toBeNull();
  });

  it("selects an arrow from a box's reach, and a box from an arrow's ends", async () => {
    mount(() => ESTATE);
    fireEvent.click(await waitFor(() => box("scope:prod")));
    const panel = screen.getByRole("complementary", { name: "About the map" });

    await userEvent.click(
      [...panel.querySelectorAll("button")].find((b) =>
        b.textContent?.startsWith("Directory"),
      )!,
    );
    expect(panel).toHaveTextContent("Directory → Sub prod");

    await userEvent.click(screen.getByRole("button", { name: "Directory" }));
    expect(box("scope:directory")).toHaveAttribute("aria-pressed", "true");
  });

  it("sends an old link to walk a route to the attack-path page", async () => {
    mount(() => ESTATE, "/assets?view=graph&walk=vm%7Csa&hop=1");

    await waitFor(() =>
      expect(screen.getByTestId("where")).toHaveTextContent(
        "/attack-paths?trace=vm%7Csa&hop=1",
      ),
    );
  });
});
