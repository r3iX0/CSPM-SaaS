/**
 * The estate map on the assets page.
 *
 * The layout is tested as a function, because that is where its promises
 * live: reach reads left to right from where it starts, a quiet box is never
 * mistaken for part of a route, and the same estate draws the same picture.
 * The view is tested for what it decides: the lens is the list's scope
 * filter, opening a box is a step Back can retrace, and a lens on nothing
 * offers the way back rather than a blank frame.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { EstateGraph } from "@/components/assets/EstateGraph";
import { ESTATE_COLUMN_GAP, QUIET_ROWS, layoutEstate } from "@/components/graph/estateLayout";
import { boxHref, boxLabel, edgeLabel } from "@/components/graph/estateNames";
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
  on_route = false,
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
  on_route,
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
    link("web", "directory", "has_identity", 1, true),
    link("directory", "prod", "grants_role", 3, true),
  ],
};

describe("the estate layout", () => {
  it("reads left to right from the box holding a way in", () => {
    const at = layoutEstate(ESTATE);

    expect(at.get("scope:web")!.x).toBe(0);
    expect(at.get("scope:directory")!.x).toBe(ESTATE_COLUMN_GAP);
    expect(at.get("scope:prod")!.x).toBe(2 * ESTATE_COLUMN_GAP);
  });

  it("puts boxes with no reach after the route rather than on it", () => {
    const at = layoutEstate(ESTATE);
    expect(at.get("scope:quiet")!.x).toBe(3 * ESTATE_COLUMN_GAP);
  });

  it("stacks a quiet estate into a grid rather than one tall column", () => {
    const boxes = Array.from({ length: QUIET_ROWS + 2 }, (_, i) => scope(`s${i}`));
    const at = layoutEstate({ lens: ESTATE.lens, boxes, edges: [] });
    const columns = new Set([...at.values()].map((p) => p.x));
    expect(columns.size).toBe(2);
  });

  it("draws a cycle nothing leads into rather than losing it", () => {
    const at = layoutEstate({
      lens: ESTATE.lens,
      boxes: [scope("a"), scope("b")],
      edges: [link("a", "b"), link("b", "a")],
    });
    expect(at.get("scope:a")!.x).toBe(0);
    expect(at.get("scope:b")!.x).toBe(ESTATE_COLUMN_GAP);
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
  return <output data-testid="where">{location.search}</output>;
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

    expect(await screen.findByText("Reach across boundaries")).toBeInTheDocument();
    expect(get).toHaveBeenCalledWith("/api/v1/attack-paths/estate?");
    // The text form of the arrows, reach on a route first. Each is a toggle
    // that picks its arrow out on the canvas.
    const items = screen
      .getAllByRole("button", { pressed: false })
      .map((row) => row.textContent ?? "");
    expect(items[0]).toContain("Sub web");
    expect(items[0]).toContain("runs as");
    expect(items.some((text) => text.includes("can act over ×3"))).toBe(true);
  });

  it("opens a subscription by writing the list's own scope filter", async () => {
    mount(() => ESTATE);

    // The canvas is a lazy chunk: wait for the box itself, not its name,
    // which the list under the canvas carries first.
    fireEvent.click(await waitFor(() => box("scope:prod")));

    expect(screen.getByTestId("where")).toHaveTextContent("subscription_id=prod");
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

  it("lists what the map holds worst first, and opens a row as the box would", async () => {
    // The hierarchy view, folded into the map: the same boxes as rows.
    mount(() => ESTATE);

    const heading = await screen.findByText("Your subscriptions");
    const rows = [...heading.closest("div")!.querySelectorAll("li")].map(
      (li) => li.textContent ?? "",
    );
    expect(rows[0]).toContain("Sub web");
    await userEvent.click(
      screen.getAllByRole("button").find((b) => b.textContent?.startsWith("Sub prod"))!,
    );
    expect(screen.getByTestId("where")).toHaveTextContent("subscription_id=prod");
  });

  it("picks an arrow out on the map from its sentence", async () => {
    mount(() => ESTATE);
    await waitFor(() => box("scope:web"));

    const row = screen
      .getAllByRole("button", { pressed: false })
      .find((b) => b.textContent?.includes("runs as"))!;
    await userEvent.click(row);

    expect(row).toHaveAttribute("aria-pressed", "true");
    // Its two ends stay; everything else fades.
    expect(box("scope:quiet").className).toContain("opacity-30");
    expect(box("scope:web").className).not.toContain("opacity-30");
  });
});
