/**
 * The inventory's two readings.
 *
 * The list is a queue: what is wrong, worst first. The map is the estate's
 * shape — subscription, then resource group — with the reach between them;
 * it replaced the hierarchy view, whose rows are now the map's contents list
 * (DECISIONS.md §112). The map's own behaviour is in estate.test.tsx.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AssetsPage } from "@/pages/Assets";

const ASSET: Record<string, unknown> = {
  id: "asset-1",
  name: "payroll",
  provider_resource_id:
    "/subscriptions/sub-1/resourceGroups/prod-rg/providers/Microsoft.Storage/storageAccounts/payroll",
  resource_type: "STORAGE_ACCOUNT",
  region: "westeurope",
  environment: "PRODUCTION",
  criticality: "HIGH",
  data_sensitivity: "HIGH",
  public_exposure: "LOW",
  open_findings: 3,
  first_seen_at: "2026-08-01T00:00:00Z",
  last_seen_at: "2026-08-30T00:00:00Z",
};

const UNCHECKED = {
  ...ASSET,
  id: "asset-2",
  name: "checkout-api",
  provider_resource_id:
    "/subscriptions/sub-1/resourceGroups/prod-rg/providers/Microsoft.Web/sites/checkout-api",
  resource_type: "unknown",
  azure_type: "Microsoft.Web/sites",
  public_exposure: "UNKNOWN",
  open_findings: 0,
};

let requested: string[] = [];

function mount(
  assets: object[] = [ASSET],
  meta: Record<string, unknown> = { total: 40 },
  path = "/assets",
) {
  requested = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      requested.push(url);
      const data = url.includes("/attack-paths/estate")
        ? { lens: { scope_id: null, group: null }, boxes: [], edges: [] }
        : assets;
      return {
        ok: true,
        status: 200,
        json: async () => ({ data, error: null, meta }),
      } as Response;
    }),
  );

  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <AssetsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("the assets page", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("narrows the list to the group a link arrived with", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        requested.push(String(input));
        return {
          ok: true,
          status: 200,
          json: async () => ({ data: [ASSET], error: null, meta: { total: 1 } }),
        } as Response;
      }),
    );
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter
          initialEntries={["/assets?subscription_id=sub-1&resource_group=prod-rg"]}
        >
          <AssetsPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    // The scope is shown as a filter that can be taken off, rather than as an
    // unexplained short list.
    expect(await screen.findByText("prod-rg")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Clear scope filter" }),
    ).toBeInTheDocument();
    expect(
      requested.some((url) => url.includes("resource_group=prod-rg")),
    ).toBe(true);
  });

  it("names what an unchecked resource actually is", async () => {
    /** A row reading "Unknown" would be a worse answer than the omission it
     * replaced. The point of listing these is that the customer can see what
     * is unchecked, not merely how many. */
    mount([UNCHECKED], { total: 1, unchecked: 1 });

    expect(await screen.findByText("Microsoft.Web/sites")).toBeInTheDocument();
  });

  it("still labels a modelled asset by its neutral type", async () => {
    /** The other branch. `azure_type` is null for anything the connector
     * models, whose cloud-neutral label is the better one -- an Azure storage
     * account and an S3 bucket are one kind of thing to a reader. */
    mount([ASSET], { total: 1, unchecked: 0 });

    expect(await screen.findByText("STORAGE ACCOUNT")).toBeInTheDocument();
  });

  it("says how many resources have no checks", async () => {
    /** CloudGuard reporting its own limits, which is the one thing a customer
     * cannot work out for themselves. Before the inventory was read, a
     * subscription full of App Services looked like a tidy inventory of
     * storage and virtual machines -- an absence that read as coverage. */
    mount([UNCHECKED], { total: 47, unchecked: 35 });

    expect(await screen.findByText(/35 with no checks yet/)).toBeInTheDocument();
  });

  it("says nothing when every resource is covered", async () => {
    /** A line that always appears is a line nobody reads. */
    mount([ASSET], { total: 12, unchecked: 0 });

    expect(await screen.findByText("payroll")).toBeInTheDocument();
    expect(screen.queryByText(/no checks yet/)).not.toBeInTheDocument();
  });

  it("offers every type in the filtered set, not only the ones on this page", async () => {
    /** The menu used to be read off the fifty rows on screen, so a type that
     * sorted onto page two could not be chosen. The API now counts the options
     * over the whole set, and the page offers what it was told. */
    const user = userEvent.setup();
    mount([ASSET], {
      total: 60,
      facets: {
        resource_type: { STORAGE_ACCOUNT: 40, VIRTUAL_MACHINE: 20 },
        environment: { PRODUCTION: 50, staging: 10 },
      },
    });
    await screen.findByText("payroll");

    await user.click(screen.getByRole("combobox", { name: "Filter by type" }));
    const types = (await screen.findAllByRole("option")).map((o) => o.textContent);
    expect(types.some((label) => /virtual machine/i.test(label ?? ""))).toBe(true);
  });

  it("shows a region set by a link as a chip, and drops it on clear", async () => {
    /** Region and environment are not menus any more, but the dashboard's
     * region map still drills in with `?region=`. The list has to say it is
     * narrowed, and let it be undone. */
    const user = userEvent.setup();
    mount([ASSET], { total: 1 }, "/assets?region=westeurope");
    await screen.findByText("payroll");

    expect(screen.queryByRole("combobox", { name: "Filter by region" })).toBeNull();
    expect(screen.queryByRole("combobox", { name: "Filter by environment" })).toBeNull();
    expect(requested.some((url) => url.includes("region=westeurope"))).toBe(true);

    await user.click(screen.getByRole("button", { name: "Clear region filter" }));
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: "Clear region filter" })).toBeNull(),
    );
  });

  it("keeps the order the API sent rather than re-sorting the page", async () => {
    /** The queue order is decided over the whole set on the server. A page
     * that re-sorted its own rows could only ever rank within one page. */
    mount([{ ...UNCHECKED, name: "first-by-server", open_findings: 0 }, ASSET], {
      total: 2,
    });

    await screen.findByText("payroll");
    const names = screen
      .getAllByRole("link")
      .map((link) => link.textContent)
      .filter((text) => text === "first-by-server" || text === "payroll");
    expect(names).toEqual(["first-by-server", "payroll"]);
  });

  it("opens an old link to the hierarchy on the map", async () => {
    /** The hierarchy is the map's contents list now; a bookmark to it should
     * land on the map rather than fall back to the list. */
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        requested.push(String(input));
        return {
          ok: true,
          status: 200,
          json: async () => ({
            data: { lens: { scope_id: null, group: null }, boxes: [], edges: [] },
            error: null,
            meta: {},
          }),
        } as Response;
      }),
    );
    requested = [];
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={["/assets?view=tree"]}>
          <AssetsPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    expect(await screen.findByText(/nothing discovered yet/i)).toBeInTheDocument();
    expect(requested.some((url) => url.includes("/attack-paths/estate"))).toBe(true);
    expect(screen.queryByRole("button", { name: /Hierarchy/ })).not.toBeInTheDocument();
  });

  it("marks an asset on an attack path, and only that one", async () => {
    mount([{ ...ASSET, on_attack_path: true }, { ...UNCHECKED, on_attack_path: false }], {
      total: 2,
    });

    await screen.findByText("payroll");
    expect(screen.getAllByTitle("On an attack path")).toHaveLength(1);
  });

  it("narrows the list to what the map marks", async () => {
    const user = userEvent.setup();
    mount([ASSET], { total: 1 });
    await screen.findByText("payroll");

    await user.click(screen.getByRole("combobox", { name: "Filter by what the map marks" }));
    await user.click(await screen.findByRole("option", { name: "On an attack path" }));

    await waitFor(() =>
      expect(requested.some((url) => url.includes("on_attack_path=true"))).toBe(true),
    );
  });

  it("says the map ignores the list's filters rather than seeming to apply them", async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => ({
        ok: true,
        status: 200,
        json: async () => ({
          data: { lens: { scope_id: null, group: null }, boxes: [], edges: [] },
          error: null,
          meta: {},
        }),
      })) as unknown as typeof fetch,
    );
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={["/assets?view=graph&exposure=HIGH"]}>
          <AssetsPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    expect(await screen.findByText(/apply to the list only/)).toHaveTextContent("exposure");
  });
});
