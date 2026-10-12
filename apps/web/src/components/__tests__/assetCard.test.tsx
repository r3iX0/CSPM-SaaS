/**
 * A box you can ask (DECISIONS.md §254): what it is, what it holds up, the best
 * cut touching it, and what the inspector reads -- code, activity -- asked for
 * only when the card opens.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AssetCard } from "@/components/graph/AssetCard";
import { api } from "@/lib/api";
import type { AssetInspection, MappedRoute, RouteMap, RouteMapNode } from "@/lib/types";

const NODE: RouteMapNode = {
  id: "mi",
  asset_id: "row-mi",
  name: "mi-jump",
  resource_type: "service_principal",
  provider: "AZURE",
  scope_id: "sub-1",
  scope_name: "Production",
  group: null,
  column: 1,
  public_exposure: "LOW",
  data_sensitivity: "LOW",
  entry: false,
  sensitive: false,
  routes: 2,
  findings: { open: 1, worst: "HIGH" },
};

const route = (key: string, entry: string, target: string): MappedRoute => ({
  key,
  pattern: null,
  risk: null,
  entry: { id: entry, name: entry, resource_type: "virtual_machine", public_exposure: "HIGH" },
  target: { id: target, name: target, resource_type: "key_vault", data_sensitivity: "HIGH" },
  hops: 2,
  steps: [],
  cheapest_break: null,
});

const MAP: RouteMap = {
  nodes: [NODE],
  edges: [
    {
      source: "mi",
      relationship: "grants_role",
      target: "kv",
      label: "can act over",
      facts: ["Owner"],
      detail: "mi-jump can act over kv (Owner)",
      severs: 2,
      closes: ["a|kv", "b|kv"],
      on_routes: 2,
      alternate: false,
    },
  ],
  routes: [],
  patterns: [],
  loose: [],
  choke_points: [],
  plan: { cuts: [], total_routes: 0, remaining: 0 },
};

const INSPECTION: AssetInspection = {
  asset_id: "row-mi",
  defined_in: [{ repository: "acme/infra", working_directory: "prod", address: "azurerm_x.mi" }],
  changes: [],
  sign_in: { read: false, last_sign_in: null, days_since: null },
};

function mount() {
  vi.spyOn(api, "get").mockImplementation((url: string) =>
    Promise.resolve({ data: url.includes("/inspect/") ? INSPECTION : [], meta: {} }),
  );
  const handlers = { onTrace: vi.fn(), onCut: vi.fn(), onCompromise: vi.fn(), onClose: vi.fn() };
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <AssetCard
          node={NODE}
          map={MAP}
          through={[route("a|kv", "a", "kv"), route("b|kv", "b", "kv")]}
          compromised={false}
          {...handlers}
        />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return handlers;
}

describe("AssetCard", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("says what it holds up and offers the best cut touching it", async () => {
    const { onCut, onTrace } = mount();
    const card = screen.getByRole("region", { name: "About mi-jump" });

    expect(card).toHaveTextContent("Routes through it2");
    expect(card).toHaveTextContent("Ways in2");
    // The card rises in (§256); jsdom runs no animation, so presence is the check.
    expect(screen.getByText("mi-jump can act over kv (Owner)")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Add to the plan" }));
    expect(onCut).toHaveBeenCalledWith(MAP.edges[0]);
    await userEvent.click(screen.getByRole("button", { name: "Trace worst route" }));
    expect(onTrace).toHaveBeenCalledWith("a|kv");
  });

  it("reads where it is defined, and never calls an unread sign-in dormant", async () => {
    mount();
    expect(await screen.findByText(/acme\/infra\/prod · azurerm_x.mi/)).toBeInTheDocument();
    expect(screen.getByText(/Sign-in activity was not read/)).toBeInTheDocument();
  });
});
