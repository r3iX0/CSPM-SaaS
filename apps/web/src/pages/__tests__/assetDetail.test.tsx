/**
 * One asset's page (DECISIONS.md §112).
 *
 * What these hold down: the page answers "is this in trouble" before anything
 * else, returns to the list the reader came from, tells a clean asset apart
 * from an unchecked one, and does not ask for the tenant's graph until the
 * Connections tab is opened.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AssetDetailPage } from "@/pages/AssetDetail";
import { api, ApiError } from "@/lib/api";
import { portalUrl } from "@/lib/portal";

const ARM =
  "/subscriptions/sub-1/resourceGroups/prod-rg/providers/Microsoft.Storage/storageAccounts/payroll";
const TENANT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

function asset(extra: Record<string, unknown> = {}) {
  return {
    id: "asset-1",
    name: "payroll",
    resource_type: "storage_account",
    provider: "AZURE",
    provider_resource_id: ARM,
    region: "westeurope",
    environment: "production",
    criticality: "HIGH",
    data_sensitivity: "HIGH",
    public_exposure: "LOW",
    metadata: { kind: "StorageV2" },
    first_seen_at: "2026-08-01T00:00:00Z",
    last_seen_at: "2026-09-18T00:00:00Z",
    absent_since: null,
    placement: { scope_id: "sub-1", scope_name: "Production", resource_group: "prod-rg" },
    tenant_id: TENANT,
    open_findings: 1,
    findings: [
      {
        id: "f-open",
        rule_id: "AZ-STO-001",
        title: "Public blob access is enabled",
        severity: "CRITICAL",
        status: "OPEN",
        risk_score: 92,
      },
      {
        id: "f-closed",
        rule_id: "AZ-STO-002",
        title: "Secure transfer is not required",
        severity: "MEDIUM",
        status: "RESOLVED",
        risk_score: 40,
      },
    ],
    ...extra,
  };
}

let requested: string[] = [];

function mount(
  detail: Record<string, unknown>,
  entry: string | { pathname: string; search?: string; state?: unknown } = "/assets/asset-1",
) {
  requested = [];
  vi.spyOn(api, "get").mockImplementation((url: string) => {
    requested.push(url);
    if (url === "/api/v1/assets/asset-1") return Promise.resolve({ data: detail, meta: {} }) as never;
    // The graph endpoints: a 404 is enough to prove they were asked.
    return Promise.reject(new ApiError("NOT_FOUND", "not a vertex", 404)) as never;
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[entry]}>
        <Routes>
          <Route path="/assets/:assetId" element={<AssetDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

const graphAsked = () => requested.some((url) => url.includes("/attack-paths/"));

describe("the asset page", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("goes back to the list exactly as it was left", async () => {
    mount(asset(), {
      pathname: "/assets/asset-1",
      state: { from: "/assets?exposure=HIGH&page=2" },
    });

    const back = await screen.findByRole("link", { name: "Assets" });
    expect(back).toHaveAttribute("href", "/assets?exposure=HIGH&page=2");
  });

  it("names where the asset sits, each level opening the map there", async () => {
    mount(asset());

    expect(await screen.findByRole("link", { name: "Production" })).toHaveAttribute(
      "href",
      "/assets?view=graph&subscription_id=sub-1",
    );
    expect(screen.getByRole("link", { name: "prod-rg" })).toHaveAttribute(
      "href",
      "/assets?view=graph&subscription_id=sub-1&resource_group=prod-rg",
    );
  });

  it("opens on what is open, with what is closed one press away", async () => {
    const user = userEvent.setup();
    mount(asset());

    expect(await screen.findByText("Public blob access is enabled")).toBeInTheDocument();
    expect(screen.queryByText("Secure transfer is not required")).toBeNull();

    await user.click(screen.getByRole("button", { name: "Closed (1)" }));
    expect(screen.getByText("Secure transfer is not required")).toBeInTheDocument();
  });

  it("offers no open/closed switch when nothing is closed", async () => {
    mount(asset({ findings: [asset().findings[0]] }));

    await screen.findByText("Public blob access is enabled");
    expect(screen.queryByRole("button", { name: /Closed/ })).toBeNull();
  });

  it("does not call an unchecked asset clean", async () => {
    mount(
      asset({
        resource_type: "unknown",
        metadata: { azure_type: "Microsoft.Web/sites" },
        open_findings: 0,
        findings: [],
      }),
    );

    expect(
      await screen.findByText(/no checks for this kind of resource \(Microsoft.Web\/sites\)/),
    ).toBeInTheDocument();
    expect(screen.queryByText(/No open findings/)).toBeNull();
  });

  it("says when a modelled asset has nothing open", async () => {
    mount(asset({ open_findings: 0, findings: [] }));

    expect(await screen.findByText(/No open findings\. Last scanned/)).toBeInTheDocument();
  });

  it("says an asset the last scan did not find is gone", async () => {
    mount(asset({ absent_since: "2026-09-10T00:00:00Z" }));

    expect(await screen.findByText(/Not seen since/)).toBeInTheDocument();
  });

  it("asks for the graph only once Connections is opened", async () => {
    const user = userEvent.setup();
    mount(asset());
    await screen.findByText("Public blob access is enabled");

    expect(graphAsked()).toBe(false);

    await user.click(screen.getByRole("tab", { name: "Connections" }));

    await waitFor(() => expect(graphAsked()).toBe(true));
    // Opening the tab is the request: no second "draw it" button.
    expect(screen.queryByRole("button", { name: /Draw the graph/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Work out reach/ })).toBeNull();
  });

  it("opens on Connections when the link came for the graph", async () => {
    mount(asset(), `/assets/asset-1?around=${encodeURIComponent(ARM)}`);

    await waitFor(() => expect(graphAsked()).toBe(true));
    expect(screen.getByRole("tab", { name: "Connections" })).toHaveAttribute(
      "aria-selected",
      "true",
    );
  });
});

describe("when the graph cannot be read", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("says CloudGuard failed rather than that the asset is not in the graph", async () => {
    // Only a 404 means "not a vertex". A 500 said that way would present an
    // outage as a fact about the estate.
    vi.spyOn(api, "get").mockImplementation((url: string) =>
      url === "/api/v1/assets/asset-1"
        ? (Promise.resolve({ data: asset(), meta: {} }) as never)
        : (Promise.reject(new ApiError("INTERNAL", "boom", 500)) as never),
    );
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={["/assets/asset-1?tab=connections"]}>
          <Routes>
            <Route path="/assets/:assetId" element={<AssetDetailPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );

    expect(await screen.findByText("Could not draw the graph")).toBeInTheDocument();
    expect(await screen.findByText("Could not work out its reach")).toBeInTheDocument();
    expect(screen.queryByText(/not a vertex in the current graph/)).toBeNull();
  });
});

describe("the portal link", () => {
  it("opens an ARM resource in its own directory", () => {
    expect(portalUrl({ provider: "AZURE", provider_resource_id: ARM, tenant_id: TENANT })).toBe(
      `https://portal.azure.com/#@${TENANT}/resource${ARM}`,
    );
  });

  it("offers none for a directory object or another cloud", () => {
    expect(
      portalUrl({ provider: "AZURE", provider_resource_id: "/principals/mi-1", tenant_id: TENANT }),
    ).toBeNull();
    expect(
      portalUrl({ provider: "AWS", provider_resource_id: "arn:aws:s3:::bucket", tenant_id: null }),
    ).toBeNull();
  });
});
