/**
 * The sidebar's second width.
 *
 * Sixty pixels of label per row is a good trade on a wide monitor and a bad one
 * on a thirteen-inch laptop, so the rail exists — and because it is a choice
 * about the shape of somebody's workspace rather than a transient state, it has
 * to survive a reload.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Shell } from "@/components/Shell";

function renderShell() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/"]}>
        <Shell />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

let dashboard: unknown = null;
let riskTotal: number | null = null;

describe("the application shell", () => {
  beforeEach(() => {
    dashboard = null;
    riskTotal = null;
    window.localStorage.clear();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        const data = url.includes("/organizations")
          ? [{ id: "org-1", name: "Acme", slug: "acme", role: "OWNER" }]
          : url.includes("/dashboard")
            ? dashboard
            : [];
        // The risks list's own total, which is what the nav counts: it holds
        // attack paths and escalations the dashboard's bands leave out.
        const meta = url.includes("/risks") && riskTotal !== null ? { total: riskTotal } : {};
        return {
          ok: true,
          status: 200,
          json: async () => ({ data, error: null, meta }),
        } as Response;
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    window.localStorage.clear();
  });

  it("collapses to a rail and remembers that it did", async () => {
    const { unmount } = renderShell();

    fireEvent.click(
      await screen.findByRole("button", { name: "Collapse navigation" }),
    );

    // The labels go; the destinations do not. An icon rail that stopped being
    // navigable would be a worse trade than the width it saves.
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Expand navigation" }),
      ).toBeInTheDocument(),
    );
    expect(screen.getAllByRole("link", { name: "Findings" }).length).toBeGreaterThan(0);

    unmount();
    renderShell();

    expect(
      await screen.findByRole("button", { name: "Expand navigation" }),
    ).toBeInTheDocument();
  });

  it("counts what is open beside the lists of problems, and when the estate was last read", async () => {
    dashboard = {
      open_finding_count: 32,
      // Finding risks only; the list also holds 2 routes.
      risk_bands: { CRITICAL: 2, HIGH: 3 },
      history: [{ observed_at: "2026-09-01T00:00:00Z", attack_path_count: 4 }],
      last_scan: { status: "COMPLETED", completed_at: new Date(Date.now() - 3 * 3600e3).toISOString() },
    };
    riskTotal = 7;
    renderShell();

    expect(await screen.findByRole("link", { name: /^Findings\b.*\b32 open$/ })).toBeInTheDocument();
    expect(await screen.findByRole("link", { name: /^Risks\b.*\b7 open$/ })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /^Attack paths\b.*\b4 open$/ })).toBeInTheDocument();
    expect(screen.getByText(/Last read/)).toHaveTextContent("Last read 3 hours ago");
  });

  it("draws no count and no read time it does not have", async () => {
    renderShell();

    expect(await screen.findByRole("link", { name: "Findings" })).toBeInTheDocument();
    expect(screen.queryByText(/Last read/)).not.toBeInTheDocument();
  });
});
