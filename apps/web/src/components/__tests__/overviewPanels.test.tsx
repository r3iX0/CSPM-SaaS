/**
 * The overview's panels that the Cleave redesign added: the one link to cut,
 * the fixes a scan proved, and what moved this week.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import type { ReactNode } from "react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { CutPanel } from "@/components/dashboard/CutPanel";
import { FixesProved } from "@/components/dashboard/FixesProved";
import { RecentChanges } from "@/components/dashboard/RecentChanges";
import type { ChangeEvent, ChokePoint } from "@/lib/types";

function wrap(node: ReactNode) {
  return render(
    <QueryClientProvider client={new QueryClient()}>
      <MemoryRouter>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const choke: ChokePoint = {
  description: "Remove the Reader role assignment",
  detail: "vm-jumpbox —Reader→ storage-prod-01",
  facts: [],
  relationship: "HAS_ROLE",
  source: { id: "vm-1", name: "vm-jumpbox", resource_type: "virtual_machine" },
  target: { id: "st-1", name: "storage-prod-01", resource_type: "storage_account" },
  severs: 3,
  on_routes: 3,
  total_routes: 4,
  closes: [],
};

describe("CutPanel", () => {
  it("names the link with its evidence and what cutting it alone closes", () => {
    wrap(<CutPanel chokes={[choke]} loading={false} failed={false} />);

    expect(screen.getByText("vm-jumpbox —Reader→ storage-prod-01")).toBeInTheDocument();
    expect(screen.getByText(/Cutting this link closes/)).toHaveTextContent(
      "Cutting this link closes 3 of 4 routes.",
    );
  });

  it("opens the simulation with that cut already in the plan", () => {
    wrap(<CutPanel chokes={[choke]} loading={false} failed={false} />);

    const link = screen.getByRole("link", { name: /Simulate this cut/ });
    const href = new URL(link.getAttribute("href") ?? "", "http://x");
    expect(href.pathname).toBe("/attack-paths");
    expect(href.searchParams.getAll("cut")).toEqual(["vm-1|HAS_ROLE|st-1"]);
  });

  it("never reads no routes as a clean estate", () => {
    wrap(<CutPanel chokes={[]} loading={false} failed={false} />);
    expect(screen.getByText(/What counts as sensitive is something you declare/)).toBeInTheDocument();
  });

  it("says a failed read is a display problem, not a change", () => {
    wrap(<CutPanel chokes={undefined} loading={false} failed />);
    expect(screen.getByText(/Nothing about your environment has changed/)).toBeInTheDocument();
  });
});

describe("FixesProved", () => {
  it("keeps work in progress apart from what a scan verified", () => {
    wrap(<FixesProved verified={12} inProgress={4} open={28} />);

    expect(screen.getByText("Verified closed · 30 days").nextElementSibling).toHaveTextContent("12");
    expect(screen.getByText("In progress, not yet proved").nextElementSibling).toHaveTextContent("4");
    expect(screen.getByText(/Nobody can close one by hand/)).toBeInTheDocument();
  });
});

describe("RecentChanges", () => {
  const event = (change: ChangeEvent["change"], previous: string | null, current: string | null) =>
    ({
      id: change,
      change,
      previous_value: previous,
      current_value: current,
      observed_at: "2026-09-20T09:00:00Z",
      scan_id: null,
      asset: { id: "a", name: "storage-prod-01", resource_type: "storage_account", environment: null, absent_since: null },
    }) as ChangeEvent;

  it("says in a word which way each change went", () => {
    wrap(
      <RecentChanges
        loading={false}
        events={[event("EXPOSURE_CHANGED", "LOW", "CRITICAL"), event("APPEARED", null, null)]}
      />,
    );

    expect(screen.getByText("Worse").className).toContain("text-critical");
    expect(screen.getByText("New")).toBeInTheDocument();
  });
});
