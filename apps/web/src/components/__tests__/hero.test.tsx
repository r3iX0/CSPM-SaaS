/**
 * The dashboard's anchor, and what the number is about.
 *
 * "82" alone invites exactly two questions — out of what, and is that good —
 * and a panel answering neither makes the reader hunt for both. The map beside
 * it answers a third the score cannot: what is this a score *of*.
 */
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { DashboardHero } from "@/components/dashboard/Hero";
import type { ExposureMapData } from "@/lib/types";

const MAP: ExposureMapData = {
  nodes: [
    {
      id: "/vm/jump-01",
      name: "jump-01",
      resource_type: "VIRTUAL_MACHINE",
      public_exposure: "CRITICAL",
      data_sensitivity: "UNKNOWN",
      criticality: "UNKNOWN",
      is_entry: true,
    },
    {
      id: "/storage/customerdata",
      name: "customerdata",
      resource_type: "STORAGE_ACCOUNT",
      public_exposure: "LOW",
      data_sensitivity: "HIGH",
      criticality: "HIGH",
      is_entry: false,
    },
  ],
  edges: [
    {
      source: "/vm/jump-01",
      relationship: "grants_role",
      target: "/storage/customerdata",
    },
  ],
};

function mount(props: Partial<Parameters<typeof DashboardHero>[0]> = {}) {
  return render(
    <MemoryRouter>
      <DashboardHero
        score={82}
        delta={null}
        history={[]}
        map={MAP}
        omitted={0}
        loadingMap={false}
        routes={0}
        entryPoints={1}
        sensitiveTargets={1}
        {...props}
      />
    </MemoryRouter>,
  );
}

describe("the overview hero", () => {
  it("gives the number a scale", () => {
    mount();

    expect(screen.getByText("82")).toBeInTheDocument();
    expect(screen.getByText("out of 100")).toBeInTheDocument();
  });

  it("does not claim a trend it cannot measure", () => {
    // No earlier reading is not "no change": the two mean opposite things to
    // somebody deciding whether remediation is working.
    mount({ score: 70 });

    expect(screen.getByText(/no previous scan/i)).toBeInTheDocument();
  });

  it("draws what the internet touches", () => {
    mount();

    expect(screen.getByText("jump-01")).toBeInTheDocument();
    expect(screen.getByText("customerdata")).toBeInTheDocument();
  });

  it("says why there is no route, not merely that there is none", () => {
    // "No attack paths" reads as reassurance. Nothing classified as sensitive
    // is a gap in what CloudGuard was told, and the two must not render alike.
    mount({ routes: 0, sensitiveTargets: 0 });

    expect(
      screen.getByText(/path analysis starts once a subscription is declared sensitive/),
    ).toBeInTheDocument();
  });

  it("does not draw a map it does not have", () => {
    mount({ map: { nodes: [], edges: [] }, entryPoints: 0 });

    expect(
      screen.getByText(/Nothing in this estate is reachable from the internet/),
    ).toBeInTheDocument();
  });

  it("says how much of the estate it left out of the drawing", () => {
    // A diagram that quietly truncates is a diagram of a smaller, tidier
    // estate than the customer has.
    mount({ omitted: 7 });

    expect(screen.getByText("7 more assets not drawn")).toBeInTheDocument();
  });
});
