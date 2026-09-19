/**
 * The region map's refusals are what is worth pinning (DECISIONS.md §113): a
 * region with no known coordinates is listed and not drawn, "global" is a line
 * under the list rather than a place, and an unread region is never presented
 * as a clean one.
 */
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { RegionPanel } from "@/components/dashboard/RegionPanel";
import { regionLabel } from "@/lib/geo/regions";
import type { DashboardRegion } from "@/lib/types";

const region = (overrides: Partial<DashboardRegion>): DashboardRegion => ({
  region: "westeurope",
  provider: "azure",
  assets: 1,
  open_findings: 0,
  by_severity: {},
  readings: 0,
  unread: 0,
  ...overrides,
});

function mount(regions: DashboardRegion[]) {
  return render(
    <MemoryRouter>
      <RegionPanel regions={regions} />
    </MemoryRouter>,
  );
}

describe("RegionPanel", () => {
  it("links every region to the asset list filtered to it", () => {
    mount([
      region({ region: "eastus", open_findings: 1, by_severity: { CRITICAL: 1 } }),
      region({ region: "westeurope", assets: 20 }),
    ]);

    const east = screen.getByRole("link", { name: /East US/ });
    expect(east).toHaveAttribute("href", "/assets?region=eastus");
    expect(east).toHaveTextContent("1 open");
    expect(screen.getByRole("link", { name: /West Europe/ })).toHaveTextContent(
      "nothing open",
    );
    expect(screen.getByText(/The worst is East US/)).toBeInTheDocument();
  });

  it("lists a region it cannot place, and does not draw it", () => {
    const { container } = mount([
      region({ region: "westeurope" }),
      region({ region: "atlantis1" }),
    ]);

    expect(screen.getByRole("link", { name: /atlantis1/ })).toHaveTextContent(
      "location not known to CloudGuard",
    );
    const drawn = [...container.querySelectorAll("[data-region]")].map((node) =>
      node.getAttribute("data-region"),
    );
    expect(drawn).toEqual(["westeurope"]);
  });

  it("puts what has no region under the list, never on the map", () => {
    const { container } = mount([
      region({ region: "westeurope" }),
      region({
        region: null,
        provider: null,
        assets: 4,
        open_findings: 2,
        by_severity: { HIGH: 2 },
      }),
    ]);

    const unplaced = screen.getByRole("link", { name: /not tied to a region/ });
    expect(unplaced).toHaveAttribute("href", "/assets?region=none");
    expect(unplaced).toHaveTextContent("2 open");
    expect(container.querySelectorAll("[data-region]")).toHaveLength(1);
  });

  it("says an unread region is unread rather than clean", () => {
    mount([region({ region: "us-east-1", provider: "aws", readings: 17, unread: 2 })]);

    expect(screen.getByText("2 unread")).toBeInTheDocument();
    expect(screen.getByText(/could not be fully read/)).toBeInTheDocument();
  });

  it("draws nothing when nothing is tied to a region", () => {
    const { container } = mount([region({ region: null, provider: null })]);
    expect(container).toBeEmptyDOMElement();
  });

  it("keeps the map out of the accessibility tree", () => {
    mount([region({})]);
    expect(screen.getByTestId("region-map")).toHaveAttribute("aria-hidden", "true");
  });
});

describe("regionLabel", () => {
  it("names a region the way its console does, whatever ARM spelled", () => {
    expect(regionLabel("West Europe")).toBe("West Europe");
    expect(regionLabel("eu-west-1")).toBe("Europe (Ireland)");
    expect(regionLabel("none")).toBe("Not tied to a region");
    expect(regionLabel("atlantis1")).toBe("atlantis1");
  });
});
