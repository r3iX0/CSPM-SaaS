/**
 * The cut, played: routes a settled plan newly closes are struck in list
 * order, each after its own delay, and "Closed by the plan" arrives with the
 * strike (DECISIONS.md §146).
 */
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { RouteRow, type RouteMarks } from "@/components/graph/RouteRows";
import type { MappedRoute } from "@/lib/types";

const route = (key: string, entry: string, target: string): MappedRoute => ({
  key,
  pattern: null,
  entry: { id: entry, name: entry, resource_type: "virtual_machine", public_exposure: "CRITICAL" },
  target: { id: target, name: target, resource_type: "storage_account", data_sensitivity: "HIGH" },
  hops: 1,
  steps: [
    {
      source: entry,
      source_id: entry,
      relationship: "has_role",
      target,
      target_id: target,
      description: "",
      facts: [],
      detail: "",
    },
  ],
  cheapest_break: null,
});

function row(r: MappedRoute, marks: RouteMarks) {
  return render(<RouteRow route={r} marks={marks} onTrace={() => {}} onPreview={() => {}} />);
}

describe("the cut, played", () => {
  it("strikes a newly closed route after its delay, and marks it closed with the strike", () => {
    row(route("b", "ci-runner", "payments-db"), {
      tracked: new Set(),
      closed: new Set(["b"]),
      closeDelay: new Map([["b", 260]]),
    });

    const name = screen.getByText(/ci-runner/);
    expect(name.className).toContain("decoration-muted-foreground");
    expect(name.style.transitionDelay).toBe("260ms");
    expect(screen.getByText("Closed by the plan").style.animationDelay).toBe("260ms");
  });

  it("lands at once when there is no delay: already closed, or less motion asked for", () => {
    row(route("a", "logs-runner", "storage-prod-01"), {
      tracked: new Set(),
      closed: new Set(["a"]),
    });

    expect(screen.getByText(/logs-runner/).style.transitionDelay).toBe("");
  });

  it("leaves an open route unstruck, its strike transparent", () => {
    row(route("c", "prod-vm-01", "storage-prod-01"), { tracked: new Set(), closed: new Set() });

    const name = screen.getByText(/prod-vm-01/);
    expect(name.className).toContain("decoration-transparent");
    expect(name.className).not.toContain("decoration-muted-foreground");
    expect(screen.queryByText("Closed by the plan")).not.toBeInTheDocument();
  });
});
