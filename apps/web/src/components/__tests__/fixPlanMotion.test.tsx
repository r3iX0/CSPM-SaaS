/**
 * Motion that explains what changed (DECISIONS.md §256): a plan tried is told
 * in plan order, once -- the step classes are added when it is tried and a
 * re-render leaves them alone, so nothing replays.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

import { FixPlanCard } from "@/components/graph/FixPlanCard";
import type { FixPlan, FixPlanCut } from "@/lib/types";

const cut = (n: number): FixPlanCut => ({
  description: `cut ${n}`,
  detail: `cut ${n} (Owner)`,
  facts: ["Owner"],
  relationship: "grants_role",
  source: { id: `s${n}`, name: `s${n}`, resource_type: "service_principal" },
  target: { id: `t${n}`, name: `t${n}`, resource_type: "resource_group" },
  cost: 1,
  closes: [`r${n}`],
  closed_after: n,
});

const PLAN: FixPlan = { cuts: [cut(1), cut(2)], total_routes: 2, remaining: 0 };

function card(trying: boolean) {
  return (
    <QueryClientProvider client={new QueryClient()}>
      <MemoryRouter>
        <FixPlanCard
          plan={PLAN}
          entryPoints={1}
          sensitiveTargets={1}
          onTry={vi.fn()}
          trying={trying}
        />
      </MemoryRouter>
    </QueryClientProvider>
  );
}

const row = (text: string) => screen.getByText(text).closest("li");

describe("the fix plan's motion", () => {
  it("stays still until the plan is tried", () => {
    render(card(false));
    expect(row("cut 1 (Owner)")?.className).not.toContain("cg-reveal");
  });

  it("tells the plan in order when tried, and a re-render does not replay it", () => {
    const { rerender } = render(card(true));
    expect(row("cut 1 (Owner)")?.className).toContain("cg-step-0");
    expect(row("cut 2 (Owner)")?.className).toContain("cg-step-1");

    const before = row("cut 2 (Owner)");
    rerender(card(true));
    expect(row("cut 2 (Owner)")).toBe(before);
    expect(row("cut 2 (Owner)")?.className).toContain("cg-step-1");
  });
});
