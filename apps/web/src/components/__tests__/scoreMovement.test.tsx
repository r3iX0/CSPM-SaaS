/**
 * Why the score moved (DECISIONS.md §235): the delta, split into causes that
 * add up to it, each naming the findings that decided it.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ScoreMovement } from "@/components/dashboard/ScoreMovement";
import { api } from "@/lib/api";
import type { ScoreMovement as Movement } from "@/lib/types";

const MOVED: Movement = {
  available: true,
  reason: null,
  since: "2026-10-01T09:00:00Z",
  from_score: 60,
  to_score: 66,
  delta: 6,
  causes: [
    {
      cause: "fixes_verified",
      points: 9,
      exact: 8.6,
      risks: 2,
      findings: [
        {
          id: "f1",
          title: "RDP open to the internet",
          severity: "CRITICAL",
          rule_id: "AZ-NET-001",
          status: "RESOLVED",
        },
      ],
    },
    { cause: "new_failures", points: -3, exact: -3.4, risks: 1, findings: [] },
    { cause: "context_changed", points: 0, exact: 0.2, risks: 1, findings: [] },
  ],
};

function mount(movement: Movement) {
  const get = vi.spyOn(api, "get").mockResolvedValue({ data: movement, meta: {} });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <ScoreMovement />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return get;
}

describe("ScoreMovement", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("reads nothing until it is asked", () => {
    const get = mount(MOVED);
    expect(get).not.toHaveBeenCalled();
  });

  it("names each cause with its signed points and the findings behind it", async () => {
    mount(MOVED);
    fireEvent.click(screen.getByRole("button", { name: "Why it moved" }));

    expect(await screen.findByText("Fixes a scan verified")).toBeInTheDocument();
    expect(screen.getByText("+9")).toBeInTheDocument();
    expect(screen.getByText("−3")).toBeInTheDocument();
    expect(screen.getByText("From 60 to 66, since the scan before last")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "RDP open to the internet" })).toHaveAttribute(
      "href",
      "/findings/f1",
    );
  });

  it("says a share under a point rather than showing it as nothing", async () => {
    mount(MOVED);
    fireEvent.click(screen.getByRole("button", { name: "Why it moved" }));
    expect(await screen.findByText("under 1")).toBeInTheDocument();
  });

  it("says why there is no breakdown for a reading recorded before it existed", async () => {
    mount({ ...MOVED, available: false, reason: "not_recorded", causes: [] });
    fireEvent.click(screen.getByRole("button", { name: "Why it moved" }));
    expect(await screen.findByText(/predates this breakdown/)).toBeInTheDocument();
  });
});
