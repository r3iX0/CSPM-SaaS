/**
 * A finding can be queued from its own page.
 *
 * Once the fix moved into the remediation page's sheet (DECISIONS.md §202),
 * "Track this fix" sat at the foot of that sheet only, and a reader on the
 * finding saw no way to queue it at all (§205).
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { FixSummary } from "@/components/security/FixSummary";
import type { FindingDetail } from "@/lib/types";

const FINDING = {
  id: "finding-1",
  rule_id: "AZ-STORAGE-001",
  severity: "HIGH",
  status: "OPEN",
  title: "Storage account allows public access",
  description: "",
  evidence: {},
  remediation: "Set 'Allow Blob anonymous access' to Disabled.",
  rule_version: "1.0",
  risk_score: 70,
  first_detected_at: "2026-09-01T00:00:00Z",
  last_detected_at: "2026-09-01T00:00:00Z",
  resolved_at: null,
  resolved_by_scan_id: null,
  estimated_effort_minutes: 20,
  resource: null,
} as unknown as FindingDetail; // Only the fields the card reads are arranged.

const TASK = {
  id: "task-1",
  finding_id: "finding-1",
  risk_id: null,
  status: "TODO",
  priority: "HIGH",
  due_date: null,
  estimated_effort_minutes: 20,
  notes: null,
  completed_at: null,
  created_at: "2026-09-02T00:00:00Z",
};

function mount(tasks: unknown[], finding: FindingDetail = FINDING) {
  const fetchMock = vi.fn((_input: string, init?: RequestInit) =>
    Promise.resolve({
      ok: true,
      status: init?.method === "POST" ? 201 : 200,
      json: () =>
        Promise.resolve({ data: init?.method === "POST" ? TASK : tasks, error: null, meta: {} }),
    }),
  );
  vi.stubGlobal("fetch", fetchMock);

  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <FixSummary finding={finding} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return fetchMock;
}

afterEach(() => vi.unstubAllGlobals());

describe("the fix card on a finding", () => {
  it("tracks the fix without leaving the finding", async () => {
    const fetchMock = mount([]);
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: "Track this fix" }));

    await waitFor(() => {
      const post = fetchMock.mock.calls.find(([, init]) => init?.method === "POST");
      expect(post?.[0]).toContain("/api/v1/remediation");
      expect(post?.[1]?.body).toBe(JSON.stringify({ finding_id: "finding-1" }));
    });
    expect(screen.getByRole("link", { name: /Open fix/ })).toHaveAttribute(
      "href",
      "/remediation?fix=finding-1",
    );
  });

  it("says the work is tracked rather than offering it twice", async () => {
    mount([TASK]);

    expect(await screen.findByText(/In the remediation queue since/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Track this fix" })).toBeNull();
  });

  it("offers nothing on a risk already accepted", async () => {
    mount([], { ...FINDING, status: "ACCEPTED_RISK" });

    expect(await screen.findByRole("link", { name: /Open fix/ })).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: "Track this fix" })).toBeNull(),
    );
  });
});
