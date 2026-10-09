/**
 * Acceptances waiting for a second approver (DECISIONS.md §239): who is offered the decision,
 * and that a rejection says why.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "@/lib/api";
import type { Acceptance, Organization } from "@/lib/types";
import { AcceptanceRequests } from "@/components/security/AcceptanceRequests";

let subject = "u-admin";
vi.mock("@/lib/useAuth", () => ({
  useSessionClaims: () => ({ subject, sessionId: null, secondFactor: false, guest: false }),
}));

function request(overrides: Partial<Acceptance> = {}): Acceptance {
  return {
    id: "a-1",
    finding_id: "f-1",
    risk_id: null,
    subject_title: "Storage account allows public blob access",
    subject_severity: "HIGH",
    subject_status: "OPEN",
    reason: "Behind the VPN until the rebuild",
    expires_at: "2026-11-30T23:59:59Z",
    status: "PENDING",
    requested_by: "u-analyst",
    requested_by_email: "analyst@example.com",
    created_at: new Date().toISOString(),
    decided_by: null,
    decided_by_email: null,
    decided_at: null,
    decision_note: null,
    ...overrides,
  };
}

function organization(role: string): Organization {
  return {
    id: "o-1",
    name: "Contoso",
    slug: "contoso",
    industry: null,
    country: null,
    created_at: "2026-01-01T00:00:00Z",
    role,
    mode: "TEAM",
    acceptance_approval_from: "HIGH",
  };
}

function mount(rows: Acceptance[], role = "ADMIN") {
  vi.spyOn(api, "get").mockResolvedValue({ data: rows, meta: {} });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <AcceptanceRequests organization={organization(role)} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  subject = "u-admin";
});

describe("acceptances waiting for a second approver", () => {
  it("says nothing while nothing waits", async () => {
    const { container } = mount([]);
    await waitFor(() => expect(api.get).toHaveBeenCalled());
    expect(container).toBeEmptyDOMElement();
  });

  it("offers an admin who did not ask the decision", async () => {
    const user = userEvent.setup();
    const post = vi.spyOn(api, "post").mockResolvedValue({ data: {}, meta: {} });
    mount([request()]);

    expect(await screen.findByText("1 acceptance waits for a second approver")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Approve" }));

    await waitFor(() => expect(post).toHaveBeenCalledWith("/api/v1/acceptances/a-1/approve"));
  });

  it("tells the person who asked that it waits for somebody else", async () => {
    subject = "u-analyst";
    mount([request()], "SECURITY_ANALYST");

    expect(await screen.findByText("Waits for an owner or admin")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Approve" })).not.toBeInTheDocument();
  });

  it("offers a member who cannot decide no buttons", async () => {
    mount([request()], "SECURITY_ANALYST");

    await screen.findByText("1 acceptance waits for a second approver");
    expect(screen.queryByRole("button", { name: "Approve" })).not.toBeInTheDocument();
  });

  it("rejects only with a note, and sends it", async () => {
    const user = userEvent.setup();
    const post = vi.spyOn(api, "post").mockResolvedValue({ data: {}, meta: {} });
    mount([request()]);

    await user.click(await screen.findByRole("button", { name: "Reject…" }));
    const dialog = await screen.findByRole("dialog");
    const submit = within(dialog).getByRole("button", { name: "Reject" });
    expect(submit).toHaveAttribute("aria-disabled", "true");

    await user.type(within(dialog).getByLabelText("Why"), "Not without a compensating control");
    await user.click(submit);

    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/v1/acceptances/a-1/reject", {
        note: "Not without a compensating control",
      }),
    );
  });
});
