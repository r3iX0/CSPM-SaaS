/**
 * The invitation page (DECISIONS.md §162).
 *
 * Three things must hold. A link opened while signed out survives the sign-in
 * that follows it. A signed-in reader is told which organization and role the
 * link offers before they commit. And an account other than the invited one is
 * told so before a click the API would refuse, rather than after.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { InvitePage } from "../Invite";
import { api, auth } from "@/lib/api";
import { forgetInvite, heldInvite } from "@/lib/pendingInvite";
import type { InvitationPreview } from "@/lib/types";

const TOKEN = "a-token-from-the-link-long-enough";

let signedIn = true;
vi.mock("@/lib/useAuth", () => ({ useAuthToken: () => (signedIn ? "jwt" : null) }));

function preview(overrides: Partial<InvitationPreview> = {}): InvitationPreview {
  return {
    organization_name: "Contoso",
    role: "SECURITY_ANALYST",
    email: "ana@contoso.example",
    status: "OPEN",
    email_matches: true,
    ...overrides,
  };
}

function mount(offer: InvitationPreview | null = preview()) {
  const post = vi.spyOn(api, "post").mockImplementation((path: string) => {
    if (path.endsWith("/preview")) {
      return (
        offer ? Promise.resolve({ data: offer, meta: {} }) : Promise.reject(new Error("404"))
      ) as never;
    }
    return Promise.resolve({
      data: { id: "o-9", name: "Contoso", role: "SECURITY_ANALYST" },
      meta: {},
    }) as never;
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[`/invite#${TOKEN}`]}>
        <Routes>
          <Route path="/invite" element={<InvitePage />} />
          <Route path="/" element={<main>Home</main>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return post;
}

describe("InvitePage", () => {
  beforeEach(() => {
    signedIn = true;
    forgetInvite();
  });
  afterEach(() => {
    vi.restoreAllMocks();
    auth.organizationId = null;
  });

  it("holds the link through a sign-in", async () => {
    signedIn = false;
    mount();
    expect(await screen.findByRole("link", { name: "Sign in to accept" })).toBeInTheDocument();
    await waitFor(() => expect(heldInvite()).toBe(TOKEN));
  });

  it("says what the link offers, then joins and lands in that organization", async () => {
    const post = mount();
    expect(
      await screen.findByText("You have been invited to Contoso as Security analyst."),
    ).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Join organization" }));

    await waitFor(() => expect(screen.getByText("Home")).toBeInTheDocument());
    expect(post).toHaveBeenCalledWith("/api/v1/invitations/accept", { token: TOKEN });
    expect(auth.organizationId).toBe("o-9");
    expect(heldInvite()).toBeNull();
  });

  it("tells another account it is not the one invited, before any click", async () => {
    mount(preview({ email_matches: false }));
    expect(await screen.findByText(/signed in with a different address/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Join organization" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Sign out" })).toBeInTheDocument();
  });

  it("says a spent link is spent, and stops holding it", async () => {
    mount(preview({ status: "EXPIRED" }));
    expect(await screen.findByText(/has expired/)).toBeInTheDocument();
    await waitFor(() => expect(heldInvite()).toBeNull());
  });
});
