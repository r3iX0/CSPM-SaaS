/**
 * A guest: somebody exploring the demo without an account (DECISIONS.md §219).
 * One click opens it, the way out is an account kept as the same user, and
 * nothing offers a guest what the API would refuse.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import * as supabase from "@/lib/supabase";
import { DemoBanner } from "@/components/layout/DemoBanner";
import { DemoPage } from "@/pages/Demo";
import { OnboardingPage } from "@/pages/Onboarding";
import { SignInPage } from "@/pages/SignIn";
import { api, auth } from "@/lib/api";
import type { Organization } from "@/lib/types";

vi.mock("@/lib/supabase", async (importOriginal) => ({
  ...(await importOriginal<typeof supabase>()),
  signInAsGuest: vi.fn(),
  saveGuestWithEmail: vi.fn(),
  saveGuestWithProvider: vi.fn(),
}));

const signInAsGuest = vi.mocked(supabase.signInAsGuest);
const saveGuestWithEmail = vi.mocked(supabase.saveGuestWithEmail);

const DEMO: Organization = {
  id: "demo-1",
  name: "Cleave demo",
  slug: "cloudguard-demo",
  industry: null,
  country: null,
  created_at: "2026-09-01T00:00:00Z",
  role: "VIEWER",
  is_demo: true,
};

function encode(value: object): string {
  return btoa(JSON.stringify(value)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** A token in the shape Supabase issues; nothing here checks its signature. */
function token(claims: object): string {
  return `${encode({ alg: "HS256" })}.${encode({ sub: "u-1", session_id: "s-1", ...claims })}.sig`;
}

const GUEST_TOKEN = token({ is_anonymous: true });
const ACCOUNT_TOKEN = token({ email: "person@example.com" });

function Where() {
  return <p data-testid="where">{useLocation().pathname}</p>;
}

function mount(ui: React.ReactNode, entry = "/") {
  vi.spyOn(api, "get").mockResolvedValue({ data: [DEMO], meta: {} });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[entry]}>
        <Where />
        <Routes>
          <Route path="*" element={ui} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("a guest", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    signInAsGuest.mockReset();
    saveGuestWithEmail.mockReset();
    localStorage.clear();
    auth.token = null;
    auth.organizationId = null;
  });

  it("opens the demo in one visit, with no account and no organization", async () => {
    signInAsGuest.mockImplementation(async () => {
      auth.token = GUEST_TOKEN;
    });
    const post = vi.spyOn(api, "post").mockResolvedValue({ data: DEMO, meta: {} });
    mount(<DemoPage />, "/demo");

    await waitFor(() => expect(post).toHaveBeenCalledWith("/api/v1/organizations/demo/join"));
    expect(signInAsGuest).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(auth.organizationId).toBe(DEMO.id));
    expect(screen.getByTestId("where")).toHaveTextContent(/^\/$/);
  });

  it("is not made of somebody already signed in", async () => {
    auth.token = ACCOUNT_TOKEN;
    const post = vi.spyOn(api, "post").mockResolvedValue({ data: DEMO, meta: {} });
    mount(<DemoPage />, "/demo");

    await waitFor(() => expect(post).toHaveBeenCalledWith("/api/v1/organizations/demo/join"));
    expect(signInAsGuest).not.toHaveBeenCalled();
  });

  it("is told plainly when the demo cannot open, with a way to try again", async () => {
    signInAsGuest.mockRejectedValue(new Error("anonymous sign-ins are disabled"));
    mount(<DemoPage />, "/demo");

    expect(await screen.findByText("The demo is not available right now.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Sign in" })).toHaveAttribute("href", "/sign-in");
  });

  it("is offered an account in the banner, not a way out to nowhere", async () => {
    auth.token = GUEST_TOKEN;
    auth.organizationId = DEMO.id;
    mount(<DemoBanner />);

    expect(await screen.findByRole("link", { name: "Create an account" })).toHaveAttribute(
      "href",
      "/sign-in",
    );
    expect(screen.queryByRole("button", { name: "Leave the demo" })).not.toBeInTheDocument();
  });

  it("makes an account before an organization", async () => {
    auth.token = GUEST_TOKEN;
    mount(<OnboardingPage />, "/onboarding");

    await waitFor(() => expect(screen.getByTestId("where")).toHaveTextContent("/sign-in"));
  });

  it("keeps their session as an account by confirming an email", async () => {
    auth.token = GUEST_TOKEN;
    saveGuestWithEmail.mockResolvedValue();
    mount(<SignInPage />, "/sign-in");

    expect(screen.getByRole("heading", { name: "Create your account" })).toBeInTheDocument();
    // Supabase sets a guest's password only once the address is confirmed.
    expect(screen.queryByLabelText("Password")).not.toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Email address"), {
      target: { value: "person@example.com" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Send confirmation link" }));

    await waitFor(() => expect(saveGuestWithEmail).toHaveBeenCalledWith("person@example.com"));
    expect(await screen.findByRole("heading", { name: "Check your email" })).toBeInTheDocument();
  });
});
