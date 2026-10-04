/**
 * Two-factor authentication (DECISIONS.md §217): the code asked for after
 * sign-in, and the authenticator app added and removed under Settings.
 *
 * Supabase is replaced at the module boundary; what is under test is when the
 * page asks, what it sends, and that the API's refusal asks too. The API's own
 * refusal of a one-factor session is proven in the API's tests.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { SecondFactorGate } from "../SecondFactorGate";
import { SecuritySection } from "@/components/settings/Security";
import { auth, SECOND_FACTOR_REQUIRED_EVENT } from "@/lib/api";
import * as supabase from "@/lib/supabase";

vi.mock("@/lib/supabase", async (importOriginal) => ({
  ...(await importOriginal<typeof supabase>()),
  secondFactorNeeded: vi.fn(),
  listSecondFactors: vi.fn(),
  startSecondFactor: vi.fn(),
  confirmSecondFactor: vi.fn(),
  removeSecondFactor: vi.fn(),
  supabaseSignOut: vi.fn(),
}));

const needed = vi.mocked(supabase.secondFactorNeeded);
const listed = vi.mocked(supabase.listSecondFactors);
const started = vi.mocked(supabase.startSecondFactor);
const confirmed = vi.mocked(supabase.confirmSecondFactor);
const removed = vi.mocked(supabase.removeSecondFactor);

function encode(value: object): string {
  return btoa(JSON.stringify(value)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** A token in Supabase's shape; nothing here checks its signature. */
function token(aal: "aal1" | "aal2"): string {
  return `${encode({ alg: "HS256" })}.${encode({ sub: "u-1", session_id: "s-1", aal })}.sig`;
}

function renderWith(ui: React.ReactNode) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{ui}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const FACTOR = { id: "f-1", createdAt: "2026-10-01T09:00:00Z" };

beforeEach(() => {
  vi.clearAllMocks();
  listed.mockResolvedValue([FACTOR]);
  confirmed.mockResolvedValue();
  removed.mockResolvedValue();
});

afterEach(() => {
  auth.token = null;
});

describe("SecondFactorGate", () => {
  it("lets a two-factor session through without asking", async () => {
    auth.token = token("aal2");
    renderWith(<SecondFactorGate>page</SecondFactorGate>);
    expect(await screen.findByText("page")).toBeInTheDocument();
    expect(needed).not.toHaveBeenCalled();
  });

  it("lets a one-factor session through when the user has no authenticator", async () => {
    auth.token = token("aal1");
    needed.mockResolvedValue(false);
    renderWith(<SecondFactorGate>page</SecondFactorGate>);
    expect(await screen.findByText("page")).toBeInTheDocument();
  });

  it("asks for the code, and sends the digits only", async () => {
    auth.token = token("aal1");
    needed.mockResolvedValue(true);
    renderWith(<SecondFactorGate>page</SecondFactorGate>);

    const field = await screen.findByLabelText("Code");
    expect(screen.queryByText("page")).not.toBeInTheDocument();
    await userEvent.type(field, "123 456");
    expect(field).toHaveValue("123456");
    await userEvent.click(screen.getByRole("button", { name: "Verify" }));

    await waitFor(() => expect(confirmed).toHaveBeenCalledWith("f-1", "123456"));
  });

  it("says so when the code does not match", async () => {
    auth.token = token("aal1");
    needed.mockResolvedValue(true);
    confirmed.mockRejectedValue(new Error("Invalid TOTP code entered"));
    renderWith(<SecondFactorGate>page</SecondFactorGate>);

    await userEvent.type(await screen.findByLabelText("Code"), "000000");
    await userEvent.click(screen.getByRole("button", { name: "Verify" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("That code did not match");
  });

  it("asks when the API refuses the session, even if this browser thought it was fine", async () => {
    auth.token = token("aal1");
    needed.mockResolvedValue(false);
    renderWith(<SecondFactorGate>page</SecondFactorGate>);
    await screen.findByText("page");

    act(() => {
      window.dispatchEvent(new Event(SECOND_FACTOR_REQUIRED_EVENT));
    });

    expect(await screen.findByLabelText("Code")).toBeInTheDocument();
  });
});

describe("Settings: two-factor authentication", () => {
  it("adds an authenticator app and confirms it with the first code", async () => {
    listed.mockResolvedValue([]);
    started.mockResolvedValue({
      id: "f-new",
      qrCode: "data:image/svg+xml;utf-8,<svg xmlns='http://www.w3.org/2000/svg'/>",
      secret: "JBSWY3DPEHPK3PXP",
    });
    renderWith(<SecuritySection />);

    await userEvent.click(await screen.findByRole("button", { name: "Set up" }));
    expect(
      await screen.findByAltText("QR code that adds Cleave to an authenticator app"),
    ).toBeInTheDocument();
    expect(screen.getByText("JBSWY3DPEHPK3PXP")).toBeInTheDocument();

    await userEvent.type(
      screen.getByLabelText("Then enter the 6-digit code the app shows."),
      "654321",
    );
    await userEvent.click(screen.getByRole("button", { name: "Turn on" }));

    await waitFor(() => expect(confirmed).toHaveBeenCalledWith("f-new", "654321"));
  });

  it("removes the app the user has, after asking", async () => {
    renderWith(<SecuritySection />);

    expect(await screen.findByText("On")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Remove" }));
    await userEvent.click(
      within(await screen.findByRole("alertdialog")).getByRole("button", { name: "Remove" }),
    );

    await waitFor(() => expect(removed).toHaveBeenCalledWith("f-1"));
  });
});
