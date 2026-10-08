/**
 * Where the shell sends somebody who belongs to no organization
 * (DECISIONS.md §211, §218).
 *
 * Onboarding asks a person with no membership to create an organization, which
 * is the wrong thing to ask an auditor. So a link held across sign-in goes to
 * the auditor's page first, and an account that has opened a grant goes back to
 * it. Anybody else with no organization still lands in onboarding.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { Shell } from "@/components/Shell";
import { holdGrant } from "@/lib/pendingGrant";

const urlOf = (input: RequestInfo | URL) =>
  typeof input === "string" ? input : input instanceof URL ? input.href : input.url;

let organizations: unknown[] = [];
let grants: unknown[] = [];

function renderShell() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/"]}>
        <Routes>
          <Route element={<Shell />}>
            <Route path="/" element={<p>The page itself</p>} />
          </Route>
          <Route path="/auditor" element={<main>Auditor page</main>} />
          <Route path="/onboarding" element={<main>Onboarding page</main>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("the shell, for somebody with no organization", () => {
  beforeEach(() => {
    organizations = [];
    grants = [];
    window.localStorage.clear();
    vi.stubGlobal(
      "fetch",
      vi.fn((input: RequestInfo | URL) => {
        const url = urlOf(input);
        const data = url.includes("/auditor/grants")
          ? grants
          : url.includes("/organizations")
            ? organizations
            : [];
        return Promise.resolve(
          new Response(JSON.stringify({ data, error: null, meta: {} }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          }),
        );
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    window.localStorage.clear();
  });

  it("sends a held auditor link to the auditor's page", async () => {
    holdGrant("a-grant-token-from-the-link-long-enough");
    renderShell();
    expect(await screen.findByText("Auditor page")).toBeInTheDocument();
  });

  it("sends an account that has opened a grant back to its packages", async () => {
    grants = [{ id: "g-1" }];
    renderShell();
    expect(await screen.findByText("Auditor page")).toBeInTheDocument();
  });

  it("still sends anybody else to onboarding", async () => {
    renderShell();
    expect(await screen.findByText("Onboarding page")).toBeInTheDocument();
  });

  it("does not ask whether a member of an organization is an auditor", async () => {
    organizations = [{ id: "org-1", name: "Acme", slug: "acme", role: "OWNER" }];
    renderShell();
    expect(await screen.findByText("The page itself")).toBeInTheDocument();
    const asked = vi
      .mocked(fetch)
      .mock.calls.some(([input]) => urlOf(input).includes("/auditor/grants"));
    expect(asked).toBe(false);
  });
});
