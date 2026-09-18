/**
 * The shared demo, as the reader meets it: a way in before anything is set up,
 * a banner on every page while inside, and no write action drawn there.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { DemoBanner } from "@/components/layout/DemoBanner";
import { PostureHeader } from "@/components/dashboard/PostureHeader";
import { OnboardingPage } from "@/pages/Onboarding";
import { api, auth } from "@/lib/api";
import type { Organization } from "@/lib/types";

const DEMO: Organization = {
  id: "demo-1",
  name: "CloudGuard demo",
  slug: "cloudguard-demo",
  industry: null,
  country: null,
  created_at: "2026-09-01T00:00:00Z",
  role: "VIEWER",
  is_demo: true,
};
const OWN: Organization = { ...DEMO, id: "own-1", name: "Acme", slug: "acme", role: "OWNER", is_demo: false };

function Where() {
  return <p data-testid="where">{useLocation().pathname}</p>;
}

function mount(ui: React.ReactNode, orgs: Organization[], entry = "/") {
  vi.spyOn(api, "get").mockResolvedValue({ data: orgs, meta: {} } as never);
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

describe("the demo organization", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it("says so on the page while the reader is inside it", async () => {
    auth.organizationId = DEMO.id;
    mount(<DemoBanner />, [DEMO]);

    expect(await screen.findByText("You are exploring the CloudGuard demo.")).toBeInTheDocument();
    // No organization of their own yet: the way out is to make one.
    expect(screen.getByRole("link", { name: "Create your organization" })).toHaveAttribute(
      "href",
      "/onboarding",
    );
  });

  it("offers the way back to the reader's own organization when there is one", async () => {
    auth.organizationId = DEMO.id;
    mount(<DemoBanner />, [OWN, DEMO]);

    fireEvent.click(await screen.findByRole("button", { name: "Back to Acme" }));
    expect(auth.organizationId).toBe(OWN.id);
  });

  it("draws nothing outside the demo", async () => {
    auth.organizationId = OWN.id;
    const { container } = mount(<DemoBanner />, [OWN]);
    await waitFor(() => expect(api.get).toHaveBeenCalled());
    expect(container.querySelector('[role="status"]')).toBeNull();
  });

  it("does not offer a scan of a recording", async () => {
    auth.organizationId = DEMO.id;
    mount(<PostureHeader scannedAt={null} staleHours={null} scanning={false} />, [DEMO]);

    await screen.findByText("Overview");
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: /Scan now/ })).not.toBeInTheDocument(),
    );
  });

  it("opens from onboarding, before anything is set up", async () => {
    auth.organizationId = null;
    const post = vi.spyOn(api, "post").mockResolvedValue({ data: DEMO, meta: {} } as never);
    mount(<OnboardingPage />, [], "/onboarding");

    fireEvent.click(await screen.findByRole("button", { name: /Explore a demo environment/ }));

    await waitFor(() => expect(post).toHaveBeenCalledWith("/api/v1/organizations/demo/join"));
    await waitFor(() => expect(auth.organizationId).toBe(DEMO.id));
    expect(screen.getByTestId("where")).toHaveTextContent("/");
  });
});
