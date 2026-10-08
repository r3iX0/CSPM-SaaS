/**
 * Linking Cleave's GitHub App (DECISIONS.md §231).
 *
 * The card appears only where the deployment offers GitHub. What GitHub hands
 * back after an installation goes to the API once, under the reader's session,
 * because GitHub's code is single-use and the API asks GitHub whether the
 * installation is really theirs.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { api } from "@/lib/api";
import type { GitHubStatus } from "@/lib/types";
import { GitHubCallback, GitHubSection } from "@/components/settings/GitHub";

function mount(element: React.ReactNode, at = "/settings/integrations") {
  render(
    <QueryClientProvider
      client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}
    >
      <MemoryRouter initialEntries={[at]}>
        <Routes>
          <Route path="/settings/integrations" element={element} />
          <Route path="/settings/integrations/github" element={element} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function status(data: GitHubStatus) {
  vi.spyOn(api, "get").mockResolvedValue({ data, meta: {} });
}

afterEach(() => vi.restoreAllMocks());

describe("the GitHub card", () => {
  it("is not drawn where the deployment does not offer GitHub", async () => {
    status({ available: false, installations: [] });
    mount(<GitHubSection />);
    await waitFor(() => expect(api.get).toHaveBeenCalled());
    expect(screen.queryByRole("button", { name: "Install on GitHub" })).not.toBeInTheDocument();
  });

  it("names each linked installation, and offers to unlink it", async () => {
    status({
      available: true,
      installations: [
        {
          installation_id: 7,
          account_login: "contoso",
          account_type: "Organization",
          connected_at: "2026-10-08T09:00:00Z",
        },
      ],
    });
    mount(<GitHubSection />);

    expect(await screen.findByText(/Linked to contoso/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Unlink contoso" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Install on GitHub" })).toBeInTheDocument();
  });
});

describe("coming back from GitHub", () => {
  it("links what GitHub handed back, once", async () => {
    const post = vi.spyOn(api, "post").mockResolvedValue({ data: {}, meta: {} });
    mount(
      <GitHubCallback />,
      "/settings/integrations/github?installation_id=7&code=abc&state=signed&setup_action=install",
    );

    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/v1/integrations/github/installations", {
        installation_id: 7,
        code: "abc",
        state: "signed",
      }),
    );
    expect(post).toHaveBeenCalledTimes(1);
  });

  it("says so when GitHub sent nothing to link", () => {
    const post = vi.spyOn(api, "post");
    mount(<GitHubCallback />, "/settings/integrations/github?setup_action=install");

    expect(screen.getByText(/GitHub sent no installation to link/)).toBeInTheDocument();
    expect(post).not.toHaveBeenCalled();
  });
});
