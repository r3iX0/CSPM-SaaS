/**
 * Saying an asset holds data that matters (DECISIONS.md §251): only ever up,
 * applied by the next scan, and not offered in the demo.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { DeclareSensitive } from "@/components/graph/DeclareSensitive";
import { api } from "@/lib/api";
import type { AssetDeclaration } from "@/lib/types";

const DECLARED: AssetDeclaration = {
  resource_id: "row-1",
  data_sensitivity: "CRITICAL",
  note: null,
  declared_by_user_id: "u-1",
  declared_at: "2026-10-11T09:00:00Z",
};

function mount(current: AssetDeclaration | null) {
  vi.spyOn(api, "get").mockResolvedValue({ data: current, meta: {} });
  const put = vi.spyOn(api, "put").mockResolvedValue({ data: DECLARED, meta: {} });
  const del = vi.spyOn(api, "del").mockResolvedValue({ data: null, meta: {} });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <DeclareSensitive assetId="row-1" name="stpayroll" />
    </QueryClientProvider>,
  );
  return { put, del };
}

describe("DeclareSensitive", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("asks, and declares a level for the next scan", async () => {
    const { put } = mount(null);
    await userEvent.click(await screen.findByRole("button", { name: "Critical" }));

    await waitFor(() =>
      expect(put).toHaveBeenCalledWith("/api/v1/assets/row-1/context", {
        data_sensitivity: "CRITICAL",
      }),
    );
  });

  it("says what was declared, and withdraws it", async () => {
    const { del } = mount(DECLARED);
    expect(await screen.findByText("You said this holds critical data.")).toBeVisible();
    expect(screen.queryByRole("button", { name: /does not/i })).toBeNull();

    await userEvent.click(screen.getByRole("button", { name: "Withdraw" }));
    await waitFor(() => expect(del).toHaveBeenCalledWith("/api/v1/assets/row-1/context"));
  });
});
