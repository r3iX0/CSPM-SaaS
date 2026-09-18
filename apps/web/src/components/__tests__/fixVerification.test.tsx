/**
 * Following a verification scan on the finding. The verdict is the finding's
 * status once the scan ends -- never inferred from how long it has run.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { FixVerification } from "@/components/security/FixVerification";
import { api } from "@/lib/api";
import type { FindingStatus } from "@/lib/types";

function mount(scanStatus: string, findingStatus: FindingStatus, error: string | null = null) {
  vi.spyOn(api, "get").mockResolvedValue({
    data: { id: "s1", status: scanStatus, completed_at: "2026-09-18T10:00:00Z", error_message: error },
    meta: {},
  } as never);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <FixVerification
        scanId="s1"
        findingId="f1"
        findingStatus={findingStatus}
        resourceName="stprod"
        onRetry={() => {}}
        onClose={() => {}}
        retrying={false}
      />
    </QueryClientProvider>,
  );
}

describe("verifying a fix", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("says it is checking while the scan runs", async () => {
    mount("DISCOVERING", "OPEN");
    expect(await screen.findByText("Checking your fix")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Verify again" })).not.toBeInTheDocument();
  });

  it("calls a resolved finding verified once the scan ends", async () => {
    mount("COMPLETED", "RESOLVED");
    expect(await screen.findByText("Verified fixed")).toBeInTheDocument();
  });

  it("calls a finding still open after a finished scan still failing, and offers another try", async () => {
    mount("COMPLETED", "OPEN");
    expect(await screen.findByText("Still failing")).toBeInTheDocument();
    expect(screen.getByText(/still fails on stprod/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Verify again" })).toBeInTheDocument();
  });

  it("does not let a failed scan pass for a verdict either way", async () => {
    mount("FAILED", "OPEN", "The scanner role could not list subscriptions.");
    expect(await screen.findByText("The scan could not finish")).toBeInTheDocument();
    expect(screen.getByText("The scanner role could not list subscriptions.")).toBeInTheDocument();
    expect(screen.queryByText("Still failing")).not.toBeInTheDocument();
  });
});
