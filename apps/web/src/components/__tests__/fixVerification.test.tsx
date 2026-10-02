/**
 * Following a verification scan on the finding. The verdict is the finding's
 * status once the scan ends -- never inferred from how long it has run.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { FixVerification } from "@/components/security/FixVerification";
import { api } from "@/lib/api";
import type { EvidenceCitation, FindingStatus } from "@/lib/types";

function mount(
  scanStatus: string,
  findingStatus: FindingStatus,
  error: string | null = null,
  evidence: EvidenceCitation[] | null = null,
) {
  vi.spyOn(api, "get").mockResolvedValue({
    data: {
      id: "s1",
      status: scanStatus,
      completed_at: "2026-09-18T10:00:00Z",
      error_message: error,
    },
    meta: {},
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <FixVerification
        scanId="s1"
        findingId="f1"
        findingStatus={findingStatus}
        resourceName="stprod"
        evidence={evidence}
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

  it("draws the check it proves, rather than showing a stock icon", async () => {
    // The one moment the product exists for (DECISIONS.md §180): the check is a
    // stroke drawn on when the verdict lands, not a glyph that was always there.
    const { container } = mount("COMPLETED", "RESOLVED");
    await screen.findByText("Verified fixed");
    expect(container.querySelector('path[d="M20 6 9 17l-5-5"]')).not.toBeNull();
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

  const citation = (scan: string): EvidenceCitation => ({
    evidence_key: "network.nsg_rules",
    cloud_account_id: "a1",
    outcome: "COMPLETE",
    item_count: 3,
    permissions: [],
    endpoints: [],
    content_hash: "4c1f9ab77e02d5aa0000000000000000000000000000000000000000000000ff",
    collected_at: "2026-09-18T09:58:00Z",
    age_seconds: 120,
    source_scan_id: scan,
    payload_available: true,
  });

  it("names the reading that proved the fix, with its hash", async () => {
    mount("COMPLETED", "RESOLVED", null, [citation("s1")]);
    expect(
      await screen.findByText(
        /evidence sha256 4c1f9ab77e02… · network\.nsg_rules · read 2026-09-18T09:58:00Z/,
      ),
    ).toBeInTheDocument();
  });

  it("never offers a reading from another scan as the proof", async () => {
    mount("COMPLETED", "RESOLVED", null, [citation("older-scan")]);
    expect(await screen.findByText("Verified fixed")).toBeInTheDocument();
    expect(screen.queryByText(/evidence sha256/)).not.toBeInTheDocument();
  });
});
