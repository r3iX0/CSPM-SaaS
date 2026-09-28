/**
 * The engine audit (DECISIONS.md §150).
 *
 * What these hold down: an unexpected disagreement is the headline, an
 * expected one is labelled as such, a service Prowler could not read is said
 * to read as unknown rather than passing, and a deployment without the
 * scanner service says so instead of showing an empty audit.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { EngineAuditPage } from "@/pages/EngineAudit";
import { api } from "@/lib/api";
import type { EngineAudit } from "@/lib/types";

const ENGINE = {
  enabled: true,
  prowler_version: "5.43.0",
  checks_enabled: 816,
  checks_covered: 111,
  native_rules: 98,
};

function audit(overrides: Partial<EngineAudit> = {}): EngineAudit {
  return {
    engine: ENGINE,
    scan: { id: "scan-1", status: "PARTIAL", completed_at: "2026-09-28T10:00:00Z" },
    assessments: [
      {
        scope: "Payments",
        provider: "azure",
        outcome: "PARTIAL",
        engine_version: "5.43.0",
        checks_requested: 165,
        checks_completed: 165,
        result_count: 412,
        fatal: null,
        services_unread: ["storage"],
        checks_raised: [],
        duration_seconds: 240,
      },
    ],
    summary: { total: 3, unexpected: 1, by_kind: { NATIVE_MISSED: 1, PROWLER_MISSED: 2 } },
    pairs: [
      {
        rule_id: "AZ-STO-001",
        rule_name: "Storage account allows public access",
        checks: ["storage_blob_public_access_level_is_disabled"],
        count: 1,
        expected: false,
        note: null,
      },
      {
        rule_id: "AZ-ID-005",
        rule_name: "Nothing enforces multi-factor authentication tenant-wide",
        checks: ["entra_security_defaults_enabled"],
        count: 2,
        expected: true,
        note: "Expected to disagree wherever Conditional Access is used.",
      },
    ],
    divergences: [
      {
        rule_id: "AZ-STO-001",
        rule_name: "Storage account allows public access",
        check_id: "storage_blob_public_access_level_is_disabled",
        kind: "NATIVE_MISSED",
        native_state: "PASS",
        prowler_state: "FAIL",
        expected: false,
        detail: null,
        resource: { id: "asset-1", name: "payroll", resource_type: "storage_account" },
        provider_resource_id: "/subscriptions/s/payroll",
      },
    ],
    ...overrides,
  };
}

function mount(body: EngineAudit) {
  vi.spyOn(api, "get").mockResolvedValue({ data: body, meta: {} });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <EngineAuditPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("the engine audit", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("leads with the disagreements nobody expected", async () => {
    mount(audit());

    expect(await screen.findByText("Unexpected disagreements")).toBeInTheDocument();
    expect(screen.getByText("unexpected")).toBeInTheDocument();
    expect(screen.getByText("expected")).toBeInTheDocument();
    expect(screen.getByText("Prowler failed, Cleave passed")).toBeInTheDocument();
    expect(screen.getByText(/Read these first/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "payroll" })).toHaveAttribute(
      "href",
      "/assets/asset-1",
    );
  });

  it("says an unread service reads as unknown, never as passing", async () => {
    mount(audit());

    expect(await screen.findByText(/Could not read storage/)).toBeInTheDocument();
  });

  it("says the engines agreed when they did", async () => {
    mount(
      audit({ pairs: [], divergences: [], summary: { total: 0, unexpected: 0, by_kind: {} } }),
    );

    expect(await screen.findByText("The engines agreed")).toBeInTheDocument();
  });

  it("says the scanner service is off rather than showing an empty audit", async () => {
    mount(audit({ engine: { ...ENGINE, enabled: false }, scan: null }));

    expect(
      await screen.findByText("The extended checks are not switched on"),
    ).toBeInTheDocument();
  });
});
