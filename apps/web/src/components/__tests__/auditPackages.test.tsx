/**
 * The owner's side of audit packages (DECISIONS.md §208, §211, §218).
 *
 * What must hold: a package is sealed from exactly what was chosen, and the page
 * says what a package holds as counts and the hash that seals it, never as
 * controls. Checking the seal says plainly when it fails. A link made for an
 * auditor is shown once and the dialog holding it stays until it is copied --
 * Cleave keeps only its hash. A grant is revoked behind a confirmation, and what
 * the auditor read is the grant's own trail.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AuditPackagesSection } from "../settings/AuditPackages";
import { api } from "@/lib/api";
import type {
  AuditGrant,
  AuditGrantEvent,
  AuditPackage,
  AuditPackageDetail,
  AuditPackageVerification,
  ComplianceFramework,
} from "@/lib/types";

/** The names the browser was asked to save files under, from the anchor `saveBlob` clicks. */
const saved: string[] = [];

const HASH = "c".repeat(64);

function pack(overrides: Partial<AuditPackage> = {}): AuditPackage {
  return {
    id: "p-1",
    name: "SOC 2 Type II, FY2026",
    frameworks: [
      {
        id: "SOC2",
        name: "SOC 2",
        short_name: "SOC 2",
        version: "2017",
        authority: "AICPA",
        url: "https://example.test",
        summary: "",
        scope_note: "",
      },
    ],
    scan_id: "s-1",
    scan_status: "COMPLETED",
    scan_completed_at: "2026-09-30T00:00:00Z",
    period_start: null,
    period_end: null,
    manifest_sha256: HASH,
    sealed_by: "u-1",
    sealed_at: "2026-10-01T08:00:00Z",
    ...overrides,
  };
}

function detail(overrides: Partial<AuditPackageDetail> = {}): AuditPackageDetail {
  return {
    ...pack(),
    assessment: [
      {
        framework_id: "SOC2",
        controls: 61,
        statuses: { FAILING: 4, INCONCLUSIVE: 2, PASSING: 30, NOT_ASSESSED: 0, NOT_COVERED: 25 },
      },
    ],
    evidence: {
      readings: 120,
      outcomes: { COMPLETE: 120 },
      payloads_named: 40,
      payloads_stored: 38,
    },
    ...overrides,
  };
}

function grant(overrides: Partial<AuditGrant> = {}): AuditGrant {
  return {
    id: "g-1",
    package_id: "p-1",
    email: "auditor@firm.example",
    status: "PENDING",
    created_by: "u-1",
    created_at: "2026-10-01T09:00:00Z",
    expires_at: "2026-11-01T09:00:00Z",
    opened_at: null,
    revoked_at: null,
    ...overrides,
  };
}

function framework(overrides: Partial<ComplianceFramework> = {}): ComplianceFramework {
  return {
    id: "SOC2",
    name: "SOC 2",
    short_name: "SOC 2",
    version: "2017",
    authority: "AICPA",
    url: "https://example.test",
    summary: "",
    scope_note: "",
    control_count: 61,
    status_counts: { FAILING: 0, INCONCLUSIVE: 0, PASSING: 0, NOT_ASSESSED: 61, NOT_COVERED: 0 },
    coverage_ratio: null,
    open_finding_count: 0,
    ...overrides,
  };
}

function mount({
  packages = [pack()],
  grants = [] as AuditGrant[],
  events = [] as AuditGrantEvent[],
  verification = { verified: true },
}: {
  packages?: AuditPackage[];
  grants?: AuditGrant[];
  events?: AuditGrantEvent[];
  verification?: Partial<AuditPackageVerification>;
} = {}) {
  vi.spyOn(api, "get").mockImplementation((path: string) => {
    if (path.includes("/events")) return Promise.resolve({ data: events, meta: {} });
    if (path.includes("/verification")) {
      return Promise.resolve({
        data: { sealed_sha256: HASH, recomputed_sha256: HASH, checked_at: "", ...verification },
        meta: {},
      });
    }
    if (path.includes("/audit-grants")) return Promise.resolve({ data: grants, meta: {} });
    if (path.includes("/audit-packages/p-1")) return Promise.resolve({ data: detail(), meta: {} });
    if (path.includes("/audit-packages")) return Promise.resolve({ data: packages, meta: {} });
    return Promise.resolve({
      data: [framework(), framework({ id: "ISO_27001", name: "ISO 27001" })],
      meta: {},
    });
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <AuditPackagesSection organizationId="o-1" />
    </QueryClientProvider>,
  );
}

async function openPackage(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("button", { name: /SOC 2 Type II, FY2026/ }));
}

describe("AuditPackagesSection", () => {
  beforeEach(() => {
    // jsdom has no object URLs and does not follow a click on an anchor.
    URL.createObjectURL = () => "blob:test";
    URL.revokeObjectURL = () => {};
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      saved.push(this.download);
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    saved.length = 0;
  });

  it("offers to seal the first package", async () => {
    mount({ packages: [] });
    expect(await screen.findByText("No packages sealed yet")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Seal a package" })).toBeInTheDocument();
  });

  it("seals exactly the standards that were chosen", async () => {
    const user = userEvent.setup();
    const post = vi.spyOn(api, "post").mockResolvedValue({ data: pack(), meta: {} });
    mount({ packages: [] });

    await user.click(await screen.findByRole("button", { name: "Seal a package" }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText("Name"), "  Audit FY26  ");
    await user.click(await within(dialog).findByRole("checkbox", { name: "ISO 27001" }));
    await user.type(within(dialog).getByLabelText("Audit period starts"), "2026-01-01");
    await user.click(within(dialog).getByRole("button", { name: "Seal package" }));

    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/v1/audit-packages", {
        name: "Audit FY26",
        framework_ids: ["ISO_27001"],
        period_start: "2026-01-01",
        period_end: null,
      }),
    );
  });

  it("cannot seal with no standard chosen", async () => {
    const user = userEvent.setup();
    mount({ packages: [] });

    await user.click(await screen.findByRole("button", { name: "Seal a package" }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText("Name"), "Audit");

    expect(within(dialog).getByRole("button", { name: "Seal package" })).toHaveAttribute(
      "aria-disabled",
      "true",
    );
  });

  it("draws a package as counts and the hash that seals it", async () => {
    const user = userEvent.setup();
    mount();
    await openPackage(user);

    expect(await screen.findByText("61 controls")).toBeInTheDocument();
    expect(screen.getByText(HASH)).toBeInTheDocument();
    expect(screen.getByText(/38 of 40 payloads still stored/)).toBeInTheDocument();
  });

  it("says when the stored rows no longer give the sealed hash", async () => {
    const user = userEvent.setup();
    mount({ verification: { verified: false, recomputed_sha256: "d".repeat(64) } });
    await openPackage(user);

    await user.click(await screen.findByRole("button", { name: "Check seal" }));

    expect(
      await screen.findByText("The stored rows no longer give the sealed hash."),
    ).toBeInTheDocument();
  });

  it("downloads the archive under a name made from the package's", async () => {
    const user = userEvent.setup();
    const blob = new Blob(["zip"]);
    const document = vi.spyOn(api, "document").mockResolvedValue(blob);
    mount();
    await openPackage(user);

    await user.click(await screen.findByRole("button", { name: "Download archive" }));

    await waitFor(() => expect(saved).toEqual(["soc-2-type-ii-fy2026.zip"]));
    expect(document).toHaveBeenCalledWith("/api/v1/audit-packages/p-1/archive");
  });

  it("shows a link once, and the dialog stays until it is copied", async () => {
    const user = userEvent.setup();
    const post = vi.spyOn(api, "post").mockResolvedValue({
      data: { ...grant(), link: "https://app.example/auditor#tok" },
      meta: {},
    });
    mount();
    await openPackage(user);

    await user.click(await screen.findByRole("button", { name: "Give to an auditor" }));
    const dialog = await screen.findByRole("dialog");
    await user.type(
      within(dialog).getByLabelText("Auditor's email address"),
      "auditor@firm.example",
    );
    await user.click(within(dialog).getByRole("button", { name: "Make link" }));

    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/v1/audit-grants", {
        package_id: "p-1",
        email: "auditor@firm.example",
        expires_in_days: 30,
      }),
    );
    expect(await screen.findByText("https://app.example/auditor#tok")).toBeInTheDocument();
    const done = screen.getByRole("button", { name: "Done" });
    expect(done).toHaveAttribute("aria-disabled", "true");
    await user.click(screen.getByRole("checkbox", { name: "I have copied the link" }));
    expect(done).not.toHaveAttribute("aria-disabled", "true");
  });

  it("will not make a link that lasts longer than the API allows", async () => {
    const user = userEvent.setup();
    mount();
    await openPackage(user);

    await user.click(await screen.findByRole("button", { name: "Give to an auditor" }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText("Auditor's email address"), "a@firm.example");
    const days = within(dialog).getByLabelText("Access lasts (days)");
    await user.clear(days);
    await user.type(days, "91");

    expect(within(dialog).getByRole("button", { name: "Make link" })).toHaveAttribute(
      "aria-disabled",
      "true",
    );
  });

  it("revokes a grant only after it is confirmed", async () => {
    const user = userEvent.setup();
    const del = vi.spyOn(api, "del").mockResolvedValue({ data: { revoked: "g-1" }, meta: {} });
    mount({ grants: [grant()] });
    await openPackage(user);

    await user.click(await screen.findByRole("button", { name: "Revoke auditor@firm.example" }));
    expect(del).not.toHaveBeenCalled();
    const confirm = await screen.findByRole("alertdialog");
    await user.click(within(confirm).getByRole("button", { name: "Revoke" }));

    await waitFor(() => expect(del).toHaveBeenCalledWith("/api/v1/audit-grants/g-1"));
  });

  it("offers no revoke for a grant that has already ended", async () => {
    const user = userEvent.setup();
    mount({ grants: [grant({ status: "REVOKED", revoked_at: "2026-10-02T00:00:00Z" })] });
    await openPackage(user);

    expect(await screen.findByText("Revoked")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Revoke auditor/ })).not.toBeInTheDocument();
  });

  it("shows what an auditor read from the grant's own trail", async () => {
    const user = userEvent.setup();
    mount({
      grants: [grant({ status: "OPENED", opened_at: "2026-10-02T10:00:00Z" })],
      events: [
        {
          id: "e-1",
          grant_id: "g-1",
          event: "ARCHIVE_DOWNLOADED",
          user_id: "u-9",
          detail: {},
          at: "2026-10-02T11:00:00Z",
        },
      ],
    });
    await openPackage(user);

    await user.click(await screen.findByRole("button", { name: "What they read" }));

    expect(await screen.findByText(/Downloaded the archive/)).toBeInTheDocument();
  });
});
