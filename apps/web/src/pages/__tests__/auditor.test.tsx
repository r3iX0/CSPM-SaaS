/**
 * What an auditor sees (DECISIONS.md §211, §218).
 *
 * Four things must hold. A link opened while signed out survives the sign-in
 * that follows it, and leaves the address bar. Opening is a click, not
 * something done on arrival, and a refusal for the wrong address keeps the link
 * for the right one. The package is drawn as counts with the hash that seals
 * it. And the archive is tested here: one that is what was sealed says so, one
 * that is not says that.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { strToU8, zipSync } from "fflate";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AuditorGrantPage, AuditorPage } from "../Auditor";
import { api, ApiError } from "@/lib/api";
import { sha256Hex } from "@/lib/archiveVerify";
import { forgetGrant, heldGrant } from "@/lib/pendingGrant";
import type { AuditorGrant, AuditPackageDetail } from "@/lib/types";

const TOKEN = "a-grant-token-from-the-link-long-enough";
const MANIFEST = '{"package":"sealed"}';
const sha = (text: string) => sha256Hex(strToU8(text));
const SEALED = await sha(MANIFEST);

let signedIn = true;
vi.mock("@/lib/useAuth", () => ({ useAuthToken: () => (signedIn ? "jwt" : null) }));

function grant(overrides: Partial<AuditorGrant> = {}): AuditorGrant {
  return {
    id: "g-1",
    package_id: "p-1",
    package_name: "SOC 2 Type II, FY2026",
    organization_name: "Contoso",
    email: "auditor@firm.example",
    opened_at: "2026-10-01T09:00:00Z",
    expires_at: "2026-11-01T09:00:00Z",
    ...overrides,
  };
}

function detail(): AuditPackageDetail {
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
    manifest_sha256: SEALED,
    sealed_by: "u-1",
    sealed_at: "2026-10-01T08:00:00Z",
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
      payloads_stored: 40,
    },
  };
}

/** A zip laid out as the API writes one, with a payload changed when asked. */
async function archive(changed = false): Promise<Blob> {
  const files: Record<string, string> = {
    "manifest.json": MANIFEST,
    "evidence/payloads/aaa.json": '{"a":1}',
  };
  const sums = (
    await Promise.all(
      Object.entries(files).map(async ([path, content]) => `${await sha(content)}  ${path}\n`),
    )
  ).join("");
  const folder: Record<string, Uint8Array> = { "pkg/SHA256SUMS": strToU8(sums) };
  for (const [path, content] of Object.entries(files)) {
    folder[`pkg/${path}`] = strToU8(changed && path.includes("payloads") ? '{"a":2}' : content);
  }
  const bytes = zipSync(folder);
  const buffer = bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
  // jsdom's Blob has no `arrayBuffer`; the page reads one, so this stands in for the response.
  return { arrayBuffer: () => Promise.resolve(buffer) } as unknown as Blob;
}

function mount(
  at: string,
  { grants = [grant()], fail }: { grants?: AuditorGrant[]; fail?: ApiError } = {},
) {
  vi.spyOn(api, "get").mockImplementation((path: string) => {
    if (fail) return Promise.reject(fail);
    if (path.endsWith("/package")) return Promise.resolve({ data: detail(), meta: {} });
    if (path.endsWith("/auditor/grants")) return Promise.resolve({ data: grants, meta: {} });
    return Promise.resolve({ data: grant(), meta: {} });
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[at]}>
        <Routes>
          <Route path="/auditor" element={<AuditorPage />} />
          <Route path="/auditor/:grantId" element={<AuditorGrantPage />} />
          <Route path="/sign-in" element={<main>Sign in page</main>} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("AuditorPage", () => {
  beforeEach(() => {
    signedIn = true;
    forgetGrant();
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("holds the link through a sign-in", async () => {
    signedIn = false;
    mount(`/auditor#${TOKEN}`);
    expect(await screen.findByRole("link", { name: "Sign in to open" })).toBeInTheDocument();
    await waitFor(() => expect(heldGrant()).toBe(TOKEN));
  });

  it("sends a signed-out reader with no link to sign in", async () => {
    signedIn = false;
    mount("/auditor");
    expect(await screen.findByText("Sign in page")).toBeInTheDocument();
  });

  it("opens the package on a click and goes to it", async () => {
    const post = vi.spyOn(api, "post").mockResolvedValue({ data: grant({ id: "g-9" }), meta: {} });
    mount(`/auditor#${TOKEN}`, { grants: [] });

    await userEvent.click(await screen.findByRole("button", { name: "Open package" }));

    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/v1/auditor/grants/open", { token: TOKEN }),
    );
    await waitFor(() => expect(heldGrant()).toBeNull());
    expect(
      await screen.findByRole("heading", { name: "SOC 2 Type II, FY2026" }),
    ).toBeInTheDocument();
  });

  it("keeps the link when the address is not the one it was made for", async () => {
    vi.spyOn(api, "post").mockRejectedValue(
      new ApiError("FORBIDDEN", "This link was made for another address.", 403),
    );
    mount(`/auditor#${TOKEN}`, { grants: [] });

    await userEvent.click(await screen.findByRole("button", { name: "Open package" }));

    expect(await screen.findByText("This link was made for another address.")).toBeInTheDocument();
    expect(heldGrant()).toBe(TOKEN);
  });

  it("forgets a link that can never work", async () => {
    vi.spyOn(api, "post").mockRejectedValue(
      new ApiError("CONFLICT", "This link has expired.", 409),
    );
    mount(`/auditor#${TOKEN}`, { grants: [] });

    await userEvent.click(await screen.findByRole("button", { name: "Open package" }));

    expect(await screen.findByText("This link has expired.")).toBeInTheDocument();
    expect(heldGrant()).toBeNull();
  });

  it("lists the packages this account may read", async () => {
    mount("/auditor");
    expect(await screen.findByText("SOC 2 Type II, FY2026")).toBeInTheDocument();
    expect(screen.getByText(/Shared by Contoso/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Read" })).toHaveAttribute("href", "/auditor/g-1");
  });
});

describe("AuditorGrantPage", () => {
  beforeEach(() => {
    signedIn = true;
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("draws counts and the hash that seals the package", async () => {
    mount("/auditor/g-1");
    expect(await screen.findByText("61 controls")).toBeInTheDocument();
    expect(screen.getByText(SEALED)).toBeInTheDocument();
    expect(screen.getByText(/40 of 40 payloads still stored/)).toBeInTheDocument();
  });

  it("says an archive that is what was sealed is", async () => {
    vi.spyOn(api, "document").mockResolvedValue(await archive());
    mount("/auditor/g-1");

    await userEvent.click(await screen.findByRole("button", { name: "Download and check" }));

    expect(await screen.findByText(/all 2 listed files match/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Save the archive" })).toBeInTheDocument();
  });

  it("says an archive that is not what was sealed is not, and names why", async () => {
    vi.spyOn(api, "document").mockResolvedValue(await archive(true));
    mount("/auditor/g-1");

    await userEvent.click(await screen.findByRole("button", { name: "Download and check" }));

    expect(await screen.findByText("1 file differs from SHA256SUMS")).toBeInTheDocument();
    expect(screen.queryByText(/listed files match/)).not.toBeInTheDocument();
  });

  it("says why a package could not be opened", async () => {
    mount("/auditor/g-1", { fail: new ApiError("CONFLICT", "This grant is no longer open.", 409) });
    expect(await screen.findByText("This grant is no longer open.")).toBeInTheDocument();
  });
});
