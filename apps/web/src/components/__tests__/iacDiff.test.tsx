/**
 * Writing a finding's fix into the customer's own Terraform (DECISIONS.md §166).
 *
 * The file goes up as a multipart upload and a diff comes back -- or a reason
 * the edit was not made, which is an answer to show, not an error to raise.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { IacDiffCheck } from "@/components/security/IacDiffCheck";

const PATCHED = {
  filename: "storage.tf",
  outcome: "patched",
  diff: '--- a/storage.tf\n+++ b/storage.tf\n@@ -1,3 +1,3 @@\n-  min_tls_version = "TLS1_0"\n+  min_tls_version = "TLS1_2"\n',
  edits: [{ attribute: "min_tls_version", before: '"TLS1_0"', after: '"TLS1_2"', line: 3 }],
  decline_reason: null,
  detail: null,
  provider_version: null,
  checked_against: ["3.117.1", "4.81.0"],
};

const DECLINED = {
  ...PATCHED,
  outcome: "declined",
  diff: null,
  edits: [],
  decline_reason: "interpolated_name",
  detail: "A resource of this type takes its name from an expression.",
};

function mount(answer: unknown) {
  const fetchMock = vi.fn(async () => ({
    ok: true,
    status: 200,
    json: async () => ({ data: answer, error: null, meta: {} }),
  })) as unknown as typeof fetch;
  vi.stubGlobal("fetch", fetchMock);
  const client = new QueryClient({ defaultOptions: { mutations: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <IacDiffCheck findingId="finding-1" resourceName="payroll" />
    </QueryClientProvider>,
  );
  return fetchMock as unknown as ReturnType<typeof vi.fn>;
}

async function upload() {
  const user = userEvent.setup();
  const file = new File(['resource "azurerm_storage_account" "p" {}'], "storage.tf");
  await user.upload(screen.getByLabelText(/Terraform file/), file);
  await user.click(screen.getByRole("button", { name: /Write the fix/ }));
  return user;
}

afterEach(() => vi.unstubAllGlobals());

describe("writing the fix into a Terraform file", () => {
  it("cannot be sent before a file is chosen, and says so by staying focusable", () => {
    mount(PATCHED);
    const send = screen.getByRole("button", { name: /Write the fix/ });
    expect(send).toHaveAttribute("aria-disabled", "true");
  });

  it("uploads the file as multipart, not as JSON", async () => {
    const fetchMock = mount(PATCHED);
    await upload();

    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toContain("/api/v1/findings/finding-1/iac-diff");
    expect(init.method).toBe("POST");
    expect(init.body).toBeInstanceOf(FormData);
    expect((init.body as FormData).get("file")).toBeInstanceOf(File);
    // The browser sets the multipart boundary; a JSON content type would break it.
    expect(new Headers(init.headers).get("Content-Type")).toBeNull();
  });

  it("shows the diff and offers it as a file", async () => {
    mount(PATCHED);
    await upload();

    expect(await screen.findByText(/min_tls_version = "TLS1_2"/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Download the diff/ })).toBeInTheDocument();
    // No lock file went up, so the release is not claimed as checked.
    expect(screen.getByText(/checked against azurerm 3\.117\.1 and 4\.81\.0/)).toBeInTheDocument();
  });

  it("asks the reviewer to check a block matched as the only one", async () => {
    mount({ ...PATCHED, matched_by: "sole_block" });
    await upload();

    expect(
      await screen.findByText(/only block of its kind in storage\.tf.*check it is payroll/i),
    ).toBeInTheDocument();
  });

  it("says nothing extra for a block matched by name", async () => {
    mount({ ...PATCHED, matched_by: "name" });
    await upload();

    await screen.findByText(/min_tls_version = "TLS1_2"/);
    expect(screen.queryByText(/block of its kind/)).toBeNull();
  });

  it("says why a fix was not written, and speaks it", async () => {
    mount(DECLINED);
    await upload();

    expect(
      await screen.findByText(/takes its name from an expression/, { selector: "p:not([role])" }),
    ).toBeInTheDocument();
    await waitFor(() =>
      expect(screen.getByRole("status")).toHaveTextContent(/Not written/),
    );
    expect(screen.queryByRole("button", { name: /Download the diff/ })).toBeNull();
  });
});
