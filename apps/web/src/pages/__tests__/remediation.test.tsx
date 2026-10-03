/**
 * The queue has to say what the work is.
 *
 * `GET /remediation` returns a task and nothing of the finding behind it, so
 * the page used to offer a severity badge, a status and a link reading "View
 * finding" — everything about the record and nothing about the problem. A
 * person deciding what to do next had to open every card to find out.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { RemediationPage } from "@/pages/Remediation";

const TASK = {
  id: "task-1",
  finding_id: "finding-1",
  risk_id: null,
  status: "TODO",
  priority: "CRITICAL",
  due_date: null,
  estimated_effort_minutes: 15,
  notes: null,
  completed_at: null,
  created_at: "2026-08-01T00:00:00Z",
};

const FINDING = {
  id: "finding-1",
  rule_id: "AZ-STORAGE-001",
  severity: "CRITICAL",
  status: "IN_PROGRESS",
  title: "Storage account allows public blob access",
  description: "",
  evidence: {},
  remediation: "",
  rule_version: "1.0",
  risk_score: 91,
  first_detected_at: "2026-08-01T00:00:00Z",
  last_detected_at: "2026-08-01T00:00:00Z",
  resolved_at: null,
  resolved_by_scan_id: null,
  resource: {
    id: "asset-1",
    name: "prodstorage",
    resource_type: "STORAGE_ACCOUNT",
    environment: "PRODUCTION",
    region: "westeurope",
    criticality: "HIGH",
    data_sensitivity: "HIGH",
    public_exposure: "HIGH",
  },
};

function renderPage(entry = "/remediation") {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[entry]}>
        <RemediationPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

let tasks: Record<string, unknown>[] = [TASK];
let openFindings: Record<string, unknown>[] = [{ ...FINDING, status: "OPEN" }];

describe("the remediation queue", () => {
  beforeEach(() => {
    tasks = [TASK];
    openFindings = [{ ...FINDING, status: "OPEN" }];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        const body = url.includes("/findings/")
          ? FINDING
          : url.includes("/findings?")
            ? openFindings
            : tasks;
        return {
          ok: true,
          status: 200,
          json: async () => ({ data: body, error: null, meta: {} }),
        } as Response;
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("offers the worst open findings when the queue is empty", async () => {
    // "Track a finding from its detail page", to somebody with fifty-eight
    // open ones, was a page away from the answer (DECISIONS.md §187).
    tasks = [];
    renderPage();

    const start = await screen.findByRole("region", { name: "Where to start" });
    expect(start).toHaveTextContent("Storage account allows public blob access");
    expect(
      screen.getByRole("button", {
        name: "Track the fix for Storage account allows public blob access",
      }),
    ).toBeInTheDocument();
  });

  it("names the finding and the asset the work is on, and opens its fix", async () => {
    // The title opens the fix, read in full here; the finding is a link
    // inside it (DECISIONS.md §202).
    renderPage();
    const user = userEvent.setup();

    const title = await screen.findByRole("button", {
      name: "Storage account allows public blob access",
    });
    expect(await screen.findByText(/prodstorage/)).toBeInTheDocument();

    await user.click(title);
    const sheet = await screen.findByRole("dialog");
    expect(within(sheet).getByText("Recommended fix")).toBeInTheDocument();
    expect(within(sheet).getByRole("link", { name: /Open finding/ })).toHaveAttribute(
      "href",
      "/findings/finding-1",
    );
  });

  it("opens a fix nobody has tracked yet, to read before committing to it", async () => {
    // A finding's "Open fix" lands here whether or not the work is queued.
    tasks = [];
    renderPage("/remediation?fix=finding-1");

    const sheet = await screen.findByRole("dialog");
    const track = await within(sheet).findByRole("button", { name: /Track this fix/ });
    // Under the title, not below the steps and every form of them (§205).
    expect(track.closest('[data-slot="sheet-header"]')).not.toBeNull();
    expect(within(sheet).getByRole("button", { name: /Verify it now/ })).toBeInTheDocument();
  });

  it("keeps offering what is not in the queue once something is (§205)", async () => {
    // Offered only to an empty queue, the list went with the first task
    // tracked, and the page had no way left to add any.
    openFindings = [
      { ...FINDING, status: "OPEN" },
      { ...FINDING, id: "finding-2", status: "OPEN", title: "Key vault purge protection off" },
    ];
    renderPage();

    const rest = await screen.findByRole("region", { name: "Not in the queue yet" });
    expect(rest).toHaveTextContent("Key vault purge protection off");
    // finding-1 is the queued task: it is offered once, in the queue.
    expect(within(rest).queryByText("Storage account allows public blob access")).toBeNull();
    expect(
      within(rest).getByRole("button", {
        name: "Track the fix for Key vault purge protection off",
      }),
    ).toBeInTheDocument();
  });

  it("finishes tracked work in the header of its fix", async () => {
    renderPage("/remediation?fix=finding-1");

    const sheet = await screen.findByRole("dialog");
    expect(await within(sheet).findByRole("button", { name: /Mark done/ })).toBeInTheDocument();
    expect(within(sheet).queryByRole("button", { name: /Track this fix/ })).toBeNull();
  });

  it("says when the work sits on an attack path, and only then (§127)", async () => {
    tasks = [{ ...TASK, on_routes: 3 }];
    renderPage();

    expect(await screen.findByText(/on 3 attack paths/)).toBeInTheDocument();
  });

  it("says nothing about routes for work that is on none", async () => {
    tasks = [{ ...TASK, on_routes: 0 }];
    renderPage();

    await screen.findByText(/prodstorage/);
    expect(screen.queryByText(/on \d+ attack path/)).toBeNull();
  });

  it("says work marked done waits on a scan, and never that the finding closed", async () => {
    tasks = [{ ...TASK, status: "DONE", completed_at: "2026-09-21T10:00:00Z" }];
    renderPage();

    expect(await screen.findByText("Waiting on a scan")).toBeInTheDocument();
    expect(screen.queryByText("Verified fixed")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Mark done/ })).not.toBeInTheDocument();
    expect(screen.getByText(/Marked done does not close a finding/)).toBeInTheDocument();
  });
});

describe("the queue, grouped by rule (DECISIONS.md §203)", () => {
  const RULE_FINDING = {
    ...FINDING,
    rule_name: "Public blob access",
    remediation: "Turn off public blob access.",
    remediation_spec: {
      expected_state: [],
      cli: ["az storage account update --name <account> --allow-blob-public-access false"],
      terraform: [],
      azure_policy: null,
      notes: null,
    },
  };
  const BY_ID: Record<string, object> = {
    "finding-1": RULE_FINDING,
    "finding-2": {
      ...RULE_FINDING,
      id: "finding-2",
      resource: { ...FINDING.resource, id: "asset-2", name: "devstorage" },
    },
  };
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    fetchMock = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = input instanceof Request ? input.url : input.toString();
      const id = /\/findings\/([^/?]+)$/.exec(url)?.[1];
      const body =
        init?.method === "PATCH"
          ? { ...TASK, status: "DONE" }
          : id
            ? BY_ID[id]
            : url.includes("/findings?")
              ? // The rule's open findings: the two tracked, and one nobody has.
                [
                  { ...RULE_FINDING, status: "OPEN" },
                  { ...BY_ID["finding-2"], status: "OPEN" },
                  { ...RULE_FINDING, id: "finding-3", status: "OPEN" },
                ]
              : url.includes("/assets/")
                ? { provider_resource_id: "/subscriptions/s1/resourceGroups/rg/x" }
                : [TASK, { ...TASK, id: "task-2", finding_id: "finding-2" }];
      const response: Pick<Response, "ok" | "status" | "json"> = {
        ok: true,
        status: 200,
        json: () => Promise.resolve({ data: body, error: null, meta: {} }),
      };
      // The page reads only these three members of a response.
      return Promise.resolve(response as Response);
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("draws two tasks of one rule as one row, naming both assets", async () => {
    renderPage();

    expect(await screen.findByRole("button", { name: "Public blob access" })).toBeInTheDocument();
    expect(screen.getByText(/2 assets: prodstorage, devstorage/)).toBeInTheDocument();
    // No queue row of its own; finding-3, untracked, is offered below the queue.
    const rest = await screen.findByRole("region", { name: "Not in the queue yet" });
    const titles = screen.queryAllByRole("button", {
      name: "Storage account allows public blob access",
    });
    expect(titles.every((title) => rest.contains(title))).toBe(true);
  });

  it("opens the rule's fix as one script over every asset, with the work done together", async () => {
    renderPage();
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: "Public blob access" }));
    const sheet = await screen.findByRole("dialog");
    expect(within(sheet).getByRole("button", { name: /Mark all 2 done/ })).toBeInTheDocument();
    expect(await within(sheet).findByRole("button", { name: /Track 1 more/ })).toBeInTheDocument();

    await user.click(within(sheet).getByRole("tab", { name: "CLI" }));
    const script = within(sheet).getByText(/# prodstorage/);
    expect(script).toHaveTextContent("# devstorage");
  });

  it("marks every open task of the rule done from its row", async () => {
    renderPage();
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: /Mark all done/ }));

    await vi.waitFor(() => {
      const patched = fetchMock.mock.calls
        .filter(([, init]) => (init as RequestInit | undefined)?.method === "PATCH")
        .map(([url]) => String(url));
      expect(patched).toEqual(
        expect.arrayContaining([
          expect.stringContaining("/remediation/task-1"),
          expect.stringContaining("/remediation/task-2"),
        ]),
      );
    });
  });
});
