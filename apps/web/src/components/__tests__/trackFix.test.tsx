/**
 * The queue has to be reachable from the work.
 *
 * `POST /remediation` existed from the start and nothing called it: the queue's
 * empty state sent the reader to the finding's detail page, and that page had
 * no way to assign anything. The queue could therefore only ever be empty.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { TrackFix } from "@/components/security/TrackFix";

const TASK = {
  id: "task-1",
  finding_id: "finding-1",
  risk_id: null,
  status: "TODO",
  priority: "HIGH",
  assigned_to: null,
  due_date: null,
  estimated_effort_minutes: 15,
  notes: null,
  completed_at: null,
  created_at: "2026-08-20T00:00:00Z",
};

const MEMBERS = [
  {
    id: "m-1",
    user_id: "user-1",
    email: "sam@example.com",
    role: "IT_ADMIN",
    joined_at: "2026-09-01T00:00:00Z",
    is_you: false,
  },
];

/** A request's JSON body, as `api` sends it: always a string. */
function bodyOf(init: RequestInit | undefined): unknown {
  return typeof init?.body === "string" ? (JSON.parse(init.body) as unknown) : undefined;
}

function patches(fetchMock: ReturnType<typeof vi.fn>): unknown[] {
  return fetchMock.mock.calls
    .filter(([, init]) => (init as RequestInit | undefined)?.method === "PATCH")
    .map(([, init]) => bodyOf(init as RequestInit));
}

function mount(tasks: unknown[], status = "OPEN") {
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => ({
    ok: true,
    status: init?.method === "POST" ? 201 : 200,
    json: async () => ({
      data:
        init?.method === "POST"
          ? TASK
          : init?.method === "PATCH"
            ? { ...TASK, ...(bodyOf(init) as object) }
            : (input instanceof Request ? input.url : input.toString()).includes("/members")
              ? MEMBERS
              : tasks,
      error: null,
      meta: {},
    }),
  })) as unknown as typeof fetch;
  vi.stubGlobal("fetch", fetchMock);

  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <TrackFix findingId="finding-1" status={status as "OPEN"} effortMinutes={15} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return fetchMock as unknown as ReturnType<typeof vi.fn>;
}

afterEach(() => vi.unstubAllGlobals());

describe("tracking a fix", () => {
  it("assigns the work through the API the queue reads", async () => {
    const fetchMock = mount([]);
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: /Track this fix/ }));

    await waitFor(() => {
      const post = fetchMock.mock.calls.find(
        ([, init]) => (init as RequestInit | undefined)?.method === "POST",
      );
      expect(post?.[0]).toContain("/api/v1/remediation");
      expect((post?.[1] as RequestInit).body).toBe(JSON.stringify({ finding_id: "finding-1" }));
    });
  });

  it("does not promise the finding closes", async () => {
    mount([]);

    expect(await screen.findByText(/does not close the finding — a scan does/)).toBeInTheDocument();
  });

  it("says the work is already tracked rather than offering it twice", async () => {
    // The API refuses a second open task for one finding, so a button that was
    // always offered would be a button that sometimes only produced an error.
    mount([TASK]);

    expect(await screen.findByText(/In the remediation queue since/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Track this fix/ })).not.toBeInTheDocument();
  });

  it("marks tracked work done where the fix is, and says done is not closed", async () => {
    // The fix is read in full in the remediation page's sheet, so finishing
    // the work belongs at its foot too (DECISIONS.md §202).
    const fetchMock = mount([TASK]);
    const user = userEvent.setup();

    expect(await screen.findByText(/Marked done does not close a finding/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Mark done" }));

    await waitFor(() => {
      const patch = fetchMock.mock.calls.find(
        ([, init]) => (init as RequestInit | undefined)?.method === "PATCH",
      );
      expect(patch?.[0]).toContain("/api/v1/remediation/task-1");
      expect((patch?.[1] as RequestInit).body).toBe(JSON.stringify({ status: "DONE" }));
    });
  });

  it("offers only reopening on work already marked done (§208)", async () => {
    const fetchMock = mount([{ ...TASK, status: "DONE", completed_at: "2026-09-21T10:00:00Z" }]);
    const user = userEvent.setup();

    expect(await screen.findByText(/^Done /)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Mark done/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Track this fix/ })).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Reopen" }));
    await waitFor(() => expect(patches(fetchMock)).toEqual([{ status: "TODO" }]));
  });

  it("starts the work, and drops it from the queue (§208)", async () => {
    const fetchMock = mount([TASK]);
    const user = userEvent.setup();

    await user.click(await screen.findByRole("button", { name: "Start" }));
    await user.click(screen.getByRole("button", { name: "Stop tracking" }));

    await waitFor(() =>
      expect(patches(fetchMock)).toEqual([{ status: "IN_PROGRESS" }, { status: "CANCELLED" }]),
    );
  });

  it("gives the work a due date and takes it off again (§208)", async () => {
    const fetchMock = mount([{ ...TASK, due_date: "2026-10-09" }]);

    const due = await screen.findByLabelText("Due");
    expect(due).toHaveValue("2026-10-09");
    fireEvent.change(due, { target: { value: "" } });

    await waitFor(() => expect(patches(fetchMock)).toEqual([{ due_date: null }]));
  });

  it("names the owner from the organization's members", async () => {
    mount([{ ...TASK, assigned_to: "user-1" }]);

    expect(await screen.findByText("sam@example.com")).toBeInTheDocument();
  });

  it("offers nothing on a finding a scan has already closed", async () => {
    mount([], "RESOLVED");

    await waitFor(() =>
      expect(screen.queryByRole("button", { name: /Track this fix/ })).not.toBeInTheDocument(),
    );
  });
});
