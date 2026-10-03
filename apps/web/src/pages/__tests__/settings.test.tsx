/**
 * Settings: the half of CloudGuard's evidence that a person supplies.
 *
 * Two things must survive here. A context declaration is a *statement* — it is
 * replaced whole, and an unset field withdraws a claim rather than declaring
 * the value unknown. And UNKNOWN is never offered: it is CloudGuard's own word
 * for "nothing said anything", so a choice for it would let a customer assert
 * an absence that saying nothing already asserts — and the API rejects it, so
 * the option would always fail.
 *
 * The pages are one per topic under /settings (DECISIONS.md §207), so each
 * test mounts the address it is about.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { SettingsPage } from "../Settings";
import { api } from "@/lib/api";
import type {
  AuditEntry,
  CloudAccount,
  ContextDeclaration,
  Invitation,
  Member,
  Organization,
  Webhook,
} from "@/lib/types";

function organization(overrides: Partial<Organization> = {}): Organization {
  return {
    id: "o-1",
    name: "Contoso",
    slug: "contoso-a1b2c3",
    industry: "Banking",
    country: "AL",
    created_at: "2026-01-01T00:00:00Z",
    role: "OWNER",
    ...overrides,
  };
}

function member(overrides: Partial<Member> = {}): Member {
  return {
    id: "m-1",
    user_id: "u-1",
    email: "owner@contoso.example",
    role: "OWNER",
    joined_at: "2026-01-01T00:00:00Z",
    is_you: true,
    ...overrides,
  };
}

function account(overrides: Partial<CloudAccount> = {}): CloudAccount {
  return {
    id: "a-1",
    provider: "azure",
    account_name: "Production subscription",
    tenant_id: "t-1",
    subscription_id: "sub-1",
    consent_status: "GRANTED",
    rbac_verified_at: "2026-08-01T00:00:00Z",
    status: "ACTIVE",
    status_detail: null,
    last_scan_at: null,
    is_scannable: true,
    ...overrides,
  };
}

const sandbox = () => account({ id: "a-2", account_name: "Sandbox", subscription_id: "s-2" });

function declaration(overrides: Partial<ContextDeclaration> = {}): ContextDeclaration {
  return {
    cloud_account_id: "a-1",
    environment: "production",
    criticality: "HIGH",
    data_sensitivity: "CRITICAL",
    note: "Holds cardholder data",
    declared_by_user_id: "u-1",
    declared_at: "2026-08-31T09:00:00Z",
    ...overrides,
  };
}

/** Where the router is, so a redirect can be asserted. */
function Location() {
  const { pathname, search, hash } = useLocation();
  return <output data-testid="location">{`${pathname}${search}${hash}`}</output>;
}

function mount({
  at = "/settings/general",
  orgs = [organization()],
  accounts = [account()],
  declarations = [] as ContextDeclaration[],
  members = [member()],
  invitations = [] as Invitation[],
  activity = [] as AuditEntry[],
  webhooks = [] as Webhook[],
}: {
  at?: string;
  orgs?: Organization[];
  accounts?: CloudAccount[];
  declarations?: ContextDeclaration[];
  members?: Member[];
  invitations?: Invitation[];
  activity?: AuditEntry[];
  webhooks?: Webhook[];
} = {}) {
  const get = vi.spyOn(api, "get").mockImplementation((path: string) => {
    if (path.includes("/context-declarations")) {
      return Promise.resolve({ data: declarations, meta: {} });
    }
    if (path.includes("cloud-accounts")) {
      return Promise.resolve({ data: accounts, meta: {} });
    }
    if (path.endsWith("/members")) {
      return Promise.resolve({ data: members, meta: {} });
    }
    if (path.endsWith("/invitations")) {
      return Promise.resolve({ data: invitations, meta: {} });
    }
    if (path.endsWith("/webhooks")) {
      return Promise.resolve({ data: webhooks, meta: {} });
    }
    if (path.includes("/audit-log")) {
      return Promise.resolve({ data: activity, meta: { total: activity.length } });
    }
    return Promise.resolve({ data: orgs, meta: {} });
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[at]}>
        <Routes>
          <Route path="/settings/*" element={<SettingsPage />} />
        </Routes>
        <Location />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  return { get };
}

const location = () => screen.getByTestId("location").textContent;

describe("Settings pages", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("lands /settings on General", async () => {
    mount({ at: "/settings" });
    await waitFor(() => expect(location()).toBe("/settings/general"));
  });

  it("sends an anchor from the single page to the page that now holds it", async () => {
    // An asset's "declare it" link was /settings#context before the split.
    mount({ at: "/settings#context" });
    await waitFor(() => expect(location()).toBe("/settings/context"));
  });

  it("lists only the pages this reader may open, and marks the current one", async () => {
    mount({ at: "/settings/context", orgs: [organization({ role: "VIEWER" })] });
    const nav = await screen.findByRole("navigation", { name: "Settings sections" });
    const names = within(nav)
      .getAllByRole("link")
      .map((link) => link.textContent);
    expect(names).toEqual(["General", "Members", "Risk context", "Security", "Preferences"]);
    expect(within(nav).getByRole("link", { name: "Risk context" })).toHaveAttribute(
      "aria-current",
      "page",
    );
  });

  it("turns a page this reader may not see back to General", async () => {
    mount({ at: "/settings/activity", orgs: [organization({ role: "VIEWER" })] });
    await waitFor(() => expect(location()).toBe("/settings/general"));
  });
});

describe("General", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("shows the organization as it currently describes itself", async () => {
    mount();

    await waitFor(() => expect(screen.getByLabelText("Name")).toHaveValue("Contoso"));
    expect(screen.getByLabelText("Industry")).toHaveValue("Banking");
    // The country by name, not the code the reader used to have to know.
    expect(screen.getByLabelText("Country")).toHaveTextContent("Albania");
  });

  it("never lets the identifier be edited, and says why", async () => {
    mount();

    // Read-only rather than disabled, so it can still be selected and copied.
    await waitFor(() => expect(screen.getByLabelText("Identifier")).toHaveAttribute("readonly"));
    expect(screen.getByText(/unchanged by a rename/)).toBeInTheDocument();
  });

  it("offers Save only once something changed, and Discard puts it back", async () => {
    mount();

    const save = await screen.findByRole("button", { name: "Save changes" });
    expect(save).toHaveAttribute("aria-disabled", "true");

    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Contoso Group" } });
    expect(save).not.toHaveAttribute("aria-disabled", "true");
    expect(screen.getByText("Unsaved changes")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Discard" }));
    expect(screen.getByLabelText("Name")).toHaveValue("Contoso");
    expect(screen.queryByText("Unsaved changes")).not.toBeInTheDocument();
  });

  it("saves an edited name without clearing what was not touched", async () => {
    const patch = vi
      .spyOn(api, "patch")
      .mockResolvedValue({ data: organization({ name: "Contoso Group" }), meta: {} });
    mount();

    const name = await screen.findByLabelText("Name");
    fireEvent.change(name, { target: { value: "Contoso Group" } });
    fireEvent.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() =>
      expect(patch).toHaveBeenCalledWith("/api/v1/organizations", {
        name: "Contoso Group",
        industry: "Banking",
        country: "AL",
      }),
    );
  });

  it("chooses a country by name and stores its code", async () => {
    const user = userEvent.setup();
    const patch = vi.spyOn(api, "patch").mockResolvedValue({ data: organization(), meta: {} });
    mount();

    await user.click(await screen.findByLabelText("Country"));
    await user.type(await screen.findByLabelText("Search countries…"), "Portugal");
    await user.click(await screen.findByRole("option", { name: /Portugal/ }));
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() =>
      expect(patch).toHaveBeenCalledWith(
        "/api/v1/organizations",
        expect.objectContaining({ country: "PT" }),
      ),
    );
  });

  it("tells a reader who cannot edit why, and shows the profile as text", async () => {
    mount({ orgs: [organization({ role: "VIEWER" })] });

    await waitFor(() =>
      expect(screen.getByText(/Your role can read this but not change it/)).toBeInTheDocument(),
    );
    expect(screen.getByText("contoso-a1b2c3")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Save changes" })).not.toBeInTheDocument();
  });

  it("deletes only from a dialog that says what goes and asks for the name", async () => {
    const user = userEvent.setup();
    mount({ members: [member(), member({ id: "m-2", is_you: false })] });

    await user.click(await screen.findByRole("button", { name: "Delete organization…" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(
      await within(dialog).findByText("1 subscription and every asset found in them"),
    ).toBeInTheDocument();
    expect(
      await within(dialog).findByText("2 members, who lose access at once"),
    ).toBeInTheDocument();

    const confirm = within(dialog).getByRole("button", { name: "Delete organization" });
    // Unavailable but focusable, so it is marked rather than disabled (§165).
    expect(confirm).toHaveAttribute("aria-disabled", "true");
    fireEvent.change(within(dialog).getByLabelText("Type the organization name to confirm"), {
      target: { value: "Contoso" },
    });
    expect(confirm).not.toHaveAttribute("aria-disabled", "true");
  });

  it("does not offer deletion to anyone but an owner", async () => {
    mount({ orgs: [organization({ role: "ADMIN" })] });

    await waitFor(() =>
      expect(screen.getByText("Only an owner can delete an organization.")).toBeInTheDocument(),
    );
    expect(screen.queryByRole("button", { name: "Delete organization…" })).not.toBeInTheDocument();
  });
});

describe("Risk context", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("leads with how many subscriptions are declared, from one request", async () => {
    const { get } = mount({
      at: "/settings/context",
      accounts: [account(), sandbox()],
      declarations: [declaration()],
    });

    expect(await screen.findByText("1 of 2 subscriptions declared")).toBeInTheDocument();
    // The whole estate's declarations in one call, never one per subscription.
    expect(get.mock.calls.filter(([path]) => path.includes("/context"))).toEqual([
      ["/api/v1/context-declarations"],
    ]);
  });

  it("marks what is undeclared, and shows those alone when asked", async () => {
    const user = userEvent.setup();
    mount({
      at: "/settings/context",
      accounts: [account(), sandbox()],
      declarations: [declaration()],
    });

    await screen.findByText("1 of 2 subscriptions declared");
    await user.click(screen.getByRole("button", { name: "Not declared" }));

    await waitFor(() =>
      expect(screen.queryByText("Production subscription")).not.toBeInTheDocument(),
    );
    expect(screen.getByText("Sandbox")).toBeInTheDocument();
    expect(location()).toBe("/settings/context?show=undeclared");
  });

  it("declares a subscription from its sheet, as a whole statement", async () => {
    const put = vi.spyOn(api, "put").mockResolvedValue({
      data: declaration({ criticality: null, data_sensitivity: null, note: null }),
      meta: {},
    });
    mount({ at: "/settings/context" });

    fireEvent.click(
      await screen.findByRole("button", { name: "Edit context for Production subscription" }),
    );
    fireEvent.change(await screen.findByLabelText("Environment"), {
      target: { value: "production" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save declaration" }));

    await waitFor(() =>
      expect(put).toHaveBeenCalledWith("/api/v1/cloud-accounts/a-1/context", {
        environment: "production",
        criticality: null,
        data_sensitivity: null,
        note: null,
      }),
    );
  });

  it("opens the sheet from a link that names the provider's subscription", async () => {
    // An asset page knows the subscription an asset sits in, not our record of it.
    mount({ at: "/settings/context?account=sub-1" });
    expect(await screen.findByRole("dialog", { name: "Production subscription" })).toBeVisible();
  });

  it("does not offer UNKNOWN, and says what each level means", async () => {
    mount({ at: "/settings/context?account=a-1" });

    const group = await screen.findByRole("radiogroup", { name: "Criticality" });
    const offered = within(group)
      .getAllByRole("radio")
      .map((radio) => radio.closest("label")?.textContent ?? "");

    expect(offered.some((text) => text.startsWith("Not declared"))).toBe(true);
    expect(offered.some((text) => text.startsWith("Critical"))).toBe(true);
    // UNKNOWN is CloudGuard's word for "nothing said anything". A customer
    // declaring it would assert an absence that leaving the field unset
    // already asserts.
    expect(offered.some((text) => text.startsWith("Unknown"))).toBe(false);
    expect(within(group).getByText("Disposable: test, sandbox or demo")).toBeInTheDocument();
  });

  it("seeds the sheet from an existing declaration", async () => {
    mount({ at: "/settings/context?account=a-1", declarations: [declaration()] });

    await waitFor(() => expect(screen.getByLabelText("Environment")).toHaveValue("production"));
    expect(screen.getByLabelText("Note")).toHaveValue("Holds cardholder data");
    const criticality = screen.getByRole("radiogroup", { name: "Criticality" });
    expect(within(criticality).getByRole("radio", { name: /^High/ })).toBeChecked();
  });

  it("offers to withdraw a declaration only where there is one", async () => {
    mount({ at: "/settings/context?account=a-1" });

    await screen.findByLabelText("Environment");
    // Nothing declared: a clear button here would do nothing and imply it might.
    expect(screen.queryByRole("button", { name: "Clear declaration" })).not.toBeInTheDocument();
  });

  it("says that an unset field is not a declaration of unknown", async () => {
    mount({ at: "/settings/context?account=a-1" });

    expect(await screen.findByText(/not the same as declaring it unknown/)).toBeInTheDocument();
  });

  it("says a declaration is not retroactive", async () => {
    // A customer who expects existing scores to move would otherwise read the
    // unchanged dashboard as a bug.
    mount({ at: "/settings/context" });

    expect(await screen.findByText(/Applied by the next evaluation/)).toBeInTheDocument();
  });

  it("changes one field on many subscriptions and keeps the rest of each statement", async () => {
    const user = userEvent.setup();
    const put = vi.spyOn(api, "put").mockResolvedValue({ data: declaration(), meta: {} });
    mount({
      at: "/settings/context",
      accounts: [account(), sandbox()],
      declarations: [declaration()],
    });

    await user.click(await screen.findByLabelText("Select every subscription shown"));
    await user.click(screen.getByRole("button", { name: "Set criticality" }));
    await user.click(await screen.findByRole("menuitem", { name: "Low" }));

    await waitFor(() => expect(put).toHaveBeenCalledTimes(2));
    expect(put).toHaveBeenCalledWith("/api/v1/cloud-accounts/a-1/context", {
      environment: "production",
      criticality: "LOW",
      data_sensitivity: "CRITICAL",
      note: "Holds cardholder data",
    });
    expect(put).toHaveBeenCalledWith("/api/v1/cloud-accounts/a-2/context", {
      environment: null,
      criticality: "LOW",
      data_sensitivity: null,
      note: null,
    });
  });

  it("shows a viewer the declarations without a way to change them", async () => {
    mount({ at: "/settings/context", orgs: [organization({ role: "VIEWER" })] });

    expect(
      await screen.findByText("Your role can read these declarations but not change them."),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText("Select every subscription shown")).not.toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "View context for Production subscription" }),
    ).toBeInTheDocument();
  });
});

describe("Members", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const ana = (overrides: Partial<Member> = {}) =>
    member({
      id: "m-2",
      user_id: "u-2",
      email: "ana@contoso.example",
      role: "VIEWER",
      is_you: false,
      ...overrides,
    });

  it("lists who is in the organization, and marks the reader", async () => {
    mount({ at: "/settings/members", members: [member(), ana()] });
    await waitFor(() => expect(screen.getByText("ana@contoso.example")).toBeInTheDocument());
    expect(screen.getByText("(you)")).toBeInTheDocument();
  });

  it("invites from a dialog that says what each role may do, and hands over the link", async () => {
    const user = userEvent.setup();
    const post = vi.spyOn(api, "post").mockResolvedValue({
      data: {
        id: "i-1",
        email: "new@contoso.example",
        role: "VIEWER",
        status: "OPEN",
        invited_by: "u-1",
        created_at: "2026-09-29T00:00:00Z",
        expires_at: "2026-10-06T00:00:00Z",
        link: "https://app.example/invite#a-token-that-is-long-enough",
      },
      meta: {},
    });
    mount({ at: "/settings/members" });

    await user.click(await screen.findByRole("button", { name: "Invite someone" }));
    const dialog = await screen.findByRole("dialog");
    expect(within(dialog).getByText("Reads everything and changes nothing")).toBeInTheDocument();

    await user.type(within(dialog).getByLabelText("Email address"), "new@contoso.example");
    await user.click(within(dialog).getByRole("button", { name: "Create invitation link" }));

    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/v1/invitations", {
        email: "new@contoso.example",
        role: "VIEWER",
      }),
    );
    expect(
      await screen.findByText("https://app.example/invite#a-token-that-is-long-enough"),
    ).toBeInTheDocument();
    expect(screen.getAllByText(/will not be shown again/).length).toBeGreaterThan(0);
  });

  it("asks before removing someone", async () => {
    const user = userEvent.setup();
    const del = vi.spyOn(api, "del").mockResolvedValue({ data: null, meta: {} });
    mount({ at: "/settings/members", members: [member(), ana()] });

    await user.click(await screen.findByRole("button", { name: "Remove ana@contoso.example" }));
    const dialog = await screen.findByRole("alertdialog");
    expect(del).not.toHaveBeenCalled();
    await user.click(within(dialog).getByRole("button", { name: "Remove" }));
    await waitFor(() => expect(del).toHaveBeenCalledWith("/api/v1/members/m-2"));
  });

  it("offers the only owner no removal and no demotion, and says why", async () => {
    // The API refuses both (§162); the button beside the one person who cannot
    // be removed led straight to that refusal (DECISIONS.md §188).
    mount({ at: "/settings/members", members: [member(), ana()] });
    await waitFor(() => expect(screen.getByText("The last owner stays")).toBeInTheDocument());
    expect(
      screen.queryByRole("button", { name: "Remove owner@contoso.example" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Role: owner@contoso.example")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Remove ana@contoso.example" })).toBeInTheDocument();
  });

  it("lets one of two owners go", async () => {
    mount({ at: "/settings/members", members: [member(), ana({ role: "OWNER" })] });
    expect(
      await screen.findByRole("button", { name: "Remove ana@contoso.example" }),
    ).toBeInTheDocument();
    expect(screen.queryByText("The last owner stays")).not.toBeInTheDocument();
  });

  it("does not let an admin change an owner", async () => {
    mount({
      at: "/settings/members",
      orgs: [organization({ role: "ADMIN" })],
      members: [
        member({ is_you: false }),
        ana({ email: "me@contoso.example", role: "ADMIN", is_you: true }),
      ],
    });
    await waitFor(() => expect(screen.getByText("owner@contoso.example")).toBeInTheDocument());
    expect(
      screen.queryByRole("button", { name: "Remove owner@contoso.example" }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Remove me@contoso.example" })).toBeInTheDocument();
  });

  it("tells a reader who cannot manage members why", async () => {
    mount({ at: "/settings/members", orgs: [organization({ role: "VIEWER" })] });
    await waitFor(() =>
      expect(screen.getByText(/An owner or an admin manages members/)).toBeInTheDocument(),
    );
    expect(screen.queryByRole("button", { name: "Invite someone" })).not.toBeInTheDocument();
  });
});

describe("Activity", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  const removal: AuditEntry = {
    id: "e-1",
    action: "member.removed",
    resource_type: "member",
    resource_id: "m-2",
    actor_id: "u-1",
    actor_email: "owner@contoso.example",
    ip_address: "203.0.113.9",
    request_id: "abc",
    details: { email: "ana@contoso.example", role: "VIEWER" },
    created_at: "2026-09-29T10:00:00Z",
  };

  it("says who changed what, and from where", async () => {
    mount({ at: "/settings/activity", activity: [removal] });
    await waitFor(() => expect(screen.getByText("removed a member")).toBeInTheDocument());
    expect(screen.getByText("ana@contoso.example")).toBeInTheDocument();
    expect(screen.getByText("from 203.0.113.9")).toBeInTheDocument();
    expect(screen.getByText("Showing 1 of 1 change")).toBeInTheDocument();
  });

  it("narrows by the kind of change, through the API's own filter", async () => {
    const user = userEvent.setup();
    const { get } = mount({ at: "/settings/activity", activity: [removal] });

    await user.click(await screen.findByRole("combobox", { name: "Kind of change" }));
    await user.click(await screen.findByRole("option", { name: "Members" }));

    await waitFor(() =>
      expect(
        get.mock.calls.some(
          ([path]) => path.includes("/audit-log") && path.includes("action=member."),
        ),
      ).toBe(true),
    );
    expect(location()).toBe("/settings/activity?action=member.");
  });
});

describe("Integrations", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("shows a stored webhook only in part, and says it is failing", async () => {
    mount({
      at: "/settings/integrations",
      webhooks: [
        {
          id: "w-1",
          name: "Security channel",
          url_preview: "hooks.slack.com/…1234",
          format: "SLACK",
          kinds: ["REACHABLE_FINDING"],
          enabled: true,
          created_at: "2026-09-01T00:00:00Z",
          last_success_at: null,
          last_failure_at: "2026-09-29T10:00:00Z",
          last_error: "HTTP 404: no_service",
        },
      ],
    });
    await waitFor(() => expect(screen.getByText("Security channel")).toBeInTheDocument());
    expect(screen.getByText("Slack · hooks.slack.com/…1234")).toBeInTheDocument();
    expect(screen.getByText("Failing")).toBeInTheDocument();
    expect(screen.getByText(/HTTP 404: no_service/)).toBeInTheDocument();
  });

  it("shows a generic webhook's secret once, and closes only once it is stored", async () => {
    const user = userEvent.setup();
    const post = vi.spyOn(api, "post").mockResolvedValue({
      data: {
        id: "w-2",
        name: "SIEM",
        url_preview: "siem.example.com/…hook",
        format: "GENERIC",
        kinds: ["REACHABLE_FINDING", "VERIFIED_FIX", "COVERAGE_DROP"],
        enabled: true,
        created_at: "2026-09-29T00:00:00Z",
        last_success_at: null,
        last_failure_at: null,
        last_error: null,
        secret: "a".repeat(64),
      },
      meta: {},
    });
    mount({ at: "/settings/integrations" });

    await user.click(await screen.findByRole("button", { name: "New integration" }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText("Integration name"), "SIEM");
    await user.click(within(dialog).getByRole("radio", { name: /Webhook \(signed JSON\)/ }));
    await user.type(within(dialog).getByLabelText("Webhook URL"), "https://siem.example.com/hook");
    await user.click(within(dialog).getByRole("button", { name: "Add integration" }));

    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/v1/webhooks", {
        name: "SIEM",
        url: "https://siem.example.com/hook",
        format: "GENERIC",
        kinds: ["REACHABLE_FINDING", "VERIFIED_FIX", "COVERAGE_DROP"],
      }),
    );
    expect(await screen.findByText("a".repeat(64))).toBeInTheDocument();
    const done = screen.getByRole("button", { name: "Done" });
    expect(done).toHaveAttribute("aria-disabled", "true");
    await user.click(
      screen.getByRole("checkbox", { name: "I have stored this secret somewhere safe" }),
    );
    expect(done).not.toHaveAttribute("aria-disabled", "true");
  });
});

describe("Preferences", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("offers the theme and the single-key shortcuts to every reader", async () => {
    mount({ at: "/settings/preferences", orgs: [organization({ role: "VIEWER" })] });

    const group = await screen.findByRole("radiogroup", { name: "Theme" });
    expect(within(group).getAllByRole("radio")).toHaveLength(3);
    expect(screen.getByRole("switch", { name: /Single-key shortcuts/ })).toBeInTheDocument();
  });
});
