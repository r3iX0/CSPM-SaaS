/**
 * Settings: the half of CloudGuard's evidence that a person supplies.
 *
 * Two things must survive here. A context declaration is a *statement* — it is
 * replaced whole, and an unset field withdraws a claim rather than declaring
 * the value unknown. And UNKNOWN is never offered: it is CloudGuard's own word
 * for "nothing said anything", so a menu item for it would let a customer
 * assert an absence that saying nothing already asserts — and the API rejects
 * it, so the option would always fail.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
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

function mount({
  orgs = [organization()],
  accounts = [account()],
  declaration = null as ContextDeclaration | null,
  members = [member()],
  invitations = [] as Invitation[],
  activity = [] as AuditEntry[],
  webhooks = [] as Webhook[],
}: {
  orgs?: Organization[];
  accounts?: CloudAccount[];
  declaration?: ContextDeclaration | null;
  members?: Member[];
  invitations?: Invitation[];
  activity?: AuditEntry[];
  webhooks?: Webhook[];
} = {}) {
  vi.spyOn(api, "get").mockImplementation((path: string) => {
    if (path.includes("/context")) {
      return Promise.resolve({ data: declaration, meta: {} }) as never;
    }
    if (path.includes("cloud-accounts")) {
      return Promise.resolve({ data: accounts, meta: {} }) as never;
    }
    if (path.endsWith("/members")) {
      return Promise.resolve({ data: members, meta: {} }) as never;
    }
    if (path.endsWith("/invitations")) {
      return Promise.resolve({ data: invitations, meta: {} }) as never;
    }
    if (path.endsWith("/webhooks")) {
      return Promise.resolve({ data: webhooks, meta: {} }) as never;
    }
    if (path.includes("/audit-log")) {
      return Promise.resolve({ data: activity, meta: { total: activity.length } }) as never;
    }
    return Promise.resolve({ data: orgs, meta: {} }) as never;
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <SettingsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("SettingsPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("shows the organization as it currently describes itself", async () => {
    mount();

    await waitFor(() => expect(screen.getByLabelText("Name")).toHaveValue("Contoso"));
    expect(screen.getByLabelText("Industry")).toHaveValue("Banking");
    expect(screen.getByLabelText("Country")).toHaveValue("AL");
  });

  it("never lets the identifier be edited, and says why", async () => {
    mount();

    await waitFor(() => expect(screen.getByLabelText("Identifier")).toBeDisabled());
    expect(screen.getByText(/unchanged by a rename/)).toBeInTheDocument();
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

  it("tells a reader who cannot edit why, rather than greying the fields silently", async () => {
    mount({ orgs: [organization({ role: "VIEWER" })] });

    await waitFor(() =>
      expect(screen.getByText(/Your role can read this but not change it/)).toBeInTheDocument(),
    );
    expect(screen.queryByRole("button", { name: "Save changes" })).not.toBeInTheDocument();
  });

  // --- context declarations ------------------------------------------------

  it("lets a subscription be declared, which is what the risk engine multiplies by", async () => {
    const put = vi.spyOn(api, "put").mockResolvedValue({
      data: {
        cloud_account_id: "a-1",
        environment: "production",
        criticality: "HIGH",
        data_sensitivity: null,
        note: null,
        declared_by_user_id: "u-1",
        declared_at: "2026-08-31T09:00:00Z",
      },
      meta: {},
    });
    mount();

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

  it("does not offer UNKNOWN as something a customer can declare", async () => {
    // `userEvent`, because the listbox is built out of pointer events and a
    // synthetic click never opens it.
    const user = userEvent.setup();
    mount();

    await user.click(await screen.findByRole("combobox", { name: "Criticality" }));

    // Asserted on the options rather than on the page text: the trigger now
    // says the chosen label too, which is the point of the control and would
    // otherwise make every one of these match twice.
    const offered = (await screen.findAllByRole("option")).map((option) => option.textContent);

    expect(offered).toContain("Not declared");
    expect(offered).toContain("Critical");
    // UNKNOWN is CloudGuard's word for "nothing said anything". A customer
    // declaring it would assert an absence that leaving the field unset
    // already asserts.
    expect(offered).not.toContain("Unknown");
  });

  it("seeds the form from an existing declaration rather than showing it as undeclared", async () => {
    mount({
      declaration: {
        cloud_account_id: "a-1",
        environment: "production",
        criticality: "HIGH",
        data_sensitivity: "CRITICAL",
        note: "Holds cardholder data",
        declared_by_user_id: "u-1",
        declared_at: "2026-08-31T09:00:00Z",
      },
    });

    await waitFor(() => expect(screen.getByLabelText("Environment")).toHaveValue("production"));
    expect(screen.getByLabelText("Note")).toHaveValue("Holds cardholder data");
  });

  it("offers to withdraw a declaration only where there is one", async () => {
    mount();

    await screen.findByLabelText("Environment");
    // Nothing declared: a clear button here would do nothing and imply it might.
    expect(screen.queryByRole("button", { name: "Clear declaration" })).not.toBeInTheDocument();
  });

  it("says that an unset field is not a declaration of unknown", async () => {
    mount();

    await waitFor(() =>
      expect(screen.getByText(/not the same as declaring it unknown/)).toBeInTheDocument(),
    );
  });

  it("says a declaration is not retroactive", async () => {
    // A customer who expects existing scores to move would otherwise read the
    // unchanged dashboard as a bug.
    mount();

    await waitFor(() =>
      expect(screen.getByText(/Applied by the next evaluation/)).toBeInTheDocument(),
    );
  });

  // --- deletion ------------------------------------------------------------

  it("refuses to delete until the organization is named", async () => {
    mount();

    const button = await screen.findByRole("button", { name: "Delete organization" });
    // Unavailable but focusable, so it is marked rather than disabled (§165).
    expect(button).toHaveAttribute("aria-disabled", "true");

    fireEvent.change(screen.getByLabelText("Type the organization name to confirm"), {
      target: { value: "Contoso" },
    });
    expect(button).not.toHaveAttribute("aria-disabled", "true");
  });

  it("does not offer deletion to anyone but an owner", async () => {
    mount({ orgs: [organization({ role: "ADMIN" })] });

    await waitFor(() =>
      expect(screen.getByText("Only an owner can delete an organization.")).toBeInTheDocument(),
    );
    expect(screen.queryByRole("button", { name: "Delete organization" })).not.toBeInTheDocument();
  });
});

describe("Members", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("lists who is in the organization, and marks the reader", async () => {
    mount({
      members: [
        member(),
        member({
          id: "m-2",
          user_id: "u-2",
          email: "ana@contoso.example",
          role: "VIEWER",
          is_you: false,
        }),
      ],
    });
    await waitFor(() => expect(screen.getByText("ana@contoso.example")).toBeInTheDocument());
    expect(screen.getByText("(you)")).toBeInTheDocument();
  });

  it("hands the inviter the link, since Cleave sends no email", async () => {
    const post = vi.spyOn(api, "post").mockResolvedValue({
      data: {
        id: "i-1",
        email: "new@contoso.example",
        role: "SECURITY_ANALYST",
        status: "OPEN",
        invited_by: "u-1",
        created_at: "2026-09-29T00:00:00Z",
        expires_at: "2026-10-06T00:00:00Z",
        link: "https://app.example/invite#a-token-that-is-long-enough",
      },
      meta: {},
    } as never);
    mount();

    await userEvent.type(await screen.findByLabelText("Email address"), "new@contoso.example");
    await userEvent.click(screen.getByRole("button", { name: "Create invitation link" }));

    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/v1/invitations", {
        email: "new@contoso.example",
        role: "VIEWER",
      }),
    );
    expect(
      await screen.findByText("https://app.example/invite#a-token-that-is-long-enough"),
    ).toBeInTheDocument();
    expect(screen.getByText(/will not be shown again/)).toBeInTheDocument();
  });

  it("links to each of its sections from the top, and only to those shown", async () => {
    mount();
    const nav = await screen.findByRole("navigation", { name: "Settings sections" });
    const links = within(nav).getAllByRole("link");
    for (const link of links) {
      const target = document.getElementById(link.getAttribute("href")!.slice(1));
      expect(target, link.textContent ?? "").not.toBeNull();
    }
    expect(links.map((link) => link.textContent)).toContain("Members");
  });

  it("offers the only owner no removal and no demotion, and says why", async () => {
    // The API refuses both (§162); the button beside the one person who cannot
    // be removed led straight to that refusal (DECISIONS.md §188).
    mount({
      members: [
        member(),
        member({
          id: "m-2",
          user_id: "u-2",
          email: "ana@contoso.example",
          role: "VIEWER",
          is_you: false,
        }),
      ],
    });
    await waitFor(() => expect(screen.getByText("The last owner stays")).toBeInTheDocument());
    expect(
      screen.queryByRole("button", { name: "Remove owner@contoso.example" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Role: owner@contoso.example")).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Remove ana@contoso.example" })).toBeInTheDocument();
  });

  it("lets one of two owners go", async () => {
    mount({
      members: [
        member(),
        member({
          id: "m-2",
          user_id: "u-2",
          email: "ana@contoso.example",
          role: "OWNER",
          is_you: false,
        }),
      ],
    });
    expect(
      await screen.findByRole("button", { name: "Remove ana@contoso.example" }),
    ).toBeInTheDocument();
    expect(screen.queryByText("The last owner stays")).not.toBeInTheDocument();
  });

  it("does not let an admin change an owner", async () => {
    mount({
      orgs: [organization({ role: "ADMIN" })],
      members: [
        member({ is_you: false }),
        member({
          id: "m-2",
          user_id: "u-2",
          email: "me@contoso.example",
          role: "ADMIN",
          is_you: true,
        }),
      ],
    });
    await waitFor(() => expect(screen.getByText("owner@contoso.example")).toBeInTheDocument());
    expect(
      screen.queryByRole("button", { name: "Remove owner@contoso.example" }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Remove me@contoso.example" })).toBeInTheDocument();
  });

  it("tells a reader who cannot manage members why", async () => {
    mount({ orgs: [organization({ role: "VIEWER" })] });
    await waitFor(() =>
      expect(screen.getByText(/An owner or an admin manages members/)).toBeInTheDocument(),
    );
    expect(screen.queryByLabelText("Email address")).not.toBeInTheDocument();
  });
});

describe("Activity", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("says who changed what, and from where", async () => {
    mount({
      activity: [
        {
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
        },
      ],
    });
    await waitFor(() => expect(screen.getByText("removed a member")).toBeInTheDocument());
    expect(screen.getByText("ana@contoso.example")).toBeInTheDocument();
    expect(screen.getByText("from 203.0.113.9")).toBeInTheDocument();
  });

  it("is not shown to a role that cannot read it", async () => {
    mount({ orgs: [organization({ role: "VIEWER" })] });
    await waitFor(() => expect(screen.getByLabelText("Name")).toBeInTheDocument());
    expect(screen.queryByText("Activity")).not.toBeInTheDocument();
  });
});

describe("Integrations", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("shows a stored webhook only in part, and when it last delivered", async () => {
    mount({
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
    expect(screen.getByText(/HTTP 404: no_service/)).toBeInTheDocument();
  });

  it("shows a generic webhook's secret once, on the answer that created it", async () => {
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
    } as never);
    mount();

    await userEvent.type(await screen.findByLabelText("Integration name"), "SIEM");
    await userEvent.type(screen.getByLabelText("Webhook URL"), "https://siem.example.com/hook");
    await userEvent.click(screen.getByRole("button", { name: "Add integration" }));

    await waitFor(() =>
      expect(post).toHaveBeenCalledWith("/api/v1/webhooks", {
        name: "SIEM",
        url: "https://siem.example.com/hook",
        format: "SLACK",
        kinds: ["REACHABLE_FINDING", "VERIFIED_FIX", "COVERAGE_DROP"],
      }),
    );
    expect(await screen.findByText("a".repeat(64))).toBeInTheDocument();
  });
});
