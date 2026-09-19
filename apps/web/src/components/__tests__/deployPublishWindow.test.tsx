/**
 * The first minutes after consent.
 *
 * Entra publishes CloudGuard's service principal in a new directory when
 * replication gets there, and until it does the lookup is refused. The setup
 * page showed that as "CloudGuard cannot generate the deployment yet" the
 * moment consent returned, which read as a fault in every new tenant. It now
 * waits three minutes from consent -- re-reading every five seconds all the
 * while -- before showing the reason.
 */
import { act, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { StepDeploy } from "@/components/connections/setup/StepDeploy";
import type { CloudConnection } from "@/lib/types";

const NOW = Date.parse("2026-09-19T12:00:00Z");
const REFUSED =
  "Microsoft Graph refused this lookup. CloudGuard's own app registration is most likely missing its API permissions.";

function mount(consentedSecondsAgo: number | null) {
  const connection = {
    provider: "azure",
    scope_type: "TENANT_ROOT",
    consent_status: "GRANTED",
    consented_at:
      consentedSecondsAgo === null
        ? null
        : new Date(NOW - consentedSecondsAgo * 1000).toISOString(),
    template_url: null,
    status_detail: REFUSED,
    provider_ref: {},
  } as unknown as CloudConnection;
  return render(
    <StepDeploy
      connection={connection}
      onRecheck={() => {}}
      rechecking={false}
      onDiscard={() => {}}
      discarding={false}
    />,
  );
}

describe("the deploy step, just after consent", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });
  afterEach(() => vi.useRealTimers());

  it("waits rather than reporting a fault, and says for how long", () => {
    mount(30);

    expect(screen.getByRole("status")).toHaveTextContent(/setting cloudguard up/i);
    expect(screen.getByText(/2:30/)).toBeInTheDocument();
    expect(screen.queryByText(REFUSED)).not.toBeInTheDocument();
  });

  it("shows the reason once three minutes have passed", () => {
    mount(170);
    expect(screen.queryByText(REFUSED)).not.toBeInTheDocument();

    act(() => {
      vi.advanceTimersByTime(11_000);
    });

    expect(screen.getByText(REFUSED)).toBeInTheDocument();
    expect(screen.getByText(/cannot generate the deployment yet/i)).toBeInTheDocument();
  });

  it("does not restart the wait for a consent long past", () => {
    mount(600);
    expect(screen.getByText(REFUSED)).toBeInTheDocument();
  });

  it("does not wait on a consent it has no time for", () => {
    mount(null);
    expect(screen.getByText(REFUSED)).toBeInTheDocument();
  });
});
