/**
 * The coverage card's hardest job is the part people act on: what could not be
 * collected, and why.
 *
 * Azure reports a failure per evidence key, so one missing admin consent
 * arrives as the same nine-hundred-character sentence three times over. Printed
 * verbatim it buried the one line worth reading under its own repetitions.
 */
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { BlindSpots } from "@/components/dashboard/BlindSpots";
import { groupCauses } from "@/lib/collectionErrors";
import { containingText } from "@/test/text";

const CONSENT_FAILURE =
  "Access denied. Admin consent for CloudGuard's directory permissions is " +
  "missing or incomplete. A Global Administrator must grant it under Microsoft " +
  "Entra ID > Enterprise applications > CloudGuard > Permissions.";

describe("collection failures", () => {
  it("states one cause once, naming everything it cost", () => {
    const causes = groupCauses(
      `users: ${CONSENT_FAILURE}; directory_roles: ${CONSENT_FAILURE}; ` +
        "user_role_map: needs users, which did not produce usable data",
    );

    expect(causes).toHaveLength(2);
    expect(causes[0].keys).toEqual(["users", "directory_roles"]);
    expect(causes[1].keys).toEqual(["user_role_map"]);
  });

  it("never cuts a provider message in half on a semicolon of its own", () => {
    // Azure's text carries its own punctuation, and a reader searching for the
    // error they were given must find the whole of it.
    const causes = groupCauses(
      "users: Access denied; the tenant did not grant Directory.Read.All",
    );

    expect(causes).toHaveLength(1);
    expect(causes[0].message).toContain("did not grant Directory.Read.All");
  });

  it("clips a long message rather than filling the banner with it", () => {
    render(
      <MemoryRouter>
        <BlindSpots
          ratio={0.75}
          gaps={[["identity", `users: ${CONSENT_FAILURE}`]]}
          unclassified={0}
          classified={12}
        />
      </MemoryRouter>,
    );

    // The provider's own words, in the provider's own order — just not all
    // nine hundred of them.
    expect(screen.getByText(/Access denied/)).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Grant admin consent" }),
    ).toHaveAttribute("href", "/connections");
  });

  it("says what share of the estate the score is charged for", () => {
    render(
      <MemoryRouter>
        <BlindSpots
          ratio={0.68}
          gaps={[["identity", `users: ${CONSENT_FAILURE}`]]}
          unclassified={0}
          classified={12}
        />
      </MemoryRouter>,
    );

    expect(
      screen.getByText("The score is charged for 68% of your estate"),
    ).toBeInTheDocument();
  });
});

describe("assets CloudGuard could not classify", () => {
  it("states what the score is not charging for, and what to do about it", () => {
    // The half of coverage the score used to spend silently. Missing evidence
    // never becomes a finding; missing context did reach the number, because an
    // unknown criticality ranks just under High so nothing hides behind a
    // missing label. That caution belongs to the ordering, not the posture.
    render(
      <MemoryRouter>
        <BlindSpots ratio={1} gaps={[]} unclassified={9} classified={3} />
      </MemoryRouter>,
    );

    expect(
      screen.getByText(containingText(/9 of 12 open risks/)),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Classify subscriptions" }),
    ).toHaveAttribute("href", "/settings");
  });

  it("says nothing when every open risk sits on a classified asset", () => {
    // A panel that reported "0 unclassified" would be a line of noise on the
    // estates that did the work.
    // A banner that reported "0 unclassified" would be a permanent caveat on
    // the estates that did the work, and a caveat always on screen is one
    // nobody reads.
    const { container } = render(
      <MemoryRouter>
        <BlindSpots ratio={1} gaps={[]} unclassified={0} classified={12} />
      </MemoryRouter>,
    );

    expect(container).toBeEmptyDOMElement();
  });
});
