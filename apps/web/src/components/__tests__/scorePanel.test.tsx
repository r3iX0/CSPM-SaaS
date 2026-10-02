/**
 * The dashboard's anchor.
 *
 * "82" alone invites exactly two questions — out of what, and is that good —
 * and a panel that answers neither makes the reader hunt for both.
 */
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ScorePanel } from "@/components/dashboard/ScorePanel";

describe("ScorePanel", () => {
  it("gives the number a scale and a meaning", () => {
    render(<ScorePanel score={82} delta={null} history={[]} />);

    expect(screen.getByText("82")).toBeInTheDocument();
    expect(screen.getByText("/ 100")).toBeInTheDocument();
    expect(screen.getByText("Needs attention")).toBeInTheDocument();
  });

  it("does not claim a trend it cannot measure", () => {
    // No earlier reading is not "no change": the two mean opposite things to
    // somebody deciding whether remediation is working.
    render(<ScorePanel score={70} delta={null} history={[]} />);

    expect(screen.getByText(/no previous scan/i)).toBeInTheDocument();
  });

  it("exposes the proportion to assistive technology", () => {
    render(<ScorePanel score={41} delta={-3} history={[]} />);

    expect(screen.getByRole("meter", { name: /security score/i })).toHaveAttribute(
      "aria-valuenow",
      "41",
    );
  });

  it("draws the trend only once there are two readings to draw between", () => {
    const reading = (score: number, day: number) => ({
      observed_at: `2026-09-${String(day).padStart(2, "0")}T09:00:00Z`,
      security_score: score,
      open_finding_count: 1,
      findings_by_severity: {},
      risk_bands: {},
      attack_path_count: 0,
    });
    const { rerender } = render(<ScorePanel score={70} delta={null} history={[reading(70, 1)]} />);
    expect(screen.getByText(/One scan so far/)).toBeInTheDocument();
    expect(screen.queryByRole("img", { name: /Security score:/ })).not.toBeInTheDocument();

    rerender(<ScorePanel score={74} delta={4} history={[reading(70, 1), reading(74, 2)]} />);
    expect(
      screen.getByRole("img", { name: /Security score: risen from 70 to 74/ }),
    ).toBeInTheDocument();
    // Said on screen too: an unlabelled line in the band's red read as a
    // warning rather than as the score moving (DECISIONS.md §189).
    expect(screen.getByText("70 → 74")).toBeInTheDocument();
  });
});
