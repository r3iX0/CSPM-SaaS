/**
 * The score's movement since the previous reading. A delta says something
 * moved, and which way -- and a decline must never look like an improvement.
 */
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { ScoreDelta } from "../ScoreDelta";

describe("ScoreDelta", () => {
  it("shows an improvement as one", () => {
    const { container } = render(<ScoreDelta delta={12} />);
    expect(screen.getByText("↑")).toBeInTheDocument();
    // Asserted on the rendered text rather than as a standalone node: JSX
    // whitespace splits the number away from the words around it, and a
    // matcher that cared would be testing the spacing.
    expect(container.textContent).toContain("12");
  });

  it("does not dress a decline up as an improvement", () => {
    // The regression this exists for. The delta used to be an estimate that
    // could only ever be positive, so the arrow and the green were hard-coded;
    // measuring it makes a decline possible, and a green ↑ over a worsening
    // posture is a plain untruth.
    const { container } = render(<ScoreDelta delta={-9} />);

    expect(screen.getByText("↓")).toBeInTheDocument();
    expect(screen.queryByText("↑")).not.toBeInTheDocument();
    // The magnitude, not the minus sign: the arrow already carries direction.
    expect(container.textContent).toContain("9");
    expect(container.textContent).not.toContain("-9");
  });

  it("colours a decline as a problem rather than a success", () => {
    const { container } = render(<ScoreDelta delta={-9} />);
    expect(container.firstElementChild?.className).toContain("text-critical");
    expect(container.firstElementChild?.className).not.toContain("text-ok");
  });

  it("distinguishes no comparison from no change", () => {
    // A first scan has nothing to have moved from, and "No change" would claim
    // a comparison that was never made.
    render(<ScoreDelta delta={null} />);
    expect(screen.getByText("No previous scan to compare against")).toBeInTheDocument();
  });

  it("reports a genuine standstill as one", () => {
    render(<ScoreDelta delta={0} />);
    expect(screen.getByText("No change since last scan")).toBeInTheDocument();
  });
});
