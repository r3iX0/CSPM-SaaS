/**
 * The setup rail: where the reader is in connecting a cloud, and a step that
 * finishes while they watch said by movement once (DECISIONS.md §181).
 */
import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SetupRail } from "@/components/connections/setup/SetupRail";

const drawn = (container: HTMLElement) => container.querySelectorAll("path[pathLength]");
const checks = (container: HTMLElement) => container.querySelectorAll('path[d="M20 6 9 17l-5-5"]');

describe("SetupRail", () => {
  it("draws the steps already behind the reader as done, without moving", () => {
    const { container } = render(<SetupRail stage="deploy" provider="azure" connection={null} />);

    // Scope and consent are behind the reader on arrival: the state of things.
    expect(checks(container)).toHaveLength(2);
    expect(drawn(container)).toHaveLength(0);
  });

  it("draws the check of a step that finishes while the reader watches", () => {
    const { container, rerender } = render(
      <SetupRail stage="consent" provider="azure" connection={null} />,
    );
    expect(drawn(container)).toHaveLength(0);

    rerender(<SetupRail stage="deploy" provider="azure" connection={null} />);

    // Consent just landed: its check is drawn on. Scope was already done.
    expect(checks(container)).toHaveLength(2);
    expect(drawn(container)).toHaveLength(1);
  });
});
