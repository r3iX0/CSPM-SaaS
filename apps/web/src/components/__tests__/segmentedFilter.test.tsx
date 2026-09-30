/**
 * A filter of a few choices, all on screen, with one fill that moves to the
 * choice made (DECISIONS.md §179).
 */
import { fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { describe, expect, it } from "vitest";

import { SegmentedFilter } from "@/components/common/SegmentedFilter";

function Harness() {
  const [value, setValue] = useState("all");
  return (
    <SegmentedFilter
      label="Status"
      value={value}
      onChange={setValue}
      segments={[
        { value: "all", label: "All" },
        { value: "open", label: "Open" },
        { value: "resolved", label: "Resolved" },
      ]}
    />
  );
}

describe("SegmentedFilter", () => {
  it("draws one fill, under the choice that is pressed, and moves it on a press", () => {
    const { container } = render(<Harness />);
    const fills = () => container.querySelectorAll("button > span[aria-hidden]");

    expect(fills()).toHaveLength(1);
    expect(screen.getByRole("button", { name: "All" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "All" }).contains(fills()[0])).toBe(true);

    fireEvent.click(screen.getByRole("button", { name: "Open" }));

    expect(fills()).toHaveLength(1);
    expect(screen.getByRole("button", { name: "Open" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByRole("button", { name: "Open" }).contains(fills()[0])).toBe(true);
  });
});
