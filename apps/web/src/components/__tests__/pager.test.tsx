/**
 * The page numbers a list draws under itself.
 */
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { Pager } from "@/components/common/Pager";

describe("Pager", () => {
  it("draws a single hidden page as its number, never as an ellipsis", () => {
    // "1 2 … 4" took the room of "1 2 3 4" and hid page 3 (DECISIONS.md §188).
    render(<Pager page={0} pages={4} onPage={() => {}} />);

    expect(screen.getByRole("button", { name: "Page 3" })).toBeInTheDocument();
    expect(screen.queryByText("More pages")).not.toBeInTheDocument();
  });

  it("keeps the ellipsis for a gap of two pages or more", () => {
    render(<Pager page={0} pages={10} onPage={() => {}} />);

    expect(screen.getByText("More pages")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Page 5" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Page 10" })).toBeInTheDocument();
  });
});
