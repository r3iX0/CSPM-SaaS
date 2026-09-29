/**
 * Two things a screen reader could not tell before §165: that a filter left
 * the list with a different count, and that a button pressed was still where
 * focus was.
 */
import { act, fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { LiveStatus, SETTLE_MS } from "@/components/common/LiveStatus";
import { Button } from "@/components/ui/button";

describe("LiveStatus", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("says nothing on arrival with quietFirst, then says what changed", () => {
    const { rerender } = render(<LiveStatus quietFirst message={null} />);
    rerender(<LiveStatus quietFirst message="1–25 of 132 findings" />);
    act(() => vi.advanceTimersByTime(SETTLE_MS));
    expect(screen.getByRole("status")).toHaveTextContent("");

    rerender(<LiveStatus quietFirst message="1–4 of 4 findings matching these filters" />);
    act(() => vi.advanceTimersByTime(SETTLE_MS));
    expect(screen.getByRole("status")).toHaveTextContent(
      "1–4 of 4 findings matching these filters",
    );
  });

  it("says only the message the reader stopped on", () => {
    const { rerender } = render(<LiveStatus quietFirst message="12 routes listed" />);
    rerender(<LiveStatus quietFirst message="3 routes listed" />);
    act(() => vi.advanceTimersByTime(SETTLE_MS / 2));
    rerender(<LiveStatus quietFirst message="1 route listed" />);
    act(() => vi.advanceTimersByTime(SETTLE_MS / 2));
    expect(screen.getByRole("status")).toHaveTextContent("");

    act(() => vi.advanceTimersByTime(SETTLE_MS));
    expect(screen.getByRole("status")).toHaveTextContent("1 route listed");
  });

  it("keeps what it said while there is nothing new, and does not repeat it", () => {
    const { rerender } = render(<LiveStatus quietFirst message="12 routes listed" />);
    rerender(<LiveStatus quietFirst message="No route passes anything named “x”." />);
    rerender(<LiveStatus quietFirst message="12 routes listed" />);
    act(() => vi.advanceTimersByTime(SETTLE_MS));
    // Back where it started before anything settled: nothing to say.
    expect(screen.getByRole("status")).toHaveTextContent("");

    rerender(<LiveStatus quietFirst message="No rules match" />);
    act(() => vi.advanceTimersByTime(SETTLE_MS));
    rerender(<LiveStatus quietFirst message={null} />);
    act(() => vi.advanceTimersByTime(SETTLE_MS));
    expect(screen.getByRole("status")).toHaveTextContent("No rules match");
  });

  it("says the first message when it is news, as a form's success is", () => {
    const { rerender } = render(<LiveStatus message={null} />);
    rerender(<LiveStatus message="Invitation link for ana@contoso.com is ready." />);
    act(() => vi.advanceTimersByTime(SETTLE_MS));
    expect(screen.getByRole("status")).toHaveTextContent(
      "Invitation link for ana@contoso.com is ready.",
    );
  });
});

describe("Button", () => {
  function Saving({ onSave }: { onSave: () => void }) {
    const [pending, setPending] = useState(false);
    return (
      <Button
        disabled={pending}
        onClick={() => {
          onSave();
          setPending(true);
        }}
      >
        Save
      </Button>
    );
  }

  it("keeps focus when it disables itself, and refuses the next press", () => {
    const onSave = vi.fn();
    render(<Saving onSave={onSave} />);
    const button = screen.getByRole("button", { name: "Save" });

    button.focus();
    fireEvent.click(button);

    expect(button).toHaveFocus();
    expect(button).toHaveAttribute("aria-disabled", "true");
    expect(button).not.toHaveAttribute("disabled");

    fireEvent.click(button);
    expect(onSave).toHaveBeenCalledTimes(1);
  });

  it("does not submit its form while unavailable", () => {
    const onSubmit = vi.fn((event: React.FormEvent) => event.preventDefault());
    render(
      <form onSubmit={onSubmit} aria-label="Invite">
        <Button type="submit" disabled>
          Invite
        </Button>
      </form>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Invite" }));
    expect(onSubmit).not.toHaveBeenCalled();
  });
});
