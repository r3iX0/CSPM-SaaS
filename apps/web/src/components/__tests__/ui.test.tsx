import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SeverityBadge as Badge } from "../security/SeverityBadge";
import { StatusPill } from "../security/StatusPill";
import { ContextRow } from "../security/ContextProvenance";

describe("Badge", () => {
  it("labels a level when no children are given", () => {
    render(<Badge level="CRITICAL" />);
    expect(screen.getByText("Critical")).toBeInTheDocument();
  });

  it("marks UNKNOWN visually distinctly from LOW", () => {
    const { container: unknown } = render(<Badge level="UNKNOWN" />);
    const { container: low } = render(<Badge level="LOW" />);
    expect(unknown.firstElementChild?.className).not.toBe(low.firstElementChild?.className);
  });
});

describe("StatusPill", () => {
  it("presents a verified fix as a success state", () => {
    const { container } = render(<StatusPill status="RESOLVED" />);
    expect(screen.getByText("Verified fixed")).toBeInTheDocument();
    expect(container.firstElementChild?.className).toContain("text-ok");
  });

  it("presents a partial scan as a caution, not a success", () => {
    const { container } = render(<StatusPill status="PARTIAL" />);
    expect(container.firstElementChild?.className).toContain("text-medium");
  });

  it("stays text, with no icon", () => {
    const { container } = render(<StatusPill status="OPEN" />);
    expect(container.querySelector("svg")).not.toBeInTheDocument();
  });

  it("does not present an accepted risk as resolved", () => {
    const { container } = render(<StatusPill status="ACCEPTED_RISK" />);
    expect(container.firstElementChild?.className).not.toContain("text-ok");
  });
});

describe("SeverityBadge", () => {
  it("stays text, with no icon, at every level", () => {
    for (const level of ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]) {
      const { container } = render(<Badge level={level} />);
      expect(container.querySelector("svg")).not.toBeInTheDocument();
    }
  });

  it("marks UNKNOWN with more than a colour", () => {
    // Someone who cannot separate the hues still has to be able to tell "we
    // could not look" from "we looked and it was fine" -- here by the dashed
    // border, since the badge carries no icon.
    const { container } = render(<Badge level="UNKNOWN" />);
    expect(container.firstElementChild?.className).toContain("border-dashed");
  });
});

describe("ContextRow", () => {
  it("distinguishes a value somebody chose from one CloudGuard guessed", () => {
    // The three context values multiply a finding into a risk. "CRITICAL"
    // invites the question "says who", and until the backend recorded
    // provenance there was no answer to give.
    const { container: declared } = render(
      <ContextRow
        label="Criticality"
        fact={{ value: "CRITICAL", source: "customer", confidence: 1 }}
      />,
    );
    const { container: guessed } = render(
      <ContextRow
        label="Criticality"
        fact={{ value: "CRITICAL", source: "inferred", confidence: 0.4 }}
      />,
    );
    expect(declared.innerHTML).not.toBe(guessed.innerHTML);
  });

  it("falls back without provenance rather than claiming a source", () => {
    render(<ContextRow label="Criticality" fallback={<Badge level="HIGH" />} />);
    expect(screen.getByText("High")).toBeInTheDocument();
  });
});
