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

  it("does not present an accepted risk as resolved", () => {
    const { container } = render(<StatusPill status="ACCEPTED_RISK" />);
    expect(container.firstElementChild?.className).not.toContain("text-ok");
  });
});

describe("SeverityBadge", () => {
  it("marks every level with more than a colour", () => {
    // Someone who cannot separate the hues still has to be able to tell the
    // levels apart, so each one carries a shape of its own.
    const shapes = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].map((level) => {
      const { container } = render(<Badge level={level} />);
      const svg = container.querySelector("svg");
      expect(svg).toBeInTheDocument();
      return svg?.getAttribute("class");
    });
    expect(new Set(shapes).size).toBe(shapes.length);
  });

  it("does not give UNKNOWN the shape of a determined level", () => {
    // "We could not look" and "we looked and it was fine" are the distinction
    // the product exists to keep; UNKNOWN must never share LOW's mark.
    const { container: unknown } = render(<Badge level="UNKNOWN" />);
    const { container: low } = render(<Badge level="LOW" />);
    expect(unknown.querySelector("svg")?.getAttribute("class")).not.toBe(
      low.querySelector("svg")?.getAttribute("class"),
    );
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
