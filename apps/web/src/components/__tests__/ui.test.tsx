import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SeverityBadge as Badge } from "../security/SeverityBadge";
import { StatusPill } from "../security/StatusPill";
import { ContextRow } from "../security/ContextProvenance";
import { ProviderMark } from "../security/ProviderMark";
import { ResourceIcon } from "../security/ResourceIcon";
import { ScoreTile } from "../security/ScoreTile";
import { StatStrip } from "../common/StatStrip";
import { buttonVariants } from "../ui/button";

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
  // A row is a term and its value, so it is drawn inside the `dl` it always
  // sits in on a page; alone, it is markup no reader could be given.
  const inList = () => ({ container: document.body.appendChild(document.createElement("dl")) });

  it("distinguishes a value somebody chose from one Cleave guessed", () => {
    // The three context values multiply a finding into a risk. "CRITICAL"
    // invites the question "says who", and until the backend recorded
    // provenance there was no answer to give.
    const { container: declared } = render(
      <ContextRow
        label="Criticality"
        fact={{ value: "CRITICAL", source: "customer", confidence: 1 }}
      />,
      inList(),
    );
    const { container: guessed } = render(
      <ContextRow
        label="Criticality"
        fact={{ value: "CRITICAL", source: "inferred", confidence: 0.4 }}
      />,
      inList(),
    );
    expect(declared.innerHTML).not.toBe(guessed.innerHTML);
  });

  it("falls back without provenance rather than claiming a source", () => {
    render(<ContextRow label="Criticality" fallback={<Badge level="HIGH" />} />, inList());
    expect(screen.getByText("High")).toBeInTheDocument();
  });
});

describe("buttonVariants", () => {
  it("gives a link styled as an outline button its border", () => {
    // A `Link` takes these classes bare, not through `Button`. Unmerged, the
    // base's `border-transparent` won over the outline's `border-border` and
    // the link drew no border (DECISIONS.md section 135).
    const classes = buttonVariants({ variant: "outline", size: "sm" }).split(" ");
    expect(classes).toContain("border-border");
    expect(classes).not.toContain("border-transparent");
  });

  it("keeps a borderless variant borderless", () => {
    expect(buttonVariants({ variant: "ghost" }).split(" ")).toContain("border-transparent");
  });

  it("lets a class passed in win over the variant's", () => {
    const classes = buttonVariants({ variant: "outline", className: "h-auto" }).split(" ");
    expect(classes).toContain("h-auto");
    expect(classes).not.toContain("h-8");
  });
});

describe("ScoreTile", () => {
  it("shows a question mark, dashed, rather than a number it cannot stand behind", () => {
    const { container } = render(<ScoreTile score={41} level="UNKNOWN" />);
    expect(screen.getByText("?")).toBeInTheDocument();
    expect(screen.queryByText("41")).not.toBeInTheDocument();
    expect(container.firstElementChild?.className).toContain("border-dashed");
    expect(screen.getByLabelText("Risk score: no verdict")).toBeInTheDocument();
  });

  it("names the level in its label, not only in its tint", () => {
    render(<ScoreTile score={94.4} level="CRITICAL" />);
    expect(screen.getByLabelText("Risk score 94, critical")).toBeInTheDocument();
  });
});

describe("StatStrip", () => {
  it("colours the figure by its level, never the cell", () => {
    render(<StatStrip stats={[{ label: "Critical", value: 6, tone: "CRITICAL" }]} />);
    const figure = screen.getByText("6");
    expect(figure.className).toContain("text-critical");
    expect(figure.parentElement?.className).not.toContain("critical");
  });
});

describe("ResourceIcon", () => {
  it("draws the same glyph the rest of the product uses for the type", () => {
    const { container } = render(<ResourceIcon type="storage_account" />);
    expect(container.querySelector("svg.lucide-cylinder")).toBeInTheDocument();
    expect(container.firstElementChild).toHaveAttribute("aria-hidden");
  });

  it("falls back to a box for a type it does not know", () => {
    const { container } = render(<ResourceIcon type="something_new" />);
    expect(container.querySelector("svg.lucide-box")).toBeInTheDocument();
  });
});

describe("ProviderMark", () => {
  it("names the provider for a reader who cannot see the glyph, in a tile too", () => {
    render(<ProviderMark provider="gcp" tile />);
    expect(screen.getByRole("img", { name: "Google Cloud" })).toBeInTheDocument();
  });
});
