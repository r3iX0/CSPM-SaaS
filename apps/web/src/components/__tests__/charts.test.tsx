/**
 * The rules the charts are not allowed to break.
 *
 * Every one of these is a way a security dashboard can lie quietly: a shape
 * that implies a measurement nobody took, a status carried by colour alone, or
 * motion that keeps moving for a reader who asked it not to.
 */
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";

import { Sparkline } from "@/components/charts/Sparkline";
import { SeverityStrip } from "@/components/dashboard/SeverityStrip";
import { Bars } from "@/components/charts/Bars";
import { Donut } from "@/components/charts/Donut";
import { CIRCUMFERENCE, ringArcs } from "@/components/charts/ring";

describe("Sparkline", () => {
  it("draws nothing from a single reading", () => {
    // A dot is not a trend. Drawing one invites the reader to see a direction
    // nobody has measured.
    const { container } = render(<Sparkline values={[4]} label="Critical" />);

    expect(container.querySelector("svg")).not.toBeInTheDocument();
  });

  it("describes the movement in words, not only in a line", () => {
    render(<Sparkline values={[1, 3, 6]} label="Critical findings" />);

    expect(
      screen.getByRole("img", { name: /Critical findings: risen from 1 to 6/ }),
    ).toBeInTheDocument();
  });

  it("survives a flat series without collapsing", () => {
    // A constant series has a zero range; dividing by it would put every point
    // at the same edge of the box, or produce NaN coordinates.
    const { container } = render(<Sparkline values={[2, 2, 2]} label="High" />);

    const path = container.querySelector("path")?.getAttribute("d") ?? "";
    expect(path).not.toContain("NaN");
    expect(screen.getByRole("img", { name: /held from 2 to 2/ })).toBeInTheDocument();
  });
});

describe("Bars", () => {
  it("measures every bar against the same scale", () => {
    const { container } = render(
      <MemoryRouter>
        <Bars
          ariaLabel="Risk bands"
          bars={[
            { key: "a", label: "Critical", value: 5, tone: "var(--sev-critical)" },
            { key: "b", label: "Low", value: 1, tone: "var(--sev-low)" },
          ]}
        />
      </MemoryRouter>,
    );

    const widths = [...container.querySelectorAll("span[style*='width']")].map(
      (node) => (node as HTMLElement).style.width,
    );
    // The largest fills the track and the rest are proportional to it, so two
    // bars can be compared by length rather than by reading their numbers.
    expect(widths).toEqual(["100%", "20%"]);
  });
});

describe("SeverityStrip", () => {
  it("links each level to its findings, and no verdict to the scans that could not read it", () => {
    render(
      <MemoryRouter>
        <SeverityStrip counts={{ CRITICAL: 2, HIGH: 0 }} unknown={5} />
      </MemoryRouter>,
    );

    expect(screen.getByRole("link", { name: /Critical\s*2/ })).toHaveAttribute(
      "href",
      "/findings?severity=CRITICAL",
    );
    expect(screen.getByRole("link", { name: /No verdict\s*5/ })).toHaveAttribute("href", "/scans");
  });

  it("says what each figure counts, findings apart from checks", () => {
    // "Critical 2" sat above five critical risks with nothing saying one
    // counted findings and the other risks (§186).
    render(
      <MemoryRouter>
        <SeverityStrip counts={{ CRITICAL: 2 }} unknown={5} />
      </MemoryRouter>,
    );

    expect(screen.getByRole("link", { name: /Critical\s*2\s*open findings/ })).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /No verdict\s*5\s*checks, not findings/ }),
    ).toBeInTheDocument();
  });

  it("marks no verdict dashed, so it never reads as a quiet low", () => {
    render(
      <MemoryRouter>
        <SeverityStrip counts={{}} unknown={1} />
      </MemoryRouter>,
    );

    expect(screen.getByText("No verdict").className).toContain("border-dashed");
  });
});

describe("Donut", () => {
  const slices = [
    { key: "pass", label: "Passed", value: 396, tone: "var(--sev-ok)" },
    { key: "fail", label: "Failed", value: 1, tone: "var(--sev-critical)" },
    { key: "none", label: "Not assessed", value: 0, tone: "var(--sev-unknown)" },
  ];

  it("keeps a tiny share visible and leaves out a share of nothing", () => {
    // One failure in four hundred is still a failure; drawn to scale it would
    // be a sliver nobody sees. A zero is not part of the whole, so no arc.
    const arcs = ringArcs(slices);

    expect(arcs.map((arc) => arc.slice.key)).toEqual(["pass", "fail"]);
    expect(arcs[1].length).toBeCloseTo((4 / 360) * CIRCUMFERENCE);
  });

  it("closes at the full circle, gaps included", () => {
    const arcs = ringArcs(slices);
    const last = arcs[arcs.length - 1];
    const gap = (1.5 / 360) * CIRCUMFERENCE;

    expect(last.offset + last.length + gap).toBeCloseTo(CIRCUMFERENCE);
  });

  it("names every segment's share, and draws no Recharts", () => {
    const { container } = render(
      <Donut slices={slices} centerValue="99%" centerLabel="" ariaLabel="396 of 397 passed" />,
    );

    expect(screen.getByRole("img", { name: "396 of 397 passed" })).toBeInTheDocument();
    const titles = [...container.querySelectorAll("circle[data-slice] title")].map(
      (title) => title.textContent,
    );
    expect(titles).toEqual(["Passed · 396 · 100%", "Failed · 1 · 0%"]);
    expect(container.querySelector(".recharts-wrapper")).not.toBeInTheDocument();
  });
});
