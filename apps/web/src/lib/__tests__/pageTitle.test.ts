/**
 * Every route has a name of its own in the browser's title (WCAG 2.4.2).
 */
import { describe, expect, it } from "vitest";

import { documentTitle, routeTitle } from "@/lib/pageTitle";

describe("the page title", () => {
  it("names a page what the navigation calls it", () => {
    expect(documentTitle("/", null)).toBe("Overview · Cleave");
    expect(documentTitle("/attack-paths", null)).toBe("Attack paths · Cleave");
    expect(documentTitle("/connections", null)).toBe("Environments · Cleave");
  });

  it("names the routes the navigation does not list", () => {
    expect(routeTitle("/sign-in")).toBe("Sign in");
    expect(routeTitle("/connections/new")).toBe("Connect an environment");
    expect(routeTitle("/connections/abc/setup")).toBe("Environment setup");
  });

  it("names the audit pages, the owner's and the auditor's", () => {
    expect(documentTitle("/settings/audit", null)).toBe("Audit packages · Settings · Cleave");
    expect(routeTitle("/auditor")).toBe("Audit packages");
    expect(documentTitle("/auditor/g-1", "SOC 2 FY26")).toBe("SOC 2 FY26 · Audit package · Cleave");
  });

  it("puts a detail page's own name first", () => {
    expect(documentTitle("/findings/f1", null)).toBe("Finding · Cleave");
    expect(documentTitle("/findings/f1", "Storage open to the internet")).toBe(
      "Storage open to the internet · Finding · Cleave",
    );
  });

  it("falls back to the product for a path it does not know", () => {
    expect(documentTitle("/nowhere", null)).toBe("Cleave");
  });
});
