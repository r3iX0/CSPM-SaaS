import { describe, expect, it } from "vitest";

import { en } from "@/i18n/en";
import {
  confidenceReasons,
  confidenceSummary,
  confidenceWindow,
  needsContext,
  needsRescan,
  routeConfidenceWord,
} from "@/lib/confidence";
import type { ConfidenceInfo } from "@/lib/types";

const READ = {
  observed_at: "2026-01-01T00:00:00Z",
  fresh_until: "2026-01-02T12:00:00Z",
  stale_at: "2026-01-08T00:00:00Z",
};

function info(overrides: Partial<ConfidenceInfo>): ConfidenceInfo {
  return { ...READ, level: "HIGH", freshness: "FRESH", reasons: [], ...overrides };
}

describe("how confidence is said (§262)", () => {
  it("lists both context fields the way a sentence would", () => {
    const [reason] = confidenceReasons(
      en,
      info({
        level: "MEDIUM",
        reasons: [{ code: "CONTEXT_UNKNOWN", fields: ["criticality", "data_sensitivity"] }],
      }),
    );
    expect(reason).toBe(
      "Ranked on a cautious default: no criticality and data sensitivity on record.",
    );
  });

  it("phrases a guessed target as the route's caveat", () => {
    const guessed = info({
      level: "MEDIUM",
      reasons: [{ code: "CONTEXT_INFERRED", fields: ["data_sensitivity"] }],
    });
    expect(confidenceReasons(en, guessed, { route: true })).toEqual([
      "Its target's data sensitivity is a guess from its name.",
    ]);
    expect(routeConfidenceWord(en, guessed)).toBe("Target guessed");
  });

  it("says a settled finding is settled", () => {
    expect(confidenceSummary(en, info({}))).toBe(
      "Confidence: High. Current, and ranked on context that was declared or read.",
    );
  });

  it("dates a current reading to when it stops being current, and a stale one to when it did", () => {
    expect(confidenceWindow(en, info({}))).toMatch(/· Current until /);
    expect(confidenceWindow(en, info({ level: "LOW", freshness: "STALE" }))).toMatch(
      /· Stale from /,
    );
  });

  it("knows which remedy each reason asks for", () => {
    const stale = info({ level: "LOW", reasons: [{ code: "EVIDENCE_STALE", fields: [] }] });
    expect(needsRescan(stale)).toBe(true);
    expect(needsContext(stale)).toBe(false);
  });
});
