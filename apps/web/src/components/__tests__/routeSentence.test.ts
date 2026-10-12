/**
 * A route in one sentence (DECISIONS.md §247): built from the hops' own facts,
 * with the containment that only says where the target sits folded away.
 */
import { describe, expect, it } from "vitest";

import { routeSentence } from "@/components/graph/routeSentence";
import type { AttackPath, AttackPathStep } from "@/lib/types";

function step(
  source: string,
  relationship: string,
  target: string,
  facts: string[] = [],
): AttackPathStep {
  return {
    source,
    source_id: source,
    relationship,
    target,
    target_id: target,
    description: `${source} ${relationship} ${target}`,
    facts,
    detail: `${source} ${relationship} ${target}`,
  };
}

function route(steps: AttackPathStep[]): AttackPath {
  const first = steps[0];
  const last = steps[steps.length - 1];
  return {
    entry: {
      id: first?.source ?? "",
      name: first?.source ?? "",
      resource_type: "virtual_machine",
      public_exposure: "HIGH",
    },
    target: {
      id: last?.target ?? "",
      name: last?.target ?? "",
      resource_type: "key_vault",
      data_sensitivity: "HIGH",
    },
    hops: steps.length,
    steps,
    cheapest_break: null,
  };
}

describe("routeSentence", () => {
  it("tells a workload's own identity and its role as one story", () => {
    expect(
      routeSentence(
        route([
          step("app-payments-api", "has_identity", "app-payments-api (managed identity)", [
            "managed identity",
          ]),
          step("app-payments-api (managed identity)", "grants_role", "kv-payments", [
            "Key Vault Secrets User",
          ]),
        ]),
      ),
    ).toBe(
      "From the internet, app-payments-api runs as its own identity, which holds Key Vault Secrets User over kv-payments.",
    );
  });

  it("folds the containment at the end into where the target sits", () => {
    expect(
      routeSentence(
        route([
          step("vm-jumpbox", "has_identity", "mi-jump"),
          step("mi-jump", "grants_role", "Production", ["Contributor"]),
          step("Production", "contains", "rg-data"),
          step("rg-data", "contains", "stledger"),
        ]),
      ),
    ).toBe(
      "From the internet, vm-jumpbox runs as mi-jump, which holds Contributor over Production, and so reaches stledger inside Production.",
    );
  });

  it("names a role only where the hop records one", () => {
    expect(routeSentence(route([step("mi", "grants_role", "rg")]))).toBe(
      "From the internet, mi can act over rg.",
    );
  });

  it("says a directory takeover with the role behind it", () => {
    expect(
      routeSentence(
        route([step("Arben K", "can_take_over", "Production", ["Global Administrator"])]),
      ),
    ).toBe("From the internet, Arben K can take ownership of Production as Global Administrator.");
  });
});
