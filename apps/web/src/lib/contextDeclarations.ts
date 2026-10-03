import { api } from "@/lib/api";
import type { ContextDeclaration, Level } from "@/lib/types";

/**
 * The levels a customer may declare.
 *
 * UNKNOWN is deliberately absent. It is CloudGuard's own answer for "nothing
 * said anything", so offering it would let a customer assert an absence that
 * leaving the field unset already asserts -- and the API rejects it for the
 * same reason, so an option here would be a choice that always fails.
 */
export const DECLARABLE_LEVELS: Level[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

/** The value a level choice holds while nothing is declared. */
export const NOT_DECLARED = "none";

/**
 * Every declaration in the organization, in one request (DECISIONS.md §207).
 *
 * The one query every view of the declarations reads and every write updates:
 * the Risk context table and the getting-started checklist.
 */
export const DECLARATIONS_KEY = ["context-declarations"];

export function fetchDeclarations(): Promise<ContextDeclaration[]> {
  return api.get<ContextDeclaration[]>("/api/v1/context-declarations").then((r) => r.data);
}

/** What a declaration says, as the PUT takes it: the whole statement. */
export interface Statement {
  environment: string | null;
  criticality: Level | null;
  data_sensitivity: Level | null;
  note: string | null;
}

export function statementOf(declaration: ContextDeclaration | null | undefined): Statement {
  return {
    environment: declaration?.environment ?? null,
    criticality: declaration?.criticality ?? null,
    data_sensitivity: declaration?.data_sensitivity ?? null,
    note: declaration?.note ?? null,
  };
}

/** "CRITICAL" as a person writes it. */
export function levelLabel(level: string): string {
  return level.charAt(0) + level.slice(1).toLowerCase();
}
