/**
 * Two tasks of one rule are one fix applied twice (DECISIONS.md §203), and the
 * queue says so without giving up the server's order.
 */
import { describe, expect, it } from "vitest";

import { groupByRule } from "@/lib/remediation";
import type { FindingDetail, RemediationTask } from "@/lib/types";

function task(id: string, findingId: string): RemediationTask {
  return {
    id,
    finding_id: findingId,
    risk_id: null,
    status: "TODO",
    priority: "HIGH",
    due_date: null,
    estimated_effort_minutes: 15,
    notes: null,
    completed_at: null,
    created_at: "2026-10-01T00:00:00Z",
  };
}

function findings(rules: Record<string, string>): Map<string, FindingDetail> {
  // Only the rule matters to grouping; the rest of a finding is not read.
  return new Map(
    Object.entries(rules).map(([id, ruleId]) => [
      id,
      { id, rule_id: ruleId } as unknown as FindingDetail,
    ]),
  );
}

describe("grouping the queue by rule", () => {
  it("draws the tasks of one rule as one item, where its highest-ranked task was", () => {
    const tasks = [task("t1", "f1"), task("t2", "f2"), task("t3", "f3")];
    const items = groupByRule(tasks, findings({ f1: "A", f2: "B", f3: "A" }));

    expect(items).toEqual([
      { kind: "group", ruleId: "A", tasks: [tasks[0], tasks[2]] },
      { kind: "task", task: tasks[1] },
    ]);
  });

  it("leaves a rule's only task on its own", () => {
    const tasks = [task("t1", "f1"), task("t2", "f2")];
    const items = groupByRule(tasks, findings({ f1: "A", f2: "B" }));

    expect(items.map((item) => item.kind)).toEqual(["task", "task"]);
  });

  it("leaves a task whose finding has not arrived on its own", () => {
    const tasks = [task("t1", "f1"), task("t2", "f2")];
    const items = groupByRule(tasks, findings({ f1: "A" }));

    expect(items).toEqual([
      { kind: "task", task: tasks[0] },
      { kind: "task", task: tasks[1] },
    ]);
  });
});
