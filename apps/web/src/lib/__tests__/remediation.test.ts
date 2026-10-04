/**
 * Two tasks of one rule are one fix applied twice (DECISIONS.md §203), and the
 * queue says so without giving up the server's order.
 */
import { describe, expect, it } from "vitest";

import {
  groupByRule,
  groupUntracked,
  ruleTitle,
  workState,
  worstSeverity,
} from "@/lib/remediation";
import type { Finding, FindingDetail, RemediationTask, Verification } from "@/lib/types";

function task(id: string, findingId: string): RemediationTask {
  return {
    id,
    finding_id: findingId,
    risk_id: null,
    status: "TODO",
    priority: "HIGH",
    assigned_to: null,
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

describe("where a tracked fix has got to (DECISIONS.md §212)", () => {
  const done: RemediationTask = { ...task("t1", "f1"), status: "DONE" };

  function claimed(verification: Partial<Verification> | null, status = "IN_PROGRESS") {
    const full: Verification | null = verification && {
      status: "PENDING",
      claimed_at: "2026-10-03T00:00:00Z",
      expected_state: [],
      attempts: 0,
      last_state: null,
      next_attempt_at: null,
      settled_at: null,
      detail: null,
      ...verification,
    };
    // Only the status and the verification are read.
    return { status, verification: full } as unknown as FindingDetail;
  }

  it("follows the task until the work is claimed", () => {
    expect(workState(task("t1", "f1"))).toBe("todo");
    expect(workState({ ...task("t1", "f1"), status: "IN_PROGRESS" })).toBe("in_progress");
  });

  it("says checking only until a check has looked", () => {
    expect(workState(done, claimed(null))).toBe("checking");
    expect(workState(done, claimed({ attempts: 0 }))).toBe("checking");
    expect(workState(done, claimed({ attempts: 2, last_state: "FAIL" }))).toBe("not_yet");
  });

  it("takes the verdict once there is one", () => {
    expect(workState(done, claimed({ status: "STILL_FAILING" }))).toBe("still_failing");
    expect(workState(done, claimed({ status: "INSUFFICIENT_EVIDENCE" }))).toBe("unverified");
    expect(workState(done, claimed({ status: "VERIFIED" }))).toBe("fixed");
    expect(workState(done, claimed(null, "RESOLVED"))).toBe("fixed");
  });
});

describe("the findings nobody tracked", () => {
  function open(id: string, ruleId: string, name: string): Finding {
    // Only these fields are read.
    return {
      id,
      rule_id: ruleId,
      title: `Rule ${ruleId} — ${name}`,
      resource: { name },
    } as unknown as Finding;
  }

  it("draws one rule's findings as one line, where the worst of them was", () => {
    const findings = [open("a", "R1", "x"), open("b", "R2", "y"), open("c", "R1", "z")];

    expect(groupUntracked(findings)).toEqual([
      { ruleId: "R1", findings: [findings[0], findings[2]] },
      { ruleId: "R2", findings: [findings[1]] },
    ]);
  });

  it("names the rule by taking the asset off the title, and only then", () => {
    expect(ruleTitle(open("a", "R1", "x"))).toBe("Rule R1");
    expect(ruleTitle({ title: "Something else", resource: null })).toBe("Something else");
  });

  it("badges a line with its worst severity", () => {
    expect(worstSeverity(["LOW", "HIGH", "MEDIUM"])).toBe("HIGH");
  });
});
