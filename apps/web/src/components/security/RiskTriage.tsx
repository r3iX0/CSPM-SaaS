import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { api, ApiError } from "@/lib/api";
import { endOfDayIso, tomorrowDay } from "@/lib/format";
import type { Risk } from "@/lib/types";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { Textarea } from "@/components/ui/textarea";

type Decision = "OPEN" | "IN_PROGRESS" | "ACCEPTED";

/** The shortest reason the API takes. Checked here so the button says so first. */
const MIN_REASON = 10;

/**
 * What to do about the risks selected in the queue (DECISIONS.md §103).
 *
 * One bar for one risk or fifty, because the API takes both the same way and
 * applies a decision to all of them or to none.
 */
export function RiskTriageBar({
  selected,
  onDone,
}: {
  selected: Risk[];
  onDone: () => void;
}) {
  if (selected.length === 0) return null;

  return (
    <div
      role="region"
      aria-label="Selected risks"
      className="sticky top-2 z-20 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border bg-card px-4 py-2.5 shadow-sm"
    >
      <p className="text-sm text-foreground">
        <strong className="tabular-nums">{selected.length}</strong> selected
      </p>
      <div className="flex flex-wrap gap-2">
        <RiskDecisions risks={selected} size="sm" onDone={onDone} />
        <Button variant="ghost" size="sm" onClick={onDone}>
          Clear
        </Button>
      </div>
    </div>
  );
}

/**
 * The decisions about one or more risks -- the only place in the product a
 * risk, or a finding, is triaged (DECISIONS.md §107). Used by the queue's bar
 * and by the risk page.
 *
 * The buttons offered are the ones that would change something: nothing to
 * reopen is no Reopen button. Accept is the exception -- on an accepted risk it
 * changes the end date.
 *
 * A decision on a finding risk is written to every open finding in it, so the
 * accept dialog says how many that is. Forty accounts is one click here, and
 * the dialog is where that has to be visible rather than discovered.
 */
export function RiskDecisions({
  risks,
  size = "default",
  onDone,
}: {
  risks: Risk[];
  size?: "sm" | "default";
  onDone?: () => void;
}) {
  const queryClient = useQueryClient();
  const [accepting, setAccepting] = useState(false);
  const [reason, setReason] = useState("");
  // A day, not an instant (`endOfDayIso`).
  const [until, setUntil] = useState("");

  const decide = useMutation({
    mutationFn: (decision: { status: Decision; reason?: string; expires_at?: string }) =>
      api.post("/api/v1/risks/status", {
        risk_ids: risks.map((risk) => risk.id),
        ...decision,
      }),
    onSuccess: (_, decision) => {
      toast.success(DONE[decision.status], {
        description:
          decision.status === "ACCEPTED"
            ? "Recorded in the audit log with your reason. Accepted risks stay listed under Accepted — never hidden."
            : "A status is intent, not proof. A risk resolves when a scan observes the fix.",
      });
      setAccepting(false);
      setReason("");
      setUntil("");
      onDone?.();
      // The risk page and every finding in it show the status just written.
      for (const key of ["risks", "risk", "findings", "finding", "dashboard"]) {
        queryClient.invalidateQueries({ queryKey: [key] });
      }
    },
    onError: (err) =>
      toast.error("Nothing was changed", {
        description:
          err instanceof ApiError ? err.message : "The API rejected the decision.",
      }),
  });

  if (risks.length === 0) return null;

  const canStart = risks.some((risk) => risk.status === "OPEN");
  const canReopen = risks.some(
    (risk) => risk.status === "ACCEPTED" || risk.status === "IN_PROGRESS",
  );
  const findings = risks.reduce(
    (sum, risk) => sum + (risk.kind === "FINDING" ? (risk.finding_count ?? 1) : 0),
    0,
  );
  const routes = risks.filter((risk) => risk.kind !== "FINDING").length;

  return (
    <>
      {canStart && (
        <Button
          variant="outline"
          size={size}
          disabled={decide.isPending}
          onClick={() => decide.mutate({ status: "IN_PROGRESS" })}
        >
          Mark in progress
        </Button>
      )}
      {/* Always offered, accepted risks included: accepting again is how an
          end date is moved or removed, and it replaces the running one. */}
      <Button
        variant="outline"
        size={size}
        disabled={decide.isPending}
        onClick={() => setAccepting(true)}
      >
        Accept…
      </Button>
      {canReopen && (
        <Button
          variant="outline"
          size={size}
          disabled={decide.isPending}
          onClick={() => decide.mutate({ status: "OPEN" })}
        >
          Reopen
        </Button>
      )}

      <Dialog open={accepting} onOpenChange={setAccepting}>
        <DialogContent className="sm:max-w-lg">
          <form
            onSubmit={(e) => {
              e.preventDefault();
              decide.mutate({
                status: "ACCEPTED",
                reason: reason.trim(),
                ...(until ? { expires_at: endOfDayIso(until) } : {}),
              });
            }}
            className="flex flex-col gap-4"
          >
            <DialogHeader>
              <DialogTitle>
                Accept {risks.length === 1 ? "this risk" : `${risks.length} risks`}
              </DialogTitle>
              <DialogDescription>{acceptScope(findings, routes)}</DialogDescription>
            </DialogHeader>
            <Field>
              <FieldLabel htmlFor="risk-accept-reason">Why is this acceptable?</FieldLabel>
              <Textarea
                id="risk-accept-reason"
                required
                autoFocus
                minLength={MIN_REASON}
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Compensating control in place: WAF restricts source addresses"
              />
              <FieldDescription>
                Recorded in the audit log. Accepted risks stay visible — they are never
                hidden, and never counted as fixed.
              </FieldDescription>
            </Field>
            <Field>
              <FieldLabel htmlFor="risk-accept-until">Until (optional)</FieldLabel>
              <Input
                id="risk-accept-until"
                type="date"
                min={tomorrowDay()}
                value={until}
                onChange={(e) => setUntil(e.target.value)}
                className="w-fit"
              />
              <FieldDescription>
                {until
                  ? "After this date the risk comes back to Needs triage on its own, and the timeline says why."
                  : "With no date, it stays accepted until somebody reopens it."}
              </FieldDescription>
            </Field>
            <DialogFooter>
              <Button type="button" variant="ghost" onClick={() => setAccepting(false)}>
                Cancel
              </Button>
              <Button
                type="submit"
                variant="destructive"
                disabled={decide.isPending || reason.trim().length < MIN_REASON}
              >
                {decide.isPending && <Spinner data-icon="inline-start" />}
                Accept
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  );
}

const DONE: Record<Decision, string> = {
  OPEN: "Reopened",
  IN_PROGRESS: "Marked in progress",
  ACCEPTED: "Accepted",
};

/** What accepting reaches, said before the click rather than after it. */
function acceptScope(findings: number, routes: number): string {
  const parts: string[] = [];
  if (findings > 0) {
    parts.push(
      `${findings} open finding${findings === 1 ? "" : "s"}, each recorded as an accepted risk`,
    );
  }
  if (routes > 0) {
    parts.push(
      `${routes} route${routes === 1 ? "" : "s"} marked as by design — the findings along ${routes === 1 ? "it" : "them"} stay open`,
    );
  }
  return `This applies to ${parts.join(", and ")}.`;
}
