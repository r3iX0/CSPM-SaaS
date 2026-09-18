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
 * applies a decision to all of them or to none. The buttons offered are the
 * ones that would change something: nothing to reopen is no Reopen button.
 * Accept is the exception -- on an accepted row it changes the end date.
 *
 * A decision on a finding risk is written to every open finding in it, so the
 * accept dialog says how many that is. Forty accounts is one click here, and
 * the dialog is where that has to be visible rather than discovered.
 */
export function RiskTriageBar({
  selected,
  onDone,
}: {
  selected: Risk[];
  onDone: () => void;
}) {
  const queryClient = useQueryClient();
  const [accepting, setAccepting] = useState(false);
  const [reason, setReason] = useState("");
  // A day, not an instant (`endOfDayIso`).
  const [until, setUntil] = useState("");

  const decide = useMutation({
    mutationFn: (decision: { status: Decision; reason?: string; expires_at?: string }) =>
      api.post("/api/v1/risks/status", {
        risk_ids: selected.map((risk) => risk.id),
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
      onDone();
      queryClient.invalidateQueries({ queryKey: ["risks"] });
      queryClient.invalidateQueries({ queryKey: ["findings"] });
      queryClient.invalidateQueries({ queryKey: ["dashboard"] });
    },
    onError: (err) =>
      toast.error("Nothing was changed", {
        description:
          err instanceof ApiError ? err.message : "The API rejected the decision.",
      }),
  });

  if (selected.length === 0) return null;

  const canStart = selected.some((risk) => risk.status === "OPEN");
  const canReopen = selected.some(
    (risk) => risk.status === "ACCEPTED" || risk.status === "IN_PROGRESS",
  );
  const findings = selected.reduce(
    (sum, risk) => sum + (risk.kind === "FINDING" ? (risk.finding_count ?? 1) : 0),
    0,
  );
  const routes = selected.filter((risk) => risk.kind !== "FINDING").length;

  return (
    <>
      <div
        role="region"
        aria-label="Selected risks"
        className="sticky top-2 z-20 flex flex-wrap items-center justify-between gap-3 rounded-xl border border-border bg-card px-4 py-2.5 shadow-sm"
      >
        <p className="text-sm text-foreground">
          <strong className="tabular-nums">{selected.length}</strong> selected
        </p>
        <div className="flex flex-wrap gap-2">
          {canStart && (
            <Button
              variant="outline"
              size="sm"
              disabled={decide.isPending}
              onClick={() => decide.mutate({ status: "IN_PROGRESS" })}
            >
              Mark in progress
            </Button>
          )}
          {/* Always offered, accepted rows included: accepting again is how an
              end date is moved or removed, and it replaces the running one. */}
          <Button
            variant="outline"
            size="sm"
            disabled={decide.isPending}
            onClick={() => setAccepting(true)}
          >
            Accept…
          </Button>
          {canReopen && (
            <Button
              variant="outline"
              size="sm"
              disabled={decide.isPending}
              onClick={() => decide.mutate({ status: "OPEN" })}
            >
              Reopen
            </Button>
          )}
          <Button variant="ghost" size="sm" onClick={onDone}>
            Clear
          </Button>
        </div>
      </div>

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
                Accept {selected.length === 1 ? "this risk" : `${selected.length} risks`}
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
