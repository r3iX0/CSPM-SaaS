import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { api, ApiError } from "@/lib/api";
import type { FixWithinDays, Organization, Severity } from "@/lib/types";
import { useT } from "@/i18n";
import { LeaveGuard } from "@/components/common/LeaveGuard";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { FieldDescription } from "@/components/ui/field";
import { Input } from "@/components/ui/input";

type Key = keyof FixWithinDays;
type Draft = Record<Key, string>;

/** The policy's keys, highest severity first, with the severity each one names. */
const SEVERITIES: readonly (readonly [Key, Severity])[] = [
  ["critical", "CRITICAL"],
  ["high", "HIGH"],
  ["medium", "MEDIUM"],
  ["low", "LOW"],
];

const NONE: FixWithinDays = { critical: null, high: null, medium: null, low: null };

function draftOf(days: FixWithinDays): Draft {
  return {
    critical: days.critical?.toString() ?? "",
    high: days.high?.toString() ?? "",
    medium: days.medium?.toString() ?? "",
    low: days.low?.toString() ?? "",
  };
}

/** A box's days: `null` for an empty box, `undefined` for one the API would refuse. */
function daysOf(value: string): number | null | undefined {
  if (value.trim() === "") return null;
  const days = Number(value);
  return Number.isInteger(days) && days >= 1 && days <= 365 ? days : undefined;
}

/**
 * How long the organization gives itself to fix a finding, by severity
 * (DECISIONS.md §225).
 *
 * A task with no due date of its own is due this many days after its finding
 * was first detected, so "Overdue" above the queue means something before
 * anybody has picked a date. Sent whole, as one statement of the policy, and
 * held until Save like the profile above it (§207).
 */
export function FixDeadlines({ organization }: { organization: Organization }) {
  const t = useT();
  const policy = organization.fix_within_days ?? NONE;
  const editable =
    (organization.role === "OWNER" || organization.role === "ADMIN") && !organization.is_demo;

  if (!editable) {
    return (
      <div className="flex flex-col gap-4 rounded-xl bg-card p-5 ring-1 ring-foreground/10">
        <p className="text-body text-muted-foreground">{t.settings.deadlinesReadOnly}</p>
        <dl className="grid grid-cols-[6rem_minmax(0,1fr)] gap-x-6 gap-y-3 text-body">
          {SEVERITIES.map(([key, severity]) => (
            <div key={key} className="contents">
              <dt>
                <SeverityBadge level={severity} />
              </dt>
              <dd className="text-foreground">
                {policy[key] === null
                  ? t.settings.deadlinesNone
                  : `${policy[key]} ${t.settings.deadlinesDays}`}
              </dd>
            </div>
          ))}
        </dl>
      </div>
    );
  }

  return <DeadlinesForm policy={policy} />;
}

function DeadlinesForm({ policy }: { policy: FixWithinDays }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [saved, setSaved] = useState<Draft>(() => draftOf(policy));
  const [draft, setDraft] = useState<Draft>(saved);
  const [error, setError] = useState<string | null>(null);

  const valid = SEVERITIES.every(([key]) => daysOf(draft[key]) !== undefined);
  const dirty = SEVERITIES.some(([key]) => draft[key].trim() !== saved[key]);

  const save = useMutation({
    mutationFn: (days: FixWithinDays) =>
      api.patch<Organization>("/api/v1/organizations", { fix_within_days: days }),
    onSuccess: (_, days) => {
      setError(null);
      setSaved(draftOf(days));
      setDraft(draftOf(days));
      toast.success(t.settings.deadlinesSaved);
      void queryClient.invalidateQueries({ queryKey: ["organizations"] });
      // Every task's deadline may have moved with the policy.
      void queryClient.invalidateQueries({ queryKey: ["remediation"] });
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : t.settings.deadlinesFailed),
  });

  const submit = () => {
    if (!dirty || !valid) return;
    const days: FixWithinDays = { ...NONE };
    for (const [key] of SEVERITIES) days[key] = daysOf(draft[key]) ?? null;
    save.mutate(days);
  };

  return (
    <form
      className="rounded-xl bg-card ring-1 ring-foreground/10"
      onSubmit={(event) => {
        event.preventDefault();
        submit();
      }}
    >
      <LeaveGuard dirty={dirty && !save.isPending} />
      <div className="flex flex-col gap-4 p-5">
        <div className="grid max-w-md grid-cols-[6rem_minmax(0,1fr)] items-center gap-x-4 gap-y-3">
          {SEVERITIES.map(([key, severity]) => (
            <div key={key} className="contents">
              <label htmlFor={`fix-within-${key}`}>
                <SeverityBadge level={severity} />
              </label>
              <div className="flex items-center gap-2">
                <Input
                  id={`fix-within-${key}`}
                  type="number"
                  inputMode="numeric"
                  min={1}
                  max={365}
                  step={1}
                  value={draft[key]}
                  placeholder={t.settings.deadlinesNone}
                  aria-invalid={daysOf(draft[key]) === undefined}
                  onChange={(event) =>
                    setDraft((current) => ({ ...current, [key]: event.target.value }))
                  }
                  className="w-32"
                />
                <span className="text-body text-muted-foreground">{t.settings.deadlinesDays}</span>
              </div>
            </div>
          ))}
        </div>
        <FieldDescription>{t.settings.deadlinesRange}</FieldDescription>
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
      </div>

      <div className="flex flex-wrap items-center justify-end gap-2 border-t border-border px-5 py-3">
        {dirty && (
          <p className="mr-auto text-meta text-muted-foreground" role="status">
            {t.settings.unsaved}
          </p>
        )}
        {dirty && (
          <Button
            type="button"
            variant="ghost"
            disabled={save.isPending}
            onClick={() => {
              setDraft(saved);
              setError(null);
            }}
          >
            {t.settings.discard}
          </Button>
        )}
        <Button type="submit" disabled={!dirty || !valid || save.isPending}>
          {save.isPending ? t.settings.saving : t.settings.deadlinesSave}
        </Button>
      </div>
    </form>
  );
}
