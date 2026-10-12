import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { api, ApiError } from "@/lib/api";
import type { Organization, Severity } from "@/lib/types";
import { useT } from "@/i18n";
import { SelectField } from "@/components/common/SelectField";
import { managesOrganization } from "@/components/settings/sections";

const OFF = "OFF";
const FROM: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

/**
 * Which acceptances wait for a second owner or admin (DECISIONS.md §239).
 *
 * An instant control answered in a toast, as the organization's mode is (§236): it changes how a
 * decision is made from now on and nothing already decided. A team's only; the settings page
 * leaves it out in solo, where there is nobody else to approve.
 */
export function AcceptanceApproval({ organization }: { organization: Organization }) {
  const t = useT();
  const queryClient = useQueryClient();
  const manages = managesOrganization(organization);
  const current = organization.acceptance_approval_from ?? OFF;

  const change = useMutation({
    mutationFn: (from: Severity | null) =>
      api.patch("/api/v1/organizations", { acceptance_approval_from: from }),
    onSuccess: () => {
      toast.success(t.settings.approvalChanged);
      void queryClient.invalidateQueries({ queryKey: ["organizations"] });
    },
    onError: (error) =>
      toast.error(error instanceof ApiError ? error.message : t.settings.approvalFailed),
  });

  return (
    <div className="flex flex-col gap-2">
      <SelectField
        id="acceptance-approval"
        className="w-full sm:w-64"
        size="default"
        ariaLabel={t.settings.approvalLabel}
        value={current}
        disabled={!manages || change.isPending}
        options={[
          { value: OFF, label: t.settings.approvalOff },
          ...FROM.map((severity) => ({
            value: severity,
            label: t.settings.approvalFrom[severity],
          })),
        ]}
        onValueChange={(next) => {
          if (next === current) return;
          change.mutate(FROM.find((severity) => severity === next) ?? null);
        }}
      />
      {!manages && <p className="text-meta text-muted-foreground">{t.settings.approvalReadOnly}</p>}
    </div>
  );
}
