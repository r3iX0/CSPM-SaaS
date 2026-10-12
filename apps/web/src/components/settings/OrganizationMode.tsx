import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { api, ApiError } from "@/lib/api";
import type { Organization, OrganizationMode } from "@/lib/types";
import { useT } from "@/i18n";
import { OptionCard } from "@/components/settings/OptionCard";
import { isTeam, managesOrganization } from "@/components/settings/sections";
import { RadioGroup } from "@/components/ui/radio-group";

const MODES: OrganizationMode[] = ["SOLO", "TEAM"];

/**
 * One person or a team (DECISIONS.md §236).
 *
 * An instant control, answered in a toast, as an integration's switch is (§207):
 * the choice changes what the product shows and nothing it stores. The API
 * refuses solo while anybody else is in the organization or invited to it, and
 * says so; that refusal is the toast.
 */
export function OrganizationModeChoice({ organization }: { organization: Organization }) {
  const t = useT();
  const queryClient = useQueryClient();
  const manages = managesOrganization(organization);
  const current: OrganizationMode = isTeam(organization) ? "TEAM" : "SOLO";

  const change = useMutation({
    mutationFn: (mode: OrganizationMode) => api.patch("/api/v1/organizations", { mode }),
    onSuccess: (_, mode) => {
      toast.success(t.settings.modeChanged(t.settings.modes[mode]));
      void queryClient.invalidateQueries({ queryKey: ["organizations"] });
    },
    onError: (error) =>
      toast.error(error instanceof ApiError ? error.message : t.settings.modeFailed),
  });

  return (
    <div className="flex flex-col gap-2">
      <RadioGroup
        aria-label={t.settings.modeTitle}
        value={current}
        disabled={!manages || change.isPending}
        onValueChange={(next) => {
          const mode = MODES.find((value) => value === next);
          if (mode && mode !== current) change.mutate(mode);
        }}
        className="gap-1.5"
      >
        {MODES.map((mode) => (
          <OptionCard
            key={mode}
            id={`organization-mode-${mode}`}
            value={mode}
            title={t.settings.modes[mode]}
            description={t.settings.modeHelpOf[mode]}
            checked={current === mode}
          />
        ))}
      </RadioGroup>
      {!manages && <p className="text-meta text-muted-foreground">{t.settings.modeReadOnly}</p>}
    </div>
  );
}
