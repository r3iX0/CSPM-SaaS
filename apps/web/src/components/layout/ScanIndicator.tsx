import { useQuery } from "@tanstack/react-query";
import { AlertTriangleIcon, LoaderIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { Scan } from "@/lib/types";
import { label } from "@/lib/format";
import { useScanWizard } from "@/components/scans/ScanWizardProvider";
import { IN_FLIGHT } from "@/components/scans/status";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

/**
 * Whether CloudGuard is reading the environment right now.
 *
 * In the header because a scan takes minutes and outlives the page somebody
 * started it from. Previously the only way to know was to be on the scans page,
 * so a user who kicked one off and navigated away had no idea whether the
 * numbers in front of them were about to change.
 *
 * It is also where a minimised scan wizard lives: clicking it reopens the
 * dialog on the running scan, over whatever page the reader is on, rather
 * than navigating away from it.
 *
 * It also surfaces the one failure that used to be invisible: a scan that has
 * sat QUEUED long enough that no worker can plausibly be coming for it. That
 * shows as a warning rather than a spinner, because a spinner for a job nobody
 * is running is a lie told slowly.
 */
export function ScanIndicator() {
  const wizard = useScanWizard();
  const { data } = useQuery({
    queryKey: ["scans", "indicator"],
    queryFn: () => api.get<Scan[]>("/api/v1/scans?limit=5").then((r) => r.data),
    // Only while something is in flight. A dashboard left open overnight should
    // not poll a finished scan every ten seconds until the tab is closed.
    refetchInterval: (query) => {
      const scans = query.state.data as Scan[] | undefined;
      return scans?.some((s) => IN_FLIGHT.includes(s.status)) ? 10_000 : false;
    },
    retry: false,
  });

  const active = data?.find((s) => IN_FLIGHT.includes(s.status));
  if (!active) return null;

  const stalled = active.stuck_in_queue === true;

  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <button
            type="button"
            onClick={() => wizard.watch(active.id)}
            className="flex items-center gap-2 rounded-full border px-2.5 py-1 text-xs text-muted-foreground transition-colors hover:text-foreground"
          />
        }
      >
        {stalled ? (
          <AlertTriangleIcon className="size-3.5 text-medium" aria-hidden />
        ) : (
          <LoaderIcon className="size-3.5 animate-spin text-muted-foreground" aria-hidden />
        )}
        <span className="hidden sm:inline">
          {stalled ? "Scan not picked up" : label(active.status)}
        </span>
      </TooltipTrigger>
      <TooltipContent>
        {stalled
          ? "This scan has been queued long enough that no worker appears to be running."
          : "A scan is reading your environment. Click to watch it."}
      </TooltipContent>
    </Tooltip>
  );
}
