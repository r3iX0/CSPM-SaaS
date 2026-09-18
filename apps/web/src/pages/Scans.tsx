import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ActivityIcon, PlayIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { Scan } from "@/lib/types";
import { useT } from "@/i18n";
import { ScanCard } from "@/components/scans/ScanCard";
import { AutomaticScanning } from "@/components/scans/AutomaticScanning";
import { useScanWizard } from "@/components/scans/ScanWizardProvider";
import { IN_FLIGHT } from "@/components/scans/status";
import { useIsDemo } from "@/lib/useDemo";
import { CardsSkeleton, EmptyState, PageHeader } from "@/components/common/states";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";

/**
 * Every run, and the button that starts the next one.
 *
 * The page is a list and a control; a scan's own card is
 * `components/scans/ScanCard.tsx`, and everything it can open -- the stage
 * breakdown, what was and was not collected, the two-way delete -- lives beside
 * it. That split is not tidying: the card polls two endpoints on its own
 * schedule and the panels below it fetch only when opened, and keeping those
 * lifetimes in one 600-line file made it genuinely hard to see which request
 * fired when.
 *
 * Starting a scan is the scan wizard's job (`ScanWizard.tsx`), mounted in the
 * shell so a run can be followed from any page. The button here only opens it.
 */
export function ScansPage() {
  const t = useT();
  const wizard = useScanWizard();
  const isDemo = useIsDemo();
  const [error, setError] = useState<string | null>(null);

  const scans = useQuery({
    queryKey: ["scans"],
    queryFn: () => api.get<Scan[]>("/api/v1/scans").then((r) => r.data),
    // Poll while a scan is in flight so progress is visible live, then stop.
    refetchInterval: (query) => {
      const rows = query.state.data as Scan[] | undefined;
      return rows?.some((s) => IN_FLIGHT.includes(s.status)) ? 2000 : false;
    },
  });

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <PageHeader
          icon={ActivityIcon}
          title={t.scans.title}
          description="Every time CloudGuard has read your environment, and what it could reach."
        />
        {!isDemo && (
        <Button className="shrink-0" onClick={() => wizard.start()}>
          <PlayIcon data-icon="inline-start" />
          {t.scans.runScan}
        </Button>
        )}
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertTitle>Could not change automatic scanning</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {/* The clock, above the history it explains: a list of runs with no
          visible cadence makes the gaps between them look like something that
          happened rather than something that was chosen. */}
      {!isDemo && <AutomaticScanning onError={setError} />}

      {scans.isLoading && <CardsSkeleton />}

      {scans.data && scans.data.length === 0 && (
        <EmptyState
          icon={ActivityIcon}
          title={t.scans.empty}
          detail="Once a connection is verified, run a scan to discover resources and assess them."
        />
      )}

      {/* One history, one container: rows divided rather than cards stacked,
          so a month of runs scans as a list and a failure stands out by its
          status rather than by being one more box. */}
      {scans.data && scans.data.length > 0 && (
        <section>
          <h2 className="mb-2 text-sm font-medium text-foreground">{t.scans.history}</h2>
          <div className="divide-y divide-border overflow-hidden rounded-xl border border-border bg-card">
            {scans.data.map((scan) => (
              <ScanCard key={scan.id} scan={scan} />
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
