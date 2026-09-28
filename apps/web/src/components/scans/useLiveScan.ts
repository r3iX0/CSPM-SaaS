import { useEffect, useRef } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type { Scan, ScanDetail } from "@/lib/types";
import { useScanEvents } from "@/lib/scanEvents";
import { IN_FLIGHT } from "@/components/scans/status";

/**
 * One scan, kept current while it runs, and the run it is compared with.
 *
 * Pushed over `GET /scans/{id}/events` while that stream is live, and polled
 * whenever it is not -- the two write the same query, so which one delivered a
 * state is invisible on screen. Neither runs once the scan has finished.
 *
 * In the wizard rather than in the pipeline it draws because the wizard's step
 * bar and footer turn on the same answer: whether the scan is still running
 * decides between the Scan step and the Result step, and between Cancel and
 * Run another.
 */
export function useLiveScan(scanId: string) {
  const queryClient = useQueryClient();
  const live = useScanEvents(scanId);

  const detail = useQuery({
    queryKey: ["scan-detail", scanId],
    queryFn: () => api.get<ScanDetail>(`/api/v1/scans/${scanId}/detail`).then((r) => r.data),
    refetchInterval: (query) => {
      if (live) return false;
      const status = (query.state.data as ScanDetail | undefined)?.status;
      return !status || IN_FLIGHT.includes(status) ? 2500 : false;
    },
  });

  const scans = useQuery({
    queryKey: ["scans"],
    queryFn: () => api.get<Scan[]>("/api/v1/scans").then((r) => r.data),
  });

  const data = detail.data ?? null;
  const running = data === null || IN_FLIGHT.includes(data.status);

  // Once, on the transition to finished: a scan that ends changes findings,
  // the score and the scan list, and none of those poll on their own.
  const settled = useRef(false);
  useEffect(() => {
    if (!data || running || settled.current) return;
    settled.current = true;
    for (const key of ["scans", "findings", "risks", "dashboard"]) {
      queryClient.invalidateQueries({ queryKey: [key] });
    }
  }, [data, running, queryClient]);

  // The last finished scan of the same connection -- left out rather than
  // guessed when there is none.
  const previous = data
    ? (scans.data ?? [])
        .filter(
          (s) =>
            s.id !== data.id &&
            s.connection_id != null &&
            s.connection_id === data.connection_id &&
            (s.status === "COMPLETED" || s.status === "PARTIAL") &&
            s.created_at < data.created_at,
        )
        .sort((a, b) => b.created_at.localeCompare(a.created_at))[0]
    : undefined;

  return { data, running, previous };
}
