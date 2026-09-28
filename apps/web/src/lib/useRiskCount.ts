import { useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type { Risk } from "@/lib/types";

/**
 * How many live risks the risks list holds, optionally at one level.
 *
 * Counted by the list's own endpoint rather than summed from the dashboard's
 * `risk_bands`: those bands count finding risks only, so any estate with an
 * attack path or an escalation got a smaller number than the list it opened.
 * One row is fetched; `meta.total` is the count. Null until it has arrived, so
 * a count that is not known is never drawn as 0.
 */
export function useRiskCount(level?: "CRITICAL" | "HIGH"): number | null {
  const { data } = useQuery({
    queryKey: ["risks", "count", level ?? "all"],
    queryFn: () =>
      api
        .get<Risk[]>(`/api/v1/risks?limit=1${level ? `&risk_level=${level}` : ""}`)
        .then((r) => (r.meta as { total?: number } | undefined)?.total ?? null),
    staleTime: 60_000,
    retry: false,
  });
  return typeof data === "number" ? data : null;
}
