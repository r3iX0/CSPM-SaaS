import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { RadarIcon } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/common/states";
import { ResourceTypeLabel } from "@/components/security/IconLabel";

interface Reached {
  id: string;
  /** The row id, for opening it; null for a vertex with no row. */
  asset_id?: string | null;
  name: string;
  resource_type: string;
  data_sensitivity: string;
}

/**
 * What this asset can act on, if it were taken.
 *
 * Loaded on demand rather than with the page, and that is a cost decision
 * rather than a stylistic one: the endpoint rebuilds the organization's whole
 * asset graph to answer, so firing it automatically would put that behind every
 * asset anybody merely clicked into.
 *
 * Keyed on the provider resource id, not the row id -- the graph's vertices are
 * the cloud's own identifiers, and the database UUID names nothing in it.
 */
export function BlastRadius({
  providerResourceId,
  name,
  drawNow = false,
}: {
  providerResourceId: string;
  name: string;
  /**
   * Draw on mount rather than behind a button. Set where opening the view is
   * itself the request -- the asset page's Connections tab -- so the reader
   * is not asked twice.
   */
  drawNow?: boolean;
}) {
  const [asked, setAsked] = useState(drawNow);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: ["blast-radius", providerResourceId],
    queryFn: () =>
      api
        .get<Reached[]>(
          `/api/v1/attack-paths/blast-radius/${encodeURIComponent(providerResourceId)}`,
        )
        .then((r) => r.data),
    enabled: asked,
    retry: false,
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>Blast radius</CardTitle>
        <CardDescription>
          What {name} could act on if an attacker controlled it
        </CardDescription>
      </CardHeader>
      <CardContent>
        {!asked && (
          <Button variant="outline" size="sm" onClick={() => setAsked(true)}>
            <RadarIcon data-icon="inline-start" />
            Work out reach
          </Button>
        )}

        {asked && isLoading && (
          <div className="flex flex-col gap-2">
            <Skeleton className="h-4 w-48" />
            <Skeleton className="h-4 w-64" />
          </div>
        )}

        {asked && error && (error instanceof ApiError && error.status === 404) && (
          <p className="text-sm text-muted-foreground">
            This asset is not a vertex in the current graph — it may not have been in the
            most recent scan.
          </p>
        )}
        {asked && error && !(error instanceof ApiError && error.status === 404) && (
          <ErrorState
            title="Could not work out its reach"
            detail="CloudGuard could not reach its own API to read the graph."
            impact="Nothing about your environment has changed — this is a problem displaying it."
            onRetry={() => refetch()}
          />
        )}

        {data && data.length === 0 && (
          <p className="text-sm text-muted-foreground">
            Nothing. This asset holds no role and runs as no identity that reaches
            anything else CloudGuard has seen.
          </p>
        )}

        {data && data.length > 0 && (
          <ul className="flex flex-col divide-y">
            {data.map((reached) => (
              <li
                key={reached.id}
                className="flex items-center gap-3 py-2 text-sm first:pt-0 last:pb-0"
              >
                {reached.asset_id ? (
                  <Link
                    to={`/assets/${reached.asset_id}`}
                    className="min-w-0 flex-1 truncate hover:underline"
                  >
                    {reached.name}
                  </Link>
                ) : (
                  <span className="min-w-0 flex-1 truncate">{reached.name}</span>
                )}
                <ResourceTypeLabel
                  type={reached.resource_type}
                  className="shrink-0 text-xs text-muted-foreground"
                />
                <SeverityBadge level={reached.data_sensitivity} size="sm" />
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
