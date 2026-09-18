import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";

import { api } from "@/lib/api";
import { GRAPH_ICON } from "@/lib/icons";
import { useT } from "@/i18n";
import { Button } from "@/components/ui/button";

/**
 * Open the graph around a route's entry point, with the route traced.
 *
 * A button rather than a link because the route knows its assets by provider
 * id and the asset page is addressed by row id: the one lookup is made when
 * somebody follows it, not for every route in a list. Once resolved it is an
 * ordinary navigation, so Back returns to the route it came from.
 *
 * The straight line stays where it is. This is the way from "which link do I
 * cut" to "what is around it", not a replacement for the first question.
 */
export function OpenInGraph({
  entryId,
  traceKey,
}: {
  /** Provider id of the asset the graph opens around. */
  entryId: string;
  /** The route to trace once there, if it is an attack path through that asset. */
  traceKey?: string;
}) {
  const t = useT();
  const navigate = useNavigate();
  const [opening, setOpening] = useState(false);
  const Icon = GRAPH_ICON;

  async function open() {
    setOpening(true);
    try {
      const { data } = await api.get<{ id: string }>(
        `/api/v1/assets/resolve?${new URLSearchParams({ provider_resource_id: entryId })}`,
      );
      const query = traceKey ? `?${new URLSearchParams({ trace: traceKey })}` : "";
      navigate(`/assets/${data.id}${query}`);
    } catch {
      toast.error(t.graph.gone, { description: t.graph.goneDetail });
      setOpening(false);
    }
  }

  return (
    <Button variant="outline" size="sm" onClick={open} disabled={opening}>
      <Icon data-icon="inline-start" />
      {opening ? t.graph.opening : t.graph.explore}
    </Button>
  );
}
