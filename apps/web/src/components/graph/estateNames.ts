import type { EstateBox, EstateEdge } from "@/lib/types";
import { resourceTypeLabel } from "@/lib/format";
import { DIRECTORY_ICON, resourceTypeIcon } from "@/lib/icons";

const plural = (n: number, one: string) => `${n} ${one}${n === 1 ? "" : "s"}`;

/**
 * What a box on the estate map is called, and the line under the name.
 *
 * Shared by the canvas and the list of links under it, so a box and the
 * sentence about it name the same thing. What sits directly in a subscription
 * is named as that, not as "Ungrouped", which would read as an oversight
 * rather than as where it actually is -- the hierarchy's rule.
 */
export function boxLabel(box: EstateBox): { title: string; detail: string } {
  switch (box.kind) {
    case "scope":
      return {
        title: box.name ?? box.scope_name,
        detail: plural(box.assets, "asset"),
      };
    case "group":
      return {
        title: box.group ?? `Directly in ${box.scope_name}`,
        detail: box.inside
          ? plural(box.assets, "asset")
          : `In ${box.scope_name} · ${plural(box.assets, "asset")}`,
      };
    case "asset":
      return {
        title: box.name ?? box.provider_resource_id ?? box.id,
        detail: resourceTypeLabel(box.resource_type ?? "unknown"),
      };
    case "fold":
      return {
        title: `${box.assets} more`,
        detail: box.with_reach
          ? `${box.with_reach} with reach · list them`
          : "No reach · list them",
      };
  }
}

/**
 * Where pressing a box goes, for the kinds that leave the map.
 *
 * An asset opens its page with its own graph already drawn (`?around=`), the
 * question the map hands on to; the fold opens the inventory filtered to what
 * the map had opened, because what it holds is inventory. Scopes and groups
 * stay on the map, so they have none.
 */
export function boxHref(box: EstateBox): string | null {
  if (box.kind === "asset") {
    if (!box.asset_id || !box.provider_resource_id) return null;
    return `/assets/${box.asset_id}?around=${encodeURIComponent(box.provider_resource_id)}`;
  }
  if (box.kind === "fold") {
    const query = new URLSearchParams({ subscription_id: box.scope_id });
    if (box.group) query.set("resource_group", box.group);
    return `/assets?${query}`;
  }
  return null;
}

/**
 * What a link between two boxes reads as: each verb, and how many when more
 * than one. Containment has no words, as on the neighbourhood -- it is where
 * things live, never the link somebody cuts -- so an edge that is only
 * containment has no label at all.
 */
export function edgeLabel(links: EstateEdge["links"]): string | undefined {
  const named = links.filter((link) => link.relationship !== "contains");
  if (named.length === 0) return undefined;
  return named
    .map((link) => (link.count > 1 ? `${link.label} ×${link.count}` : link.label))
    .join(" · ");
}

/** The glyph a box is drawn with, on the canvas and in the contents list. */
export function boxIcon(box: EstateBox) {
  if (box.kind === "asset") return resourceTypeIcon(box.resource_type ?? "unknown");
  // A scope, or what sits directly in one, is drawn as the scope.
  if (box.kind === "scope" || (box.kind === "group" && box.group === null)) {
    return box.scope_id === "directory" ? DIRECTORY_ICON : resourceTypeIcon("subscription");
  }
  return resourceTypeIcon("resource_group");
}
