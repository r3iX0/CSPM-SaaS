/**
 * Where an asset is in the provider's own portal, when there is one to open.
 *
 * An ARM resource only: a directory object lives in Entra under a different
 * blade, and AWS is not in the UI (`AWS_ENABLED`). The tenant goes in the
 * link, or the portal opens in the viewer's default directory -- where a
 * resource in any other tenant, which is every one an MSP manages, reads as
 * "not found" (DECISIONS.md §112).
 */
export function portalUrl(asset: {
  provider: string;
  provider_resource_id: string;
  tenant_id?: string | null;
}): string | null {
  if (asset.provider.toLowerCase() !== "azure") return null;
  if (!/^\/subscriptions\//i.test(asset.provider_resource_id)) return null;
  const directory = asset.tenant_id ? `@${asset.tenant_id}/` : "";
  return `https://portal.azure.com/#${directory}resource${asset.provider_resource_id}`;
}
