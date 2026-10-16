import type { ProviderCapabilities } from "@/lib/types";

/** What `GET /cloud-connections/providers` declares for Azure (DECISIONS.md §263). */
export const AZURE_CAPABILITIES: ProviderCapabilities = {
  separate_consent: true,
  scopes: [
    { scope: "TENANT_ROOT", requires_id: false },
    { scope: "MANAGEMENT_GROUP", requires_id: true },
    { scope: "SUBSCRIPTION", requires_id: true },
  ],
};

/** And for AWS: no consent step, and every scope is named. */
export const AWS_CAPABILITIES: ProviderCapabilities = {
  separate_consent: false,
  scopes: [
    { scope: "ORGANIZATION", requires_id: true },
    { scope: "ORGANIZATIONAL_UNIT", requires_id: true },
    { scope: "ACCOUNT", requires_id: true },
  ],
};
