import { Navigate, NavLink, Route, Routes, useLocation } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";

import { api, auth } from "@/lib/api";
import type { Organization } from "@/lib/types";
import { useT } from "@/i18n";
import { cn } from "@/lib/format";
import { ActivitySection } from "@/components/settings/Activity";
import { AuditPackagesSection } from "@/components/settings/AuditPackages";
import { ContextSettings } from "@/components/settings/ContextSettings";
import { GeneralSettings } from "@/components/settings/GeneralSettings";
import { MembersSection } from "@/components/settings/Members";
import { PreferencesSection } from "@/components/settings/Preferences";
import { SecuritySection } from "@/components/settings/Security";
import { WebhooksSection } from "@/components/settings/Webhooks";
import {
  LEGACY_ANCHORS,
  settingsSections,
  type SettingsSectionLink,
} from "@/components/settings/sections";
import { CardsSkeleton, ErrorState, PageHeader } from "@/components/common/states";

/**
 * What a person has told CloudGuard.
 *
 * Everything else in the product is something CloudGuard observed. This is the
 * other half of the evidence: how the organization is named, who is in it,
 * what its subscriptions are actually for -- the highest-leverage input a
 * customer has, because the risk engine multiplies every finding by it -- and
 * where its notifications go.
 *
 * One page per topic under `/settings/*`, with the topics listed beside them
 * (DECISIONS.md §207). The single page they replaced was seven topics and
 * 2,600 pixels long, mixing forms edited once a year with lists that only
 * grow, and a row of anchor links (§188) helped a reader jump but never said
 * where they were. A link from before the split (`/settings#context`) lands on
 * the page that now holds that section.
 */
export function SettingsPage() {
  const t = useT();
  const { hash } = useLocation();

  const organizations = useQuery({
    queryKey: ["organizations"],
    queryFn: () => api.get<Organization[]>("/api/v1/organizations").then((r) => r.data),
  });

  // The one being acted in, which is what every other request on these pages
  // targets. Falls back to the first membership for the common single-org
  // case, exactly as the API does when no header is sent.
  const current =
    organizations.data?.find((org) => org.id === auth.organizationId) ?? organizations.data?.[0];

  if (organizations.isLoading) return <CardsSkeleton count={2} />;

  if (organizations.error) {
    return (
      <ErrorState
        title="Could not load your organization"
        detail="Cleave could not reach its own API."
        impact="Nothing about your environment has changed — this is a problem displaying it."
        onRetry={() => void organizations.refetch()}
      />
    );
  }

  if (!current) return null;

  const sections = settingsSections(current, t);
  const shown = new Set(sections.map((section) => section.id));

  // Where `/settings` alone lands: an old anchor's page if it names one this
  // reader may see, General otherwise. `#danger` keeps its anchor, since
  // General holds two sections.
  const anchor = decodeURIComponent(hash.slice(1));
  const legacy = LEGACY_ANCHORS[anchor];
  const landing =
    legacy && shown.has(legacy)
      ? `/settings/${legacy}${anchor === "danger" ? "#danger" : ""}`
      : "/settings/general";

  return (
    <div className="flex flex-col gap-6">
      <PageHeader title={t.settings.title} description={t.settings.intro} />

      <div className="flex flex-col gap-6 md:flex-row md:items-start md:gap-10">
        <SettingsNav sections={sections} />

        <div className="min-w-0 max-w-3xl flex-1">
          {/* Keyed on the organization, so switching it remounts every page
              with that organization's values rather than the last one's. */}
          <Routes key={current.id}>
            <Route index element={<Navigate to={landing} replace />} />
            <Route path="general" element={<GeneralSettings organization={current} />} />
            {shown.has("members") && (
              <Route path="members" element={<MembersSection organization={current} />} />
            )}
            <Route path="context" element={<ContextSettings organization={current} />} />
            {shown.has("integrations") && (
              <Route
                path="integrations"
                element={<WebhooksSection organizationId={current.id} />}
              />
            )}
            {shown.has("audit") && (
              <Route path="audit" element={<AuditPackagesSection organizationId={current.id} />} />
            )}
            {shown.has("activity") && (
              <Route path="activity" element={<ActivitySection organizationId={current.id} />} />
            )}
            <Route path="security" element={<SecuritySection />} />
            <Route path="preferences" element={<PreferencesSection />} />
            {/* A page this reader may not see, or one that does not exist. */}
            <Route path="*" element={<Navigate to="/settings/general" replace />} />
          </Routes>
        </div>
      </div>
    </div>
  );
}

/**
 * The topics, beside the page on a wide screen and above it on a narrow one.
 *
 * Links rather than tabs: each is a page with its own address, history entry
 * and title, which is what a link is. The current one is marked
 * `aria-current="page"` by `NavLink`.
 */
function SettingsNav({ sections }: { sections: SettingsSectionLink[] }) {
  const t = useT();
  return (
    <nav aria-label={t.settings.navLabel} className="shrink-0 md:sticky md:top-20 md:w-48">
      <ul className="-mx-1 flex gap-1 overflow-x-auto px-1 pb-1 md:mx-0 md:flex-col md:overflow-visible md:px-0 md:pb-0">
        {sections.map((section) => (
          <li key={section.id} className="shrink-0">
            <NavLink
              to={`/settings/${section.id}`}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2 rounded-md px-2.5 py-1.5 text-body whitespace-nowrap outline-none transition-colors focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring",
                  isActive
                    ? "bg-muted font-medium text-foreground"
                    : "text-muted-foreground hover:bg-muted/60 hover:text-foreground",
                )
              }
            >
              <section.icon aria-hidden className="size-4 shrink-0" />
              {section.label}
            </NavLink>
          </li>
        ))}
      </ul>
    </nav>
  );
}
