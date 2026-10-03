import {
  Building2Icon,
  CrosshairIcon,
  HistoryIcon,
  PlugIcon,
  SlidersHorizontalIcon,
  UsersIcon,
  type LucideIcon,
} from "lucide-react";

import type { Organization } from "@/lib/types";
import type { Strings } from "@/i18n/en";

export type SettingsSectionId =
  "general" | "members" | "context" | "integrations" | "activity" | "preferences";

export interface SettingsSectionLink {
  readonly id: SettingsSectionId;
  readonly label: string;
  readonly icon: LucideIcon;
}

/** Whether this reader manages the organization: owners and admins, never in the demo. */
export function managesOrganization(organization: Organization): boolean {
  return (organization.role === "OWNER" || organization.role === "ADMIN") && !organization.is_demo;
}

/**
 * The settings pages this reader is shown, in order (DECISIONS.md §207).
 *
 * A page the API would refuse is not offered: the demo has no members to list
 * (its visitors are strangers to one another), and integrations and the
 * activity log are for owners and admins, as the API allows. Preferences are
 * this browser's, so everyone has them.
 */
export function settingsSections(organization: Organization, t: Strings): SettingsSectionLink[] {
  const manages = managesOrganization(organization);
  const all: (SettingsSectionLink & { shown: boolean })[] = [
    { id: "general", label: t.settings.nav.general, icon: Building2Icon, shown: true },
    {
      id: "members",
      label: t.settings.nav.members,
      icon: UsersIcon,
      shown: !organization.is_demo,
    },
    { id: "context", label: t.settings.nav.context, icon: CrosshairIcon, shown: true },
    {
      id: "integrations",
      label: t.settings.nav.integrations,
      icon: PlugIcon,
      shown: manages,
    },
    { id: "activity", label: t.settings.nav.activity, icon: HistoryIcon, shown: manages },
    {
      id: "preferences",
      label: t.settings.nav.preferences,
      icon: SlidersHorizontalIcon,
      shown: true,
    },
  ];
  return all.filter((section) => section.shown).map(({ id, label, icon }) => ({ id, label, icon }));
}

/**
 * Where an anchor from the single-page layout lands now.
 *
 * Links written before the split (`/settings#context`, from an asset whose
 * context is undeclared) keep working: the old section ids map to the page
 * that holds them, and the organization's two sections both live on General.
 */
export const LEGACY_ANCHORS: Record<string, SettingsSectionId> = {
  organization: "general",
  danger: "general",
  members: "members",
  context: "context",
  integrations: "integrations",
  activity: "activity",
};
