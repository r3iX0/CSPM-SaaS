import {
  ArchiveIcon,
  Building2Icon,
  CrosshairIcon,
  HistoryIcon,
  PlugIcon,
  ShieldCheckIcon,
  SlidersHorizontalIcon,
  UserRoundCheckIcon,
  UsersIcon,
  type LucideIcon,
} from "lucide-react";

import type { Organization } from "@/lib/types";
import type { Strings } from "@/i18n/en";

export type SettingsSectionId =
  | "general"
  | "members"
  | "context"
  | "ownership"
  | "integrations"
  | "audit"
  | "activity"
  | "security"
  | "preferences";

export interface SettingsSectionLink {
  readonly id: SettingsSectionId;
  readonly label: string;
  readonly icon: LucideIcon;
}

/**
 * Whether the organization is a team (DECISIONS.md §236). A solo organization is one person,
 * so what only a team needs -- members, ownership, owners on tasks -- is left out. An
 * organization read before the mode existed is a team, as the column's default is.
 */
export function isTeam(organization: Organization | undefined): boolean {
  return organization?.mode !== "SOLO";
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
 * activity log are for owners and admins, as the API allows. Security is the
 * reader's own sign-in and Preferences this browser's, so everyone has them.
 */
export function settingsSections(
  organization: Organization,
  t: Strings,
  guest = false,
): SettingsSectionLink[] {
  const manages = managesOrganization(organization);
  const all: (SettingsSectionLink & { shown: boolean })[] = [
    { id: "general", label: t.settings.nav.general, icon: Building2Icon, shown: true },
    {
      id: "members",
      label: t.settings.nav.members,
      icon: UsersIcon,
      shown: !organization.is_demo && isTeam(organization),
    },
    { id: "context", label: t.settings.nav.context, icon: CrosshairIcon, shown: true },
    // Owners are members, and the demo lists none (DECISIONS.md §236).
    {
      id: "ownership",
      label: t.settings.nav.ownership,
      icon: UserRoundCheckIcon,
      shown: !organization.is_demo && isTeam(organization),
    },
    {
      id: "integrations",
      label: t.settings.nav.integrations,
      icon: PlugIcon,
      shown: manages,
    },
    { id: "audit", label: t.settings.nav.audit, icon: ArchiveIcon, shown: manages },
    { id: "activity", label: t.settings.nav.activity, icon: HistoryIcon, shown: manages },
    // A guest has no sign-in of their own to protect yet (DECISIONS.md §219).
    { id: "security", label: t.settings.nav.security, icon: ShieldCheckIcon, shown: !guest },
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
  audit: "audit",
  activity: "activity",
};
