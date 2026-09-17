import {
  AppWindowIcon,
  BotIcon,
  BoxIcon,
  BrickWallIcon,
  BriefcaseBusinessIcon,
  BugIcon,
  CalendarPlusIcon,
  CircleCheckIcon,
  CircleDashedIcon,
  CircleHelpIcon,
  CircleXIcon,
  ClockIcon,
  CrownIcon,
  DatabaseIcon,
  EthernetPortIcon,
  FolderIcon,
  GlobeIcon,
  HardDriveIcon,
  KeyRoundIcon,
  LayersIcon,
  MapPinIcon,
  MinusIcon,
  NetworkIcon,
  PanelsTopLeftIcon,
  PlusIcon,
  RouteIcon,
  ScrollTextIcon,
  ServerIcon,
  ShieldAlertIcon,
  TableIcon,
  TagIcon,
  TrendingUpIcon,
  UserCogIcon,
  UserIcon,
  WaypointsIcon,
  type LucideIcon,
} from "lucide-react";

import type { AssetChange } from "./types";

/**
 * Every icon that carries meaning, defined once.
 *
 * Two screens picking their own glyph for the same thing is how a reader
 * learns that the shapes mean nothing. So each concept has exactly one map, and
 * components read from it rather than importing a glyph of their own.
 *
 * Severity and status are deliberately absent. Their badges and pills stay
 * text on a tone (DECISIONS.md §86): they sit in dense rows several to a line,
 * and a shape on each one made those rows busier without telling the reader
 * anything the word did not.
 */

/** What a resource is, by the neutral type the rules match on. */
const RESOURCE_TYPE_ICONS: Record<string, LucideIcon> = {
  subscription: LayersIcon,
  resource_group: FolderIcon,
  virtual_machine: ServerIcon,
  network_security_group: BrickWallIcon,
  network_interface: EthernetPortIcon,
  public_ip: GlobeIcon,
  virtual_network: NetworkIcon,
  subnet: WaypointsIcon,
  storage_account: HardDriveIcon,
  sql_server: DatabaseIcon,
  sql_database: TableIcon,
  postgresql_server: DatabaseIcon,
  user: UserIcon,
  service_principal: BotIcon,
  application: AppWindowIcon,
  role_assignment: UserCogIcon,
  diagnostic_setting: ScrollTextIcon,
  key_vault: KeyRoundIcon,
  // A hosted web app. Not AppWindowIcon, which is already an Entra application.
  app_service: PanelsTopLeftIcon,
  unknown: BoxIcon,
};

/** Falls back to a plain box: a type this map has not caught up with is still a resource. */
export const resourceTypeIcon = (type: string): LucideIcon =>
  RESOURCE_TYPE_ICONS[type] ?? BoxIcon;

/**
 * Whether a fix was verified, in the verification panel.
 *
 * The absence of a verdict (pending) is drawn dashed, so it cannot look like a
 * quiet pass.
 */
export const VERDICT_ICONS = {
  pass: CircleCheckIcon,
  fail: CircleXIcon,
  unknown: CircleHelpIcon,
  pending: CircleDashedIcon,
} as const;

/** The factors a finding is weighed by, named the same way on every screen. */
export const FACTOR_ICONS = {
  criticality: CrownIcon,
  dataSensitivity: DatabaseIcon,
  exposure: GlobeIcon,
  exploitability: BugIcon,
  businessImpact: BriefcaseBusinessIcon,
} as const;

/** Plain facts on a detail page. */
export const FACT_ICONS = {
  environment: TagIcon,
  region: MapPinIcon,
  firstSeen: CalendarPlusIcon,
  lastSeen: ClockIcon,
  resolved: VERDICT_ICONS.pass,
} as const;

/**
 * What kind of change a row is. The direction -- worse or better -- is a
 * separate mark, because an exposure change can go either way.
 */
export const CHANGE_KIND_ICONS: Record<AssetChange, LucideIcon> = {
  APPEARED: PlusIcon,
  DISAPPEARED: MinusIcon,
  EXPOSURE_CHANGED: FACTOR_ICONS.exposure,
  SENSITIVITY_CHANGED: FACTOR_ICONS.dataSensitivity,
  CRITICALITY_CHANGED: FACTOR_ICONS.criticality,
};

/** The kinds of thing the risks page ranks. */
export const RISK_KIND_ICONS: Record<string, LucideIcon> = {
  FINDING: ShieldAlertIcon,
  ATTACK_PATH: RouteIcon,
  ESCALATION: TrendingUpIcon,
};
