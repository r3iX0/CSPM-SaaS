import {
  AppWindowIcon,
  BotIcon,
  BoxIcon,
  BrickWallIcon,
  BriefcaseBusinessIcon,
  BugIcon,
  CalendarPlusIcon,
  CircleAlertIcon,
  CircleCheckIcon,
  CircleDashedIcon,
  CircleDotIcon,
  CircleEllipsisIcon,
  CircleHelpIcon,
  CircleIcon,
  CircleMinusIcon,
  CircleSlashIcon,
  CircleXIcon,
  ClockIcon,
  CrownIcon,
  DatabaseIcon,
  EthernetPortIcon,
  FolderIcon,
  GlobeIcon,
  HardDriveIcon,
  InfoIcon,
  KeyRoundIcon,
  LayersIcon,
  LoaderCircleIcon,
  MapPinIcon,
  MinusIcon,
  NetworkIcon,
  OctagonAlertIcon,
  PlusIcon,
  RouteIcon,
  ScrollTextIcon,
  ServerIcon,
  ShieldAlertIcon,
  ShieldOffIcon,
  TableIcon,
  TagIcon,
  TrendingUpIcon,
  TriangleAlertIcon,
  UserCogIcon,
  UserIcon,
  WaypointsIcon,
  type LucideIcon,
} from "lucide-react";

import type {
  AssetChange,
  CollectionOutcome,
  ControlStatus,
  Level,
} from "./types";

/**
 * Every icon that carries meaning, defined once.
 *
 * An icon is a claim, the same as a colour: a shield-off means a person chose
 * to live with a finding, a crossed circle means CloudGuard looked and it
 * failed. Two screens picking their own glyph for the same state is how a
 * reader learns that the shapes mean nothing. So each concept has exactly one
 * map, and components read from it rather than importing a glyph of their own.
 *
 * Icons here are never the only signal. Every one sits beside a word, and
 * where it also has a colour the colour comes from the severity and status
 * tokens -- the point of adding shape is that it survives for a reader who
 * cannot separate the hues.
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
  unknown: BoxIcon,
};

/** Falls back to a plain box: a type this map has not caught up with is still a resource. */
export const resourceTypeIcon = (type: string): LucideIcon =>
  RESOURCE_TYPE_ICONS[type] ?? BoxIcon;

/**
 * One shape per level, so severity is not carried by colour alone.
 *
 * UNKNOWN is a question mark rather than a weaker warning: "we could not look"
 * is a different kind of statement from "this is low", not a smaller one.
 */
export const LEVEL_ICONS: Record<Level, LucideIcon> = {
  CRITICAL: OctagonAlertIcon,
  HIGH: TriangleAlertIcon,
  MEDIUM: CircleAlertIcon,
  LOW: InfoIcon,
  UNKNOWN: CircleHelpIcon,
};

/**
 * A verdict, wherever one is shown: a control, a collection, a verification.
 *
 * Pass, fail and unknown are the same three shapes on every screen that can
 * reach them. "Not applicable" and "pending" are deliberately hollow -- they
 * are the absence of a verdict, and must not look like a quiet pass.
 */
export const VERDICT_ICONS = {
  pass: CircleCheckIcon,
  fail: CircleXIcon,
  unknown: CircleHelpIcon,
  partial: CircleAlertIcon,
  pending: CircleDashedIcon,
  notApplicable: CircleMinusIcon,
} as const;

export const CONTROL_STATUS_ICONS: Record<ControlStatus, LucideIcon> = {
  PASSING: VERDICT_ICONS.pass,
  FAILING: VERDICT_ICONS.fail,
  INCONCLUSIVE: VERDICT_ICONS.unknown,
  NOT_ASSESSED: VERDICT_ICONS.pending,
  NOT_COVERED: VERDICT_ICONS.notApplicable,
};

export const OUTCOME_ICONS: Record<CollectionOutcome, LucideIcon> = {
  COMPLETE: VERDICT_ICONS.pass,
  PARTIAL: VERDICT_ICONS.partial,
  FAILED: VERDICT_ICONS.fail,
  SKIPPED: VERDICT_ICONS.unknown,
};

/**
 * The state of a finding, risk, task or scan.
 *
 * ACCEPTED_RISK is a shield switched off rather than a tick. A person deciding
 * to live with a finding is not a fix, and the one thing this map must never
 * do is give that decision the shape of RESOLVED.
 */
export const STATUS_ICONS: Record<string, LucideIcon> = {
  OPEN: CircleDotIcon,
  IN_PROGRESS: CircleEllipsisIcon,
  RESOLVED: VERDICT_ICONS.pass,
  ACCEPTED_RISK: ShieldOffIcon,
  ACCEPTED: ShieldOffIcon,
  FALSE_POSITIVE: CircleSlashIcon,
  QUEUED: ClockIcon,
  DISCOVERING: LoaderCircleIcon,
  NORMALIZING: LoaderCircleIcon,
  EVALUATING: LoaderCircleIcon,
  CALCULATING_RISK: LoaderCircleIcon,
  COMPLETED: VERDICT_ICONS.pass,
  PARTIAL: VERDICT_ICONS.partial,
  FAILED: VERDICT_ICONS.fail,
  CANCELLED: CircleSlashIcon,
  TODO: CircleIcon,
  DONE: VERDICT_ICONS.pass,
};

export const statusIcon = (status: string): LucideIcon =>
  STATUS_ICONS[status] ?? CircleIcon;

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
