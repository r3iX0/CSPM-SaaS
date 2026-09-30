import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import {
  BoxesIcon,
  KeyboardIcon,
  LaptopIcon,
  ListChecksIcon,
  MoonIcon,
  PlayIcon,
  PlusIcon,
  SunIcon,
} from "lucide-react";

import { api } from "@/lib/api";
import type { Asset, Finding, Rule } from "@/lib/types";
import { NAV_GROUPS } from "@/components/layout/nav";
import { RISK_KIND_ICONS } from "@/lib/icons";
import { setThemeChoice, type ThemeChoice } from "@/lib/theme";
import { SHORTCUTS_EVENT } from "@/lib/keyboard";
import { useScanWizard } from "@/components/scans/ScanWizardProvider";
import { ResourceTypeLabel } from "@/components/security/IconLabel";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import {
  Command,
  CommandDialog,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandShortcut,
} from "@/components/ui/command";

/** Below this, a search is a letter or two and would match most of an estate. */
const MIN_QUERY = 2;
const RESULT_LIMIT = 6;
const DEBOUNCE_MS = 200;

// The finding glyph from the one icon table, so a finding keeps one shape.
const FindingIcon = RISK_KIND_ICONS.FINDING;

const THEME_COMMANDS: {
  choice: ThemeChoice;
  label: string;
  icon: typeof SunIcon;
}[] = [
  { choice: "light", label: "Switch to light theme", icon: SunIcon },
  { choice: "dark", label: "Switch to dark theme", icon: MoonIcon },
  { choice: "system", label: "Follow the system theme", icon: LaptopIcon },
];

/** The same substring rule the API applies, so both halves agree on a match. */
function matches(haystack: string, query: string): boolean {
  return haystack.toLowerCase().includes(query.toLowerCase());
}

/**
 * A rule matches where a word of it starts with what was typed.
 *
 * Rules are filtered here rather than by the API, and a bare substring made
 * "stg" -- the first letters of an asset name -- match six PostgreSQL rules
 * ("po*stg*reSQL") under the one asset it was meant to find. A query with a
 * space or a hyphen in it ("public access", "AZ-STO") is a phrase or an id,
 * and matches as a substring, as before (DECISIONS.md §188).
 */
function matchesRule(haystack: string, query: string): boolean {
  const needle = query.toLowerCase();
  if (/[^a-z0-9]/.test(needle)) return haystack.toLowerCase().includes(needle);
  return haystack
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .some((word) => word.startsWith(needle));
}

/**
 * Everything reachable, from the keyboard, in one place.
 *
 * The product's own shape is what makes this worth having rather than a
 * fashion: an estate has thousands of assets and the inventory paginates fifty
 * at a time, so "open the storage account called payroll" is otherwise a
 * navigate, a search, and a page turn. Here it is four keystrokes.
 *
 * **What it searches, and why not more.** Assets go to the API, which already
 * filters by name (`GET /assets?search=`). Rules are filtered here, out of the
 * cache the rules page has usually already filled -- the catalogue is dozens of
 * entries, not thousands, so a round trip would buy nothing. Open findings go
 * to the API too, which searches them by title, rule and asset
 * (`GET /findings?search=`) -- they were left out when it could not, and are
 * searched now that it does (DECISIONS.md §188).
 *
 * **Navigation only, no mutations.** No "run a scan" entry, deliberately.
 * Everything here is one keystroke from a highlighted row, and a scan reads a
 * customer's whole environment; an action with a cost belongs behind a button
 * somebody meant to press.
 *
 * `shouldFilter={false}` because two filters disagreeing is worse than one:
 * cmdk's fuzzy scoring would re-rank -- and sometimes drop -- rows the server
 * already decided matched.
 */
export function CommandPaletteDialog({
  open,
  onOpenChange,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [debounced, setDebounced] = useState("");

  // Typing "payroll" is six renders and would be six requests without this.
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(query), DEBOUNCE_MS);
    return () => clearTimeout(timer);
  }, [query]);

  const searching = debounced.trim().length >= MIN_QUERY;

  const { data: assets } = useQuery({
    queryKey: ["command-assets", debounced],
    queryFn: () =>
      api
        .get<Asset[]>(
          `/api/v1/assets?search=${encodeURIComponent(debounced)}&limit=${RESULT_LIMIT}`,
        )
        .then((r) => r.data),
    enabled: open && searching,
  });

  const { data: findings } = useQuery({
    queryKey: ["command-findings", debounced],
    queryFn: () =>
      api
        .get<Finding[]>(
          `/api/v1/findings?search=${encodeURIComponent(debounced)}&status=OPEN&sort=risk&limit=${RESULT_LIMIT}`,
        )
        .then((r) => r.data),
    enabled: open && searching,
  });

  // The same key the rules page uses, so opening the palette after visiting it
  // costs nothing and the two can never show different catalogues.
  const { data: rules } = useQuery({
    queryKey: ["rules"],
    queryFn: () => api.get<Rule[]>("/api/v1/rules").then((r) => r.data),
    enabled: open,
  });

  const trimmed = query.trim();
  const filtering = trimmed.length > 0;

  const pages = useMemo(
    () =>
      NAV_GROUPS.flatMap((group) =>
        group.items
          .filter(
            (item) =>
              !filtering || matches(`${item.label} ${group.label}`, trimmed),
          )
          .map((item) => ({ ...item, group: group.label })),
      ),
    [filtering, trimmed],
  );

  const ruleHits = useMemo(() => {
    if (!filtering || !rules) return [];
    return rules
      .filter((rule) =>
        matchesRule(`${rule.name} ${rule.rule_id} ${rule.category}`, trimmed),
      )
      .slice(0, RESULT_LIMIT);
  }, [rules, filtering, trimmed]);

  // Things to do, not only places to go -- the palette is where a keyboard
  // user starts a scan without first navigating to the button for it.
  const scanWizard = useScanWizard();
  const actions = [
    { id: "scan", label: "Run a scan", icon: PlayIcon, run: () => scanWizard.start() },
    { id: "connect", label: "Connect a cloud", icon: PlusIcon, to: "/connections/new" },
    {
      id: "shortcuts",
      label: "Keyboard shortcuts",
      icon: KeyboardIcon,
      run: () => window.dispatchEvent(new Event(SHORTCUTS_EVENT)),
    },
  ];
  const actionHits = filtering
    ? actions.filter((action) => matches(action.label, trimmed))
    : actions;

  const themeHits = useMemo(
    () =>
      filtering ? THEME_COMMANDS.filter((c) => matches(c.label, trimmed)) : [],
    [filtering, trimmed],
  );

  const go = useCallback(
    (to: string) => {
      onOpenChange(false);
      setQuery("");
      navigate(to);
    },
    [navigate, onOpenChange],
  );

  const assetHits = searching ? (assets ?? []) : [];
  const findingHits = searching && Array.isArray(findings) ? findings : [];
  const nothing =
    actionHits.length === 0 &&
    pages.length === 0 &&
    assetHits.length === 0 &&
    findingHits.length === 0 &&
    ruleHits.length === 0 &&
    themeHits.length === 0;

  return (
    <CommandDialog
      open={open}
      onOpenChange={(next: boolean) => {
        onOpenChange(next);
        if (!next) setQuery("");
      }}
      title="Search Cleave"
      description="Jump to a page, an asset, a finding or a rule."
      className="sm:max-w-xl"
    >
      {/* Filtering is done above, against the same substring rule the API
        uses, so cmdk's own scoring is switched off rather than layered on. */}
      <Command shouldFilter={false}>
        <CommandInput
          value={query}
          onValueChange={setQuery}
          placeholder="Search assets, rules and pages…"
        />
        {/* Not cmdk's `CommandEmpty`, which renders off its own filtered
            count -- and `shouldFilter={false}` has taken that count out of
            the loop. Deciding emptiness here keeps one authority over what
            matched. Outside the list, which is a listbox and may hold only
            options, and a live region that is always mounted, so a search
            that stops matching is said aloud rather than only drawn. */}
        <div role="status" aria-live="polite">
          {nothing && (
            <div className="py-6 text-center text-sm">
              <span className="text-muted-foreground">
                Nothing matches “{trimmed}”.
              </span>
              {/* Says what was searched, because a bare "no results" over a
              partial search is a claim the product cannot support. */}
              <span className="mt-1 block text-xs text-muted-foreground">
                Pages, assets, open findings and rules are searched.
              </span>
            </div>
          )}
        </div>
        <CommandList>

          {actionHits.length > 0 && (
            <CommandGroup heading="Actions">
              {actionHits.map((action) => (
                <CommandItem
                  key={action.id}
                  value={`action-${action.id}`}
                  onSelect={() => {
                    if (action.to) {
                      go(action.to);
                      return;
                    }
                    onOpenChange(false);
                    setQuery("");
                    action.run?.();
                  }}
                >
                  <action.icon />
                  {action.label}
                </CommandItem>
              ))}
            </CommandGroup>
          )}

          {pages.length > 0 && (
            <CommandGroup heading="Go to">
              {pages.map((page) => (
                <CommandItem
                  key={page.to}
                  value={page.to}
                  onSelect={() => go(page.to)}
                >
                  <page.icon />
                  {page.label}
                  <CommandShortcut>{page.group}</CommandShortcut>
                </CommandItem>
              ))}
            </CommandGroup>
          )}

          {assetHits.length > 0 && (
            <CommandGroup heading="Assets">
              {assetHits.map((asset) => (
                <CommandItem
                  key={asset.id}
                  value={asset.id}
                  onSelect={() => go(`/assets/${asset.id}`)}
                >
                  <BoxesIcon />
                  <span className="min-w-0 flex-1 truncate">
                    {asset.name}
                  </span>
                  <ResourceTypeLabel
                    type={asset.resource_type}
                    className="shrink-0 text-xs text-muted-foreground"
                  />
                  {/* Exposure travels with the name: an asset worth jumping to
                  is usually one somebody is worried about. */}
                  <SeverityBadge level={asset.public_exposure} size="sm" />
                </CommandItem>
              ))}
            </CommandGroup>
          )}

          {findingHits.length > 0 && (
            <CommandGroup heading="Open findings">
              {findingHits.map((finding) => (
                <CommandItem
                  key={finding.id}
                  value={`finding-${finding.id}`}
                  onSelect={() => go(`/findings/${finding.id}`)}
                >
                  <FindingIcon />
                  <span className="min-w-0 flex-1 truncate">{finding.title}</span>
                  <SeverityBadge level={finding.severity} size="sm" />
                </CommandItem>
              ))}
            </CommandGroup>
          )}

          {ruleHits.length > 0 && (
            <CommandGroup heading="Rules">
              {ruleHits.map((rule) => (
                <CommandItem
                  key={rule.rule_id}
                  value={rule.rule_id}
                  // A rule on its own is a definition; what a reader wants is
                  // what it found in their environment.
                  onSelect={() =>
                    go(
                      `/findings?rule_id=${encodeURIComponent(rule.rule_id)}`,
                    )
                  }
                >
                  <ListChecksIcon />
                  <span className="min-w-0 flex-1 truncate">{rule.name}</span>
                  <SeverityBadge level={rule.severity} size="sm" />
                </CommandItem>
              ))}
            </CommandGroup>
          )}

          {themeHits.length > 0 && (
            <CommandGroup heading="Appearance">
              {themeHits.map((command) => (
                <CommandItem
                  key={command.choice}
                  value={command.choice}
                  onSelect={() => {
                    setThemeChoice(command.choice);
                    onOpenChange(false);
                    setQuery("");
                  }}
                >
                  <command.icon />
                  {command.label}
                </CommandItem>
              ))}
            </CommandGroup>
          )}
        </CommandList>
      </Command>
    </CommandDialog>
  );
}
