import { useState } from "react";

import type { MappedRoute, RoutePattern } from "@/lib/types";
import { useT } from "@/i18n";
import { cn } from "@/lib/format";
import { SeverityBadge } from "@/components/security/SeverityBadge";

/*
 * A route and a group of repeated routes, as rows to pick one from. The
 * attack-path page's rail and the estate map's list read the same routes, so
 * they are the same rows (DECISIONS.md section 123).
 */

export function PatternRow({
  pattern,
  traced,
  onTrace,
  byKey,
}: {
  pattern: RoutePattern;
  traced: string | null;
  onTrace: (key: string | null) => void;
  byKey: Map<string, MappedRoute>;
}) {
  const t = useT();
  const [open, setOpen] = useState(false);

  return (
    <div className="rounded-lg border border-border">
      <button
        type="button"
        onClick={() => setOpen((was) => !was)}
        aria-expanded={open}
        className="flex w-full items-baseline justify-between gap-3 px-3 py-2 text-left hover:bg-muted/60"
      >
        <span className="min-w-0 text-xs text-foreground">{pattern.description}</span>
        <span className="shrink-0 text-xs tabular-nums text-muted-foreground">
          {pattern.hops} {pattern.hops === 1 ? t.attackPaths.oneHop : t.attackPaths.hops}
        </span>
      </button>
      {open && (
        <ul className="border-t">
          {pattern.varies.map((member) => (
            <li key={member.route}>
              <button
                type="button"
                onClick={() => onTrace(traced === member.route ? null : member.route)}
                className={cn(
                  "flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs hover:bg-muted/60",
                  traced === member.route && "bg-muted font-medium",
                )}
              >
                <span className="min-w-0 flex-1 truncate">{member.name}</span>
                {byKey.get(member.route) && (
                  <SeverityBadge
                    level={byKey.get(member.route)!.target.data_sensitivity}
                    size="sm"
                  />
                )}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function RouteRow({
  route,
  traced,
  onTrace,
}: {
  route: MappedRoute;
  traced: string | null;
  onTrace: (key: string | null) => void;
}) {
  const t = useT();
  return (
    <button
      type="button"
      onClick={() => onTrace(traced === route.key ? null : route.key)}
      className={cn(
        "rounded-lg border px-3 py-2 text-left transition-colors hover:bg-muted/60",
        traced === route.key ? "border-foreground bg-muted" : "border-border",
      )}
    >
      <span className="flex items-baseline justify-between gap-3">
        <span className="min-w-0 truncate text-xs font-medium text-foreground">
          {route.entry.name} <span className="text-muted-foreground">→</span>{" "}
          {route.target.name}
        </span>
        <span className="shrink-0 text-xs tabular-nums text-muted-foreground">
          {route.hops} {route.hops === 1 ? t.attackPaths.oneHop : t.attackPaths.hops}
        </span>
      </span>
      <span className="mt-1 flex items-center gap-1.5 text-[11px] text-muted-foreground">
        <SeverityBadge level={route.entry.public_exposure} size="sm" />
        <span aria-hidden>→</span>
        <SeverityBadge level={route.target.data_sensitivity} size="sm" />
      </span>
    </button>
  );
}
