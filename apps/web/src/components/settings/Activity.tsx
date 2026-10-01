import { useState } from "react";
import { keepPreviousData, useQuery } from "@tanstack/react-query";

import { api } from "@/lib/api";
import type { AuditEntry } from "@/lib/types";
import { useT } from "@/i18n";
import { formatDateTime } from "@/lib/format";
import { CardsSkeleton, ErrorState } from "@/components/common/states";
import { Button } from "@/components/ui/button";

const PAGE = 25;
// The API's own ceiling for one page. Past it, the trail is a question for the
// API's filters rather than for scrolling.
const MOST = 200;

/**
 * The audit trail, newest first, for owners and admins (DECISIONS.md §163).
 *
 * One line per change: who, what, when and from where. The entries cannot be
 * edited or deleted by anybody -- the database refuses it -- and the page says
 * so, because that is what makes the list worth reading.
 */
export function ActivitySection({ organizationId }: { organizationId: string }) {
  const t = useT();
  const [limit, setLimit] = useState(PAGE);

  const entries = useQuery({
    queryKey: ["audit-log", organizationId, limit],
    queryFn: () => api.get<AuditEntry[]>(`/api/v1/audit-log?limit=${limit}`),
    // Showing more keeps what is on screen while the longer page arrives.
    placeholderData: keepPreviousData,
  });

  if (entries.isLoading) return <CardsSkeleton count={1} />;
  if (entries.error || !entries.data) {
    return (
      <ErrorState
        title={t.audit.failed}
        detail="Cleave could not reach its own API."
        onRetry={() => entries.refetch()}
      />
    );
  }

  const rows = entries.data.data;
  const total = Number(entries.data.meta.total ?? rows.length);

  return (
    <div className="overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10">
      {rows.length === 0 ? (
        <p className="px-5 py-4 text-sm text-muted-foreground">{t.audit.empty}</p>
      ) : (
        <ul className="divide-y divide-border">
          {rows.map((entry) => (
            <Entry key={entry.id} entry={entry} />
          ))}
        </ul>
      )}
      {rows.length < total && limit < MOST && (
        <div className="border-t border-border px-5 py-3">
          <Button
            variant="ghost"
            size="sm"
            disabled={entries.isFetching}
            onClick={() => setLimit((current) => Math.min(current + PAGE, MOST))}
          >
            {t.audit.more}
          </Button>
        </div>
      )}
    </div>
  );
}

function Entry({ entry }: { entry: AuditEntry }) {
  const t = useT();
  const who = entry.actor_email ?? (entry.actor_id ? t.audit.formerMember : t.audit.system);
  // An action this page has no words for yet still reads as a sentence.
  const what = t.audit.actions[entry.action] ?? entry.action.replace(/[._]/g, " ");
  const subject = typeof entry.details.email === "string" ? entry.details.email : null;

  return (
    <li className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 px-5 py-2.5 text-sm">
      <span className="font-medium text-foreground">{who}</span>
      <span className="text-foreground">{what}</span>
      {subject && subject !== who && <span className="text-muted-foreground">{subject}</span>}
      <span className="ml-auto flex gap-2 text-xs text-muted-foreground">
        {entry.ip_address && <span>{t.audit.from(entry.ip_address)}</span>}
        <time dateTime={entry.created_at}>{formatDateTime(entry.created_at)}</time>
      </span>
    </li>
  );
}
