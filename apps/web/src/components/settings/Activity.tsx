import type { ReactNode } from "react";
import { useMutation, useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { toast } from "sonner";
import { DownloadIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { AuditEntry, Member } from "@/lib/types";
import type { Strings } from "@/i18n/en";
import { useT } from "@/i18n";
import { formatDate, formatTime } from "@/lib/format";
import { saveBlob } from "@/lib/download";
import { LiveStatus } from "@/components/common/LiveStatus";
import { SelectField } from "@/components/common/SelectField";
import { CardsSkeleton, ErrorState } from "@/components/common/states";
import { SettingsSection } from "@/components/settings/SettingsSection";
import { Button } from "@/components/ui/button";

const PAGE = 50;
/** The API's ceiling for one page, used when reading the whole trail for a download. */
const EXPORT_PAGE = 200;
const ACTION_PARAM = "action";
const ACTOR_PARAM = "actor";
const ANY = "any";

interface Filters {
  action: string | null;
  actor: string | null;
}

interface Page {
  rows: AuditEntry[];
  total: number;
}

async function fetchPage(filters: Filters, limit: number, offset: number): Promise<Page> {
  const query = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (filters.action) query.set("action", filters.action);
  if (filters.actor) query.set("actor", filters.actor);
  const answer = await api.get<AuditEntry[]>(`/api/v1/audit-log?${query.toString()}`);
  return { rows: answer.data, total: Number(answer.meta.total ?? answer.data.length) };
}

/**
 * The audit trail, newest first, for owners and admins (DECISIONS.md §163).
 *
 * One line per change: who, what, when and from where, under the day it
 * happened. Narrowed by the kind of change and by person, both in the URL, as
 * the API already allowed and the page never offered; paged with no ceiling,
 * where it used to stop silently at two hundred; and downloadable as CSV for
 * the auditor who asks for it (§207).
 *
 * The entries cannot be edited or deleted by anybody -- the database refuses
 * it -- and the page says so, because that is what makes the list worth reading.
 */
export function ActivitySection({ organizationId }: { organizationId: string }) {
  const t = useT();
  const [params, setParams] = useSearchParams();
  const filters: Filters = { action: params.get(ACTION_PARAM), actor: params.get(ACTOR_PARAM) };

  const setParam = (key: string, value: string | null) =>
    setParams(
      (previous) => {
        const next = new URLSearchParams(previous);
        if (value) next.set(key, value);
        else next.delete(key);
        return next;
      },
      { replace: true },
    );

  const entries = useInfiniteQuery({
    queryKey: ["audit-log", organizationId, filters.action, filters.actor],
    queryFn: ({ pageParam }) => fetchPage(filters, PAGE, pageParam),
    initialPageParam: 0,
    getNextPageParam: (last, pages) => {
      const loaded = pages.reduce((sum, page) => sum + page.rows.length, 0);
      return loaded < last.total && last.rows.length > 0 ? loaded : undefined;
    },
  });

  // The people who could have made a change, for the filter. Former members
  // are not listed: the API keeps their entries but has no address to name.
  const members = useQuery({
    queryKey: ["members", organizationId],
    queryFn: () => api.get<Member[]>("/api/v1/members").then((r) => r.data),
  });

  const download = useMutation({
    mutationFn: async () => {
      const rows: AuditEntry[] = [];
      let total = Number.POSITIVE_INFINITY;
      while (rows.length < total) {
        const page = await fetchPage(filters, EXPORT_PAGE, rows.length);
        if (page.rows.length === 0) break;
        rows.push(...page.rows);
        total = page.total;
      }
      return rows;
    },
    onSuccess: (rows) => {
      const day = new Date().toISOString().slice(0, 10);
      saveBlob(
        new Blob([toCsv(rows, t)], { type: "text/csv;charset=utf-8" }),
        `cleave-activity-${day}.csv`,
      );
    },
    onError: () => toast.error(t.audit.exportFailed),
  });

  const rows = entries.data?.pages.flatMap((page) => page.rows) ?? [];
  const total = entries.data?.pages[0]?.total ?? 0;
  const filtered = Boolean(filters.action ?? filters.actor);

  const actionOptions = [
    { value: ANY, label: t.audit.anyAction },
    ...Object.entries(t.audit.families).map(([value, label]) => ({ value, label })),
  ];
  const actorOptions = [
    { value: ANY, label: t.audit.anyone },
    ...(members.data ?? []).flatMap((member) =>
      member.email ? [{ value: member.user_id, label: member.email }] : [],
    ),
  ];

  let body: ReactNode;
  if (entries.isLoading) {
    body = <CardsSkeleton count={1} />;
  } else if (entries.error || !entries.data) {
    body = (
      <ErrorState
        title={t.audit.failed}
        detail="Cleave could not reach its own API."
        onRetry={() => void entries.refetch()}
      />
    );
  } else if (rows.length === 0) {
    body = (
      <p className="rounded-xl bg-card px-5 py-4 text-body text-muted-foreground ring-1 ring-foreground/10">
        {filtered ? t.audit.emptyFiltered : t.audit.empty}
      </p>
    );
  } else {
    body = (
      <div className="overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10">
        {byDay(rows, t).map((day) => (
          <section key={day.key} aria-label={day.label}>
            <h3 className="border-b border-border bg-muted/60 px-5 py-1.5 text-caption font-medium tracking-wide text-muted-foreground uppercase">
              {day.label}
            </h3>
            <ul className="divide-y divide-border">
              {day.entries.map((entry) => (
                <Entry key={entry.id} entry={entry} />
              ))}
            </ul>
          </section>
        ))}
        {entries.hasNextPage && (
          <div className="border-t border-border px-5 py-3">
            <Button
              variant="ghost"
              size="sm"
              disabled={entries.isFetchingNextPage}
              onClick={() => void entries.fetchNextPage()}
            >
              {t.audit.more}
            </Button>
          </div>
        )}
      </div>
    );
  }

  const countLine = entries.data ? t.audit.count(rows.length, total) : null;

  return (
    <SettingsSection
      id="activity"
      title={t.audit.title}
      description={t.audit.help}
      actions={
        <Button
          variant="outline"
          disabled={download.isPending || rows.length === 0}
          onClick={() => download.mutate()}
        >
          <DownloadIcon />
          {download.isPending ? t.audit.exporting : t.audit.export}
        </Button>
      }
    >
      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <SelectField
            value={filters.action ?? ANY}
            ariaLabel={t.audit.filterAction}
            idleValue={ANY}
            options={actionOptions}
            onValueChange={(value) => setParam(ACTION_PARAM, value === ANY ? null : value)}
          />
          <SelectField
            value={filters.actor ?? ANY}
            ariaLabel={t.audit.filterActor}
            idleValue={ANY}
            options={actorOptions}
            onValueChange={(value) => setParam(ACTOR_PARAM, value === ANY ? null : value)}
          />
          {rows.length > 0 && (
            <p className="ml-auto text-meta text-muted-foreground">{countLine}</p>
          )}
          <LiveStatus message={countLine} quietFirst />
        </div>
        {body}
      </div>
    </SettingsSection>
  );
}

function Entry({ entry }: { entry: AuditEntry }) {
  const t = useT();
  const who = actorOf(entry, t);
  const subject = subjectOf(entry);

  return (
    <li className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5 px-5 py-2.5 text-body">
      <span className="font-medium text-foreground">{who}</span>
      <span className="text-foreground">{describe(entry, t)}</span>
      {subject && subject !== who && <span className="text-muted-foreground">{subject}</span>}
      <span className="ml-auto flex gap-2 text-meta text-muted-foreground">
        {entry.ip_address && <span>{t.audit.from(entry.ip_address)}</span>}
        <time dateTime={entry.created_at}>{formatTime(entry.created_at)}</time>
      </span>
    </li>
  );
}

function actorOf(entry: AuditEntry, t: Strings): string {
  return entry.actor_email ?? (entry.actor_id ? t.audit.formerMember : t.audit.system);
}

/** What was done, in words; an action this page has no words for still reads as a sentence. */
function describe(entry: AuditEntry, t: Strings): string {
  return t.audit.actions[entry.action] ?? entry.action.replace(/[._]/g, " ");
}

function subjectOf(entry: AuditEntry): string | null {
  return typeof entry.details.email === "string" ? entry.details.email : null;
}

interface Day {
  key: string;
  label: string;
  entries: AuditEntry[];
}

/** Entries under the local day they happened, in the order they arrive (newest first). */
function byDay(entries: AuditEntry[], t: Strings): Day[] {
  const today = new Date();
  const yesterday = new Date(today);
  yesterday.setDate(today.getDate() - 1);
  const days: Day[] = [];
  for (const entry of entries) {
    const key = new Date(entry.created_at).toDateString();
    let day = days.at(-1);
    if (day?.key !== key) {
      const label =
        key === today.toDateString()
          ? t.audit.today
          : key === yesterday.toDateString()
            ? t.audit.yesterday
            : formatDate(entry.created_at);
      day = { key, label, entries: [] };
      days.push(day);
    }
    day.entries.push(entry);
  }
  return days;
}

/**
 * One cell of CSV. Quoted always; a value a spreadsheet would read as a
 * formula (`=`, `+`, `-`, `@`, a tab or a carriage return first) is prefixed
 * with an apostrophe, because an entry carries what a person typed -- an
 * address, an integration's name -- and the file is opened in a spreadsheet
 * by someone who did not write it.
 */
function cell(value: string | null): string {
  const text = value ?? "";
  const safe = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
  return `"${safe.replace(/"/g, '""')}"`;
}

function toCsv(entries: AuditEntry[], t: Strings): string {
  const header = ["time", "person", "action", "change", "subject", "ip_address", "request_id"];
  const lines = entries.map((entry) =>
    [
      entry.created_at,
      actorOf(entry, t),
      entry.action,
      describe(entry, t),
      subjectOf(entry),
      entry.ip_address,
      entry.request_id,
    ]
      .map(cell)
      .join(","),
  );
  return [header.join(","), ...lines].join("\r\n");
}
