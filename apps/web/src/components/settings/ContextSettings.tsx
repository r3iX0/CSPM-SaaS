import { useState, type ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { BoxesIcon, ChevronDownIcon, ChevronRightIcon, SearchIcon } from "lucide-react";

import { api } from "@/lib/api";
import type { CloudAccount, ContextDeclaration, Level, Organization } from "@/lib/types";
import { useT } from "@/i18n";
import { cn, formatDay, levelStyle } from "@/lib/format";
import {
  DECLARABLE_LEVELS,
  DECLARATIONS_KEY,
  fetchDeclarations,
  levelLabel,
  statementOf,
  type Statement,
} from "@/lib/contextDeclarations";
import { LiveStatus } from "@/components/common/LiveStatus";
import { CardsSkeleton, EmptyState, ErrorState } from "@/components/common/states";
import { ContextSheet } from "@/components/settings/ContextSheet";
import { SettingsSection } from "@/components/settings/SettingsSection";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group";
import { Progress } from "@/components/ui/progress";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";

const SHOW_PARAM = "show";
const SEARCH_PARAM = "q";
const ACCOUNT_PARAM = "account";
type Show = "all" | "undeclared" | "declared";
const SHOWS: Show[] = ["all", "undeclared", "declared"];

/** Above this many subscriptions the list earns a search box. */
const SEARCH_FROM = 8;

/** At most this many writes in flight at once when one change goes to many. */
const PARALLEL = 4;

type Field = "environment" | "criticality" | "data_sensitivity";

/**
 * What each subscription is for, as a table worked through (DECISIONS.md §207).
 *
 * The risk engine multiplies every finding by criticality and data sensitivity,
 * which makes these the highest-leverage answers a customer can give -- and
 * the page used to ask for them as one full form per subscription, stacked,
 * each with its own Save. With thirty subscriptions that was thirty forms and
 * no way to tell how many were left. Now each is one row, the count of
 * declared ones leads the page, the undeclared can be shown alone, and a
 * change can be made to many at once.
 *
 * A bulk change sets one field and keeps the rest of each subscription's
 * statement: the API replaces a declaration whole, so the page sends each
 * subscription its own full statement with that one field changed. Each is
 * its own write and its own audit entry, which is what a declaration is --
 * one person's statement about one subscription -- so the result is reported
 * honestly when some succeed and some do not.
 */
export function ContextSettings({ organization }: { organization: Organization }) {
  const t = useT();
  const queryClient = useQueryClient();
  // As the API allows (`require_write`): anyone but a viewer, never the demo.
  const writable = organization.role !== "VIEWER" && !organization.is_demo;
  const [params, setParams] = useSearchParams();
  const [selected, setSelected] = useState<ReadonlySet<string>>(new Set());
  const [confirmClear, setConfirmClear] = useState(false);

  const show: Show = SHOWS.find((value) => value === params.get(SHOW_PARAM)) ?? "all";
  const search = params.get(SEARCH_PARAM) ?? "";
  const openId = params.get(ACCOUNT_PARAM);

  // Replaced rather than pushed, so Back leaves the page rather than walking
  // through every filter and sheet that was opened on it.
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

  const accounts = useQuery({
    queryKey: ["cloud-accounts"],
    queryFn: () => api.get<CloudAccount[]>("/api/v1/cloud-accounts").then((r) => r.data),
  });
  const declarations = useQuery({ queryKey: DECLARATIONS_KEY, queryFn: fetchDeclarations });

  const byAccount = new Map(
    (declarations.data ?? []).map((declaration) => [declaration.cloud_account_id, declaration]),
  );

  const bulk = useMutation({
    mutationFn: (change: { ids: string[]; statement: (current: Statement) => Statement | null }) =>
      inBatches(change.ids, (id) => {
        const next = change.statement(statementOf(byAccount.get(id)));
        return next
          ? api.put(`/api/v1/cloud-accounts/${id}/context`, next)
          : api.del(`/api/v1/cloud-accounts/${id}/context`);
      }),
    onSuccess: (results) => {
      const done = results.filter((result) => result.status === "fulfilled").length;
      if (done === results.length) toast.success(t.settings.bulkDone(done));
      else if (done > 0) toast.warning(t.settings.bulkPartial(done, results.length));
      else toast.error(t.settings.bulkNone);
      setSelected(new Set());
    },
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: DECLARATIONS_KEY });
      void queryClient.invalidateQueries({ queryKey: ["account-context"] });
    },
  });

  let body: ReactNode;
  if (accounts.isLoading || declarations.isLoading) {
    body = <CardsSkeleton count={1} />;
  } else if (accounts.error || declarations.error || !accounts.data) {
    body = (
      <ErrorState
        title={t.settings.contextLoadFailed}
        detail="Cleave could not reach its own API."
        onRetry={() => {
          void accounts.refetch();
          void declarations.refetch();
        }}
      />
    );
  } else if (accounts.data.length === 0) {
    body = (
      <EmptyState
        icon={BoxesIcon}
        title={t.settings.contextEmpty}
        detail={t.settings.contextEmptyDetail}
      />
    );
  } else {
    const all = accounts.data;
    const declaredCount = all.filter((account) => byAccount.has(account.id)).length;
    const needle = search.trim().toLowerCase();
    const rows = all.filter((account) => {
      const declared = byAccount.has(account.id);
      if (show === "declared" && !declared) return false;
      if (show === "undeclared" && declared) return false;
      if (!needle) return true;
      return (
        account.account_name.toLowerCase().includes(needle) ||
        (account.subscription_id ?? "").toLowerCase().includes(needle)
      );
    });
    const filtered = rows.length !== all.length;
    const chosen = all.filter((account) => selected.has(account.id)).map((account) => account.id);
    const allShownChosen = rows.length > 0 && rows.every((account) => selected.has(account.id));
    // The record's id from a row, or the provider's subscription id from an
    // asset page, which knows where an asset sits but not the record's id.
    const openAccount =
      all.find((account) => account.id === openId || account.subscription_id === openId) ?? null;
    const shownLine = t.settings.contextShown(rows.length, all.length);

    const toggle = (ids: string[], on: boolean) =>
      setSelected((current) => {
        const next = new Set(current);
        for (const id of ids) {
          if (on) next.add(id);
          else next.delete(id);
        }
        return next;
      });

    const setField = (field: Field, value: string | null) =>
      bulk.mutate({
        ids: chosen,
        statement: (current) => {
          const next: Statement = { ...current, [field]: value };
          // A statement that claims nothing is a withdrawal, as the API reads it.
          return next.environment || next.criticality || next.data_sensitivity ? next : null;
        },
      });

    body = (
      <div className="flex flex-col gap-4">
        {!writable && (
          <Alert>
            <AlertDescription>{t.settings.contextReadOnly}</AlertDescription>
          </Alert>
        )}

        <Progress
          value={Math.round((declaredCount / all.length) * 100)}
          aria-label={t.settings.contextProgress(declaredCount, all.length)}
          className="max-w-sm gap-2"
        >
          <span className="text-body font-medium text-foreground">
            {t.settings.contextProgress(declaredCount, all.length)}
          </span>
        </Progress>

        <div className="flex flex-wrap items-center gap-3">
          <ToggleGroup
            aria-label={t.settings.show}
            variant="outline"
            size="sm"
            spacing={0}
            value={[show]}
            onValueChange={(value) => {
              const next = value[0];
              if (typeof next === "string") setParam(SHOW_PARAM, next === "all" ? null : next);
            }}
          >
            <ToggleGroupItem value="all">{t.settings.showAll}</ToggleGroupItem>
            <ToggleGroupItem value="undeclared">{t.settings.showUndeclared}</ToggleGroupItem>
            <ToggleGroupItem value="declared">{t.settings.showDeclared}</ToggleGroupItem>
          </ToggleGroup>
          {all.length > SEARCH_FROM && (
            <InputGroup className="h-7 w-56">
              <InputGroupAddon>
                <SearchIcon />
              </InputGroupAddon>
              <InputGroupInput
                type="search"
                aria-label={t.settings.searchSubscriptions}
                placeholder={t.settings.searchSubscriptions}
                value={search}
                onChange={(event) => setParam(SEARCH_PARAM, event.target.value || null)}
              />
            </InputGroup>
          )}
          {filtered && <p className="text-meta text-muted-foreground">{shownLine}</p>}
          <LiveStatus message={shownLine} quietFirst />
        </div>

        {writable && chosen.length > 0 && (
          <div
            role="toolbar"
            aria-label={t.settings.selected(chosen.length)}
            className="flex flex-wrap items-center gap-2 rounded-lg bg-muted/60 px-3 py-2"
          >
            <span className="mr-1 text-body font-medium text-foreground">
              {t.settings.selected(chosen.length)}
            </span>
            <BulkMenu
              label={t.settings.bulkEnvironment}
              disabled={bulk.isPending}
              options={t.settings.environmentSuggestions.map((name) => ({
                label: name,
                value: name,
              }))}
              onChoose={(value) => setField("environment", value)}
            />
            <BulkMenu
              label={t.settings.bulkCriticality}
              disabled={bulk.isPending}
              options={levelOptions(t.settings.notDeclared)}
              onChoose={(value) => setField("criticality", value)}
            />
            <BulkMenu
              label={t.settings.bulkSensitivity}
              disabled={bulk.isPending}
              options={levelOptions(t.settings.notDeclared)}
              onChoose={(value) => setField("data_sensitivity", value)}
            />
            <Button
              size="sm"
              variant="ghost"
              disabled={bulk.isPending}
              onClick={() => setConfirmClear(true)}
            >
              {t.settings.bulkClear}
            </Button>
            <Button
              size="sm"
              variant="ghost"
              className="ml-auto"
              onClick={() => setSelected(new Set())}
            >
              {t.settings.deselect}
            </Button>
          </div>
        )}

        <div className="overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10">
          {rows.length === 0 ? (
            <p className="px-5 py-4 text-body text-muted-foreground">
              {t.settings.noSubscriptionMatches}
            </p>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  {writable && (
                    <TableHead className="w-10 pl-4">
                      <Checkbox
                        aria-label={t.settings.selectShown}
                        checked={allShownChosen}
                        onCheckedChange={(on) =>
                          toggle(
                            rows.map((account) => account.id),
                            on,
                          )
                        }
                      />
                    </TableHead>
                  )}
                  <TableHead className={writable ? undefined : "pl-5"}>
                    {t.settings.subscription}
                  </TableHead>
                  <TableHead className="hidden md:table-cell">{t.settings.environment}</TableHead>
                  <TableHead className="hidden sm:table-cell">{t.settings.criticality}</TableHead>
                  <TableHead className="hidden sm:table-cell">
                    {t.settings.dataSensitivity}
                  </TableHead>
                  <TableHead className="pr-5">{t.settings.status}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((account) => (
                  <AccountRow
                    key={account.id}
                    account={account}
                    declaration={byAccount.get(account.id) ?? null}
                    writable={writable}
                    selected={selected.has(account.id)}
                    onSelect={(on) => toggle([account.id], on)}
                    onOpen={() => setParam(ACCOUNT_PARAM, account.id)}
                  />
                ))}
              </TableBody>
            </Table>
          )}
        </div>

        <p className="max-w-[76ch] text-meta leading-relaxed text-muted-foreground">
          {t.settings.appliesNext}
        </p>

        <ContextSheet
          account={openAccount}
          declaration={openAccount ? (byAccount.get(openAccount.id) ?? null) : null}
          writable={writable}
          onClose={() => setParam(ACCOUNT_PARAM, null)}
        />

        <AlertDialog open={confirmClear} onOpenChange={setConfirmClear}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>{t.settings.bulkClearTitle(chosen.length)}</AlertDialogTitle>
              <AlertDialogDescription>{t.settings.bulkClearDetail}</AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel>{t.settings.cancel}</AlertDialogCancel>
              <AlertDialogAction
                variant="destructive"
                onClick={() => {
                  setConfirmClear(false);
                  bulk.mutate({ ids: chosen, statement: () => null });
                }}
              >
                {t.settings.bulkClearConfirm}
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      </div>
    );
  }

  return (
    <SettingsSection
      id="context"
      title={t.settings.contextTitle}
      description={t.settings.contextHelp}
    >
      {body}
    </SettingsSection>
  );
}

function AccountRow({
  account,
  declaration,
  writable,
  selected,
  onSelect,
  onOpen,
}: {
  account: CloudAccount;
  declaration: ContextDeclaration | null;
  writable: boolean;
  selected: boolean;
  onSelect: (on: boolean) => void;
  onOpen: () => void;
}) {
  const t = useT();
  const summary = [
    declaration?.environment,
    declaration?.criticality && levelLabel(declaration.criticality),
    declaration?.data_sensitivity && levelLabel(declaration.data_sensitivity),
  ].filter(Boolean);

  return (
    <TableRow data-state={selected ? "selected" : undefined}>
      {writable && (
        <TableCell className="pl-4">
          <Checkbox
            aria-label={t.settings.selectOne(account.account_name)}
            checked={selected}
            onCheckedChange={(on) => onSelect(on)}
          />
        </TableCell>
      )}
      <TableCell className={cn("max-w-0 min-w-48", !writable && "pl-5")}>
        <button
          type="button"
          aria-label={
            writable
              ? t.settings.editContext(account.account_name)
              : t.settings.viewContext(account.account_name)
          }
          className="group flex w-full min-w-0 items-center gap-1.5 rounded-sm text-left outline-none focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring"
          onClick={onOpen}
        >
          <span className="flex min-w-0 flex-col">
            <span className="truncate font-medium text-foreground group-hover:underline">
              {account.account_name}
            </span>
            <span
              className="truncate font-mono text-caption text-muted-foreground"
              title={account.subscription_id ?? undefined}
            >
              {account.subscription_id}
            </span>
            {/* The columns a narrow screen drops, said in one line instead. */}
            {summary.length > 0 && (
              <span className="truncate text-meta text-muted-foreground sm:hidden">
                {summary.join(" · ")}
              </span>
            )}
          </span>
          <ChevronRightIcon
            aria-hidden
            className="ml-auto size-4 shrink-0 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100"
          />
        </button>
      </TableCell>
      <TableCell className="hidden text-foreground md:table-cell">
        {declaration?.environment ?? <span className="text-muted-foreground">{"—"}</span>}
      </TableCell>
      <TableCell className="hidden sm:table-cell">
        <LevelPill level={declaration?.criticality ?? null} />
      </TableCell>
      <TableCell className="hidden sm:table-cell">
        <LevelPill level={declaration?.data_sensitivity ?? null} />
      </TableCell>
      <TableCell className="pr-5">
        {declaration ? (
          <span className="text-meta whitespace-nowrap text-muted-foreground">
            {t.settings.declaredBy} {formatDay(declaration.declared_at)}
          </span>
        ) : (
          // Drawn in the unknown style -- dashed, like every other place Cleave
          // has not been told -- so the rows still to fill in are the ones the
          // eye lands on.
          <span className="rounded-full border border-dashed border-unknown-border px-2 py-px text-caption whitespace-nowrap text-unknown">
            {t.settings.notDeclared}
          </span>
        )}
      </TableCell>
    </TableRow>
  );
}

function LevelPill({ level }: { level: Level | null }) {
  if (!level) return <span className="text-muted-foreground">{"—"}</span>;
  return (
    <span
      className={cn(
        "inline-flex rounded-full border px-2 py-px text-caption font-medium",
        levelStyle(level),
      )}
    >
      {levelLabel(level)}
    </span>
  );
}

function levelOptions(notDeclared: string): { label: string; value: string | null }[] {
  return [
    ...DECLARABLE_LEVELS.map((level) => ({ label: levelLabel(level), value: level })),
    { label: notDeclared, value: null },
  ];
}

function BulkMenu({
  label,
  options,
  disabled,
  onChoose,
}: {
  label: string;
  options: { label: string; value: string | null }[];
  disabled: boolean;
  onChoose: (value: string | null) => void;
}) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger disabled={disabled} render={<Button size="sm" variant="outline" />}>
        {label}
        <ChevronDownIcon />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-44">
        {options.map((option) => (
          <DropdownMenuItem key={option.label} onClick={() => onChoose(option.value)}>
            {option.label}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

/** Run one write per id, a few at a time, and report each one's outcome. */
async function inBatches(
  ids: string[],
  write: (id: string) => Promise<unknown>,
): Promise<PromiseSettledResult<unknown>[]> {
  const results: PromiseSettledResult<unknown>[] = [];
  for (let start = 0; start < ids.length; start += PARALLEL) {
    results.push(...(await Promise.allSettled(ids.slice(start, start + PARALLEL).map(write))));
  }
  return results;
}
