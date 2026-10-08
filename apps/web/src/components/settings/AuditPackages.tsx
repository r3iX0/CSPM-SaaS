import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { ArchiveIcon, ChevronRightIcon, PlusIcon } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import type {
  AuditGrant,
  AuditGrantCreated,
  AuditGrantEvent,
  AuditGrantStatus,
  AuditPackage,
  AuditPackageDetail,
  AuditPackageVerification,
  ComplianceFramework,
} from "@/lib/types";
import { useT } from "@/i18n";
import { cn, formatDate, formatDateTime } from "@/lib/format";
import { archiveFileName, saveBlob } from "@/lib/download";
import { PackageSummary } from "@/components/audit/PackageSummary";
import { CopyButton } from "@/components/common/CopyButton";
import { LiveStatus } from "@/components/common/LiveStatus";
import { CardsSkeleton, EmptyState, ErrorState } from "@/components/common/states";
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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Field, FieldDescription, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field";
import { Input } from "@/components/ui/input";

/** The most one request reads: the API's ceiling, ample for an organization. */
const LIST_LIMIT = 200;

const GRANT_STYLES: Record<AuditGrantStatus, string> = {
  OPENED: "bg-ok-bg text-ok border-ok-border",
  PENDING: "bg-unknown-bg text-unknown border-unknown-border border-dashed",
  EXPIRED: "bg-muted text-muted-foreground border-border",
  REVOKED: "bg-muted text-muted-foreground border-border border-dashed",
};

/**
 * Sealed assessments and who may read them (DECISIONS.md §208, §211, §218).
 *
 * Owners and administrators only, as the API allows. Each package is a row that
 * opens to what it holds -- how each standard's controls came out, what they
 * rest on, the hash that seals it -- and to the people it has been given to.
 * Nothing here edits a package: a wrong one is sealed again, and the old one
 * stays what it was.
 */
export function AuditPackagesSection({ organizationId }: { organizationId: string }) {
  const t = useT();
  const [sealing, setSealing] = useState(false);
  const packages = useQuery({
    queryKey: ["audit-packages", organizationId],
    queryFn: () =>
      api.get<AuditPackage[]>(`/api/v1/audit-packages?limit=${LIST_LIMIT}`).then((r) => r.data),
  });

  const openButton = (
    <Button onClick={() => setSealing(true)}>
      <PlusIcon />
      {t.auditPackages.open}
    </Button>
  );

  return (
    <SettingsSection
      id="audit"
      title={t.auditPackages.title}
      description={t.auditPackages.help}
      actions={packages.data && packages.data.length > 0 ? openButton : undefined}
    >
      {packages.isLoading && <CardsSkeleton count={1} />}
      {packages.error && (
        <ErrorState
          title={t.auditPackages.loadFailed}
          detail={t.auditPackages.loadFailedDetail}
          onRetry={() => void packages.refetch()}
        />
      )}
      {packages.data?.length === 0 && (
        <EmptyState
          icon={ArchiveIcon}
          title={t.auditPackages.emptyTitle}
          detail={t.auditPackages.empty}
          action={openButton}
        />
      )}
      {packages.data && packages.data.length > 0 && (
        <ul className="flex flex-col gap-3">
          {packages.data.map((pack) => (
            <PackageCard key={pack.id} pack={pack} />
          ))}
        </ul>
      )}
      <SealDialog open={sealing} onOpenChange={setSealing} organizationId={organizationId} />
    </SettingsSection>
  );
}

function PackageCard({ pack }: { pack: AuditPackage }) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const panelId = `audit-package-${pack.id}`;

  return (
    <li className="rounded-xl bg-card ring-1 ring-foreground/10">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((current) => !current)}
        className="flex w-full items-start gap-3 rounded-xl px-5 py-4 text-left outline-none focus-visible:ring-3 focus-visible:ring-ring/50 focus-ring"
      >
        <ChevronRightIcon
          aria-hidden
          className={cn(
            "mt-1 size-4 shrink-0 text-muted-foreground transition-transform",
            open && "rotate-90",
          )}
        />
        <span className="min-w-0 flex-1">
          <span className="block truncate text-body font-medium text-foreground">{pack.name}</span>
          <span className="block text-meta text-muted-foreground">
            {pack.frameworks.map((framework) => framework.short_name).join(" · ")}
            {" · "}
            {t.auditPackages.sealedOn(formatDate(pack.sealed_at))}
          </span>
        </span>
      </button>
      {open && (
        <div id={panelId} className="flex flex-col gap-6 border-t border-border px-5 py-5">
          <PackageBody pack={pack} />
        </div>
      )}
    </li>
  );
}

function PackageBody({ pack }: { pack: AuditPackage }) {
  const t = useT();
  const [granting, setGranting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [verification, setVerification] = useState<AuditPackageVerification | null>(null);

  const detail = useQuery({
    queryKey: ["audit-package", pack.id],
    queryFn: () =>
      api.get<AuditPackageDetail>(`/api/v1/audit-packages/${pack.id}`).then((r) => r.data),
  });

  const download = useMutation({
    mutationFn: () => api.document(`/api/v1/audit-packages/${pack.id}/archive`),
    onSuccess: (blob) => {
      setError(null);
      saveBlob(blob, archiveFileName(pack.name));
    },
    onError: (err) =>
      setError(err instanceof ApiError ? err.message : t.auditPackages.downloadFailed),
  });

  const verify = useMutation({
    mutationFn: () =>
      api
        .get<AuditPackageVerification>(`/api/v1/audit-packages/${pack.id}/verification`)
        .then((r) => r.data),
    onSuccess: (result) => {
      setError(null);
      setVerification(result);
    },
    onError: (err) =>
      setError(err instanceof ApiError ? err.message : t.auditPackages.verifyFailed),
  });

  const verdict = verification
    ? verification.verified
      ? t.auditPackages.verified
      : t.auditPackages.notVerified
    : null;

  return (
    <>
      {detail.isLoading && <CardsSkeleton count={1} />}
      {detail.error && (
        <ErrorState
          title={t.auditPackages.loadFailed}
          detail={t.auditPackages.loadFailedDetail}
          onRetry={() => void detail.refetch()}
        />
      )}
      {detail.data && <PackageSummary detail={detail.data} />}

      <div className="flex flex-wrap items-center gap-2">
        <Button variant="outline" disabled={download.isPending} onClick={() => download.mutate()}>
          {download.isPending ? t.auditPackages.downloading : t.auditPackages.download}
        </Button>
        <Button variant="outline" disabled={verify.isPending} onClick={() => verify.mutate()}>
          {verify.isPending ? t.auditPackages.verifying : t.auditPackages.verify}
        </Button>
        <Button onClick={() => setGranting(true)}>{t.auditPackages.giveAccess}</Button>
      </div>
      <LiveStatus message={verdict} />
      {verification && (
        <p className={verification.verified ? "text-meta text-ok" : "text-meta text-critical"}>
          {verdict}
        </p>
      )}
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <GrantList pack={pack} />
      <GrantDialog pack={pack} open={granting} onOpenChange={setGranting} />
    </>
  );
}

function GrantList({ pack }: { pack: AuditPackage }) {
  const t = useT();
  const grants = useQuery({
    queryKey: ["audit-grants", pack.id],
    queryFn: () =>
      api
        .get<AuditGrant[]>(`/api/v1/audit-grants?package_id=${pack.id}&limit=${LIST_LIMIT}`)
        .then((r) => r.data),
  });

  return (
    <section aria-label={t.auditPackages.auditors} className="flex flex-col gap-2">
      <h3 className="text-body font-medium text-foreground">{t.auditPackages.auditors}</h3>
      {grants.isLoading && <CardsSkeleton count={1} />}
      {grants.error && (
        <ErrorState
          title={t.auditPackages.loadFailed}
          detail={t.auditPackages.loadFailedDetail}
          onRetry={() => void grants.refetch()}
        />
      )}
      {grants.data?.length === 0 && (
        <p className="text-meta text-muted-foreground">{t.auditPackages.noGrants}</p>
      )}
      {grants.data && grants.data.length > 0 && (
        <ul className="divide-y divide-border overflow-hidden rounded-lg border border-border">
          {grants.data.map((grant) => (
            <GrantRow key={grant.id} grant={grant} />
          ))}
        </ul>
      )}
    </section>
  );
}

function GrantRow({ grant }: { grant: AuditGrant }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const [reading, setReading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const live = grant.status === "PENDING" || grant.status === "OPENED";

  const revoke = useMutation({
    mutationFn: () => api.del(`/api/v1/audit-grants/${grant.id}`),
    onSuccess: () => {
      setConfirming(false);
      toast.success(t.auditPackages.revoked(grant.email));
      void queryClient.invalidateQueries({ queryKey: ["audit-grants", grant.package_id] });
    },
    onError: (err) => {
      setConfirming(false);
      setError(err instanceof ApiError ? err.message : t.auditPackages.revokeFailed);
    },
  });

  return (
    <li className="flex flex-col gap-2 px-4 py-3">
      <div className="flex flex-wrap items-center gap-3">
        <div className="min-w-0 flex-1">
          <p className="flex flex-wrap items-center gap-2">
            <span className="truncate text-body text-foreground">{grant.email}</span>
            <span
              className={cn(
                "rounded-full border px-2 py-px text-caption font-medium",
                GRANT_STYLES[grant.status],
              )}
            >
              {t.auditPackages.grantStatus[grant.status]}
            </span>
          </p>
          <p className="text-meta text-muted-foreground">
            {t.auditPackages.grantUntil(formatDate(grant.expires_at))}
            {grant.opened_at && ` · ${t.auditPackages.grantOpened(formatDate(grant.opened_at))}`}
          </p>
        </div>
        {grant.opened_at && (
          <Button
            variant="ghost"
            size="sm"
            aria-expanded={reading}
            onClick={() => setReading((current) => !current)}
          >
            {t.auditPackages.activity}
          </Button>
        )}
        {live && (
          <Button
            variant="ghost"
            size="sm"
            aria-label={`${t.auditPackages.revoke} ${grant.email}`}
            onClick={() => setConfirming(true)}
          >
            {t.auditPackages.revoke}
          </Button>
        )}
      </div>
      {reading && <GrantEvents grantId={grant.id} />}
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <AlertDialog open={confirming} onOpenChange={setConfirming}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t.auditPackages.revokeTitle(grant.email)}</AlertDialogTitle>
            <AlertDialogDescription>{t.auditPackages.revokeDetail}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t.auditPackages.cancel}</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={revoke.isPending}
              onClick={() => revoke.mutate()}
            >
              {t.auditPackages.revoke}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </li>
  );
}

/** The grant's own trail: the only record of what an auditor read (DECISIONS.md §211). */
function GrantEvents({ grantId }: { grantId: string }) {
  const t = useT();
  const events = useQuery({
    queryKey: ["audit-grant-events", grantId],
    queryFn: () =>
      api
        .get<AuditGrantEvent[]>(`/api/v1/audit-grants/${grantId}/events?limit=50`)
        .then((r) => r.data),
  });

  if (events.isLoading) return <CardsSkeleton count={1} />;
  if (events.error) {
    return (
      <ErrorState
        title={t.auditPackages.loadFailed}
        detail={t.auditPackages.loadFailedDetail}
        onRetry={() => void events.refetch()}
      />
    );
  }
  if (!events.data || events.data.length === 0) {
    return <p className="text-meta text-muted-foreground">{t.auditPackages.activityNone}</p>;
  }
  return (
    <ul className="flex flex-col gap-1 text-meta text-muted-foreground">
      {events.data.map((event) => (
        <li key={event.id}>
          {formatDateTime(event.at)} · {t.auditPackages.activityEvents[event.event]}
        </li>
      ))}
    </ul>
  );
}

function SealDialog({
  open,
  onOpenChange,
  organizationId,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  organizationId: string;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [chosen, setChosen] = useState<string[]>([]);
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [error, setError] = useState<string | null>(null);

  const frameworks = useQuery({
    queryKey: ["compliance"],
    queryFn: () => api.get<ComplianceFramework[]>("/api/v1/compliance").then((r) => r.data),
    enabled: open,
  });

  const close = () => {
    setName("");
    setChosen([]);
    setFrom("");
    setTo("");
    setError(null);
    onOpenChange(false);
  };

  const seal = useMutation({
    mutationFn: () =>
      api
        .post<AuditPackage>("/api/v1/audit-packages", {
          name: name.trim(),
          framework_ids: chosen,
          period_start: from || null,
          period_end: to || null,
        })
        .then((r) => r.data),
    onSuccess: (sealed) => {
      void queryClient.invalidateQueries({ queryKey: ["audit-packages", organizationId] });
      toast.success(t.auditPackages.sealed(sealed.name));
      close();
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : t.auditPackages.sealFailed),
  });

  function toggle(id: string, on: boolean) {
    setChosen((current) => (on ? [...current, id] : current.filter((value) => value !== id)));
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (next) onOpenChange(true);
        else close();
      }}
    >
      <DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{t.auditPackages.dialogTitle}</DialogTitle>
          <DialogDescription>{t.auditPackages.dialogHelp}</DialogDescription>
        </DialogHeader>
        <form
          className="flex flex-col gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            seal.mutate();
          }}
        >
          <Field>
            <FieldLabel htmlFor="audit-package-name">{t.auditPackages.name}</FieldLabel>
            <Input
              id="audit-package-name"
              required
              maxLength={120}
              placeholder="SOC 2 Type II, FY2026"
              value={name}
              onChange={(event) => setName(event.target.value)}
            />
          </Field>
          <FieldSet>
            <FieldLegend variant="label">{t.auditPackages.frameworks}</FieldLegend>
            <FieldDescription>{t.auditPackages.frameworksHelp}</FieldDescription>
            {frameworks.data?.length === 0 && (
              <p className="text-meta text-muted-foreground">{t.auditPackages.frameworksNone}</p>
            )}
            <div className="flex max-h-56 flex-col gap-2 overflow-y-auto">
              {frameworks.data?.map((framework) => (
                <label
                  key={framework.id}
                  className="flex items-center gap-2 text-body text-foreground"
                >
                  <Checkbox
                    checked={chosen.includes(framework.id)}
                    onCheckedChange={(on) => toggle(framework.id, on)}
                  />
                  {framework.name}
                </label>
              ))}
            </div>
          </FieldSet>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field>
              <FieldLabel htmlFor="audit-package-from">{t.auditPackages.periodStart}</FieldLabel>
              <Input
                id="audit-package-from"
                type="date"
                value={from}
                onChange={(event) => setFrom(event.target.value)}
              />
            </Field>
            <Field>
              <FieldLabel htmlFor="audit-package-to">{t.auditPackages.periodEnd}</FieldLabel>
              <Input
                id="audit-package-to"
                type="date"
                value={to}
                onChange={(event) => setTo(event.target.value)}
              />
            </Field>
          </div>
          <p className="-mt-2 text-meta text-muted-foreground">{t.auditPackages.periodHelp}</p>

          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          <DialogFooter>
            <Button type="submit" disabled={seal.isPending || !name.trim() || chosen.length === 0}>
              {seal.isPending ? t.auditPackages.sealing : t.auditPackages.seal}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

/**
 * Giving a package to an address. The link comes back once and Cleave keeps
 * only its hash, so the dialog that shows it closes only when the reader says
 * it is copied (DECISIONS.md §211), as a webhook's secret is.
 */
function GrantDialog({
  pack,
  open,
  onOpenChange,
}: {
  pack: AuditPackage;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const [email, setEmail] = useState("");
  const [days, setDays] = useState("30");
  const [link, setLink] = useState<string | null>(null);
  const [stored, setStored] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const close = () => {
    setEmail("");
    setDays("30");
    setLink(null);
    setStored(false);
    setError(null);
    onOpenChange(false);
  };

  const grant = useMutation({
    mutationFn: () =>
      api
        .post<AuditGrantCreated>("/api/v1/audit-grants", {
          package_id: pack.id,
          email: email.trim(),
          expires_in_days: Number(days),
        })
        .then((r) => r.data),
    onSuccess: (created) => {
      void queryClient.invalidateQueries({ queryKey: ["audit-grants", pack.id] });
      setError(null);
      setLink(created.link);
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : t.auditPackages.grantFailed),
  });

  const validDays = Number.isInteger(Number(days)) && Number(days) >= 1 && Number(days) <= 90;

  return (
    <Dialog
      open={open}
      // The link cannot be read again, so a dialog holding one stays until it is copied.
      disablePointerDismissal={link !== null}
      onOpenChange={(next) => {
        if (next) onOpenChange(true);
        else if (link === null || stored) close();
      }}
    >
      <DialogContent
        className="max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-lg"
        showCloseButton={link === null}
      >
        <DialogHeader>
          <DialogTitle>{t.auditPackages.grantDialogTitle(pack.name)}</DialogTitle>
          <DialogDescription>{t.auditPackages.grantDialogHelp}</DialogDescription>
        </DialogHeader>

        <LiveStatus message={link ? t.auditPackages.linkReady : null} />
        {link ? (
          <>
            <div className="flex flex-col gap-2.5 rounded-lg bg-muted/50 p-4">
              <p className="text-body text-foreground">{t.auditPackages.linkReady}</p>
              <code
                aria-label={t.auditPackages.linkLabel}
                className="block break-all rounded bg-background px-2.5 py-1.5 font-mono text-meta"
              >
                {link}
              </code>
              <div>
                <CopyButton text={link} label={t.auditPackages.copyLink} variant="outline" />
              </div>
            </div>
            <Field orientation="horizontal">
              <Checkbox
                id="audit-grant-link-stored"
                checked={stored}
                onCheckedChange={(on) => setStored(on)}
              />
              <FieldLabel htmlFor="audit-grant-link-stored" className="font-normal">
                {t.auditPackages.linkStored}
              </FieldLabel>
            </Field>
            <DialogFooter>
              <Button disabled={!stored} onClick={close}>
                {t.auditPackages.done}
              </Button>
            </DialogFooter>
          </>
        ) : (
          <form
            className="flex flex-col gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              grant.mutate();
            }}
          >
            <Field>
              <FieldLabel htmlFor="audit-grant-email">{t.auditPackages.email}</FieldLabel>
              <Input
                id="audit-grant-email"
                type="email"
                required
                autoComplete="off"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
              />
              <FieldDescription>{t.auditPackages.emailHelp}</FieldDescription>
            </Field>
            <Field>
              <FieldLabel htmlFor="audit-grant-days">{t.auditPackages.days}</FieldLabel>
              <Input
                id="audit-grant-days"
                type="number"
                inputMode="numeric"
                min={1}
                max={90}
                required
                value={days}
                onChange={(event) => setDays(event.target.value)}
              />
              <FieldDescription>{t.auditPackages.daysHelp}</FieldDescription>
            </Field>
            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
            <DialogFooter>
              <Button type="submit" disabled={grant.isPending || !email.trim() || !validDays}>
                {grant.isPending ? t.auditPackages.granting : t.auditPackages.grant}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
