import { useEffect, useState, type ReactNode } from "react";
import { Link, Navigate, useLocation, useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, ApiError, auth } from "@/lib/api";
import { archiveIsGenuine, checkArchive, type ArchiveCheck } from "@/lib/archiveVerify";
import { archiveFileName, saveBlob } from "@/lib/download";
import { formatDate } from "@/lib/format";
import { forgetGrant, grantFromHash, heldGrant, holdGrant } from "@/lib/pendingGrant";
import { supabaseSignOut } from "@/lib/supabase";
import { usePageTitle } from "@/lib/pageTitle";
import { useAuthToken } from "@/lib/useAuth";
import type { AuditorGrant, AuditPackageDetail } from "@/lib/types";
import { useT } from "@/i18n";
import { cn } from "@/lib/utils";
import { Wordmark } from "@/components/Brand";
import { PackageSummary } from "@/components/audit/PackageSummary";
import { CodeBlock } from "@/components/common/CodeBlock";
import { LiveStatus } from "@/components/common/LiveStatus";
import { CardsSkeleton, ErrorState, PAGE_TITLE_CLASS } from "@/components/common/states";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button, buttonVariants } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";

/**
 * Where an auditor reads: outside the organization shell, because an auditor
 * belongs to no organization (DECISIONS.md §211, §218).
 *
 * The shell would send somebody with no membership to onboarding and ask them
 * to create one. This frame has the product's name and a way out and nothing
 * else: no navigation into an estate they were never given.
 */
function AuditorFrame({ children }: { children: ReactNode }) {
  const t = useT();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const signedIn = Boolean(useAuthToken());

  function signOut() {
    auth.signOut();
    queryClient.clear();
    void supabaseSignOut();
    void navigate("/sign-in", { replace: true });
  }

  return (
    <div className="flex min-h-screen flex-col bg-muted/40 px-6">
      <header className="mx-auto flex w-full max-w-3xl items-center justify-between py-6">
        <Wordmark />
        {signedIn && (
          <Button variant="ghost" size="sm" onClick={signOut}>
            {t.invite.signOut}
          </Button>
        )}
      </header>
      <main className="mx-auto w-full max-w-3xl flex-1 pb-16">{children}</main>
    </div>
  );
}

/**
 * Where a grant link lands, `/auditor#<token>`, and where an auditor's
 * packages are listed.
 *
 * Signed out, the token is held (`lib/pendingGrant.ts`) and the reader is sent
 * to sign in; the shell brings them back. Signed in, opening is a button and
 * not something done on arrival: it ties the grant to this account for good,
 * which is worth a click, and a link followed by the wrong account then says
 * so instead of spending itself (DECISIONS.md §211).
 */
export function AuditorPage() {
  const t = useT();
  const signedIn = Boolean(useAuthToken());
  const { hash } = useLocation();

  // The fragment wins over anything held: it is the link just opened.
  const [token] = useState(() => grantFromHash(hash) ?? heldGrant());

  useEffect(() => {
    if (token) holdGrant(token);
    // Out of the address bar, so the token is not left in history or shared
    // along with a screenshot of the page.
    if (hash) window.history.replaceState(null, "", window.location.pathname);
  }, [token, hash]);

  if (!token && !signedIn) return <Navigate to="/sign-in" replace />;

  return (
    <AuditorFrame>
      <h1 className={PAGE_TITLE_CLASS}>{t.auditor.listTitle}</h1>
      <p className="mt-1 text-body text-muted-foreground">{t.auditor.listHelp}</p>
      <div className="mt-6 flex flex-col gap-6">
        {token && signedIn && <Offer token={token} />}
        {token && !signedIn && (
          <div className="flex flex-col gap-4 rounded-xl border border-border bg-background p-6 shadow-sm">
            <p className="text-body text-muted-foreground">{t.auditor.signInFirst}</p>
            <Link to="/sign-in" className={cn(buttonVariants(), "self-start")}>
              {t.auditor.signIn}
            </Link>
          </div>
        )}
        {signedIn && <Grants />}
      </div>
    </AuditorFrame>
  );
}

function Offer({ token }: { token: string }) {
  const t = useT();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  const open = useMutation({
    mutationFn: () =>
      api.post<AuditorGrant>("/api/v1/auditor/grants/open", { token }).then((r) => r.data),
    onSuccess: (grant) => {
      forgetGrant();
      void queryClient.invalidateQueries({ queryKey: ["auditor-grants"] });
      void navigate(`/auditor/${grant.id}`, { replace: true });
    },
    onError: (err) => {
      // A link that can never work is not worth keeping for the next sign-in;
      // one refused for the address on this account is, since signing in as the
      // right one would open it.
      if (err instanceof ApiError && err.status !== 403) forgetGrant();
      setError(err instanceof ApiError ? err.message : t.auditor.openFailed);
    },
  });

  return (
    <div className="flex flex-col gap-4 rounded-xl border border-border bg-background p-6 shadow-sm">
      <h2 className="text-title font-semibold text-foreground">{t.auditor.offer}</h2>
      <p className="text-body text-muted-foreground">{t.auditor.offerDetail}</p>
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <Button className="self-start" disabled={open.isPending} onClick={() => open.mutate()}>
        {open.isPending ? t.auditor.opening : t.auditor.open}
      </Button>
    </div>
  );
}

function Grants() {
  const t = useT();
  const grants = useQuery({
    queryKey: ["auditor-grants"],
    queryFn: () => api.get<AuditorGrant[]>("/api/v1/auditor/grants").then((r) => r.data),
  });

  if (grants.isLoading) return <CardsSkeleton count={1} />;
  if (grants.error) {
    return (
      <ErrorState
        title={t.auditPackages.loadFailed}
        detail={t.auditPackages.loadFailedDetail}
        onRetry={() => void grants.refetch()}
      />
    );
  }
  if (!grants.data || grants.data.length === 0) {
    return <p className="text-body text-muted-foreground">{t.auditor.listEmpty}</p>;
  }
  return (
    <ul className="flex flex-col gap-3">
      {grants.data.map((grant) => (
        <li
          key={grant.id}
          className="flex flex-wrap items-center gap-3 rounded-xl bg-card px-5 py-4 ring-1 ring-foreground/10"
        >
          <div className="min-w-0 flex-1">
            <p className="truncate text-body font-medium text-foreground">{grant.package_name}</p>
            <p className="text-meta text-muted-foreground">
              {t.auditor.by(grant.organization_name)} ·{" "}
              {t.auditor.until(formatDate(grant.expires_at))}
            </p>
          </div>
          <Link
            to={`/auditor/${grant.id}`}
            className={buttonVariants({ variant: "outline", size: "sm" })}
          >
            {t.auditor.view}
          </Link>
        </li>
      ))}
    </ul>
  );
}

/** One package, read through the grant that names it. */
export function AuditorGrantPage() {
  const t = useT();
  const { grantId = "" } = useParams();

  const grant = useQuery({
    queryKey: ["auditor-grant", grantId],
    queryFn: () => api.get<AuditorGrant>(`/api/v1/auditor/grants/${grantId}`).then((r) => r.data),
    retry: false,
  });
  const detail = useQuery({
    queryKey: ["auditor-package", grantId],
    queryFn: () =>
      api.get<AuditPackageDetail>(`/api/v1/auditor/grants/${grantId}/package`).then((r) => r.data),
    retry: false,
  });

  usePageTitle(grant.data?.package_name);

  const failure = grant.error ?? detail.error;

  return (
    <AuditorFrame>
      <Link to="/auditor" className={cn(buttonVariants({ variant: "ghost", size: "sm" }), "-ml-2")}>
        {t.auditor.back}
      </Link>
      {(grant.isLoading || detail.isLoading) && !failure && (
        <div className="mt-4">
          <CardsSkeleton count={2} />
        </div>
      )}
      {failure && (
        <ErrorState
          className="mt-4"
          title={t.auditor.openFailed}
          detail={failure instanceof ApiError ? failure.message : t.auditPackages.loadFailedDetail}
        />
      )}
      {grant.data && detail.data && (
        <div className="mt-2 flex flex-col gap-8">
          <div>
            <h1 className={PAGE_TITLE_CLASS}>{grant.data.package_name}</h1>
            <p className="mt-1 text-body text-muted-foreground">
              {t.auditor.by(grant.data.organization_name)} ·{" "}
              {t.auditor.until(formatDate(grant.data.expires_at))}
            </p>
          </div>
          <section
            aria-label={t.auditor.assessment}
            className="rounded-xl bg-card p-5 ring-1 ring-foreground/10"
          >
            <PackageSummary detail={detail.data} />
            <p className="mt-4 text-meta text-muted-foreground">{t.auditor.gapsNote}</p>
          </section>
          <CheckPanel
            grantId={grantId}
            sealedSha256={detail.data.manifest_sha256}
            packageName={grant.data.package_name}
          />
        </div>
      )}
    </AuditorFrame>
  );
}

interface Checked {
  blob: Blob;
  check: ArchiveCheck;
}

/**
 * Testing the archive against its seal, here and without Cleave's say-so.
 *
 * The page downloads the archive, hashes `manifest.json` and every file
 * `SHA256SUMS` lists with the browser's own `SubtleCrypto`, and compares the
 * first with the hash sealed in the package (DECISIONS.md §218). The same
 * commands are given for a terminal, for the auditor who would rather not take
 * a web page's word either.
 */
function CheckPanel({
  grantId,
  sealedSha256,
  packageName,
}: {
  grantId: string;
  sealedSha256: string;
  packageName: string;
}) {
  const t = useT();
  const [progress, setProgress] = useState<{ done: number; total: number } | null>(null);

  const run = useMutation({
    mutationFn: async (): Promise<Checked> => {
      setProgress(null);
      const blob = await api.document(`/api/v1/auditor/grants/${grantId}/archive`);
      const check = await checkArchive(await blob.arrayBuffer(), sealedSha256, (done, total) =>
        setProgress({ done, total }),
      );
      return { blob, check };
    },
  });

  const checked = run.data;
  const verdict = checked
    ? archiveIsGenuine(checked.check)
      ? t.auditor.genuine
      : t.auditor.notGenuine
    : null;

  return (
    <section
      aria-labelledby="auditor-check-title"
      className="flex flex-col gap-4 rounded-xl bg-card p-5 ring-1 ring-foreground/10"
    >
      <div>
        <h2 id="auditor-check-title" className="text-title font-semibold text-foreground">
          {t.auditor.checkTitle}
        </h2>
        <p className="mt-1 text-meta text-muted-foreground">{t.auditor.checkHelp}</p>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Button disabled={run.isPending} onClick={() => run.mutate()}>
          {run.isPending ? (
            <>
              <Spinner /> {t.auditor.checking}
            </>
          ) : (
            t.auditor.checkRun
          )}
        </Button>
        {checked && (
          <Button
            variant="outline"
            onClick={() => saveBlob(checked.blob, archiveFileName(packageName))}
          >
            {t.auditor.saveArchive}
          </Button>
        )}
      </div>

      {run.isPending && progress && (
        <p className="text-meta text-muted-foreground">
          {t.auditor.checkProgress(progress.done, progress.total)}
        </p>
      )}
      <LiveStatus message={verdict} />
      {run.error && (
        <Alert variant="destructive">
          <AlertDescription>
            {run.error instanceof ApiError ? run.error.message : t.auditor.checkFailed}
          </AlertDescription>
        </Alert>
      )}
      {checked && <CheckResult check={checked.check} />}

      <div className="flex flex-col gap-2">
        <p className="text-meta text-muted-foreground">{t.auditor.checkTerminal}</p>
        <CodeBlock code={"shasum -a 256 manifest.json\nshasum -a 256 -c SHA256SUMS"} />
      </div>
      <p className="text-meta text-muted-foreground">{t.auditor.caveat}</p>
    </section>
  );
}

function CheckResult({ check }: { check: ArchiveCheck }) {
  const t = useT();
  if (archiveIsGenuine(check)) {
    return (
      <div className="rounded-lg border border-ok-border bg-ok-bg px-4 py-3 text-ok">
        <p className="text-body font-medium">{t.auditor.genuine}</p>
        <p className="text-meta">{t.auditor.genuineDetail(check.checked)}</p>
      </div>
    );
  }
  return (
    <div className="flex flex-col gap-1 rounded-lg border border-critical-border bg-critical-bg px-4 py-3 text-critical">
      <p className="text-body font-medium">{t.auditor.notGenuine}</p>
      {check.malformed && <p className="text-meta">{t.auditor.malformed}</p>}
      {!check.malformed && !check.manifestMatches && (
        <p className="text-meta">{t.auditor.manifestMismatch}</p>
      )}
      {check.mismatched.length > 0 && (
        <p className="text-meta">{t.auditor.mismatched(check.mismatched.length)}</p>
      )}
      {check.missing.length > 0 && (
        <p className="text-meta">{t.auditor.missingFiles(check.missing.length)}</p>
      )}
      {check.unlisted.length > 0 && (
        <p className="text-meta">{t.auditor.unlisted(check.unlisted.length)}</p>
      )}
    </div>
  );
}
