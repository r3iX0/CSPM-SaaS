import { useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, ApiError, auth } from "@/lib/api";
import { forgetInvite, heldInvite, holdInvite, inviteFromHash } from "@/lib/pendingInvite";
import { supabaseSignOut } from "@/lib/supabase";
import { useAuthToken } from "@/lib/useAuth";
import type { InvitationPreview, Organization } from "@/lib/types";
import { useT } from "@/i18n";
import { cn } from "@/lib/utils";
import { Wordmark } from "@/components/Brand";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button, buttonVariants } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
import { PAGE_TITLE_CLASS } from "@/components/common/states";

/**
 * Where an invitation link lands: `/invite#<token>`.
 *
 * Outside `RequireAuth`, because the person opening it may not have an account
 * yet. Signed out, the token is held (`lib/pendingInvite.ts`) and they are sent
 * to sign in; the shell brings them back here afterwards. Signed in, the page
 * says which organization and role the link offers and whether this account is
 * the one invited -- the API refuses any other, and saying so before the click
 * is kinder than after it (DECISIONS.md §162).
 */
export function InvitePage() {
  const t = useT();
  const signedIn = Boolean(useAuthToken());
  const { hash } = useLocation();

  // The fragment wins over anything held: it is the link just opened.
  const [token] = useState(() => inviteFromHash(hash) ?? heldInvite());

  useEffect(() => {
    if (token) holdInvite(token);
    // Out of the address bar, so the token is not left in history or shared
    // along with a screenshot of the page.
    if (hash) window.history.replaceState(null, "", window.location.pathname);
  }, [token, hash]);

  return (
    <div className="flex min-h-screen flex-col bg-muted/40 px-6">
      <main className="flex flex-1 items-center justify-center py-12">
        <div className="w-full max-w-sm">
          <div className="mb-8 flex items-center gap-2.5">
            <Wordmark />
          </div>
          <h1 className={PAGE_TITLE_CLASS}>{t.invite.title}</h1>
          <div className="mt-6 rounded-xl border border-border bg-background p-6 shadow-sm">
            {!token ? (
              <p className="text-sm text-muted-foreground">{t.invite.missing}</p>
            ) : signedIn ? (
              <Offer token={token} />
            ) : (
              <div className="flex flex-col gap-4">
                <p className="text-sm text-muted-foreground">{t.invite.signInFirst}</p>
                <Link to="/sign-in" className={cn(buttonVariants(), "self-start")}>
                  {t.invite.signIn}
                </Link>
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}

function Offer({ token }: { token: string }) {
  const t = useT();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  const preview = useQuery({
    queryKey: ["invitation-preview", token],
    queryFn: () =>
      api.post<InvitationPreview>("/api/v1/invitations/preview", { token }).then((r) => r.data),
    retry: false,
  });

  // A link that can no longer be used is not worth holding for the next sign-in.
  const spent = Boolean(preview.error) || (preview.data && preview.data.status !== "OPEN");
  useEffect(() => {
    if (spent) forgetInvite();
  }, [spent]);

  const accept = useMutation({
    mutationFn: () =>
      api.post<Organization>("/api/v1/invitations/accept", { token }).then((r) => r.data),
    onSuccess: (organization) => {
      forgetInvite();
      // Land in the organization just joined, not whichever came first.
      auth.organizationId = organization.id;
      queryClient.clear();
      navigate("/", { replace: true });
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : t.invite.failed),
  });

  function signOut() {
    // The token stays held, so signing in as the right address comes back here.
    auth.signOut();
    queryClient.clear();
    void supabaseSignOut();
    navigate("/sign-in", { replace: true });
  }

  if (preview.isLoading) {
    return (
      <p className="flex items-center gap-2 text-sm text-muted-foreground">
        <Spinner /> {t.invite.loading}
      </p>
    );
  }

  if (preview.error || !preview.data) return <Refusal message={t.invite.invalid} />;

  const offer = preview.data;
  if (offer.status !== "OPEN") return <Refusal message={t.invite.status[offer.status]} />;

  const role = t.team.roles[offer.role];
  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-foreground">{t.invite.offer(offer.organization_name, role)}</p>
      <p className="text-sm text-muted-foreground">{t.invite.forEmail(offer.email)}</p>

      {!offer.email_matches ? (
        <>
          <Alert>
            <AlertDescription>{t.invite.wrongAccount(offer.email)}</AlertDescription>
          </Alert>
          <Button variant="outline" className="self-start" onClick={signOut}>
            {t.invite.signOut}
          </Button>
        </>
      ) : (
        <>
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
          <Button
            className="self-start"
            disabled={accept.isPending}
            onClick={() => accept.mutate()}
          >
            {accept.isPending ? t.invite.accepting : t.invite.accept}
          </Button>
        </>
      )}
    </div>
  );
}

function Refusal({ message }: { message: string }) {
  const t = useT();
  return (
    <div className="flex flex-col gap-4">
      <p className="text-sm text-muted-foreground">{message}</p>
      <Link to="/" className={cn(buttonVariants({ variant: "outline" }), "self-start")}>
        {t.invite.home}
      </Link>
    </div>
  );
}
