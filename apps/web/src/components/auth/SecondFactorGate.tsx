import { useEffect, useState, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { auth, SECOND_FACTOR_REQUIRED_EVENT } from "@/lib/api";
import {
  confirmSecondFactor,
  listSecondFactors,
  SECOND_FACTORS_KEY,
  secondFactorNeeded,
  supabaseSignOut,
} from "@/lib/supabase";
import { useSessionClaims } from "@/lib/useAuth";
import { useT } from "@/i18n";
import { Wordmark } from "@/components/Brand";
import { CODE_LENGTH, CodeField } from "@/components/auth/CodeField";
import { PAGE_TITLE_CLASS } from "@/components/common/states";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";

/**
 * Asks for a code from an authenticator app before anything else is shown,
 * when the session owes one (DECISIONS.md §213).
 *
 * A session owes one when its user has confirmed an authenticator app and it
 * was opened with one factor. That is decided once per Supabase session, from
 * the session this browser holds; the API refusing a request with
 * `MFA_REQUIRED` asks too, which covers an app added on another device since.
 * The API is what enforces it either way: this only decides when to ask.
 */
export function SecondFactorGate({ children }: { children: ReactNode }) {
  const { subject, sessionId, secondFactor } = useSessionClaims();
  const session = sessionId ?? subject;
  const [refusedFor, setRefusedFor] = useState<string | null>(null);

  useEffect(() => {
    const refuse = () => setRefusedFor(session);
    window.addEventListener(SECOND_FACTOR_REQUIRED_EVENT, refuse);
    return () => window.removeEventListener(SECOND_FACTOR_REQUIRED_EVENT, refuse);
  }, [session]);

  const owed = session !== null && !secondFactor;
  const needed = useQuery({
    queryKey: ["second-factor-needed", session],
    queryFn: secondFactorNeeded,
    enabled: owed,
    staleTime: Infinity,
  });

  if (!owed) return children;
  if (refusedFor === session || needed.data === true) return <SecondFactorPrompt />;
  if (needed.isPending) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Spinner />
      </div>
    );
  }
  // Not owed, or the check itself failed: the API still refuses a session
  // that skipped a factor, and that refusal brings the reader back here.
  return children;
}

function SecondFactorPrompt() {
  const t = useT();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [code, setCode] = useState("");
  const factors = useQuery({ queryKey: SECOND_FACTORS_KEY, queryFn: listSecondFactors });
  const factor = factors.data?.[0];

  const verify = useMutation({
    mutationFn: (factorId: string) => confirmSecondFactor(factorId, code),
    // The session is two-factor now and the gate lets the page through; what
    // the API refused before is asked again.
    onSuccess: () => void queryClient.invalidateQueries(),
    onError: () => setCode(""),
  });

  function submit(event: React.FormEvent) {
    event.preventDefault();
    if (!factor || verify.isPending || code.length !== CODE_LENGTH) return;
    verify.mutate(factor.id);
  }

  function signOut() {
    auth.signOut();
    queryClient.clear();
    void supabaseSignOut();
    void navigate("/sign-in", { replace: true });
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-background px-6 py-12">
      <div className="w-full max-w-[360px]">
        <Wordmark className="mb-10 gap-2.5" />
        <h1 className={PAGE_TITLE_CLASS}>{t.secondFactor.promptTitle}</h1>
        <p className="mt-2 text-body leading-[1.65] text-muted-foreground">
          {t.secondFactor.promptIntro}
        </p>

        {factors.isPending ? (
          <div className="mt-7 flex justify-center">
            <Spinner />
          </div>
        ) : factor ? (
          <form onSubmit={submit} className="mt-7 flex flex-col gap-4">
            <CodeField
              id="second-factor-code"
              label={t.secondFactor.codeLabel}
              value={code}
              onChange={setCode}
              // eslint-disable-next-line jsx-a11y/no-autofocus -- the code is this page's one question.
              autoFocus
            />
            {verify.error && (
              <p
                role="alert"
                className="rounded-lg border border-critical-border bg-critical-bg px-3 py-2 text-body text-critical"
              >
                {t.secondFactor.wrongCode}
              </p>
            )}
            <Button type="submit" disabled={verify.isPending} className="h-10 w-full">
              {verify.isPending ? t.secondFactor.verifying : t.secondFactor.verify}
            </Button>
          </form>
        ) : (
          <p role="alert" className="mt-7 text-body text-muted-foreground">
            {factors.error ? t.secondFactor.failed : t.secondFactor.noFactor}
          </p>
        )}

        <p className="mt-6 border-t border-border pt-5 text-caption leading-[1.7] text-muted-foreground">
          {t.secondFactor.lostDevice}
        </p>
        <button
          type="button"
          onClick={signOut}
          className="mt-3 rounded-sm text-body text-muted-foreground underline underline-offset-[3px] transition-colors hover:text-foreground focus-ring"
        >
          {t.secondFactor.signOut}
        </button>
      </div>
    </main>
  );
}
