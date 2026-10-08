import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";

import { auth } from "@/lib/api";
import { signInAsGuest } from "@/lib/supabase";
import { useJoinDemo } from "@/lib/useDemo";
import { useT } from "@/i18n";
import { Wordmark } from "@/components/Brand";
import { Button, buttonVariants } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
import { PAGE_TITLE_CLASS } from "@/components/common/states";
import { cn } from "@/lib/format";

/**
 * The demo, one click from anywhere: the marketing site links here.
 *
 * Somebody without a session becomes a guest -- Supabase's anonymous sign-in --
 * and joins the shared demo as a VIEWER, the same membership a signed-in user
 * gets from onboarding. Nobody makes an account or an organization to look
 * around, and the API keeps a guest in the demo whatever they try
 * (DECISIONS.md §219). Somebody already signed in just joins it.
 */
export function DemoPage() {
  const t = useT();
  const join = useJoinDemo();
  const [failed, setFailed] = useState(false);
  // StrictMode mounts twice in development; one visitor is one guest.
  const started = useRef(false);

  async function open() {
    setFailed(false);
    try {
      if (!auth.token) await signInAsGuest();
      await join.mutateAsync();
    } catch {
      setFailed(true);
    }
  }

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    void open();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- once per visit; `open` is recreated every render and must not re-run it.
  }, []);

  return (
    <div className="flex min-h-screen items-center justify-center bg-background px-6">
      <main className="w-full max-w-sm">
        <Wordmark />
        {failed ? (
          <div className="mt-10">
            <h1 className={PAGE_TITLE_CLASS}>{t.demo.unavailable}</h1>
            <p className="mt-2 text-body leading-relaxed text-muted-foreground">
              {t.demo.unavailableDetail}
            </p>
            <div className="mt-6 flex gap-3">
              <Button onClick={() => void open()}>{t.common.retry}</Button>
              <Link to="/sign-in" className={cn(buttonVariants({ variant: "outline" }))}>
                {t.auth.signIn}
              </Link>
            </div>
          </div>
        ) : (
          <div className="mt-10 flex items-center gap-3" role="status">
            <Spinner aria-hidden="true" role="presentation" />
            <p className="text-body text-muted-foreground">{t.demo.opening}</p>
          </div>
        )}
      </main>
    </div>
  );
}
