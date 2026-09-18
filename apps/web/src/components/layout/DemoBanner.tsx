import { Link, useNavigate } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";

import { auth } from "@/lib/api";
import { useT } from "@/i18n";
import { DEMO_ICON } from "@/lib/icons";
import { useCurrentOrganization, useLeaveDemo, useOrganizations } from "@/lib/useDemo";
import { Button, buttonVariants } from "@/components/ui/button";
import { cn } from "@/lib/format";

/**
 * Said on every page while the reader is in the demo, never only once.
 *
 * Everything in the demo looks like a real estate on purpose -- that is what
 * makes it worth exploring -- which is exactly why it must never be mistaken
 * for one. A finding about "Production Subscription (demo)" read out of
 * context, or a screenshot sent to a colleague, has to carry the fact that it
 * is a recording. The way out is on the same line: to the reader's own
 * organization if they have one, to creating one if they do not.
 */
export function DemoBanner() {
  const t = useT();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const current = useCurrentOrganization();
  const { data } = useOrganizations();
  const leave = useLeaveDemo();

  if (!current?.is_demo) return null;
  const own = (Array.isArray(data) ? data : []).find((org) => !org.is_demo);

  return (
    <div
      role="status"
      className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-medium-border bg-medium-bg px-4 py-2.5 sm:px-6"
    >
      <DEMO_ICON className="size-4 shrink-0 text-medium" aria-hidden />
      <p className="min-w-0 flex-1 text-sm">
        <span className="font-medium text-foreground">{t.demo.bannerTitle}.</span>{" "}
        <span className="text-muted-foreground">{t.demo.bannerDetail}</span>
      </p>
      <div className="flex shrink-0 items-center gap-2">
        <Button
          variant="ghost"
          size="sm"
          onClick={() => leave.mutate()}
          disabled={leave.isPending}
          className="text-muted-foreground"
        >
          {t.demo.leave}
        </Button>
        {own ? (
          <Button
            size="sm"
            onClick={() => {
              // eslint-disable-next-line react-hooks/immutability
              auth.organizationId = own.id;
              queryClient.clear();
              navigate("/", { replace: true });
            }}
          >
            {t.demo.backTo.replace("{name}", own.name)}
          </Button>
        ) : (
          <Link to="/onboarding" className={cn(buttonVariants({ size: "sm" }))}>
            {t.demo.createOwn}
          </Link>
        )}
      </div>
    </div>
  );
}
