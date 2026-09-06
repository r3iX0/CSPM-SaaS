import { Link } from "react-router-dom";

import { useT } from "@/i18n";
import { cn } from "@/lib/format";

/**
 * The four numbers this page is answerable for.
 *
 * Two of them are about the estate rather than about the board, deliberately:
 * a queue reporting only on its own cards can be empty and serene over an
 * environment with eleven open risks in it. "Still open" is what has not been
 * fixed; "came back" is what was fixed and did not stay fixed, which is the
 * one number a remediation page must never quietly net off against its fixes.
 */
export function RemediationTiles({
  verified,
  open,
  inProgress,
  cameBack,
}: {
  verified: number | null;
  open: number | null;
  inProgress: number;
  cameBack: number | null;
}) {
  const t = useT();

  return (
    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <Tile
        label={t.remediation.tileVerified}
        value={verified}
        detail={t.remediation.tileVerifiedDetail}
        tone="text-ok"
        to="/findings?status=RESOLVED"
      />
      <Tile
        label={t.remediation.tileOpen}
        value={open}
        detail={t.remediation.tileOpenDetail}
        tone="text-foreground"
        to="/risks"
      />
      <Tile
        label={t.remediation.tileInProgress}
        value={inProgress}
        detail={t.remediation.tileInProgressDetail}
        tone="text-foreground"
      />
      <Tile
        label={t.remediation.tileCameBack}
        value={cameBack}
        detail={t.remediation.tileCameBackDetail}
        tone={cameBack ? "text-critical" : "text-foreground"}
        to="/changes"
      />
    </div>
  );
}

function Tile({
  label,
  value,
  detail,
  tone,
  to,
}: {
  label: string;
  /** `null` while the number is unknown — never rendered as a zero. */
  value: number | null;
  detail: string;
  tone: string;
  to?: string;
}) {
  const body = (
    <>
      <p className="text-[11px] font-medium uppercase tracking-[0.12em] text-meta-foreground">
        {label}
      </p>
      <p className={cn("mt-2 font-mono text-3xl font-semibold leading-none", tone)}>
        {value ?? "—"}
      </p>
      <p className="mt-2 text-xs text-meta-foreground">{detail}</p>
    </>
  );

  if (!to) {
    return <div className="rounded-xl border bg-card px-4 py-3.5">{body}</div>;
  }

  return (
    <Link
      to={to}
      className="rounded-xl border bg-card px-4 py-3.5 transition-colors hover:bg-accent/40 focus-visible:outline-none focus-visible:ring-[3px] focus-visible:ring-ring/50"
    >
      {body}
    </Link>
  );
}
