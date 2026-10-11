import { useId, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { ChevronDownIcon, WrenchIcon } from "lucide-react";

import { useT } from "@/i18n";
import { cn } from "@/lib/format";
import { useTrack } from "@/lib/remediation";
import { CodeBlock } from "@/components/common/CodeBlock";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cutFixQuery, type CutLink } from "@/components/graph/graphQueries";

/**
 * "How to fix", behind a disclosure, wherever a cut is shown (§246).
 *
 * A cut used to stop at "what if": simulated, never said how to make. Opened,
 * this says the change in one sentence, gives the provider's commands where one
 * command removes the link exactly, and lists the open findings on the link's
 * two ends, each a fix somebody can track. Asked for only when opened.
 */
export function HowToFix({ link, className }: { link: CutLink; className?: string }) {
  const t = useT();
  const [open, setOpen] = useState(false);
  const panel = useId();

  return (
    <div className={cn("flex flex-col gap-2", className)}>
      <Button
        variant="ghost"
        size="sm"
        className="self-start"
        aria-expanded={open}
        aria-controls={panel}
        onClick={() => setOpen((was) => !was)}
      >
        <WrenchIcon data-icon="inline-start" />
        {t.attackPaths.fixToggle}
        <ChevronDownIcon
          data-icon="inline-end"
          className={cn("transition-transform", open && "rotate-180")}
        />
      </Button>
      <div id={panel} hidden={!open}>
        {open && <CutFixBody link={link} />}
      </div>
    </div>
  );
}

function CutFixBody({ link }: { link: CutLink }) {
  const t = useT();
  const fix = useQuery(cutFixQuery(link));
  const track = useTrack();

  if (fix.isPending) return <Skeleton className="h-20 w-full" />;
  if (fix.isError) {
    return <p className="text-meta text-muted-foreground">{t.attackPaths.fixError}</p>;
  }

  const { sentence, commands, findings, code } = fix.data;
  return (
    <div className="flex flex-col gap-3 rounded-lg bg-muted/40 p-3">
      <p className="text-body font-medium">{sentence}</p>
      {commands.length > 0 ? (
        <CodeBlock code={commands.join("\n")} label={t.attackPaths.fixCopy} />
      ) : (
        <p className="text-meta text-muted-foreground">{t.attackPaths.fixNoCommand}</p>
      )}
      {code.length > 0 && (
        <div className="flex flex-col gap-1">
          <h4 className="text-caption font-medium text-muted-foreground">
            {t.attackPaths.fixInCode}
          </h4>
          {code.map((home) => (
            <p key={`${home.repository}|${home.address}`} className="font-mono text-meta break-all">
              {home.repository}
              {home.working_directory ? `/${home.working_directory}` : ""} · {home.address}
            </p>
          ))}
          <p className="text-meta text-muted-foreground">{t.attackPaths.fixInCodeNote}</p>
        </div>
      )}
      <div className="flex flex-col gap-1.5">
        <h4 className="text-caption font-medium text-muted-foreground">
          {t.attackPaths.fixFindingsTitle}
        </h4>
        {findings.length === 0 ? (
          <p className="text-meta text-muted-foreground">{t.attackPaths.fixNoFindings}</p>
        ) : (
          <ul className="flex flex-col gap-1.5">
            {findings.map((finding) => {
              const tracked =
                finding.tracked || (track.isSuccess && track.variables === finding.id);
              return (
                <li key={finding.id} className="flex flex-wrap items-center gap-2">
                  <SeverityBadge level={finding.severity} size="sm" />
                  <Link
                    to={`/remediation?fix=${finding.id}`}
                    className="focus-ring min-w-0 flex-1 truncate text-meta underline-offset-4 hover:underline"
                  >
                    {finding.title}
                    {/* Most titles already name their asset. */}
                    {!finding.title.includes(finding.asset_name) && (
                      <span className="text-muted-foreground"> · {finding.asset_name}</span>
                    )}
                  </Link>
                  {tracked ? (
                    <span className="text-caption text-muted-foreground">
                      {t.attackPaths.fixTracked}
                    </span>
                  ) : (
                    <Button
                      variant="outline"
                      size="xs"
                      aria-disabled={track.isPending || undefined}
                      onClick={() => {
                        if (!track.isPending) track.mutate(finding.id);
                      }}
                    >
                      {t.attackPaths.fixTrack}
                    </Button>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </div>
    </div>
  );
}
