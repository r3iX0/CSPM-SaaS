import { ExternalLinkIcon } from "lucide-react";

import { CodeBlock } from "@/components/common/CodeBlock";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ENGINE_AUDIT_ICON } from "@/lib/icons";
import type { ProwlerDetail, RuleEngine } from "@/lib/types";

/**
 * Whose verdict this is (DECISIONS.md §150).
 *
 * Cleave runs two engines. Its own rules read what its collectors stored and
 * carry the graph; Prowler's checks, run by the scanner service, carry the
 * breadth. The first thing to know about a disputed finding is which one
 * reached it, so a Prowler rule says so wherever its name appears. A native
 * rule says nothing: it is the default, and a badge on every row would be
 * noise.
 */
export function EngineBadge({
  engine,
  version,
}: {
  engine?: RuleEngine | null;
  version?: string | null;
}) {
  if (engine !== "prowler") return null;
  return (
    <Badge variant="outline" className="gap-1 font-normal">
      Extended check
      <span className="text-muted-foreground">· Prowler{version ? ` ${version}` : ""}</span>
    </Badge>
  );
}

/** Prowler's templates arrive fenced as Markdown; a code block wants the code. */
function unfence(text: string): string {
  return text
    .replace(/^```[a-zA-Z0-9]*\n?/, "")
    .replace(/\n?```\s*$/, "")
    .trim();
}

function hostname(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

/**
 * What the second engine has to say about one rule.
 *
 * For a Prowler check: the check, the release, and Prowler's own fix in each
 * form it publishes -- command, Terraform, native template, console steps --
 * beside the prose Cleave copies onto each finding. For a native rule Prowler
 * cross-checks: which checks, and why the two may disagree by design.
 */
export function ProwlerPanel({ detail }: { detail?: ProwlerDetail | null }) {
  if (!detail) return null;

  if (detail.cross_checked_by?.length) {
    return (
      <div className="flex flex-col gap-1.5">
        <p className="flex items-center gap-1.5 text-xs font-medium text-muted-foreground">
          <ENGINE_AUDIT_ICON className="size-3.5" aria-hidden />
          Cross-checked by the extended checks
        </p>
        <p className="text-sm leading-relaxed text-foreground">
          Every scan compares this rule's verdict with{" "}
          {detail.cross_checked_by.map((check, i) => (
            <span key={check}>
              {i > 0 && ", "}
              <code className="font-mono text-[12px]">{check}</code>
            </span>
          ))}{" "}
          on the same assets. Where they disagree, the engine audit lists it.
        </p>
        {detail.divergence_note && (
          <p className="text-xs leading-relaxed text-muted-foreground">
            Expected to differ: {detail.divergence_note}
          </p>
        )}
      </div>
    );
  }

  if (!detail.check_id) return null;
  const remediation = detail.remediation;
  const forms = [
    { id: "cli", label: "Command", code: remediation?.cli },
    { id: "terraform", label: "Terraform", code: remediation?.terraform },
    { id: "native", label: "Template", code: remediation?.native_iac },
  ].filter((form) => form.code && form.code.trim());
  const links = [remediation?.url, ...(detail.additional_urls ?? [])]
    .filter((url): url is string => Boolean(url))
    .slice(0, 4);

  return (
    <div className="flex flex-col gap-2">
      <p className="text-xs font-medium text-muted-foreground">
        Prowler check <code className="font-mono text-[12px]">{detail.check_id}</code>
        {detail.prowler_version && ` · release ${detail.prowler_version}`}
      </p>
      {forms.length > 0 && (
        <Tabs defaultValue={forms[0].id}>
          <TabsList>
            {forms.map((form) => (
              <TabsTrigger key={form.id} value={form.id}>
                {form.label}
              </TabsTrigger>
            ))}
          </TabsList>
          {forms.map((form) => (
            <TabsContent key={form.id} value={form.id} className="flex flex-col gap-2">
              <CodeBlock code={unfence(form.code ?? "")} />
            </TabsContent>
          ))}
        </Tabs>
      )}
      {remediation?.other && (
        <p className="whitespace-pre-line text-xs leading-relaxed text-muted-foreground">
          {remediation.other}
        </p>
      )}
      {forms.length > 0 && (
        <p className="text-xs text-muted-foreground">
          Placeholders in angle brackets are Prowler's; fill them with the names from this
          finding.
        </p>
      )}
      {links.length > 0 && (
        <ul className="flex flex-wrap gap-x-4 gap-y-1 text-xs">
          {links.map((url) => (
            <li key={url}>
              <a
                href={url}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1 text-primary hover:underline"
              >
                {hostname(url)}
                <ExternalLinkIcon className="size-3" aria-hidden />
              </a>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
