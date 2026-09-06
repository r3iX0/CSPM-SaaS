import { Link } from "react-router-dom";
import { XIcon } from "lucide-react";

import type { Rule } from "@/lib/types";
import { useT } from "@/i18n";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { RemediationPanel } from "@/components/security/RemediationPanel";
import { Button, buttonVariants } from "@/components/ui/button";
import { formatEffort, resourceTypeLabel } from "@/lib/format";

/**
 * One rule, read beside the catalogue.
 *
 * Everything the cards used to unfold in place: why the check exists, what it
 * costs to fix, what it applies to, and which controls it evidences. Shown for
 * one rule rather than for ninety, which is what made the list a document.
 *
 * A rule is not a finding and this panel takes care not to read like one: it
 * describes a check CloudGuard runs against every estate, so the only link out
 * is to the findings this rule has actually raised here.
 */
export function RuleDetail({
  rule,
  onClose,
}: {
  rule: Rule;
  onClose?: () => void;
}) {
  const t = useT();

  return (
    <div className="flex flex-col gap-5">
      <div className="flex items-start gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge level={rule.severity} size="sm" />
            <code className="font-mono text-[11px] text-meta-foreground">
              {rule.rule_id}
            </code>
            <span className="font-mono text-[11px] text-meta-foreground">
              v{rule.version}
            </span>
          </div>
          <h2 className="mt-2 text-base font-semibold leading-snug text-foreground">
            {rule.name}
          </h2>
        </div>
        {onClose && (
          <Button
            variant="ghost"
            size="icon-sm"
            onClick={onClose}
            aria-label="Close this rule"
          >
            <XIcon />
          </Button>
        )}
      </div>

      {/* Dashed and stated, not greyed away. A rule that has stopped running
          is not a quieter rule — its severity describes what it used to
          check, and findings it raised are still on the estate. */}
      {!rule.enabled && (
        <p className="rounded-lg border border-dashed border-unknown-border bg-unknown-bg px-3 py-2 text-xs leading-relaxed text-foreground">
          {t.rules.withdrawnHelp}
        </p>
      )}

      <Section label={t.rules.whatItChecks}>
        <p className="text-[13px] leading-relaxed text-muted-foreground">
          {rule.description}
        </p>
      </Section>

      {rule.rationale && (
        <Section label={t.rules.why}>
          <p className="text-[13px] leading-relaxed text-muted-foreground">
            {rule.rationale}
          </p>
        </Section>
      )}

      <Section label={t.rules.whatItRunsOn}>
        <dl className="flex flex-col gap-1.5 text-xs">
          <Line
            label={t.rules.appliesToColumn}
            value={
              rule.applies_to.length > 0
                ? rule.applies_to.map(resourceTypeLabel).join(", ")
                : t.rules.appliesToDirectory
            }
          />
          <Line
            label={t.rules.effortColumn}
            value={formatEffort(rule.estimated_effort_minutes)}
          />
          <Line
            label={t.rules.exploitability}
            value={`${rule.exploitability}/5`}
          />
        </dl>
      </Section>

      {Object.keys(rule.compliance_mappings).length > 0 && (
        <Section label={t.rules.evidenceToward}>
          <ul className="flex flex-col gap-1.5 text-xs">
            {Object.entries(rule.compliance_mappings).map(
              ([framework, controls]) => (
                <li key={framework} className="flex justify-between gap-3">
                  <span className="min-w-0 truncate text-muted-foreground">
                    {framework.replace(/_/g, " ")}
                  </span>
                  <span className="shrink-0 font-mono text-foreground">
                    {controls.join(", ")}
                  </span>
                </li>
              ),
            )}
          </ul>
        </Section>
      )}

      <RemediationPanel
        remediation={rule.remediation}
        spec={rule.remediation_spec}
        effortMinutes={rule.estimated_effort_minutes}
      />

      <Link
        to={`/findings?rule_id=${encodeURIComponent(rule.rule_id)}&status=all`}
        className={buttonVariants({ variant: "outline", size: "sm" })}
      >
        {t.rules.seeFindings}
      </Link>
    </div>
  );
}

function Section({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <section>
      <h3 className="text-[11px] font-medium uppercase tracking-[0.12em] text-meta-foreground">
        {label}
      </h3>
      <div className="mt-2">{children}</div>
    </section>
  );
}

function Line({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-3">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="font-mono font-medium text-foreground">{value}</dd>
    </div>
  );
}
