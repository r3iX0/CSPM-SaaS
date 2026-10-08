import { useT } from "@/i18n";
import { formatDate } from "@/lib/format";
import type { AuditPackageDetail } from "@/lib/types";
import { StatusBar, StatusLegend } from "@/components/compliance";
import { CopyButton } from "@/components/common/CopyButton";
import { InfoTip } from "@/components/common/InfoTip";

/**
 * One sealed package as it is read: when, from which scan, how each standard's
 * controls came out, what they rest on, and the hash that seals it
 * (DECISIONS.md §208).
 *
 * The same body for the owner who sealed it and the auditor who was given it,
 * since the two must see one thing. It draws counts and never controls: the
 * controls are hundreds of rows, and they are in the archive (§208). A scan
 * that completed with gaps is said beside the date, because an assessment with
 * a hole in it is the one a reader most needs to know about.
 */
export function PackageSummary({ detail }: { detail: AuditPackageDetail }) {
  const t = useT();
  const names = new Map(detail.frameworks.map((framework) => [framework.id, framework.name]));
  const { evidence } = detail;

  return (
    <div className="flex flex-col gap-4">
      <p className="text-meta text-muted-foreground">
        {t.auditPackages.sealedOn(formatDate(detail.sealed_at))}
        {" · "}
        {t.auditPackages.fromScan(formatDate(detail.scan_completed_at))}
        {detail.scan_status === "PARTIAL" && (
          <span className="font-medium text-unknown"> · {t.auditPackages.scanGaps}</span>
        )}
        {detail.period_start && detail.period_end && (
          <>
            {" · "}
            {t.auditPackages.period(formatDate(detail.period_start), formatDate(detail.period_end))}
          </>
        )}
      </p>

      <ul className="flex flex-col gap-4">
        {detail.assessment.map((assessment) => (
          <li key={assessment.framework_id} className="flex flex-col gap-1.5">
            <p className="flex flex-wrap items-baseline justify-between gap-x-3">
              <span className="text-body font-medium text-foreground">
                {names.get(assessment.framework_id) ?? assessment.framework_id}
              </span>
              <span className="text-meta text-muted-foreground">
                {t.auditPackages.controls(assessment.controls)}
              </span>
            </p>
            <StatusBar counts={assessment.statuses} total={assessment.controls} />
            <StatusLegend counts={assessment.statuses} />
          </li>
        ))}
      </ul>

      <p className="text-meta text-muted-foreground">
        {t.auditor.readings(evidence.readings)}
        {" · "}
        {t.auditPackages.evidence(evidence.payloads_stored, evidence.payloads_named)}
      </p>

      <div className="flex flex-col gap-1.5">
        <p className="flex items-center gap-1 text-meta font-medium text-foreground">
          {t.auditPackages.sealHash}
          <InfoTip label={t.auditPackages.sealHash} contentClassName="w-80">
            {t.auditPackages.sealExplain}
          </InfoTip>
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <code className="min-w-0 break-all rounded bg-muted px-2 py-1 font-mono text-meta">
            {detail.manifest_sha256}
          </code>
          <CopyButton
            text={detail.manifest_sha256}
            label={t.auditPackages.sealHash}
            variant="outline"
          />
        </div>
      </div>
    </div>
  );
}
