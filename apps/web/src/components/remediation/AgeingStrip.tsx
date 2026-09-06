import { useT } from "@/i18n";

const WEEK_MS = 7 * 24 * 60 * 60 * 1000;

type Bucket = { key: string; label: string; tone: string; count: number };

/**
 * How long the open work has sat, since the problem was first raised.
 *
 * The one thing about this queue the four tiles above do not already say. A
 * board says what is where; it cannot say that everything on it has been there
 * a month, which is the difference between a team working through a queue and
 * a team that has stopped.
 *
 * Measured from when CloudGuard first raised the finding rather than from when
 * somebody added it to the board: the age a customer is exposed for starts at
 * the problem, not at the paperwork.
 */
export function AgeingStrip({ raisedAt }: { raisedAt: (number | null)[] }) {
  const t = useT();
  const known = raisedAt.filter((at): at is number => at !== null);

  if (known.length === 0) return null;

  const now = Date.now();
  const ages = known.map((at) => now - at);

  const buckets: Bucket[] = [
    {
      key: "week",
      label: t.remediation.underAWeek,
      tone: "var(--sev-medium)",
      count: ages.filter((age) => age < WEEK_MS).length,
    },
    {
      key: "month",
      label: t.remediation.oneToFourWeeks,
      tone: "var(--sev-high)",
      count: ages.filter((age) => age >= WEEK_MS && age < 4 * WEEK_MS).length,
    },
    {
      key: "older",
      label: t.remediation.overAMonth,
      tone: "var(--sev-critical)",
      count: ages.filter((age) => age >= 4 * WEEK_MS).length,
    },
  ];

  const oldestDays = Math.floor(Math.max(...ages) / (24 * 60 * 60 * 1000));

  return (
    <section
      aria-label={t.remediation.ageingTitle}
      className="flex flex-wrap items-center gap-x-8 gap-y-4 rounded-xl border bg-card px-5 py-4"
    >
      <div className="min-w-0">
        <h2 className="text-[13px] font-semibold text-foreground">
          {t.remediation.ageingTitle}
        </h2>
        <p className="text-xs text-meta-foreground">
          {t.remediation.ageingSince}
        </p>
      </div>

      <div className="flex min-w-[220px] flex-1 flex-col gap-2">
        <div
          className="flex h-2 overflow-hidden rounded-full bg-muted"
          role="img"
          aria-label={buckets
            .map((bucket) => `${bucket.count} ${bucket.label}`)
            .join(", ")}
        >
          {buckets.map(
            (bucket) =>
              bucket.count > 0 && (
                <span
                  key={bucket.key}
                  style={{
                    width: `${(bucket.count / known.length) * 100}%`,
                    background: bucket.tone,
                  }}
                />
              ),
          )}
        </div>

        <ul className="flex flex-wrap gap-x-5 gap-y-1 text-xs">
          {buckets.map((bucket) => (
            <li key={bucket.key} className="flex items-center gap-1.5">
              <span
                className="size-1.5 rounded-full"
                style={{ background: bucket.count > 0 ? bucket.tone : undefined }}
                aria-hidden
              />
              <span
                className={
                  bucket.count > 0 ? "text-foreground" : "text-meta-foreground"
                }
              >
                {bucket.label}
              </span>
              <span className="font-mono text-meta-foreground">{bucket.count}</span>
            </li>
          ))}
        </ul>
      </div>

      <div className="shrink-0 text-right">
        <p className="font-mono text-2xl font-semibold leading-none text-foreground">
          {oldestDays}d
        </p>
        <p className="mt-1 text-[10px] uppercase tracking-[0.12em] text-meta-foreground">
          {t.remediation.oldestOpen}
        </p>
      </div>
    </section>
  );
}
