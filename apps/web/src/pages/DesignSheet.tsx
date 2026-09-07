import { useState } from "react";

import { PageHeader } from "@/components/common/states";
import { HelpPopover } from "@/components/common/HelpPopover";
import { SeverityBadge } from "@/components/security/SeverityBadge";
import { StatusPill } from "@/components/security/StatusPill";
import { RiskScore } from "@/components/security/SecurityScore";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { EmptyState } from "@/components/common/states";
import { ShieldCheckIcon } from "lucide-react";
import type { Level } from "@/lib/types";

const LEVELS: Level[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

/**
 * Every element in every state, on one page.
 *
 * `docs/UI_REDESIGN.md` §7 listed the absence of this as a known gap: buttons,
 * chips, table rows, empty states and the severity swatches were "defined only
 * by example inside the six previews", which means the definitive answer to
 * "what does a MEDIUM chip look like on a card" was a 1440px PNG.
 *
 * Rendered from the real components rather than drawn, so it cannot describe a
 * product that no longer exists — the failure mode of every style guide kept as
 * a document. If a chip changes, this page changes with it.
 *
 * **Never shipped.** It is mounted only under `import.meta.env.DEV`, so the
 * route does not exist in a production build and the bundle does not carry it.
 * A customer has no use for CloudGuard's own swatches, and a page enumerating
 * every state of every control is a page enumerating everything the product
 * can say.
 */
export function DesignSheetPage() {
  const [selected, setSelected] = useState("b");

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title="Component sheet"
        description="Rendered from the components themselves. Development only — this route does not exist in a production build."
      />

      <Section
        label="Severity"
        note="Its own layer, deliberately: these are what a colour means to somebody reading a security finding, and they do not move when the chrome is re-themed. UNKNOWN carries a dashed border so it stays distinguishable without colour."
      >
        <div className="flex flex-wrap items-center gap-2">
          {LEVELS.map((level) => (
            <SeverityBadge key={level} level={level} />
          ))}
        </div>
        <div className="mt-3 flex flex-wrap items-center gap-2">
          {LEVELS.map((level) => (
            <SeverityBadge key={level} level={level} size="sm" />
          ))}
        </div>

        {/* On both surfaces, because a tint that works on the page can glow on
            a card and a badge that glows reads as more urgent than the one
            beside it — a ranking the rules never made. */}
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <Swatches surface="bg-background" label="on the page" />
          <Swatches surface="bg-card" label="on a card" />
        </div>
      </Section>

      <Section
        label="Status"
        note="A finding's standing, which is not a severity. Both appear in one row and must not be read as one scale."
      >
        <div className="flex flex-wrap items-center gap-2">
          {["OPEN", "IN_PROGRESS", "RESOLVED", "ACCEPTED_RISK", "FALSE_POSITIVE"].map(
            (status) => (
              <StatusPill key={status} status={status} />
            ),
          )}
          {/* The dashed pair the findings table uses for a check that reached
              no verdict. Not a status the API returns: the absence of one. */}
          <span className="inline-flex items-center rounded-md border border-dashed border-unknown-border bg-unknown-bg px-2 py-0.5 text-xs text-unknown">
            Unevaluated
          </span>
        </div>
      </Section>

      <Section
        label="Text"
        note="`--meta-foreground` and `--faint-foreground` measure 4.11:1 and 3.20:1 on the card. Neither may carry body copy; they are for the 11-12.5px meta register only (DECISIONS.md §84)."
      >
        <div className="flex flex-col gap-1.5">
          <p className="text-[28px] font-bold leading-tight tracking-[-0.028em]">
            Page title, 28/700 at -0.028em
          </p>
          <p className="text-sm font-semibold">Panel title, 14/600</p>
          <p className="text-[11px] font-medium uppercase tracking-[0.12em] text-meta-foreground">
            Section label, 11/500 at 0.12em
          </p>
          <p className="text-[13px]">Body, 13.5 — the sentence a reader reads.</p>
          <p className="text-[13px] text-muted-foreground">
            Secondary body, on `--muted-foreground`.
          </p>
          <p className="text-xs text-meta-foreground">
            Meta, 12 — the dim line under a value.
          </p>
          <p className="text-xs text-faint-foreground">
            Faint, 12 — placeholder, footnote, &ldquo;nothing here&rdquo;.
          </p>
          <p className="font-mono text-[13px]">
            Mono and tabular: 0123456789 · sacspmtstne01 · storage.public_access
          </p>
        </div>
      </Section>

      <Section
        label="Buttons"
        note="`destructive` means this button deletes something. It is not `critical`, which means an attacker can reach your data."
      >
        <div className="flex flex-wrap items-center gap-2">
          <Button>Primary</Button>
          <Button variant="secondary">Secondary</Button>
          <Button variant="outline">Outline</Button>
          <Button variant="ghost">Ghost</Button>
          <Button variant="destructive">Destructive</Button>
          <Button disabled>Disabled</Button>
          <HelpPopover label="An example popover">
            The reasoning a panel used to print under its own heading, one click
            away instead (DECISIONS.md §87).
          </HelpPopover>
        </div>
      </Section>

      <Section
        label="Table rows"
        note="One line each, clipped. Selection is a rail and a wash, never a full border: a ring around one row in a dense table reads as a second grid."
      >
        <Card className="overflow-hidden py-0">
          <CardContent className="px-0">
            <Table className="min-w-[560px]">
              <TableHeader>
                <TableRow>
                  <TableHead>Risk</TableHead>
                  <TableHead className="w-[150px]">Exposure</TableHead>
                  <TableHead className="w-[56px] text-right">Score</TableHead>
                  <TableHead className="w-[84px]">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                <Row
                  id="a"
                  title="Storage account allows public access"
                  subtitle="sacspmtstne01"
                  score={76}
                  selected={selected === "a"}
                  onSelect={setSelected}
                />
                <Row
                  id="b"
                  title="Identity can grant itself any role"
                  subtitle="3 identities"
                  score={77}
                  selected={selected === "b"}
                  onSelect={setSelected}
                />
                <Row
                  id="c"
                  title="Conditional access policies"
                  subtitle="Directory read was refused, so no verdict was reached"
                  score={null}
                  selected={selected === "c"}
                  onSelect={setSelected}
                />
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </Section>

      <Section
        label="Empty state"
        note="Never a shrug. An empty screen says which of the several nothings this is, and offers the action that changes it."
      >
        <EmptyState
          icon={ShieldCheckIcon}
          title="No findings match these filters"
          detail="Widen the filters, or clear the search, to see the rest of this environment."
          action={<Button variant="outline">Clear filters</Button>}
        />
      </Section>
    </div>
  );
}

function Section({
  label,
  note,
  children,
}: {
  label: string;
  note: string;
  children: React.ReactNode;
}) {
  return (
    <section className="flex flex-col gap-3">
      <div>
        <h2 className="text-sm font-semibold text-foreground">{label}</h2>
        <p className="mt-0.5 max-w-3xl text-xs leading-relaxed text-meta-foreground">
          {note}
        </p>
      </div>
      {children}
    </section>
  );
}

function Swatches({ surface, label }: { surface: string; label: string }) {
  return (
    <div className={`rounded-xl border p-4 ${surface}`}>
      <p className="text-[11px] uppercase tracking-[0.12em] text-meta-foreground">
        {label}
      </p>
      <div className="mt-3 flex flex-wrap gap-2">
        {LEVELS.map((level) => (
          <SeverityBadge key={level} level={level} size="sm" />
        ))}
      </div>
    </div>
  );
}

function Row({
  id,
  title,
  subtitle,
  score,
  selected,
  onSelect,
}: {
  id: string;
  title: string;
  subtitle: string;
  score: number | null;
  selected: boolean;
  onSelect: (id: string) => void;
}) {
  const unevaluated = score === null;

  return (
    <TableRow
      onClick={() => onSelect(id)}
      className={
        selected
          ? "cursor-pointer bg-primary/[0.06] shadow-[inset_2px_0_0_var(--color-primary)] hover:bg-primary/[0.06]"
          : `cursor-pointer ${unevaluated ? "text-muted-foreground" : ""}`
      }
    >
      <TableCell className="max-w-0">
        <span className="block truncate text-[13px] font-medium text-foreground">
          {title}
        </span>
        <span className="mt-0.5 block truncate text-xs text-meta-foreground">
          {subtitle}
        </span>
      </TableCell>
      <TableCell>
        {unevaluated ? (
          <SeverityBadge level="UNKNOWN" size="sm">
            No verdict
          </SeverityBadge>
        ) : (
          <SeverityBadge level="CRITICAL" size="sm">
            internet-facing
          </SeverityBadge>
        )}
      </TableCell>
      <TableCell className="text-right">
        {unevaluated ? <span aria-hidden>—</span> : <RiskScore score={score} />}
      </TableCell>
      <TableCell>
        {unevaluated ? (
          <span className="inline-flex items-center rounded-md border border-dashed border-unknown-border bg-unknown-bg px-2 py-0.5 text-xs text-unknown">
            Unevaluated
          </span>
        ) : (
          <StatusPill status="OPEN" />
        )}
      </TableCell>
    </TableRow>
  );
}
