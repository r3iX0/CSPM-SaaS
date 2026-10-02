import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { DownloadIcon } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import { saveBlob } from "@/lib/download";
import type { IacDiff } from "@/lib/types";
import { CodeBlock } from "@/components/common/CodeBlock";
import { LiveStatus } from "@/components/common/LiveStatus";
import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";

/**
 * The fix written into the customer's own Terraform, from a file they upload.
 *
 * The hint above says which argument to change; this changes it in their file
 * and hands back a diff, or says why it would not -- an interpolated name, a
 * value from a variable, a block that is not there. A refusal is shown as the
 * answer it is, not as an error: the file was read and the edit needed a guess
 * (DECISIONS.md §190). Nothing uploaded is kept.
 */
export function IacDiffCheck({
  findingId,
  resourceName,
}: {
  findingId: string;
  resourceName: string;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [lockfile, setLockfile] = useState<File | null>(null);

  const check = useMutation({
    mutationFn: () => {
      const form = new FormData();
      form.append("file", file!);
      if (lockfile) form.append("lockfile", lockfile);
      return api
        .upload<IacDiff>(`/api/v1/findings/${findingId}/iac-diff`, form)
        .then((r) => r.data);
    },
  });
  const result = check.data;

  const spoken = check.isPending
    ? null
    : result?.outcome === "patched"
      ? `The fix is written: ${result.edits.length} ${result.edits.length === 1 ? "change" : "changes"} in ${result.filename}.`
      : result?.outcome === "declined"
        ? `Not written: ${result.detail}`
        : check.error
          ? "The file could not be checked."
          : null;

  return (
    <form
      className="flex flex-col gap-3 rounded-lg border p-3"
      onSubmit={(event) => {
        event.preventDefault();
        if (file) check.mutate();
      }}
    >
      <Field>
        <FieldLabel htmlFor={`iac-file-${findingId}`}>Terraform file</FieldLabel>
        <Input
          id={`iac-file-${findingId}`}
          type="file"
          accept=".tf"
          onChange={(event) => {
            setFile(event.currentTarget.files?.[0] ?? null);
            check.reset();
          }}
        />
        <FieldDescription>
          The file that defines {resourceName}. Cleave changes the arguments above in it and nothing
          else, and keeps nothing you upload.
        </FieldDescription>
      </Field>
      <Field>
        <FieldLabel htmlFor={`iac-lock-${findingId}`}>Lock file (optional)</FieldLabel>
        <Input
          id={`iac-lock-${findingId}`}
          type="file"
          accept=".hcl"
          onChange={(event) => {
            setLockfile(event.currentTarget.files?.[0] ?? null);
            check.reset();
          }}
        />
        <FieldDescription>
          Your .terraform.lock.hcl, so the answer can say which azurerm release you run.
        </FieldDescription>
      </Field>
      <div>
        <Button type="submit" variant="outline" size="sm" disabled={!file || check.isPending}>
          {check.isPending && <Spinner />}
          Write the fix into this file
        </Button>
      </div>

      {result?.outcome === "patched" && result.diff && (
        <div className="flex flex-col gap-2">
          {result.matched_by === "sole_block" && (
            // Matched without its name: the reviewer is the check (DECISIONS.md §190).
            <p className="rounded-lg border border-dashed p-3 text-xs leading-relaxed">
              Its name is an expression, so Cleave took the only block of its kind in{" "}
              {result.filename} — check it is {resourceName} before you apply.
            </p>
          )}
          <CodeBlock code={result.diff} label="Copy the diff" />
          <p className="text-xs text-muted-foreground">
            {result.provider_version
              ? `Your lock file holds azurerm ${result.provider_version}.`
              : `No lock file was sent: checked against azurerm ${result.checked_against.join(" and ")}.`}{" "}
            Run <code>terraform plan</code> before you apply it. The finding closes when a scan sees
            the change, not when the diff is merged.
          </p>
          <div>
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() =>
                saveBlob(
                  new Blob([result.diff!], { type: "text/x-diff" }),
                  `${result.filename}.diff`,
                )
              }
            >
              <DownloadIcon aria-hidden />
              Download the diff
            </Button>
          </div>
        </div>
      )}

      {result?.outcome === "declined" && (
        <p className="rounded-lg border border-dashed p-3 text-xs leading-relaxed text-muted-foreground">
          {result.detail} Change the arguments above by hand instead.
        </p>
      )}

      {check.error && (
        <p className="text-xs text-destructive">
          {check.error instanceof ApiError ? check.error.message : "The file could not be checked."}
        </p>
      )}

      <LiveStatus message={spoken} />
    </form>
  );
}
