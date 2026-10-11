import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { api, ApiError } from "@/lib/api";
import type { AssetDeclaration } from "@/lib/types";
import { useT } from "@/i18n";
import { useIsDemo } from "@/lib/useDemo";
import { Button } from "@/components/ui/button";

/**
 * "This holds sensitive data", said about one asset (DECISIONS.md §251).
 *
 * A route ends only where data is sensitive, and only the customer knows that
 * a storage account holds the payroll export. The declaration is applied by the
 * next scan as a floor: it can give a route an end and never hide one, so there
 * is no "this does not" here.
 */
export function DeclareSensitive({ assetId, name }: { assetId: string; name: string }) {
  const t = useT();
  const demo = useIsDemo();
  const client = useQueryClient();
  const key = ["asset", assetId, "context"];
  const declared = useQuery({
    queryKey: key,
    queryFn: () =>
      api.get<AssetDeclaration | null>(`/api/v1/assets/${assetId}/context`).then((r) => r.data),
  });
  const change = useMutation({
    mutationFn: (level: "HIGH" | "CRITICAL" | null) =>
      level
        ? api.put<AssetDeclaration | null>(`/api/v1/assets/${assetId}/context`, {
            data_sensitivity: level,
          })
        : api.del<AssetDeclaration | null>(`/api/v1/assets/${assetId}/context`),
    onSuccess: (_result, level) => {
      void client.invalidateQueries({ queryKey: key });
      toast.success(level ? t.attackPaths.declaredToast(name) : t.attackPaths.withdrawnToast, {
        description: t.attackPaths.declareNextScan,
      });
    },
    onError: (err) =>
      toast.error(t.attackPaths.declareError, {
        description: err instanceof ApiError ? err.message : undefined,
      }),
  });

  if (demo || declared.isPending || declared.isError) return null;
  const current = declared.data;

  return (
    <div className="flex flex-wrap items-center gap-2 text-meta text-muted-foreground">
      {current ? (
        <>
          <span>{t.attackPaths.declaredAs(current.data_sensitivity)}</span>
          <Button
            variant="ghost"
            size="xs"
            aria-disabled={change.isPending || undefined}
            onClick={() => {
              if (!change.isPending) change.mutate(null);
            }}
          >
            {t.attackPaths.declareWithdraw}
          </Button>
        </>
      ) : (
        <>
          <span>{t.attackPaths.declareQuestion}</span>
          {(["HIGH", "CRITICAL"] as const).map((level) => (
            <Button
              key={level}
              variant="outline"
              size="xs"
              aria-disabled={change.isPending || undefined}
              onClick={() => {
                if (!change.isPending) change.mutate(level);
              }}
            >
              {level === "HIGH" ? t.attackPaths.declareSensitive : t.attackPaths.declareCritical}
            </Button>
          ))}
        </>
      )}
    </div>
  );
}
