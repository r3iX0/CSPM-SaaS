import { useState } from "react";
import { Link } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { api, ApiError } from "@/lib/api";
import { formatDate, formatRelative } from "@/lib/format";
import type { Acceptance, Organization } from "@/lib/types";
import { useSessionClaims } from "@/lib/useAuth";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Field, FieldLabel } from "@/components/ui/field";
import { Textarea } from "@/components/ui/textarea";
import { SeverityBadge } from "@/components/security/SeverityBadge";

/**
 * Acceptances waiting for a second owner or admin, above the risk queue (DECISIONS.md §239).
 *
 * Shown only while something waits. Every member sees what waits, since a request is part of
 * the finding's story; the buttons are an owner's or an admin's, and never the person's who
 * asked, who is told it waits for somebody else instead. A rejection needs a note, because the
 * person who asked is the one who reads it.
 */
export function AcceptanceRequests({ organization }: { organization: Organization | undefined }) {
  const { subject } = useSessionClaims();
  const decides =
    (organization?.role === "OWNER" || organization?.role === "ADMIN") && !organization.is_demo;
  const [rejecting, setRejecting] = useState<Acceptance | null>(null);

  const waiting = useQuery({
    queryKey: ["acceptances", "PENDING"],
    queryFn: () => api.get<Acceptance[]>("/api/v1/acceptances").then((r) => r.data),
  });
  const requests = waiting.data ?? [];
  if (requests.length === 0) return null;

  return (
    <section
      aria-labelledby="acceptance-requests"
      className="flex flex-col gap-3 rounded-xl border border-border bg-card p-4"
    >
      <h2 id="acceptance-requests" className="text-body font-medium text-foreground">
        {requests.length === 1
          ? "1 acceptance waits for a second approver"
          : `${requests.length} acceptances wait for a second approver`}
      </h2>
      <ul className="flex flex-col divide-y divide-border">
        {requests.map((request) => (
          <li key={request.id} className="flex flex-wrap items-start justify-between gap-3 py-3">
            <div className="flex min-w-0 flex-1 flex-col gap-1">
              <p className="flex flex-wrap items-center gap-2">
                <SeverityBadge level={request.subject_severity} size="sm" />
                <Link
                  to={
                    request.finding_id
                      ? `/findings/${request.finding_id}`
                      : `/risks/${request.risk_id}`
                  }
                  className="text-body font-medium text-foreground underline-offset-4 hover:underline focus-ring"
                >
                  {request.subject_title}
                </Link>
              </p>
              <p className="text-meta text-muted-foreground">
                {request.requested_by_email ?? "A member"} asked{" "}
                {formatRelative(request.created_at)}
                {request.expires_at ? `, until ${formatDate(request.expires_at)}` : ", with no end"}
              </p>
              <p className="text-body text-foreground">“{request.reason}”</p>
            </div>
            {request.requested_by === subject ? (
              <p className="text-meta text-muted-foreground">Waits for another owner or admin</p>
            ) : (
              decides && <Decide request={request} onReject={() => setRejecting(request)} />
            )}
          </li>
        ))}
      </ul>
      <RejectDialog request={rejecting} onClose={() => setRejecting(null)} />
    </section>
  );
}

function useSettled() {
  const queryClient = useQueryClient();
  return () => {
    for (const key of ["acceptances", "risks", "risk", "findings", "finding", "dashboard"]) {
      void queryClient.invalidateQueries({ queryKey: [key] });
    }
  };
}

function Decide({ request, onReject }: { request: Acceptance; onReject: () => void }) {
  const settled = useSettled();
  const approve = useMutation({
    mutationFn: () => api.post(`/api/v1/acceptances/${request.id}/approve`),
    onSuccess: () => {
      toast.success("Approved", {
        description: "The acceptance runs from now, with you named as the approver.",
      });
      settled();
    },
    onError: (error) =>
      toast.error("Nothing was changed", {
        description: error instanceof ApiError ? error.message : "The API refused the approval.",
      }),
  });

  return (
    <div className="flex shrink-0 gap-2">
      <Button size="sm" disabled={approve.isPending} onClick={() => approve.mutate()}>
        Approve
      </Button>
      <Button size="sm" variant="outline" disabled={approve.isPending} onClick={onReject}>
        Reject…
      </Button>
    </div>
  );
}

function RejectDialog({ request, onClose }: { request: Acceptance | null; onClose: () => void }) {
  const settled = useSettled();
  const [note, setNote] = useState("");
  const reject = useMutation({
    mutationFn: (id: string) => api.post(`/api/v1/acceptances/${id}/reject`, { note }),
    onSuccess: () => {
      toast.success("Rejected", { description: "The person who asked sees your note." });
      setNote("");
      onClose();
      settled();
    },
    onError: (error) =>
      toast.error("Nothing was changed", {
        description: error instanceof ApiError ? error.message : "The API refused the rejection.",
      }),
  });

  return (
    <Dialog
      open={request !== null}
      onOpenChange={(open) => {
        if (!open) {
          setNote("");
          onClose();
        }
      }}
    >
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Reject this acceptance</DialogTitle>
          <DialogDescription>
            Nothing about {request?.subject_title ?? "it"} changes. Say why, for the person who
            asked.
          </DialogDescription>
        </DialogHeader>
        <form
          id="reject-acceptance"
          onSubmit={(event) => {
            event.preventDefault();
            if (request && note.trim()) reject.mutate(request.id);
          }}
        >
          <Field>
            <FieldLabel htmlFor="reject-note">Why</FieldLabel>
            <Textarea
              id="reject-note"
              value={note}
              maxLength={2000}
              onChange={(event) => setNote(event.target.value)}
            />
          </Field>
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="submit"
            form="reject-acceptance"
            aria-disabled={!note.trim() || reject.isPending}
          >
            Reject
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
