import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, ApiError, auth } from "@/lib/api";
import type { CloudAccount, Member, Organization } from "@/lib/types";
import { useT } from "@/i18n";
import { OrganizationForm } from "@/components/settings/OrganizationForm";
import { SettingsSection } from "@/components/settings/SettingsSection";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Field, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";

/** The organization's profile, and at the foot of it, deleting the organization. */
export function GeneralSettings({ organization }: { organization: Organization }) {
  const t = useT();

  // `/settings#danger`, from before the page was split, lands on the section
  // (DECISIONS.md §207). The router does not scroll to a fragment.
  const { hash } = useLocation();
  useEffect(() => {
    if (!hash) return;
    document.getElementById(decodeURIComponent(hash.slice(1)))?.scrollIntoView?.({
      block: "start",
    });
  }, [hash]);

  return (
    <div className="flex flex-col gap-10">
      <SettingsSection
        id="organization"
        title={t.settings.orgTitle}
        description={t.settings.orgHelp}
      >
        {/* Keyed, so switching organization remounts the form with the new
            values rather than leaving the previous one's name in the boxes. */}
        <OrganizationForm key={organization.id} organization={organization} />
      </SettingsSection>
      <DangerZone organization={organization} />
    </div>
  );
}

/**
 * Deletion, behind a dialog that says what goes and asks for the name.
 *
 * Fourteen tables cascade from this row and there is no undo. The page holds
 * only the button that opens the dialog, so the one irreversible action in
 * settings is not a text box lying open beside the profile. The dialog counts
 * what the reader would lose from what this browser already knows -- the
 * subscriptions and the members -- and then asks for something only a person
 * who meant it would produce. A second "are you sure" button would be a speed
 * bump; typing the name is a check.
 */
function DangerZone({ organization }: { organization: Organization }) {
  const t = useT();
  const owner = organization.role === "OWNER" && !organization.is_demo;
  const [open, setOpen] = useState(false);

  return (
    <SettingsSection
      id="danger"
      title={t.settings.dangerTitle}
      description={t.settings.dangerHelp}
      tone="danger"
    >
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-critical-border bg-card p-5">
        {owner ? (
          <>
            <p className="text-body text-muted-foreground">{t.settings.dangerOpenHelp}</p>
            <Button
              variant="outline"
              className="border-critical-border bg-critical-bg text-critical hover:bg-critical-bg hover:text-critical"
              onClick={() => setOpen(true)}
            >
              {t.settings.dangerOpen}
            </Button>
            <DeleteDialog organization={organization} open={open} onOpenChange={setOpen} />
          </>
        ) : (
          <p className="text-body text-muted-foreground">{t.settings.dangerOwnerOnly}</p>
        )}
      </div>
    </SettingsSection>
  );
}

function DeleteDialog({
  organization,
  open,
  onOpenChange,
}: {
  organization: Organization;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}) {
  const t = useT();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [typed, setTyped] = useState("");
  const [error, setError] = useState<string | null>(null);

  // Read only while the dialog is open, under the keys the other settings
  // pages use, so a reader who has been to Members costs nothing here.
  const accounts = useQuery({
    queryKey: ["cloud-accounts"],
    queryFn: () => api.get<CloudAccount[]>("/api/v1/cloud-accounts").then((r) => r.data),
    enabled: open,
  });
  const members = useQuery({
    queryKey: ["members", organization.id],
    queryFn: () => api.get<Member[]>("/api/v1/members").then((r) => r.data),
    enabled: open,
  });

  const remove = useMutation({
    mutationFn: () => api.del(`/api/v1/organizations/${organization.id}`),
    onSuccess: () => {
      // The stored preference now names nothing, and every request carries it
      // as a header. Dropped before any refetch can send it.
      if (auth.organizationId === organization.id) auth.organizationId = null;
      queryClient.clear();
      void navigate("/", { replace: true });
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : t.settings.deleteFailed),
  });

  return (
    <AlertDialog
      open={open}
      onOpenChange={(next) => {
        onOpenChange(next);
        if (!next) {
          setTyped("");
          setError(null);
        }
      }}
    >
      <AlertDialogContent className="sm:max-w-md">
        <AlertDialogHeader>
          <AlertDialogTitle className="text-critical">
            {t.settings.dangerConfirmTitle(organization.name)}
          </AlertDialogTitle>
          <AlertDialogDescription>{t.settings.dangerWillGo}</AlertDialogDescription>
        </AlertDialogHeader>

        <ul className="flex list-disc flex-col gap-1 pl-5 text-body text-foreground">
          {accounts.data && <li>{t.settings.dangerSubscriptions(accounts.data.length)}</li>}
          {members.data && <li>{t.settings.dangerMembers(members.data.length)}</li>}
          <li>{t.settings.dangerHistory}</li>
        </ul>

        <form
          id="delete-organization"
          className="flex flex-col gap-3"
          onSubmit={(event) => {
            event.preventDefault();
            if (typed === organization.name) remove.mutate();
          }}
        >
          <Field>
            <FieldLabel htmlFor="confirm-name">{t.settings.dangerConfirmLabel}</FieldLabel>
            <Input
              id="confirm-name"
              value={typed}
              placeholder={organization.name}
              autoComplete="off"
              onChange={(event) => setTyped(event.target.value)}
            />
          </Field>
          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
        </form>

        <AlertDialogFooter>
          <AlertDialogCancel>{t.settings.cancel}</AlertDialogCancel>
          <Button
            type="submit"
            form="delete-organization"
            variant="destructive"
            disabled={typed !== organization.name || remove.isPending}
          >
            {remove.isPending ? t.settings.deleting : t.settings.delete}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
