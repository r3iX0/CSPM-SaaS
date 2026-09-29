import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api, ApiError } from "@/lib/api";
import type {
  Invitation,
  InvitationCreated,
  Member,
  MemberRole,
  Organization,
} from "@/lib/types";
import { useT } from "@/i18n";
import { formatDate } from "@/lib/format";
import { CopyButton } from "@/components/common/CopyButton";
import { LiveStatus } from "@/components/common/LiveStatus";
import { SelectField } from "@/components/common/SelectField";
import { CardsSkeleton } from "@/components/common/states";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

const MANAGERS = ["OWNER", "ADMIN"];
const ROLES: MemberRole[] = ["OWNER", "ADMIN", "SECURITY_ANALYST", "IT_ADMIN", "ADVISOR", "VIEWER"];
// Nobody is invited straight into ownership: the API refuses it, so the menu
// does not offer it (DECISIONS.md §162).
const INVITABLE = ROLES.filter((role) => role !== "OWNER");

/**
 * Who is in this organization, and the way in for somebody who is not yet.
 *
 * Every member sees the list. Owners and admins change roles, remove people
 * and invite -- and only an owner touches an owner, which the menus reflect
 * rather than offering a change the API would refuse. Cleave sends no email:
 * an invitation is a link, shown once, for the inviter to pass on.
 */
export function MembersSection({ organization }: { organization: Organization }) {
  const t = useT();
  const manages = MANAGERS.includes(organization.role ?? "") && !organization.is_demo;
  const owner = organization.role === "OWNER";

  const members = useQuery({
    queryKey: ["members", organization.id],
    queryFn: () => api.get<Member[]>("/api/v1/members").then((r) => r.data),
  });

  return (
    <div className="flex flex-col gap-4">
      <div className="overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10">
        {!manages && (
          <div className="px-5 pt-4">
            <Alert>
              <AlertDescription>{t.team.readOnly}</AlertDescription>
            </Alert>
          </div>
        )}
        {members.isLoading && <CardsSkeleton count={1} />}
        {members.data && (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="pl-5">{t.team.inviteEmail}</TableHead>
                <TableHead>{t.team.role}</TableHead>
                <TableHead>{t.team.joined}</TableHead>
                <TableHead className="pr-5">
                  <span className="sr-only">{t.team.remove}</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {members.data.map((member) => (
                <MemberRow
                  key={member.id}
                  member={member}
                  // Only an owner changes an owner, or makes one.
                  editable={manages && (owner || member.role !== "OWNER")}
                  roles={owner ? ROLES : INVITABLE}
                />
              ))}
            </TableBody>
          </Table>
        )}
      </div>

      {manages && <InviteForm />}
      {manages && <PendingInvitations organizationId={organization.id} />}
    </div>
  );
}

function MemberRow({
  member,
  editable,
  roles,
}: {
  member: Member;
  editable: boolean;
  roles: MemberRole[];
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const who = member.email ?? t.team.noEmail;

  const refresh = () => queryClient.invalidateQueries({ queryKey: ["members"] });
  const failed = (err: unknown) =>
    setError(err instanceof ApiError ? err.message : t.team.changeFailed);

  const change = useMutation({
    mutationFn: (role: string) => api.patch<Member>(`/api/v1/members/${member.id}`, { role }),
    onSuccess: () => {
      setError(null);
      void refresh();
      // Changing one's own role changes what this page may do.
      if (member.is_you) void queryClient.invalidateQueries({ queryKey: ["organizations"] });
    },
    onError: failed,
  });

  const remove = useMutation({
    mutationFn: () => api.del(`/api/v1/members/${member.id}`),
    onSuccess: () => void refresh(),
    onError: (err) => {
      setConfirming(false);
      failed(err);
    },
  });

  return (
    <>
      <TableRow>
        <TableCell className="pl-5">
          <span className={member.email ? "text-foreground" : "text-muted-foreground"}>
            {who}
          </span>
          {member.is_you && (
            <span className="ml-1.5 text-xs text-muted-foreground">({t.team.you})</span>
          )}
        </TableCell>
        <TableCell>
          {editable ? (
            <SelectField
              value={member.role}
              ariaLabel={`${t.team.role}: ${who}`}
              disabled={change.isPending}
              onValueChange={(role) => {
                if (role && role !== member.role) change.mutate(role);
              }}
              options={roles.map((role) => ({ value: role, label: t.team.roles[role] }))}
            />
          ) : (
            t.team.roles[member.role]
          )}
        </TableCell>
        <TableCell className="text-muted-foreground">{formatDate(member.joined_at)}</TableCell>
        <TableCell className="pr-5 text-right">
          {editable && !confirming && (
            <Button
              variant="ghost"
              size="sm"
              aria-label={`${t.team.remove} ${who}`}
              onClick={() => setConfirming(true)}
            >
              {t.team.remove}
            </Button>
          )}
        </TableCell>
      </TableRow>
      {(confirming || error) && (
        <TableRow>
          <TableCell colSpan={4} className="px-5">
            {confirming ? (
              <div className="flex flex-wrap items-center gap-3 text-sm">
                <span>
                  <strong className="font-medium">{t.team.removeConfirm(who)}</strong>{" "}
                  <span className="text-muted-foreground">{t.team.removeDetail}</span>
                </span>
                <Button
                  size="sm"
                  variant="outline"
                  className="border-critical-border bg-critical-bg text-critical hover:bg-critical-bg hover:text-critical"
                  disabled={remove.isPending}
                  onClick={() => remove.mutate()}
                >
                  {remove.isPending ? t.team.removing : t.team.remove}
                </Button>
                <Button size="sm" variant="ghost" onClick={() => setConfirming(false)}>
                  {t.team.cancel}
                </Button>
              </div>
            ) : (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}
          </TableCell>
        </TableRow>
      )}
    </>
  );
}

function InviteForm() {
  const t = useT();
  const queryClient = useQueryClient();
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<MemberRole>("VIEWER");
  const [created, setCreated] = useState<InvitationCreated | null>(null);
  const [error, setError] = useState<string | null>(null);

  const invite = useMutation({
    mutationFn: () =>
      api
        .post<InvitationCreated>("/api/v1/invitations", { email: email.trim(), role })
        .then((r) => r.data),
    onSuccess: (invitation) => {
      setError(null);
      setCreated(invitation);
      setEmail("");
      void queryClient.invalidateQueries({ queryKey: ["invitations"] });
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : t.team.inviteFailed),
  });

  return (
    <div className="rounded-xl bg-card p-5 ring-1 ring-foreground/10">
      <h3 className="text-sm font-semibold text-foreground">{t.team.inviteTitle}</h3>
      <form
        className="mt-3 flex flex-col gap-3.5"
        onSubmit={(event) => {
          event.preventDefault();
          invite.mutate();
        }}
      >
        <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_12rem]">
          <Field>
            <FieldLabel htmlFor="invite-email">{t.team.inviteEmail}</FieldLabel>
            <Input
              id="invite-email"
              type="email"
              required
              autoComplete="off"
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
          </Field>
          <Field>
            <FieldLabel htmlFor="invite-role">{t.team.inviteRole}</FieldLabel>
            <SelectField
              id="invite-role"
              value={role}
              size="default"
              ariaLabel={t.team.inviteRole}
              onValueChange={(next) => {
                if (next) setRole(next as MemberRole);
              }}
              options={INVITABLE.map((value) => ({ value, label: t.team.roles[value] }))}
            />
          </Field>
        </div>
        <FieldDescription>{t.team.owners}</FieldDescription>

        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <Button type="submit" className="self-start" disabled={invite.isPending || !email.trim()}>
          {invite.isPending ? t.team.inviting : t.team.invite}
        </Button>
      </form>

      <LiveStatus message={created ? t.team.linkReady(created.email) : null} />
      {created && (
        <div className="mt-4 flex flex-col gap-2.5 rounded-lg bg-muted/50 p-4">
          <p className="text-sm text-foreground">{t.team.linkReady(created.email)}</p>
          <code className="block overflow-x-auto rounded bg-background px-2.5 py-1.5 font-mono text-xs">
            {created.link}
          </code>
          <div>
            <CopyButton text={created.link} label={t.team.copy} variant="outline" />
          </div>
        </div>
      )}
    </div>
  );
}

function PendingInvitations({ organizationId }: { organizationId: string }) {
  const t = useT();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  const invitations = useQuery({
    queryKey: ["invitations", organizationId],
    queryFn: () => api.get<Invitation[]>("/api/v1/invitations").then((r) => r.data),
  });

  const revoke = useMutation({
    mutationFn: (id: string) => api.del(`/api/v1/invitations/${id}`),
    onSuccess: () => {
      setError(null);
      void queryClient.invalidateQueries({ queryKey: ["invitations"] });
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : t.team.revokeFailed),
  });

  return (
    <div className="rounded-xl bg-card p-5 ring-1 ring-foreground/10">
      <h3 className="text-sm font-semibold text-foreground">{t.team.pendingTitle}</h3>
      {error && (
        <Alert variant="destructive" className="mt-3">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {invitations.data && invitations.data.length === 0 && (
        <p className="mt-2 text-sm text-muted-foreground">{t.team.pendingEmpty}</p>
      )}
      {invitations.data && invitations.data.length > 0 && (
        <ul className="mt-2 divide-y divide-border">
          {invitations.data.map((invitation) => (
            <li key={invitation.id} className="flex flex-wrap items-center gap-3 py-2.5 text-sm">
              <span className="min-w-0 flex-1 truncate text-foreground">{invitation.email}</span>
              <span className="text-muted-foreground">{t.team.roles[invitation.role]}</span>
              <span className="text-muted-foreground">
                {invitation.status === "EXPIRED"
                  ? t.team.expired
                  : `${t.team.expires} ${formatDate(invitation.expires_at)}`}
              </span>
              <Button
                variant="ghost"
                size="sm"
                aria-label={`${t.team.revoke} ${invitation.email}`}
                disabled={revoke.isPending}
                onClick={() => revoke.mutate(invitation.id)}
              >
                {t.team.revoke}
              </Button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
