import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { SearchIcon, UserPlusIcon } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import type { Invitation, InvitationCreated, Member, MemberRole, Organization } from "@/lib/types";
import { useT } from "@/i18n";
import { formatDate } from "@/lib/format";
import { CopyButton } from "@/components/common/CopyButton";
import { InfoTip } from "@/components/common/InfoTip";
import { LiveStatus } from "@/components/common/LiveStatus";
import { SelectField } from "@/components/common/SelectField";
import { CardsSkeleton } from "@/components/common/states";
import { OptionCard } from "@/components/settings/OptionCard";
import { SettingsSection } from "@/components/settings/SettingsSection";
import { managesOrganization } from "@/components/settings/sections";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Field, FieldDescription, FieldLabel, FieldLegend, FieldSet } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { InputGroup, InputGroupAddon, InputGroupInput } from "@/components/ui/input-group";
import { RadioGroup } from "@/components/ui/radio-group";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

const MANAGERS: MemberRole[] = ["OWNER", "ADMIN"];
const ROLES: MemberRole[] = ["OWNER", "ADMIN", "SECURITY_ANALYST", "IT_ADMIN", "ADVISOR", "VIEWER"];
// Nobody is invited straight into ownership: the API refuses it, so the menu
// does not offer it (DECISIONS.md §162).
const INVITABLE = ROLES.filter((role) => role !== "OWNER");

/** Above this many members the list earns a search box. */
const SEARCH_FROM = 8;

/** Two letters for the avatar, from the address the member signed in with. */
function initials(email: string | null): string {
  if (!email) return "?";
  const local = email.split("@")[0] ?? email;
  const parts = local.split(/[._-]+/).filter(Boolean);
  const letters =
    parts.length > 1 ? `${parts[0]?.[0] ?? ""}${parts[1]?.[0] ?? ""}` : local.slice(0, 2);
  return letters.toUpperCase();
}

/**
 * Who is in this organization, and the way in for somebody who is not yet.
 *
 * Every member sees the list. Owners and admins change roles, remove people
 * and invite -- and only an owner touches an owner, which the menus reflect
 * rather than offering a change the API would refuse. Cleave sends no email:
 * an invitation is a link, shown once, for the inviter to pass on.
 *
 * A role change applies when it is chosen and offers Undo in the toast that
 * says so; lowering one's own role below admin asks first, because there is
 * no undo from a role that can no longer change roles. Removing someone asks
 * in a dialog. Each role says what it may do where it is chosen (§207).
 */
export function MembersSection({ organization }: { organization: Organization }) {
  const t = useT();
  const manages = managesOrganization(organization);
  const owner = organization.role === "OWNER";
  const [search, setSearch] = useState("");
  const [inviteOpen, setInviteOpen] = useState(false);
  const [created, setCreated] = useState<InvitationCreated | null>(null);

  const members = useQuery({
    queryKey: ["members", organization.id],
    queryFn: () => api.get<Member[]>("/api/v1/members").then((r) => r.data),
  });

  const all = members.data ?? [];
  const needle = search.trim().toLowerCase();
  const rows = needle
    ? all.filter((member) => (member.email ?? "").toLowerCase().includes(needle))
    : all;
  const owners = all.filter((member) => member.role === "OWNER").length;

  return (
    <SettingsSection
      id="members"
      title={t.team.title}
      description={t.team.help}
      actions={
        manages && (
          <Button onClick={() => setInviteOpen(true)}>
            <UserPlusIcon />
            {t.team.inviteOpen}
          </Button>
        )
      }
    >
      <div className="flex flex-col gap-4">
        {!manages && (
          <Alert>
            <AlertDescription>{t.team.readOnly}</AlertDescription>
          </Alert>
        )}

        {all.length > SEARCH_FROM && (
          <InputGroup className="h-8 max-w-xs">
            <InputGroupAddon>
              <SearchIcon />
            </InputGroupAddon>
            <InputGroupInput
              type="search"
              aria-label={t.team.searchMembers}
              placeholder={t.team.searchMembers}
              value={search}
              onChange={(event) => setSearch(event.target.value)}
            />
          </InputGroup>
        )}

        <div className="overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10">
          {members.isLoading && <CardsSkeleton count={1} />}
          {members.data && rows.length === 0 && (
            <p className="px-5 py-4 text-body text-muted-foreground">{t.team.noMemberMatches}</p>
          )}
          {members.data && rows.length > 0 && (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="pl-5">{t.team.inviteEmail}</TableHead>
                  <TableHead>
                    <span className="inline-flex items-center gap-1">
                      {t.team.role}
                      <RolesExplained />
                    </span>
                  </TableHead>
                  <TableHead className="hidden sm:table-cell">{t.team.joined}</TableHead>
                  <TableHead className="pr-5">
                    <span className="sr-only">{t.team.remove}</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((member) => (
                  <MemberRow
                    key={member.id}
                    member={member}
                    // Only an owner changes an owner, or makes one.
                    editable={manages && (owner || member.role !== "OWNER")}
                    roles={owner ? ROLES : INVITABLE}
                    lastOwner={member.role === "OWNER" && owners === 1}
                  />
                ))}
              </TableBody>
            </Table>
          )}
        </div>
        {all.length > SEARCH_FROM && (
          <LiveStatus message={t.settings.contextShown(rows.length, all.length)} quietFirst />
        )}

        {manages && (
          <PendingInvitations
            organizationId={organization.id}
            onReinvited={(invitation) => {
              setCreated(invitation);
              setInviteOpen(true);
            }}
          />
        )}
      </div>

      {manages && (
        <InviteDialog
          open={inviteOpen}
          created={created}
          onCreated={setCreated}
          onOpenChange={(open) => {
            setInviteOpen(open);
            if (!open) setCreated(null);
          }}
        />
      )}
    </SettingsSection>
  );
}

/** What each role may do, a question mark away from the column that names it. */
function RolesExplained() {
  const t = useT();
  return (
    <InfoTip label={t.team.rolesLabel} contentClassName="w-80">
      <dl className="flex flex-col gap-2">
        {ROLES.map((role) => (
          <div key={role}>
            <dt className="font-medium text-foreground">{t.team.roles[role]}</dt>
            <dd className="text-muted-foreground">{t.team.roleHelp[role]}</dd>
          </div>
        ))}
      </dl>
      <p className="mt-3 text-muted-foreground">{t.team.rolesExplain}</p>
    </InfoTip>
  );
}

function MemberRow({
  member,
  editable: canEdit,
  roles,
  lastOwner,
}: {
  member: Member;
  editable: boolean;
  roles: MemberRole[];
  /**
   * The organization's only owner. The API refuses to remove or demote them
   * (§162), and offering "Remove" beside the one person who cannot be removed
   * led straight to a refusal (DECISIONS.md §188).
   */
  lastOwner: boolean;
}) {
  const editable = canEdit && !lastOwner;
  const t = useT();
  const queryClient = useQueryClient();
  const [confirmRemove, setConfirmRemove] = useState(false);
  const [pendingSelfRole, setPendingSelfRole] = useState<MemberRole | null>(null);
  const [error, setError] = useState<string | null>(null);
  const who = member.email ?? t.team.noEmail;

  const refresh = () => queryClient.invalidateQueries({ queryKey: ["members"] });
  const failed = (err: unknown) =>
    setError(err instanceof ApiError ? err.message : t.team.changeFailed);

  const change = useMutation({
    mutationFn: ({ role }: { role: MemberRole; previous: MemberRole }) =>
      api.patch<Member>(`/api/v1/members/${member.id}`, { role }),
    onSuccess: (_, { role, previous }) => {
      setError(null);
      void refresh();
      const said = t.team.roleChanged(who, t.team.roles[role]);
      // Changing one's own role changes what this page may do, and an undo
      // from a role that can no longer change roles would be refused.
      if (member.is_you) {
        void queryClient.invalidateQueries({ queryKey: ["organizations"] });
        toast.success(said);
        return;
      }
      toast.success(said, {
        action: {
          label: t.team.undo,
          onClick: () => change.mutate({ role: previous, previous: role }),
        },
      });
    },
    onError: failed,
  });

  const remove = useMutation({
    mutationFn: () => api.del(`/api/v1/members/${member.id}`),
    onSuccess: () => {
      setConfirmRemove(false);
      toast.success(t.team.removed(who));
      void refresh();
    },
    onError: (err) => {
      setConfirmRemove(false);
      failed(err);
    },
  });

  const choose = (role: MemberRole) => {
    if (role === member.role) return;
    const losesManagement = MANAGERS.includes(member.role) && !MANAGERS.includes(role);
    if (member.is_you && losesManagement) setPendingSelfRole(role);
    else change.mutate({ role, previous: member.role });
  };

  return (
    <>
      <TableRow>
        <TableCell className="pl-5">
          <span className="flex min-w-0 items-center gap-2.5">
            <Avatar size="sm" aria-hidden>
              <AvatarFallback>{initials(member.email)}</AvatarFallback>
            </Avatar>
            <span className="min-w-0 truncate">
              <span className={member.email ? "text-foreground" : "text-muted-foreground"}>
                {who}
              </span>
              {member.is_you && (
                <span className="ml-1.5 text-meta text-muted-foreground">({t.team.you})</span>
              )}
            </span>
          </span>
        </TableCell>
        <TableCell>
          {editable ? (
            <SelectField
              value={member.role}
              ariaLabel={`${t.team.role}: ${who}`}
              disabled={change.isPending}
              onValueChange={(role) => {
                if (role) choose(role as MemberRole);
              }}
              options={roles.map((role) => ({ value: role, label: t.team.roles[role] }))}
            />
          ) : (
            t.team.roles[member.role]
          )}
        </TableCell>
        <TableCell className="hidden text-muted-foreground sm:table-cell">
          {formatDate(member.joined_at)}
        </TableCell>
        <TableCell className="pr-5 text-right">
          {lastOwner && <span className="text-meta text-muted-foreground">{t.team.lastOwner}</span>}
          {editable && (
            <Button
              variant="ghost"
              size="sm"
              aria-label={`${t.team.remove} ${who}`}
              onClick={() => setConfirmRemove(true)}
            >
              {t.team.remove}
            </Button>
          )}
        </TableCell>
      </TableRow>
      {error && (
        <TableRow>
          <TableCell colSpan={4} className="px-5">
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          </TableCell>
        </TableRow>
      )}

      <AlertDialog open={confirmRemove} onOpenChange={setConfirmRemove}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t.team.removeConfirm(who)}</AlertDialogTitle>
            <AlertDialogDescription>{t.team.removeDetail}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t.team.cancel}</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              disabled={remove.isPending}
              onClick={() => remove.mutate()}
            >
              {remove.isPending ? t.team.removing : t.team.remove}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog
        open={pendingSelfRole !== null}
        onOpenChange={(open) => {
          if (!open) setPendingSelfRole(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t.team.selfDemoteTitle}</AlertDialogTitle>
            <AlertDialogDescription>{t.team.selfDemoteDetail}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t.team.cancel}</AlertDialogCancel>
            <AlertDialogAction
              variant="destructive"
              onClick={() => {
                if (pendingSelfRole) {
                  change.mutate({ role: pendingSelfRole, previous: member.role });
                }
                setPendingSelfRole(null);
              }}
            >
              {t.team.selfDemoteConfirm}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}

/**
 * Inviting someone, in a dialog opened from the section's heading.
 *
 * The form used to sit open under the member list at all times. In a dialog it
 * is there when asked for, and its answer -- the link, shown once -- replaces
 * the form in the same place, so the one thing the inviter must copy is the
 * thing in front of them. Each role is offered with what it may do.
 */
function InviteDialog({
  open,
  created,
  onCreated,
  onOpenChange,
}: {
  open: boolean;
  created: InvitationCreated | null;
  onCreated: (invitation: InvitationCreated) => void;
  onOpenChange: (open: boolean) => void;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<MemberRole>("VIEWER");
  const [error, setError] = useState<string | null>(null);

  const invite = useMutation({
    mutationFn: () =>
      api
        .post<InvitationCreated>("/api/v1/invitations", { email: email.trim(), role })
        .then((r) => r.data),
    onSuccess: (invitation) => {
      setError(null);
      setEmail("");
      setRole("VIEWER");
      onCreated(invitation);
      void queryClient.invalidateQueries({ queryKey: ["invitations"] });
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : t.team.inviteFailed),
  });

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        onOpenChange(next);
        if (!next) setError(null);
      }}
    >
      <DialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t.team.inviteTitle}</DialogTitle>
          <DialogDescription>{t.team.inviteHelp}</DialogDescription>
        </DialogHeader>

        <LiveStatus message={created ? t.team.linkReady(created.email) : null} />
        {created ? (
          <>
            <div className="flex flex-col gap-2.5 rounded-lg bg-muted/50 p-4">
              <p className="text-body text-foreground">{t.team.linkReady(created.email)}</p>
              <code className="block overflow-x-auto rounded bg-background px-2.5 py-1.5 font-mono text-meta">
                {created.link}
              </code>
              <div>
                <CopyButton text={created.link} label={t.team.copy} variant="outline" />
              </div>
            </div>
            <DialogFooter>
              <Button onClick={() => onOpenChange(false)}>{t.team.done}</Button>
            </DialogFooter>
          </>
        ) : (
          <form
            className="flex flex-col gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              if (email.trim()) invite.mutate();
            }}
          >
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
            <FieldSet>
              <FieldLegend id="invite-role-legend" variant="label">
                {t.team.inviteRole}
              </FieldLegend>
              <RadioGroup
                aria-labelledby="invite-role-legend"
                value={role}
                onValueChange={(next) => setRole(next as MemberRole)}
                className="gap-1.5"
              >
                {INVITABLE.map((value) => (
                  <OptionCard
                    key={value}
                    id={`invite-role-${value}`}
                    value={value}
                    title={t.team.roles[value]}
                    description={t.team.roleHelp[value]}
                    checked={role === value}
                  />
                ))}
              </RadioGroup>
              <FieldDescription>{t.team.owners}</FieldDescription>
            </FieldSet>

            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <DialogFooter>
              <Button type="submit" disabled={invite.isPending || !email.trim()}>
                {invite.isPending ? t.team.inviting : t.team.invite}
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

/**
 * Invitations not yet accepted. An expired one can be sent again: the old link
 * cannot be shown twice (only its hash is stored), so "Invite again" withdraws
 * it and creates a new one for the same address and role.
 */
function PendingInvitations({
  organizationId,
  onReinvited,
}: {
  organizationId: string;
  onReinvited: (invitation: InvitationCreated) => void;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const [error, setError] = useState<string | null>(null);

  const invitations = useQuery({
    queryKey: ["invitations", organizationId],
    queryFn: () => api.get<Invitation[]>("/api/v1/invitations").then((r) => r.data),
  });
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["invitations"] });

  const revoke = useMutation({
    mutationFn: (invitation: Invitation) => api.del(`/api/v1/invitations/${invitation.id}`),
    onSuccess: (_, invitation) => {
      setError(null);
      toast.success(t.team.revoked(invitation.email));
      void refresh();
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : t.team.revokeFailed),
  });

  const reinvite = useMutation({
    mutationFn: async (invitation: Invitation) => {
      await api.del(`/api/v1/invitations/${invitation.id}`);
      const answer = await api.post<InvitationCreated>("/api/v1/invitations", {
        email: invitation.email,
        role: invitation.role,
      });
      return answer.data;
    },
    onSuccess: (created) => {
      setError(null);
      onReinvited(created);
    },
    onError: (err) => setError(err instanceof ApiError ? err.message : t.team.inviteFailed),
    onSettled: () => void refresh(),
  });

  const busy = revoke.isPending || reinvite.isPending;

  return (
    <div className="rounded-xl bg-card p-5 ring-1 ring-foreground/10">
      <h3 className="text-body font-semibold text-foreground">{t.team.pendingTitle}</h3>
      {error && (
        <Alert variant="destructive" className="mt-3">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {invitations.data && invitations.data.length === 0 && (
        <p className="mt-2 text-body text-muted-foreground">{t.team.pendingEmpty}</p>
      )}
      {invitations.data && invitations.data.length > 0 && (
        <ul className="mt-2 divide-y divide-border">
          {invitations.data.map((invitation) => {
            const expired = invitation.status === "EXPIRED";
            return (
              <li
                key={invitation.id}
                className="flex flex-wrap items-center gap-x-3 gap-y-1 py-2.5 text-body"
              >
                <span className="min-w-0 flex-1 truncate text-foreground">{invitation.email}</span>
                <span className="text-muted-foreground">{t.team.roles[invitation.role]}</span>
                <span className={expired ? "text-unknown" : "text-muted-foreground"}>
                  {expired
                    ? t.team.expired
                    : `${t.team.expires} ${formatDate(invitation.expires_at)}`}
                </span>
                {expired && (
                  <Button
                    variant="outline"
                    size="sm"
                    aria-label={`${t.team.inviteAgain} ${invitation.email}`}
                    disabled={busy}
                    onClick={() => reinvite.mutate(invitation)}
                  >
                    {t.team.inviteAgain}
                  </Button>
                )}
                <Button
                  variant="ghost"
                  size="sm"
                  aria-label={`${t.team.revoke} ${invitation.email}`}
                  disabled={busy}
                  onClick={() => revoke.mutate(invitation)}
                >
                  {t.team.revoke}
                </Button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
