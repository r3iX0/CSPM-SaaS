import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { PlusIcon, UsersIcon } from "lucide-react";

import { api, ApiError } from "@/lib/api";
import type { CloudAccount, Organization, OwnershipRule, OwnershipScope } from "@/lib/types";
import { memberName, useAssignees } from "@/lib/remediation";
import { useT } from "@/i18n";
import { InfoTip } from "@/components/common/InfoTip";
import { SelectField } from "@/components/common/SelectField";
import { CardsSkeleton, EmptyState } from "@/components/common/states";
import { managesOrganization } from "@/components/settings/sections";
import { SettingsSection } from "@/components/settings/SettingsSection";
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
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Field, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";

const RULES_KEY = ["ownership-rules"];
const SCOPES: OwnershipScope[] = ["DEFAULT", "SUBSCRIPTION", "RESOURCE_GROUP", "TAG"];

interface OwnerOption {
  value: string;
  label: string;
}

function fetchRules() {
  return api.get<OwnershipRule[]>("/api/v1/ownership-rules").then((r) => r.data);
}

/**
 * Who owns the work nobody was handed (DECISIONS.md §236).
 *
 * A list of rules, most general first, each naming a scope and a member. The
 * queue derives every unassigned task's owner from them when it is read, so a
 * change here reroutes the queue at once and never touches work a person handed
 * out. Owners and admins change the rules; everyone else reads them, so a member
 * can see why a task landed with them.
 */
export function OwnershipSection({ organization }: { organization: Organization }) {
  const t = useT();
  const manages = managesOrganization(organization);
  const [adding, setAdding] = useState(false);
  const rules = useQuery({ queryKey: RULES_KEY, queryFn: fetchRules });
  const members = useAssignees();
  const accounts = useQuery({
    queryKey: ["cloud-accounts"],
    queryFn: () => api.get<CloudAccount[]>("/api/v1/cloud-accounts").then((r) => r.data),
  });

  const accountName = new Map((accounts.data ?? []).map((a) => [a.id, a.account_name]));
  const owners: OwnerOption[] = (members.data ?? []).map((member) => ({
    value: member.user_id,
    label: memberName(member),
  }));
  const describe = (rule: OwnershipRule): string => {
    const name = (id: string | null) =>
      (id === null ? undefined : accountName.get(id)) ?? t.ownership.unknownSubscription;
    switch (rule.scope) {
      case "DEFAULT":
        return t.ownership.describeDefault;
      case "SUBSCRIPTION":
        return t.ownership.describeSubscription(name(rule.cloud_account_id));
      case "RESOURCE_GROUP":
        return t.ownership.describeGroup(rule.resource_group ?? "", name(rule.cloud_account_id));
      case "TAG":
        return t.ownership.describeTag(rule.tag_key ?? "", rule.tag_value ?? "");
    }
  };

  const addButton = manages ? (
    <Button onClick={() => setAdding(true)}>
      <PlusIcon />
      {t.ownership.add}
    </Button>
  ) : undefined;

  return (
    <SettingsSection
      id="ownership"
      title={
        <span className="inline-flex items-center gap-1">
          {t.ownership.title}
          <InfoTip label={t.ownership.helpExplainLabel}>{t.ownership.helpExplain}</InfoTip>
        </span>
      }
      description={manages ? t.ownership.help : `${t.ownership.help} ${t.ownership.readOnly}`}
      actions={rules.data && rules.data.length > 0 ? addButton : undefined}
    >
      {rules.isLoading && <CardsSkeleton count={1} />}
      {rules.data?.length === 0 && (
        <EmptyState
          icon={UsersIcon}
          title={t.ownership.emptyTitle}
          detail={t.ownership.empty}
          action={addButton}
        />
      )}
      {rules.data && rules.data.length > 0 && (
        <ul className="divide-y divide-border overflow-hidden rounded-xl bg-card ring-1 ring-foreground/10">
          {rules.data.map((rule) => (
            <RuleRow
              key={rule.id}
              rule={rule}
              scope={describe(rule)}
              owners={owners}
              ownerName={memberName(members.data?.find((m) => m.user_id === rule.owner_id))}
              manages={manages}
            />
          ))}
        </ul>
      )}
      {manages && (
        <AddRuleDialog
          open={adding}
          onOpenChange={setAdding}
          owners={owners}
          accounts={accounts.data ?? []}
        />
      )}
    </SettingsSection>
  );
}

function RuleRow({
  rule,
  scope,
  owners,
  ownerName,
  manages,
}: {
  rule: OwnershipRule;
  /** The scope said in words: "Tag owner = platform-team". */
  scope: string;
  owners: OwnerOption[];
  ownerName: string;
  manages: boolean;
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: RULES_KEY });
    // The queue derives owners from these rules, so it is read again too.
    void queryClient.invalidateQueries({ queryKey: ["remediation"] });
  };
  const failed = (error: unknown) =>
    toast.error(error instanceof ApiError ? error.message : t.ownership.failed);

  const change = useMutation({
    mutationFn: (ownerId: string) =>
      api.patch(`/api/v1/ownership-rules/${rule.id}`, { owner_id: ownerId }),
    onSuccess: () => {
      toast.success(t.ownership.changed);
      refresh();
    },
    onError: failed,
  });
  const remove = useMutation({
    mutationFn: () => api.del(`/api/v1/ownership-rules/${rule.id}`),
    onSuccess: () => {
      toast.success(t.ownership.removed);
      refresh();
    },
    onError: failed,
  });

  return (
    <li className="flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3">
      <div className="min-w-0 flex-[1_1_16rem]">
        <p className="truncate text-body font-medium">{scope}</p>
        {!rule.owner_is_member && (
          <p className="mt-0.5 text-caption text-critical">{t.ownership.ownerLeft}</p>
        )}
      </div>
      {manages ? (
        <>
          <SelectField
            value={rule.owner_id}
            onValueChange={(value) => change.mutate(value)}
            options={owners}
            ariaLabel={t.ownership.changeOwner(scope)}
            fallbackLabel={() => ownerName}
            className="w-56"
            disabled={change.isPending}
          />
          <Button variant="ghost" size="sm" onClick={() => setConfirming(true)}>
            {t.ownership.remove}
          </Button>
        </>
      ) : (
        <span className="text-meta text-muted-foreground">{ownerName}</span>
      )}
      <AlertDialog open={confirming} onOpenChange={setConfirming}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{t.ownership.removeTitle}</AlertDialogTitle>
            <AlertDialogDescription>{t.ownership.removeBody}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{t.ownership.cancel}</AlertDialogCancel>
            <AlertDialogAction variant="destructive" onClick={() => remove.mutate()}>
              {t.ownership.remove}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </li>
  );
}

function AddRuleDialog({
  open,
  onOpenChange,
  owners,
  accounts,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  owners: OwnerOption[];
  accounts: CloudAccount[];
}) {
  const t = useT();
  const queryClient = useQueryClient();
  const [scope, setScope] = useState<OwnershipScope>("DEFAULT");
  const [account, setAccount] = useState("");
  const [group, setGroup] = useState("");
  const [tagKey, setTagKey] = useState("");
  const [tagValue, setTagValue] = useState("");
  const [owner, setOwner] = useState("");

  const needsAccount = scope === "SUBSCRIPTION" || scope === "RESOURCE_GROUP";
  const complete =
    owner !== "" &&
    (!needsAccount || account !== "") &&
    (scope !== "RESOURCE_GROUP" || group.trim() !== "") &&
    (scope !== "TAG" || (tagKey.trim() !== "" && tagValue.trim() !== ""));

  const reset = () => {
    setScope("DEFAULT");
    setAccount("");
    setGroup("");
    setTagKey("");
    setTagValue("");
    setOwner("");
  };
  const add = useMutation({
    mutationFn: () =>
      api.post("/api/v1/ownership-rules", {
        scope,
        owner_id: owner,
        ...(needsAccount ? { cloud_account_id: account } : {}),
        ...(scope === "RESOURCE_GROUP" ? { resource_group: group.trim() } : {}),
        ...(scope === "TAG" ? { tag_key: tagKey.trim(), tag_value: tagValue.trim() } : {}),
      }),
    onSuccess: () => {
      toast.success(t.ownership.added);
      void queryClient.invalidateQueries({ queryKey: RULES_KEY });
      void queryClient.invalidateQueries({ queryKey: ["remediation"] });
      reset();
      onOpenChange(false);
    },
    onError: (error) => toast.error(error instanceof ApiError ? error.message : t.ownership.failed),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{t.ownership.add}</DialogTitle>
        </DialogHeader>
        <form
          className="flex flex-col gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            if (complete && !add.isPending) add.mutate();
          }}
        >
          <Field>
            <FieldLabel htmlFor="ownership-scope">{t.ownership.scopeLabel}</FieldLabel>
            <SelectField
              id="ownership-scope"
              size="default"
              value={scope}
              onValueChange={(value) => {
                const chosen = SCOPES.find((option) => option === value);
                if (chosen) setScope(chosen);
              }}
              options={SCOPES.map((value) => ({ value, label: t.ownership.scopes[value] }))}
              ariaLabel={t.ownership.scopeLabel}
            />
          </Field>
          {needsAccount && (
            <Field>
              <FieldLabel htmlFor="ownership-account">{t.ownership.subscription}</FieldLabel>
              <SelectField
                id="ownership-account"
                size="default"
                value={account}
                onValueChange={setAccount}
                options={accounts.map((a) => ({ value: a.id, label: a.account_name }))}
                ariaLabel={t.ownership.subscription}
              />
            </Field>
          )}
          {scope === "RESOURCE_GROUP" && (
            <Field>
              <FieldLabel htmlFor="ownership-group">{t.ownership.resourceGroup}</FieldLabel>
              <Input
                id="ownership-group"
                value={group}
                maxLength={90}
                onChange={(event) => setGroup(event.target.value)}
              />
            </Field>
          )}
          {scope === "TAG" && (
            <div className="grid gap-4 sm:grid-cols-2">
              <Field>
                <FieldLabel htmlFor="ownership-tag-key">{t.ownership.tagKey}</FieldLabel>
                <Input
                  id="ownership-tag-key"
                  value={tagKey}
                  maxLength={512}
                  onChange={(event) => setTagKey(event.target.value)}
                />
              </Field>
              <Field>
                <FieldLabel htmlFor="ownership-tag-value">{t.ownership.tagValue}</FieldLabel>
                <Input
                  id="ownership-tag-value"
                  value={tagValue}
                  maxLength={256}
                  onChange={(event) => setTagValue(event.target.value)}
                />
              </Field>
            </div>
          )}
          <Field>
            <FieldLabel htmlFor="ownership-owner">{t.ownership.owner}</FieldLabel>
            <SelectField
              id="ownership-owner"
              size="default"
              value={owner}
              onValueChange={setOwner}
              options={owners}
              ariaLabel={t.ownership.owner}
            />
          </Field>
          <DialogFooter>
            <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
              {t.ownership.cancel}
            </Button>
            <Button type="submit" aria-disabled={!complete || add.isPending}>
              {add.isPending ? t.ownership.saving : t.ownership.save}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
