import type { AttackPath, AttackPathStep } from "@/lib/types";

/**
 * A route said in one sentence a manager can repeat (DECISIONS.md §247).
 *
 * "app-payments-api runs as app-payments-api (managed identity) (service
 * principal)" is accurate hop by hop and is not a story. Read as one sentence
 * -- "From the internet, app-payments-api runs as its own identity, which holds
 * Key Vault Secrets User over kv-payments" -- it is. Built from the hops' own
 * relationships and facts only, in neutral words (§78): nothing here is
 * inferred that the hops do not already say.
 *
 * Containment at the end of a route is where the target sits, not something
 * anybody did, so a tail of it collapses into "and so reaches X inside it".
 */
export function routeSentence(route: AttackPath): string {
  const steps = route.steps;
  let walkedTo = steps.length;
  while (walkedTo > 0 && steps[walkedTo - 1]?.relationship === "contains") walkedTo -= 1;
  const walked = steps.slice(0, walkedTo);
  const opening = `From the internet, ${route.entry.name}`;
  if (walked.length === 0) return `${opening} holds ${route.target.name}.`;

  const sentence = `${opening} ${walked.map(clause).join(", which ")}`;
  const reached = walked[walked.length - 1]?.target;
  if (walkedTo < steps.length && reached) {
    return `${sentence}, and so reaches ${route.target.name} inside ${reached}.`;
  }
  return `${sentence}.`;
}

/** One hop as a verb phrase, its subject the hop before. */
function clause(step: AttackPathStep): string {
  const [fact] = step.facts;
  switch (step.relationship) {
    case "has_identity":
      // A system-assigned identity is named after its workload, sometimes with
      // its kind after it: "app-payments-api (managed identity)".
      return step.target === step.source || step.target.startsWith(`${step.source} (`)
        ? "runs as its own identity"
        : `runs as ${step.target}`;
    case "grants_role":
      return fact ? `holds ${fact} over ${step.target}` : `can act over ${step.target}`;
    case "can_grant_roles":
      return `can grant itself any role over ${step.target}`;
    case "network_access":
      return `can reach ${step.target} over the network`;
    case "member_of":
      return `is a member of ${step.target}`;
    case "can_act_as":
      return `can sign in as ${step.target}`;
    case "can_take_over":
      return fact
        ? `can take ownership of ${step.target} as ${fact}`
        : `can take ownership of ${step.target}`;
    case "contains":
      return `contains ${step.target}`;
    default:
      return step.description.startsWith(`${step.source} `)
        ? step.description.slice(step.source.length + 1)
        : step.description;
  }
}
