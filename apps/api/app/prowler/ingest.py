"""A stored Prowler run, turned into verdicts the rest of the pipeline can use.

Pure functions over what ANALYZE already holds -- the captures, the normalized
state, the native engine's report -- so every decision here is testable without
a database, a broker or Prowler.

Three decisions carry the weight.

**Silence is never a PASS.** Prowler emits nothing for a resource it could not
read: a service whose listing failed logs an error and its checks iterate over
an empty list, and a check that raised is caught and logged and yields nothing.
Read naively, both look exactly like a clean estate. So the capture carries what
Prowler logged (``errors``), and here a check whose service or own execution
errored becomes UNKNOWN -- for the scope as a whole, and for every asset of its
type that it said nothing about. What Prowler *did* say stands: a FAIL is an
observation whatever else went wrong around it.

**One question, one finding.** Where a native rule already answers what a check
asks (``covered_by`` in the catalogue), the native verdict is the finding and
the check's verdict is evidence about it. The two are compared asset by asset,
and every disagreement becomes a :class:`Divergence` -- the second engine
auditing the first, and the first the second (DECISIONS.md section 150).

**Every result lands on an asset Cleave knows, or on the scope.** Prowler names
resources its own way -- an ARN where Cleave stored an instance id, a key
beneath the vault Cleave inventoried. :class:`AssetResolver` tries the id, then
its parents, then its last segment. A result that still joins nothing but is
plainly a resource becomes a new inventory asset of unknown type (so no native
rule ever evaluates it); anything else is a verdict about the scope.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from app.connectors.base import NormalizedState
from app.core.enums import Provider, ResourceType, RuleState
from app.domain.resource import CloudResource
from app.prowler.catalog import PostureCheck, check, load
from app.prowler.rules import ProwlerCheckRule, rule_for_check
from app.rules.base import RuleResult
from app.rules.engine import EvaluatedResult, EvaluationReport, RuleCoverage

# How many results one combined verdict keeps in its evidence. A tenant-level
# check can report on thousands of objects that do not join Cleave's inventory,
# and a finding needs enough of them to act on rather than all of them.
EVIDENCE_LIMIT = 50

# A resource id, as opposed to a name or a tenant-level label.
_ARM_ID = re.compile(r"^/subscriptions/[^/]+/", re.IGNORECASE)

_PRECEDENCE = {RuleState.FAIL: 3, RuleState.UNKNOWN: 2, RuleState.PASS: 1}


@dataclass(frozen=True)
class StoredAssessment:
    """One ASSESS step's capture, as ANALYZE holds it."""

    cloud_account_id: UUID | None
    provider: Provider
    engine_version: str
    outcome: str
    errors: dict[str, Any]
    # ``None`` when the payload is gone -- pruned, or never written because the
    # run failed before producing one.
    content: dict[str, Any] | None
    # How messages name this scope: "subscription Payments", "the directory".
    scope_label: str

    @property
    def fatal(self) -> str | None:
        value = self.errors.get("fatal")
        return str(value) if value else None

    @property
    def requested(self) -> list[str]:
        return list((self.content or {}).get("requested") or [])

    @property
    def completed(self) -> set[str]:
        return set((self.content or {}).get("completed") or [])

    @property
    def results(self) -> list[dict[str, Any]]:
        return list((self.content or {}).get("results") or [])

    @property
    def stopped(self) -> str | None:
        """Why the run stopped before its last check, when it reached its budget."""
        value = self.errors.get("stopped")
        return str(value) if value else None

    def service_error(self, service: str) -> str | None:
        messages = (self.errors.get("services") or {}).get(service) or []
        return "; ".join(str(message) for message in messages[:3]) or None

    def check_error(self, check_id: str) -> str | None:
        value = (self.errors.get("checks") or {}).get(check_id)
        return str(value) if value else None


@dataclass
class PostureVerdict:
    """What Prowler concluded about one asset (or the scope) for one check."""

    check: PostureCheck
    state: RuleState
    resource: CloudResource | None
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass
class AssessmentReading:
    """Every verdict the stored runs support, and which checks actually ran."""

    verdicts: list[PostureVerdict] = field(default_factory=list)
    # Checks that ran somewhere in this scan: requested by a step whose capture
    # was read. A check absent from here was not assessed, which is different
    # from a check that ran and found nothing to judge.
    ran: set[str] = field(default_factory=set)
    # Assets added to the inventory because Prowler reported on them and the
    # native collectors had not listed them.
    added: list[CloudResource] = field(default_factory=list)
    # Results ANALYZE could not use, by reason -- reported, never silently lost.
    ignored: dict[str, int] = field(default_factory=dict)

    def ignore(self, reason: str) -> None:
        self.ignored[reason] = self.ignored.get(reason, 0) + 1


@dataclass(frozen=True)
class Divergence:
    """A native rule and its Prowler counterparts disagreeing."""

    rule_id: str
    check_id: str
    resource: CloudResource | None
    native_state: RuleState
    prowler_state: RuleState
    kind: str
    expected: bool
    detail: str


class AssetResolver:
    """Joins the ids Prowler reports to the assets Cleave inventoried."""

    def __init__(self, resources: Iterable[CloudResource]) -> None:
        self._by_id: dict[str, CloudResource] = {}
        tails: dict[str, list[CloudResource]] = {}
        for resource in resources:
            self._index(resource, tails)
        # A tail joins only when exactly one asset ends in it. Two security
        # groups called "default" in two regions share nothing but a name.
        self._by_tail = {key: found[0] for key, found in tails.items() if len(found) == 1}

    def _index(self, resource: CloudResource, tails: dict[str, list[CloudResource]]) -> None:
        key = resource.provider_resource_id.lower()
        self._by_id.setdefault(key, resource)
        tail = _tail(key)
        if tail and tail != key:
            tails.setdefault(tail, []).append(resource)

    def add(self, resource: CloudResource) -> None:
        """Register an asset added during reading, by its full id only."""
        self._by_id.setdefault(resource.provider_resource_id.lower(), resource)

    def resolve(self, uid: str) -> CloudResource | None:
        key = uid.strip().lower()
        if not key:
            return None
        found = self._by_id.get(key)
        if found is not None:
            return found
        # A sub-resource Cleave does not inventory -- a vault's key, a site's
        # configuration, a server's database -- belongs to its parent.
        for parent in _parents(key):
            found = self._by_id.get(parent)
            if found is not None:
                return found
        tail = _tail(key)
        if not tail:
            return None
        # An asset stored under its bare id (an EC2 instance id, a security
        # group id) is what an ARN's last segment names; otherwise, the one
        # asset whose own id ends in the same segment.
        return self._by_id.get(tail) or self._by_tail.get(tail)


def _tail(key: str) -> str:
    """The last segment of an id: an ARN's resource id, an ARM id's name."""
    return key.rstrip("/").rsplit("/", 1)[-1].rsplit(":", 1)[-1]


def _parents(key: str) -> list[str]:
    """Each ARM ancestor of a nested resource id, nearest first."""
    if not _ARM_ID.match(key):
        return []
    parts = key.rstrip("/").split("/")
    ancestors = []
    # ["", subscriptions, s, resourcegroups, g, providers, ns, type, name, ...]
    # -- anything longer than nine segments is a child of what nine name.
    while len(parts) > 9:
        parts = parts[:-2]
        ancestors.append("/".join(parts))
    return ancestors


def _looks_like_resource(uid: str, provider: Provider) -> bool:
    if provider is Provider.AWS:
        return uid.startswith("arn:")
    return bool(_ARM_ID.match(uid))


def _state(status: str) -> RuleState:
    status = status.upper()
    if status == "FAIL":
        return RuleState.FAIL
    if status == "PASS":
        return RuleState.PASS
    # MANUAL: Prowler knows the question and cannot answer it from the API.
    return RuleState.UNKNOWN


def _evidence(result: dict[str, Any], version: str) -> dict[str, Any]:
    details = str(result.get("resource_details") or "")
    return {
        "engine": "prowler",
        "prowler_version": version,
        "check_id": result.get("check_id"),
        "status": result.get("status"),
        "status_extended": result.get("status_extended"),
        "resource_uid": result.get("resource_uid"),
        "resource_name": result.get("resource_name"),
        "region": result.get("region"),
        **({"details": details[:500]} if details else {}),
    }


def _supplementary(result: dict[str, Any], entry: PostureCheck) -> CloudResource:
    """An asset Prowler reported on and the native collectors did not list.

    Always ``UNKNOWN`` in type, whatever Prowler calls it. A typed asset would
    be matched by native rules, which would then evaluate metadata this asset
    does not carry and answer UNKNOWN -- or worse -- for every one of them.
    """
    uid = str(result["resource_uid"])
    return CloudResource(
        provider_resource_id=uid,
        resource_type=ResourceType.UNKNOWN,
        name=str(result.get("resource_name") or _tail(uid)),
        provider=entry.provider,
        region=str(result.get("region") or "") or None,
        metadata={
            "source": "prowler",
            "prowler_resource_type": entry.resource_type,
            "tags": result.get("resource_tags") or {},
        },
    )


def read(
    assessments: list[StoredAssessment],
    states: dict[UUID | None, NormalizedState],
    merged: NormalizedState,
) -> AssessmentReading:
    """Interpret every stored run against the normalized state.

    ``states`` is each scope's normalized state, keyed by account id with
    ``None`` for the directory. Assets Prowler reported that no collector
    listed are appended to their scope's state *and* to ``merged``, in place,
    so the stage that persists assets writes them with the rest -- which is
    why this runs before asset persistence rather than after.
    """
    catalog = load()
    reading = AssessmentReading()
    resolver = AssetResolver(merged.resources)

    for assessment in assessments:
        state = states.get(assessment.cloud_account_id)
        if assessment.engine_version != catalog.prowler_version:
            reason = (
                f"The extended checks for {assessment.scope_label} ran on Prowler "
                f"{assessment.engine_version}; this deployment reads "
                f"{catalog.prowler_version}, so their results cannot be interpreted."
            )
            _unknown_for_all(reading, assessment, state, reason)
            continue
        if assessment.fatal or assessment.content is None:
            reason = (
                f"The extended checks could not run for {assessment.scope_label}: "
                f"{assessment.fatal or 'no results were stored'}"
            )
            _unknown_for_all(reading, assessment, state, reason)
            continue
        _read_one(reading, assessment, state, merged, resolver)
    return reading


def _anchor(assessment: StoredAssessment, state: NormalizedState | None) -> CloudResource | None:
    """The asset a verdict about one account's scope as a whole is placed on.

    The account's own asset -- ``/subscriptions/<id>``, or the AWS account --
    so that "the scope" means *this* scope. Left on no asset, a scope-level
    verdict is keyed (rule, nothing), which every account in a tenant-wide scan
    shares: one subscription's FAIL and another's would be one finding, and
    one subscription's PASS would resolve another's FAIL (DECISIONS.md section
    151). The directory has no account asset and is one scope per connection,
    so its verdicts stay on none.
    """
    if assessment.cloud_account_id is None or state is None:
        return None
    return next(
        (
            resource
            for resource in state.resources
            if resource.resource_type is ResourceType.SUBSCRIPTION
        ),
        None,
    )


def _unknown_for_all(
    reading: AssessmentReading,
    assessment: StoredAssessment,
    state: NormalizedState | None,
    reason: str,
) -> None:
    anchor = _anchor(assessment, state)
    for check_id in assessment.requested:
        entry = check(check_id)
        if entry is None or not entry.enabled:
            continue
        reading.ran.add(check_id)
        reading.verdicts.append(PostureVerdict(entry, RuleState.UNKNOWN, anchor, reason))


def _read_one(
    reading: AssessmentReading,
    assessment: StoredAssessment,
    state: NormalizedState | None,
    merged: NormalizedState,
    resolver: AssetResolver,
) -> None:
    version = assessment.engine_version
    anchor = _anchor(assessment, state)
    # (check, asset id or None) -> the verdicts reached there, combined below:
    # one verdict per question per asset, whether it came from a result or
    # from what Prowler could not do.
    grouped: dict[tuple[str, str | None], list[PostureVerdict]] = {}
    # check -> every asset id (None for the scope) a result was reached on.
    reported: dict[str, set[str | None]] = {}

    def reach(verdict: PostureVerdict) -> None:
        key = (
            verdict.check.check_id,
            verdict.resource.provider_resource_id if verdict.resource else None,
        )
        grouped.setdefault(key, []).append(verdict)

    for result in assessment.results:
        check_id = str(result.get("check_id") or "")
        entry = check(check_id)
        if entry is None:
            reading.ignore("not in the catalogue")
            continue
        if not entry.enabled:
            reading.ignore("check disabled in the catalogue")
            continue
        uid = str(result.get("resource_uid") or "")
        resource = resolver.resolve(uid) if uid else None
        if (
            resource is None
            and state is not None
            and assessment.cloud_account_id is not None
            and _looks_like_resource(uid, entry.provider)
        ):
            resource = _supplementary(result, entry)
            state.resources.append(resource)
            merged.resources.append(resource)
            resolver.add(resource)
            reading.added.append(resource)

        status = str(result.get("status") or "")
        state_reached = _state(status)
        message = str(result.get("status_extended") or entry.title)
        if status.upper() == "MANUAL":
            message = f"Prowler cannot assess this from the provider's API: {message}"
        if resource is None and assessment.cloud_account_id is not None:
            if anchor is not None:
                resource = anchor
            elif state_reached is RuleState.PASS:
                # An account's result with nowhere to go -- its collection
                # failed, so there is no account asset to hold it. A PASS on no
                # asset would resolve a finding in any account of the tenant.
                state_reached = RuleState.UNKNOWN
                message = (
                    f"Prowler passed this for {assessment.scope_label}, but the "
                    f"result could not be placed on any asset Cleave read there: {message}"
                )
        reach(
            PostureVerdict(entry, state_reached, resource, message, _evidence(result, version))
        )
        reported.setdefault(check_id, set()).add(
            resource.provider_resource_id if resource else None
        )

    completed = assessment.completed
    for check_id in assessment.requested:
        entry = check(check_id)
        if entry is None or not entry.enabled:
            continue
        reading.ran.add(check_id)
        failure = assessment.check_error(check_id)
        if failure or check_id not in completed:
            reason = failure or assessment.stopped or "it did not finish"
            reach(
                PostureVerdict(
                    entry,
                    RuleState.UNKNOWN,
                    anchor,
                    f"Prowler's {check_id} did not complete for "
                    f"{assessment.scope_label}: {reason}",
                )
            )
            continue
        service_failure = assessment.service_error(entry.service)
        if not service_failure:
            continue
        # The service could not be read in full. Whatever the check said
        # stands; every asset of its kind it said nothing about is unknown,
        # and so is the scope, in case the listing itself was what failed.
        reason = (
            f"Prowler could not read everything in {entry.service} for "
            f"{assessment.scope_label}: {service_failure}"
        )
        seen = reported.get(check_id, set())
        # Where the check did say something about the scope itself, that
        # stands like any other result; the scope is unknown only where it
        # said nothing.
        if (anchor.provider_resource_id if anchor else None) not in seen:
            reach(PostureVerdict(entry, RuleState.UNKNOWN, anchor, reason))
        for resource in _inventory(state, entry):
            if resource.provider_resource_id not in seen:
                reach(PostureVerdict(entry, RuleState.UNKNOWN, resource, reason))

    for verdicts in grouped.values():
        reading.verdicts.append(_combine(verdicts))


def _inventory(state: NormalizedState | None, entry: PostureCheck) -> list[CloudResource]:
    if state is None or not entry.applies_to:
        return []
    return [
        resource
        for resource in state.resources
        if resource.provider == entry.provider and resource.resource_type in entry.applies_to
    ]


def _combine(verdicts: list[PostureVerdict]) -> PostureVerdict:
    """Several results for one check on one asset -- per region, per child
    object folded onto its parent -- as one verdict. The worst one wins."""
    if len(verdicts) == 1:
        return verdicts[0]
    worst = max(verdicts, key=lambda verdict: _PRECEDENCE[verdict.state])
    same = [verdict for verdict in verdicts if verdict.state == worst.state]
    messages = list(dict.fromkeys(verdict.message for verdict in same))
    message = " ".join(messages[:5])
    if len(messages) > 5:
        message += f" (and {len(messages) - 5} more)"
    return PostureVerdict(
        check=worst.check,
        state=worst.state,
        resource=worst.resource,
        message=message,
        evidence={
            "engine": "prowler",
            "check_id": worst.check.check_id,
            "results": [verdict.evidence for verdict in same][:EVIDENCE_LIMIT],
            "result_count": len(same),
        },
    )


# ----------------------------------------------------------------- merging


def merge(report: EvaluationReport, reading: AssessmentReading) -> list[Divergence]:
    """Fold Prowler's verdicts into the native report, and audit the overlap.

    The divergences are computed first, from the report as the native engine
    left it: once the posture verdicts are folded in, a PASS in
    ``report.passes`` could be either engine's.
    """
    divergences = _divergences(report, reading)

    rules: dict[str, ProwlerCheckRule] = {}
    for check_id in reading.ran:
        rule = rule_for_check(check_id)
        if rule is not None:
            rules[check_id] = rule
            report.coverage.setdefault(rule.rule_id, RuleCoverage(rule_id=rule.rule_id))
    report.rules_run += len(rules)

    for verdict in reading.verdicts:
        rule = rules.get(verdict.check.check_id)
        if rule is None:
            # Covered by a native rule: evidence for the audit above, not a
            # finding of its own.
            continue
        report.coverage[rule.rule_id].record(verdict.state)
        if verdict.state is RuleState.FAIL:
            report.failures.append(
                EvaluatedResult(
                    rule=rule,
                    result=RuleResult.failed(verdict.evidence, verdict.message),
                    resource=verdict.resource,
                )
            )
        elif verdict.state is RuleState.PASS:
            report.passes.append(
                (
                    rule.rule_id,
                    verdict.resource.provider_resource_id if verdict.resource else None,
                )
            )
        else:
            report.gaps.append(
                EvaluatedResult(
                    rule=rule,
                    result=RuleResult.unknown(verdict.message),
                    resource=verdict.resource,
                )
            )
    return divergences


def _native_states(report: EvaluationReport) -> dict[str, dict[str | None, RuleState]]:
    """rule id -> asset id (lower-cased, or None) -> the native verdict there."""
    states: dict[str, dict[str | None, RuleState]] = {}

    def put(rule_id: str, resource_id: str | None, state: RuleState) -> None:
        by_asset = states.setdefault(rule_id, {})
        key = resource_id.lower() if resource_id else None
        current = by_asset.get(key)
        if current is None or _PRECEDENCE[state] > _PRECEDENCE[current]:
            by_asset[key] = state

    for rule_id, resource_id in report.passes:
        put(rule_id, resource_id, RuleState.PASS)
    for failure in report.failures:
        put(
            failure.rule.rule_id,
            failure.resource.provider_resource_id if failure.resource else None,
            RuleState.FAIL,
        )
    for gap in report.gaps:
        put(
            gap.rule.rule_id,
            gap.resource.provider_resource_id if gap.resource else None,
            RuleState.UNKNOWN,
        )
    return states


_Seen = tuple[RuleState, list[str], CloudResource | None]


def _divergences(report: EvaluationReport, reading: AssessmentReading) -> list[Divergence]:
    notes = load().divergence_notes
    native = _native_states(report)

    # native rule -> asset (or None) -> worst Prowler state, the checks behind
    # it, and the asset itself.
    prowler: dict[str, dict[str | None, _Seen]] = {}
    for verdict in reading.verdicts:
        key = verdict.resource.provider_resource_id.lower() if verdict.resource else None
        for rule_id in verdict.check.covered_by:
            by_asset = prowler.setdefault(rule_id, {})
            current = by_asset.get(key)
            if current is None or _PRECEDENCE[verdict.state] > _PRECEDENCE[current[0]]:
                by_asset[key] = (verdict.state, [verdict.check.check_id], verdict.resource)
            elif verdict.state == current[0] and verdict.check.check_id not in current[1]:
                current[1].append(verdict.check.check_id)

    found: list[Divergence] = []
    for rule_id, by_asset in prowler.items():
        native_by_asset = native.get(rule_id)
        if native_by_asset is None:
            # The native rule did not run in this scan -- a provider not
            # scanned, a rule retired. Nothing to compare against.
            continue
        joined = False
        for key, (prowler_state, checks, resource) in by_asset.items():
            if key is None or key not in native_by_asset:
                continue
            joined = True
            divergence = _compare(
                rule_id, checks, resource, native_by_asset[key], prowler_state, notes
            )
            if divergence is not None:
                found.append(divergence)
        if joined:
            continue
        # The two engines never named the same asset -- an aggregate native
        # rule against per-plan checks, say. Compare what each says about the
        # scope as a whole instead.
        native_scope = max(native_by_asset.values(), key=lambda state: _PRECEDENCE[state])
        worst = max(by_asset.values(), key=lambda seen: _PRECEDENCE[seen[0]])
        divergence = _compare(rule_id, worst[1], None, native_scope, worst[0], notes)
        if divergence is not None:
            found.append(divergence)
    return found


def _compare(
    rule_id: str,
    checks: list[str],
    resource: CloudResource | None,
    native_state: RuleState,
    prowler_state: RuleState,
    notes: dict[str, str],
) -> Divergence | None:
    if native_state == prowler_state:
        return None
    if prowler_state is RuleState.UNKNOWN:
        kind = "PROWLER_UNKNOWN"
        detail = f"Cleave concluded {native_state.value}; Prowler could not tell."
    elif native_state is RuleState.UNKNOWN:
        kind = "NATIVE_UNKNOWN"
        detail = f"Prowler concluded {prowler_state.value}; Cleave could not tell."
    elif prowler_state is RuleState.FAIL:
        kind = "NATIVE_MISSED"
        detail = f"Prowler failed what {rule_id} passed."
    else:
        kind = "PROWLER_MISSED"
        detail = f"{rule_id} failed what Prowler passed."
    note = notes.get(rule_id)
    return Divergence(
        rule_id=rule_id,
        check_id=",".join(sorted(checks)),
        resource=resource,
        native_state=native_state,
        prowler_state=prowler_state,
        kind=kind,
        expected=note is not None,
        detail=f"{detail} {note}" if note else detail,
    )
