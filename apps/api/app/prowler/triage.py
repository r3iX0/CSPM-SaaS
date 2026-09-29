"""Case files for triaging a divergence between the two engines.

``engine_divergences`` says *that* a native rule and its Prowler counterpart
disagreed (DECISIONS.md section 150). Deciding *which one is wrong* needs
everything each engine read and said, side by side: the asset as the native
rule saw it, the rule's own verdict and evidence, Prowler's results and what its
check claims to test, and what ``curation.json`` already says about the pair.
This module assembles that, and nothing else.

It is the deterministic half of an agentic workflow (DECISIONS.md section 167,
``docs/AGENTIC_WORKFLOWS.md`` section 3.1). An agent -- or a person -- reads a
case and proposes a fix; :func:`replay` then re-runs both engines over the same
captures and says whether the divergence is gone. The model judges; this code
only ever reports, so it holds to the rules the engine does: pure, no network,
no database, no model.

What leaves this module is normalized and redacted. A case is meant to be read
by a model, and a raw capture holds app settings, connection strings and SAS
URLs; normalized metadata is what a rule reads, and even that passes through
:func:`redact` first.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import pathlib
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID, uuid4

from app.connectors.base import NormalizedState, RawSnapshot
from app.connectors.registry import get_connector
from app.core.enums import CollectionScope, RuleScope, RuleState
from app.domain.resource import CloudResource
from app.prowler.catalog import load
from app.prowler.ingest import (
    AssessmentReading,
    Divergence,
    PostureVerdict,
    StoredAssessment,
    merge,
    read,
)
from app.rules.base import RuleContext, RuleResult, SecurityRule
from app.rules.engine import EvaluationReport, RuleEngine
from app.rules.registry import get_rule
from app.services.scan.assets import group_edges

_APP_ROOT = pathlib.Path(__file__).resolve().parents[1]

# A model cannot use a thousand results, and a large estate would fill its
# context with them. Each list in a case says how many it left out.
MAX_RESULTS = 20

# How a triage can end. The skill that drives the agent asks for exactly one of
# these, so a report is something a person can sort rather than prose to read.
TRIAGE_VERDICTS: dict[str, str] = {
    "NATIVE_BUG": (
        "The native rule reached the wrong verdict over evidence it read correctly. "
        "Fix the rule and add a fixture that reproduces the case."
    ),
    "NORMALIZER_GAP": (
        "The native rule was right about what it was given, but the normalizer "
        "dropped or misread a field the provider returned. Fix the normalizer."
    ),
    "PROWLER_WRONG": (
        "Prowler's check reached the wrong verdict for this asset, or reads less "
        "than Cleave does. Record the pair as expected with a divergence note, "
        "and consider reporting it upstream."
    ),
    "DIFFERENT_QUESTION": (
        "Both engines are right: the check and the rule ask related but different "
        "questions. Record a divergence note in curation.json."
    ),
    "WRONG_PAIRING": (
        "The check does not answer the rule's question at all. Remove it from the "
        "rule's covered_by in curation.json, so it raises findings of its own."
    ),
    "JOIN_ERROR": (
        "The engines are describing different assets: AssetResolver joined "
        "Prowler's id to the wrong one, or the comparison fell back to the scope."
    ),
    "EVIDENCE_GAP": (
        "One engine could not tell for a reason outside either engine's logic: a "
        "denied listing, a missing permission, a capture pruned. No code change; "
        "say what access or data would settle it."
    ),
    "NEEDS_HUMAN": (
        "The case file does not hold enough to decide. Say exactly what is missing."
    ),
}

# Where to look first, by which way round the engines disagreed. Ordered: the
# cheapest hypothesis to rule out comes first.
HYPOTHESES: dict[str, tuple[str, ...]] = {
    "NATIVE_MISSED": (
        "Does the asset's normalized metadata show the setting Prowler failed? "
        "If it shows the passing value, Prowler is wrong or reads something else.",
        "Does the rule read every field the check's description names? A field "
        "the rule never reads is a NORMALIZER_GAP or a NATIVE_BUG.",
        "Does the check test a stricter or broader condition than the rule's "
        "description? Then it is DIFFERENT_QUESTION or WRONG_PAIRING.",
        "Did Prowler name a child resource (a key, a container, a database) that "
        "joined onto this parent? Then compare against the child, not the parent.",
    ),
    "PROWLER_MISSED": (
        "Does the native rule's evidence quote the field and value it failed on, "
        "and does the asset's metadata agree? Then the native verdict stands.",
        "Does the rule fail on a condition the check does not test? Then it is "
        "DIFFERENT_QUESTION, or the rule is stricter than its description.",
        "Could the rule be reading a stale or defaulted value -- a field absent "
        "from the capture that the normalizer filled in?",
    ),
    "NATIVE_UNKNOWN": (
        "Which evidence key did the rule lack? A collection error on it is an "
        "EVIDENCE_GAP; a key the capture holds but the rule could not read is a "
        "NORMALIZER_GAP.",
    ),
    "PROWLER_UNKNOWN": (
        "Was Prowler's result MANUAL, or did its service or check error? Either "
        "is an EVIDENCE_GAP unless the check can never decide this asset, which "
        "is WRONG_PAIRING.",
    ),
}

_SECRET_KEY = re.compile(
    r"(^|_)(secret|password|passwd|token|connection_?strings?|sas(_?token|_?url)?|"
    r"credentials?|private_?key|account_?key|access_?key|api_?key|app_?settings)$",
    re.IGNORECASE,
)
_SECRET_VALUE = re.compile(
    r"(AccountKey=|SharedAccessSignature=|[?&]sig=|-{5}BEGIN [A-Z ]*PRIVATE KEY|"
    r"AKIA[0-9A-Z]{16}|Password=)",
    re.IGNORECASE,
)
REDACTED = "[redacted]"


def redact(value: Any, key: str = "") -> Any:
    """A copy of ``value`` with anything credential-shaped replaced.

    Only strings are replaced. A key named like a secret whose value is a
    boolean -- ``allow_shared_key_access: true`` -- is a setting, and the
    setting is what a triage needs to see.
    """
    if isinstance(value, dict):
        return {k: redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(item, key) for item in value]
    if isinstance(value, str) and (_SECRET_KEY.search(key) or _SECRET_VALUE.search(value)):
        return REDACTED
    return value


# ------------------------------------------------------------------ replay


@dataclass
class Replay:
    """Both engines run over stored captures, exactly as ANALYZE runs them."""

    context: RuleContext
    report: EvaluationReport
    reading: AssessmentReading
    divergences: list[Divergence]


def replay(snapshot: dict[str, Any], runs: Iterable[dict[str, Any]]) -> Replay:
    """Re-run the native engine and interpret Prowler's runs over one capture.

    ``snapshot`` is a stored ``RawSnapshot`` (its ``to_json`` form). Each run is
    what the scanner stores in ``assessment_captures``: ``content`` holding
    ``requested``, ``completed`` and ``results``, with optional
    ``engine_version`` (default: the catalogue's release), ``outcome`` and
    ``errors``, and ``scope`` -- ``account`` for the capture's subscription,
    ``directory`` for the tenant.

    One capture at a time, which is what a triage needs; ANALYZE's merging of
    several subscriptions is not reproduced here.
    """
    raw = RawSnapshot.from_json(snapshot)
    connector = get_connector(
        raw.provider,
        tenant_id=raw.tenant_id,
        subscription_id=raw.subscription_id,
        provider_ref={},
    )
    state = connector.normalize(raw)
    account: UUID | None = None if raw.scope is CollectionScope.DIRECTORY else uuid4()
    # ``read`` appends assets only Prowler saw to both the scope's state and the
    # merged one, so the two must be distinct objects over the same contents.
    merged = NormalizedState(
        resources=list(state.resources),
        relationships=list(state.relationships),
        collection_errors=dict(state.collection_errors),
        controls=dict(state.controls),
    )
    catalog = load()
    assessments = [
        StoredAssessment(
            cloud_account_id=None if run.get("scope") == "directory" else account,
            provider=raw.provider,
            engine_version=str(run.get("engine_version") or catalog.prowler_version),
            outcome=str(run.get("outcome") or "COMPLETE"),
            errors=dict(run.get("errors") or {}),
            content=run.get("content"),
            scope_label=str(run.get("scope_label") or "the replayed capture"),
        )
        for run in runs
    ]
    reading = read(assessments, {account: state, None: state}, merged)
    context = RuleContext(
        resources=merged.resources,
        relationships=group_edges(merged),
        collection_errors=merged.collection_errors,
        controls=merged.controls,
    )
    report = RuleEngine().evaluate(context)
    divergences = merge(report, reading)
    return Replay(context=context, report=report, reading=reading, divergences=divergences)


# ------------------------------------------------------------------- cases


@dataclass
class DivergenceCase:
    """Everything needed to decide one divergence, and nothing that is not."""

    case_id: str
    kind: str
    expected: bool
    detail: str
    rule: dict[str, Any]
    asset: dict[str, Any] | None
    native: list[dict[str, Any]]
    prowler: list[dict[str, Any]]
    hypotheses: list[str]
    omitted: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "kind": self.kind,
            "expected": self.expected,
            "detail": self.detail,
            "rule": self.rule,
            "asset": self.asset,
            "native": self.native,
            "prowler": self.prowler,
            "hypotheses": self.hypotheses,
            "omitted": self.omitted,
            "verdicts": TRIAGE_VERDICTS,
        }


def case_id(rule_id: str, check_id: str, resource_id: str | None) -> str:
    """Stable across replays, so a report can name the case it settled."""
    key = f"{rule_id}|{check_id}|{(resource_id or '').lower()}"
    return hashlib.sha256(key.encode()).hexdigest()[:12]


def build_cases(result: Replay, *, include_expected: bool = False) -> list[DivergenceCase]:
    """One case per divergence, unexpected ones first."""
    cases = [
        _case(divergence, result.context, result.reading)
        for divergence in result.divergences
        if include_expected or not divergence.expected
    ]
    return sorted(cases, key=lambda case: (case.expected, case.rule["rule_id"], case.case_id))


def _case(
    divergence: Divergence, context: RuleContext, reading: AssessmentReading
) -> DivergenceCase:
    rule = get_rule(divergence.rule_id)
    checks = divergence.check_id.split(",")
    resource = divergence.resource

    native = _native_results(rule, resource, context) if rule is not None else []
    verdicts = [
        verdict
        for verdict in reading.verdicts
        if verdict.check.check_id in checks and _same_asset(verdict, resource)
    ]
    return DivergenceCase(
        case_id=case_id(
            divergence.rule_id,
            divergence.check_id,
            resource.provider_resource_id if resource else None,
        ),
        kind=divergence.kind,
        expected=divergence.expected,
        detail=divergence.detail,
        rule=_rule_facts(rule, divergence.rule_id),
        asset=_asset_facts(resource),
        native=native[:MAX_RESULTS],
        prowler=[_verdict_facts(verdict) for verdict in verdicts[:MAX_RESULTS]],
        hypotheses=list(HYPOTHESES.get(divergence.kind, ())),
        omitted={
            name: count - MAX_RESULTS
            for name, count in (("native", len(native)), ("prowler", len(verdicts)))
            if count > MAX_RESULTS
        },
    )


def _same_asset(verdict: PostureVerdict, resource: CloudResource | None) -> bool:
    if resource is None:
        # A scope-level divergence: every verdict of the check is evidence.
        return True
    if verdict.resource is None:
        return False
    return verdict.resource.provider_resource_id.lower() == resource.provider_resource_id.lower()


def _native_results(
    rule: SecurityRule, resource: CloudResource | None, context: RuleContext
) -> list[dict[str, Any]]:
    """The rule's own verdict and evidence, re-derived from the same context.

    The report keeps only ids for a PASS, so the evidence behind one is read
    again here. A rule is deterministic over its context, so this is the verdict
    ANALYZE reached, not a new one. Errors are caught exactly as the engine
    catches them: a rule that raises is UNKNOWN.
    """
    scope_level = rule.scope is RuleScope.AGGREGATE
    try:
        outcome = rule.evaluate(None if scope_level else resource, context)
    except Exception as exc:
        outcome = RuleResult.unknown(f"Rule {rule.rule_id} raised {type(exc).__name__}: {exc}")
    results = [outcome] if isinstance(outcome, RuleResult) else list(outcome)
    if scope_level and resource is not None:
        wanted = resource.provider_resource_id.lower()
        results = [r for r in results if (r.resource_id or "").lower() == wanted] or results
    return [
        {
            "state": r.state.value,
            "message": r.message,
            "resource_id": r.resource_id,
            "evidence": redact(r.evidence or {}),
        }
        for r in results
    ]


def _rule_facts(rule: SecurityRule | None, rule_id: str) -> dict[str, Any]:
    catalog = load()
    covered = sorted(
        check.check_id for check in catalog.checks.values() if rule_id in check.covered_by
    )
    facts: dict[str, Any] = {
        "rule_id": rule_id,
        "covered_by_checks": covered,
        "divergence_note": catalog.divergence_notes.get(rule_id),
    }
    if rule is None:
        facts["missing"] = "no native rule is registered under this id"
        return facts
    facts.update(
        {
            "name": rule.name,
            "description": rule.description,
            "severity": rule.severity.value,
            "scope": rule.scope.value,
            "requires_evidence": [str(key) for key in rule.requires_evidence],
            "source": _source_of(rule),
        }
    )
    return facts


def _source_of(rule: SecurityRule) -> str | None:
    """``app/rules/...py:LINE`` for the rule's class, where it can be found."""
    try:
        path = pathlib.Path(inspect.getsourcefile(type(rule)) or "")
        _, line = inspect.getsourcelines(type(rule))
    except (OSError, TypeError):
        return None
    try:
        relative = path.resolve().relative_to(_APP_ROOT.parent)
    except ValueError:
        relative = path
    return f"{relative}:{line}"


def _asset_facts(resource: CloudResource | None) -> dict[str, Any] | None:
    if resource is None:
        return None
    return {
        "provider_resource_id": resource.provider_resource_id,
        "resource_type": resource.resource_type.value,
        "name": resource.name,
        "provider": resource.provider.value,
        "region": resource.region,
        "metadata": redact(resource.metadata),
    }


def _verdict_facts(verdict: PostureVerdict) -> dict[str, Any]:
    check = verdict.check
    return {
        "check_id": check.check_id,
        "title": check.title,
        "description": check.description,
        "risk": check.risk,
        "severity": check.severity.value,
        "state": verdict.state.value,
        "message": verdict.message,
        "resource_id": verdict.resource.provider_resource_id if verdict.resource else None,
        "evidence": redact(verdict.evidence),
    }


# ---------------------------------------------------------------- rendering


def render_markdown(case: DivergenceCase) -> str:
    """The case as a person or a model reads it: one page, verdicts last."""
    rule = case.rule
    checks = sorted({p["check_id"] for p in case.prowler}) or ["(no Prowler result here)"]
    lines = [
        f"# Divergence {case.case_id}: {rule['rule_id']} vs {', '.join(checks)}",
        "",
        f"- **Kind:** {case.kind}{' (expected)' if case.expected else ''}",
        f"- **Detail:** {case.detail}",
        f"- **Rule:** {rule.get('name', rule.get('missing'))} -- `{rule.get('source')}`",
        f"- **Rule reads:** {', '.join(rule.get('requires_evidence') or []) or 'nothing declared'}",
        f"- **Checks covering this rule:** {', '.join(rule['covered_by_checks']) or 'none'}",
        f"- **Divergence note:** {rule['divergence_note'] or 'none'}",
        "",
        "## Asset (normalized, redacted)",
        "",
        _json_block(case.asset) if case.asset else "Scope-level: no asset both engines named.",
        "",
        "## Native verdict",
        "",
        _json_block(case.native),
        "",
        "## Prowler verdicts",
        "",
        _json_block(case.prowler),
        "",
        "## Where to look first",
        "",
        *[f"{n}. {text}" for n, text in enumerate(case.hypotheses, 1)],
        "",
        "## Verdicts to choose from",
        "",
        *[f"- **{name}** -- {text}" for name, text in TRIAGE_VERDICTS.items()],
    ]
    if case.omitted:
        lines += ["", f"_Omitted beyond {MAX_RESULTS}: {case.omitted}_"]
    return "\n".join(lines) + "\n"


def _json_block(value: Any) -> str:
    return "```json\n" + json.dumps(value, indent=2, sort_keys=True, default=str) + "\n```"


def summary(result: Replay) -> dict[str, Any]:
    """Counts a caller can gate on: unexpected divergences are the signal."""
    unexpected = [d for d in result.divergences if not d.expected]
    return {
        "divergences": len(result.divergences),
        "unexpected": len(unexpected),
        "expected": len(result.divergences) - len(unexpected),
        "by_kind": {
            kind: sum(1 for d in unexpected if d.kind == kind)
            for kind in sorted({d.kind for d in unexpected})
        },
        "native_failures": len(result.report.failures),
        "prowler_verdicts": len(result.reading.verdicts),
        "prowler_states": {
            state.value: sum(1 for v in result.reading.verdicts if v.state is state)
            for state in RuleState
        },
    }
