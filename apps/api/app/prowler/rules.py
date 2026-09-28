"""Each enabled Prowler check, registered as a rule Cleave can raise findings for.

A Prowler verdict has to become a finding, a risk, a compliance citation and a
verification exactly as a native one does, or the second engine is a second
product bolted beside the first. The cheapest way to guarantee that is to give
every check the shape the rest of the pipeline already consumes: a
:class:`SecurityRule`. ``persist_findings`` reads ``rule.severity`` and
``rule.remediation``; the compliance view reads ``compliance_mappings`` off the
``rules`` mirror; nothing downstream needs to know which engine it is holding.

What differs is who evaluates. :meth:`ProwlerCheckRule.matches` is always false
and :meth:`ProwlerCheckRule.evaluate` answers UNKNOWN, so handing one of these to
the native engine by mistake produces no verdict rather than a wrong one. The
real verdicts are built in ``app/prowler/ingest.py`` from the scanner's capture.

One class per check, built at import. The base class declares its metadata as
class variables -- ``applies_to``, ``compliance_mappings`` -- so an instance
attribute would be a second, silently shadowing copy of each.
"""

import re
from functools import lru_cache
from typing import ClassVar

from app.compliance.catalog import FRAMEWORKS
from app.core.enums import RuleEngineKind, RuleScope
from app.domain.resource import CloudResource
from app.prowler.catalog import PostureCheck, enabled_checks, load
from app.rules.base import RuleContext, RuleResult, SecurityRule

# Minutes of work a customer should budget per fix. Prowler does not estimate
# effort; this is the same default a native rule gets when its author did not.
DEFAULT_EFFORT_MINUTES = 30

_FENCE = re.compile(r"^```[a-zA-Z0-9]*\n?|\n?```$", re.MULTILINE)


class ProwlerCheckRule(SecurityRule):
    """A Prowler check, as the rest of Cleave sees rules."""

    engine: ClassVar[RuleEngineKind] = RuleEngineKind.PROWLER
    check: ClassVar[PostureCheck]

    def matches(self, resource: CloudResource) -> bool:
        return False

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult:
        return RuleResult.unknown(
            f"{self.rule_id} is evaluated by the scanner service, not by the rule engine."
        )


def _plain(text: str) -> str:
    """Prowler's markdown, reduced to what reads as prose in a finding."""
    return _FENCE.sub("", text).replace("**", "").strip()


def remediation_text(check: PostureCheck) -> str:
    """The guidance snapshot-copied onto each finding this check raises."""
    parts = [_plain(check.remediation.text) or _plain(check.description)]
    if check.remediation.cli:
        parts.append("From the command line:\n" + _plain(check.remediation.cli))
    if check.remediation.url:
        parts.append(f"Reference: {check.remediation.url}")
    return "\n\n".join(part for part in parts if part)


def _known_controls() -> dict[str, frozenset[str]]:
    return {
        framework.id: frozenset(control.id for control in framework.controls)
        for framework in FRAMEWORKS
    }


def _mappings(check: PostureCheck, known: dict[str, frozenset[str]]) -> dict[str, list[str]]:
    """This check's mappings, kept to controls Cleave's catalogue lists.

    The builder translates Prowler's ids into Cleave's spelling; this drops any
    that still name nothing. A mapping onto a control no framework defines
    would count toward a coverage number whose denominator never included it.
    """
    kept: dict[str, list[str]] = {}
    for framework_id, ids in check.compliance.items():
        controls = known.get(framework_id)
        if not controls:
            continue
        matched = sorted(control for control in ids if control in controls)
        if matched:
            kept[framework_id] = matched
    return kept


def _rule_class(check: PostureCheck, version: str, known: dict[str, frozenset[str]]) -> type:
    return type(
        f"Prowler_{check.check_id}",
        (ProwlerCheckRule,),
        {
            "check": check,
            "rule_id": check.rule_id,
            "name": check.title,
            "description": _plain(check.description),
            "category": check.service,
            "provider": check.provider,
            "severity": check.severity,
            # The Prowler release, so a finding says which version of the check
            # raised it -- the same job ``rule_version`` does for a native rule.
            "version": version,
            "exploitability": check.exploitability,
            "scope": RuleScope.PER_RESOURCE,
            "applies_to": list(check.applies_to),
            "remediation": remediation_text(check),
            "rationale": _plain(check.risk),
            "estimated_effort_minutes": DEFAULT_EFFORT_MINUTES,
            "compliance_mappings": _mappings(check, known),
        },
    )


@lru_cache(maxsize=1)
def prowler_rules() -> tuple[ProwlerCheckRule, ...]:
    """Every enabled check a native rule does not already answer, as a rule.

    A check with ``covered_by`` is not registered: the native rule is the
    finding, and the check's verdict is compared against it instead
    (``app/prowler/ingest.py``). Registering both would raise two findings for
    one misconfiguration, worded by two engines.
    """
    version = load().prowler_version
    known = _known_controls()
    return tuple(
        _rule_class(check, version, known)()
        for check in sorted(enabled_checks(), key=lambda entry: entry.rule_id)
        if not check.covered_by
    )


@lru_cache(maxsize=1)
def inherited_mappings() -> dict[str, dict[str, list[str]]]:
    """Controls a native rule answers because the checks it covers do.

    A native rule's own mappings were written by hand against the frameworks
    Cleave had then. The Prowler checks it covers are mapped to frameworks that
    came later -- NIS2, HIPAA, the current CIS benchmarks -- and a question the
    native rule answers is evidence toward those controls too.

    Two limits keep that from overclaiming. A framework the native rule already
    maps keeps its hand-written mapping: that was a judgement, and this is not.
    And a pair recorded as disagreeing by design (``divergence_notes``) passes
    nothing on, because the two are not answering quite the same question.
    """
    catalog = load()
    known = _known_controls()
    inherited: dict[str, dict[str, list[str]]] = {}
    for check in enabled_checks():
        for rule_id in check.covered_by:
            if rule_id in catalog.divergence_notes:
                continue
            target = inherited.setdefault(rule_id, {})
            for framework_id, controls in _mappings(check, known).items():
                merged = set(target.get(framework_id, [])) | set(controls)
                target[framework_id] = sorted(merged)
    return inherited


def compliance_mappings_for(rule: SecurityRule) -> dict[str, list[str]]:
    """A rule's mappings as the compliance view should see them.

    A Prowler rule's own. A native rule's own, plus what it inherits for the
    frameworks it does not map itself (:func:`inherited_mappings`).
    """
    own = {framework: list(ids) for framework, ids in rule.compliance_mappings.items()}
    if rule.engine is not RuleEngineKind.NATIVE:
        return own
    for framework_id, controls in inherited_mappings().get(rule.rule_id, {}).items():
        own.setdefault(framework_id, controls)
    return own


@lru_cache(maxsize=1)
def _by_check() -> dict[str, ProwlerCheckRule]:
    return {rule.check.check_id: rule for rule in prowler_rules()}


@lru_cache(maxsize=1)
def _by_rule_id() -> dict[str, ProwlerCheckRule]:
    return {rule.rule_id: rule for rule in prowler_rules()}


def rule_for_check(check_id: str) -> ProwlerCheckRule | None:
    return _by_check().get(check_id)


def get_prowler_rule(rule_id: str) -> ProwlerCheckRule | None:
    return _by_rule_id().get(rule_id)


def prowler_detail(rule_id: str) -> dict | None:
    """What the rules page says about the second engine for one rule.

    For a Prowler rule: which check, which release, and Prowler's own
    remediation code -- the CLI, Terraform and native templates, kept apart
    from the prose snapshot-copied onto findings. For a native rule the
    Prowler checks that cross-check it, and why they may disagree. ``None``
    for a native rule no check answers.
    """
    rule = get_prowler_rule(rule_id)
    if rule is not None:
        check = rule.check
        return {
            "check_id": check.check_id,
            "service": check.service,
            "prowler_version": load().prowler_version,
            "resource_type": check.resource_type,
            "categories": list(check.categories),
            "remediation": {
                "cli": check.remediation.cli,
                "terraform": check.remediation.terraform,
                "native_iac": check.remediation.native_iac,
                "other": check.remediation.other,
                "url": check.remediation.url,
            },
            "additional_urls": list(check.additional_urls),
        }
    counterparts = sorted(
        check.check_id for check in enabled_checks() if rule_id in check.covered_by
    )
    if not counterparts:
        return None
    return {
        "cross_checked_by": counterparts,
        "divergence_note": load().divergence_notes.get(rule_id),
    }
