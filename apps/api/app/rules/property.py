"""Rules that judge one setting on one kind of asset (DECISIONS.md section 174).

Most of the backlog's Tier 2 is this shape: a field the normalizer already
produced, compared with the value that is safe. Written as a class per check,
each would repeat the same forty lines -- the evidence guard, the absent case,
the evidence dict -- around one comparison, and the repetition is where a
check's guard and its declaration drift apart. So the check is declared as a
:class:`PropertySpec` and :func:`property_rule` builds the ``SecurityRule``.

Everything a hand-written rule promises still holds. The rule is registered and
mirrored like any other, degrades to UNKNOWN when its evidence failed, and
carries a remediation declaration the tests hold it to: where the safe value is
one value, the spec declares it as an expected state and
``test_remediation_spec.py`` proves that satisfying it passes and violating it
fails. What an absent field means is stated per spec, never assumed: UNKNOWN,
or a failure where the service documents that its default is the unsafe value.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, ClassVar, Literal

from app.connectors.evidence import EvidenceKey
from app.core.enums import Provider, ResourceType, Severity
from app.domain.resource import CloudResource
from app.remediation import ExpectedState, RemediationSpec
from app.rules.base import RuleContext, RuleResult, SecurityRule

_NO_POLICY = {
    Provider.AZURE: (
        "No Azure Policy definition is generated: the policy aliases for this setting "
        "have not been verified yet (DECISIONS.md section 170)."
    ),
    Provider.AWS: (
        "No AWS Config rule or service control policy is generated yet, and nothing "
        "on AWS has been read from a live account (docs/AWS_INTEGRATION.md section 1)."
    ),
}


@dataclass(frozen=True)
class PropertySpec:
    """One check of one setting.

    ``safe`` is the value that passes. ``passes`` replaces it where safety is not
    one value -- a count, a list containing something -- and then no expected
    state can be declared, so ``why_no_expected_state`` must say why.
    ``absent`` is what a field the reading did not carry means: ``unknown``, or
    ``fail`` only where the service documents an unsafe default.
    """

    rule_id: str
    name: str
    description: str
    rationale: str
    remediation: str
    cli: tuple[str, ...]
    severity: Severity
    exploitability: int
    category: str
    resource_type: ResourceType
    evidence: tuple[EvidenceKey, ...]
    field: str
    describes: str
    mappings: dict[str, list[str]]
    failure: str
    safe: Any = None
    passes: Callable[[Any], bool] | None = None
    why_no_expected_state: str = ""
    absent: Literal["unknown", "fail"] = "unknown"
    terraform_attribute: str | None = None
    terraform_value: Any = None
    # The azurerm resources ``terraform_attribute`` sits on (DECISIONS.md §184).
    terraform_resource_types: tuple[str, ...] = ()
    effort_minutes: int = 30
    # Metadata a resource must carry for the check to apply, matched as a
    # case-blind substring: ``(("kind", "functionapp"),)`` limits a check to
    # function apps, and a boolean matches as "true" or "false". Anything else is
    # NOT_APPLICABLE; a field never stated is UNKNOWN, since whether the check
    # applies is then itself unknown.
    applies_when: tuple[tuple[str, str], ...] = ()
    # The cloud the check judges. A spec is one provider's, never both (§74).
    provider: Provider = Provider.AZURE

    def __post_init__(self) -> None:
        if self.passes is None and self.safe is None:
            raise ValueError(f"{self.rule_id} states neither a safe value nor a test")
        if self.passes is not None and not self.why_no_expected_state:
            raise ValueError(f"{self.rule_id} tests a value no expected state can state")

    def applies_to_resource(self, resource: CloudResource) -> bool:
        # A stated False is "false", not blank: ``(("is_function_app", "false"),)``
        # must match a web app. Only a field never stated is blank.
        return all(
            wanted.lower()
            in (str(value).lower() if (value := resource.get(key)) is not None else "")
            for key, wanted in self.applies_when
        )

    def is_safe(self, value: Any) -> bool:
        if self.passes is not None:
            return self.passes(value)
        if isinstance(self.safe, str):
            return str(value).lower() == self.safe.lower()
        return bool(value == self.safe)


def _declaration(spec: PropertySpec) -> RemediationSpec:
    if spec.passes is not None:
        return RemediationSpec(
            expected=(),
            cli=spec.cli,
            applies_when=dict(spec.applies_when),
            notes=f"{spec.why_no_expected_state} {_NO_POLICY[spec.provider]}",
        )
    extra: dict[str, Any] = {}
    if spec.terraform_value is not None:
        extra["terraform_value"] = spec.terraform_value
    return RemediationSpec(
        expected=(
            ExpectedState(
                field=spec.field,
                equals=spec.safe,
                describes=spec.describes,
                terraform_attribute=spec.terraform_attribute,
                **extra,
            ),
        ),
        cli=spec.cli,
        applies_when=dict(spec.applies_when),
        terraform_resource_types=spec.terraform_resource_types,
        notes=_NO_POLICY[spec.provider],
    )


class PropertyRule(SecurityRule):
    """A rule built from a :class:`PropertySpec`."""

    spec: ClassVar[PropertySpec]

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        if resource is None:
            return RuleResult.not_applicable("Rule is per-resource")
        failure = context.has_collection_error(*self.requires_evidence)
        if failure:
            return RuleResult.unknown(f"Configuration unavailable: {failure}")
        # Whether the check applies can rest on a reading too -- which language
        # a site runs is in its configuration -- and a field nobody stated is
        # not an answer to it (section 177).
        unstated = [key for key, _ in self.spec.applies_when if resource.get(key) is None]
        if unstated:
            return RuleResult.unknown(
                f"Cannot tell whether the check applies: {', '.join(unstated)} not stated"
            )
        if not self.spec.applies_to_resource(resource):
            return RuleResult.not_applicable("The check does not apply to this resource")

        spec = self.spec
        value = resource.get(spec.field)
        evidence = {spec.field: value}
        if value is None and spec.absent == "unknown":
            return RuleResult.unknown(f"The reading did not state {spec.field}")
        if value is not None and spec.is_safe(value):
            return RuleResult.passed(evidence)
        return RuleResult.failed(
            evidence=evidence,
            message=f"{resource.name} {spec.failure}",
        )


def property_rule(spec: PropertySpec) -> PropertyRule:
    """The registered rule for one spec."""
    cls = type(
        f"PropertyRule_{spec.rule_id.replace('-', '_')}",
        (PropertyRule,),
        {
            "spec": spec,
            "rule_id": spec.rule_id,
            "provider": spec.provider,
            "name": spec.name,
            "description": spec.description,
            "category": spec.category,
            "severity": spec.severity,
            "exploitability": spec.exploitability,
            "applies_to": [spec.resource_type],
            "requires_evidence": spec.evidence,
            "estimated_effort_minutes": spec.effort_minutes,
            "rationale": spec.rationale,
            "remediation": spec.remediation,
            "remediation_spec": _declaration(spec),
            "compliance_mappings": spec.mappings,
        },
    )
    rule: PropertyRule = cls()
    return rule
