"""A rule as the rules page and a finding's detail show it (DECISIONS.md section 157)."""

from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field

from app.core.enums import Severity
from app.remediation.spec import Comparison

# -- What "fixed" means --------------------------------------------------------


class _StateBase(BaseModel):
    field: str
    describes: str
    #: A value that satisfies it, where one says more than the comparison does.
    example: Any = None


class EqualsStateOut(_StateBase):
    """A setting that must hold one value, or one of a few."""

    comparison: Literal[Comparison.EQUALS]
    # Present only here, because only here is it a value: a collection
    # expectation serialized with ``equals: null`` would read as "this must be
    # null" rather than "this must not be empty".
    equals: Any
    also_accepts: list[Any]


class CollectionStateOut(_StateBase):
    """A statement about a collection: none of it matches, or it is not empty."""

    comparison: Literal[Comparison.NONE_MATCHING, Comparison.NOT_EMPTY]


ExpectedStateOut = Annotated[
    EqualsStateOut | CollectionStateOut, Field(discriminator="comparison")
]


class TerraformHintOut(BaseModel):
    """The argument to set, for a customer who manages this in code."""

    attribute: str
    #: Written as HCL: quoted strings, ``true``/``false``, ``null``.
    value: str
    describes: str


class RemediationSpecOut(BaseModel):
    """What must become true, and the artifacts generated from that one statement."""

    expected_state: list[ExpectedStateOut]
    #: Who the expectation is about, where it is not everyone.
    applies_when: dict[str, Any]
    cli: list[str]
    terraform: list[TerraformHintOut]
    #: An Azure Policy definition, where a policy can genuinely refuse this
    #: misconfiguration; ``None`` where none can. Azure's document format, left
    #: open rather than restated.
    azure_policy: dict[str, Any] | None
    enforceable: bool
    notes: str


# -- The second engine ---------------------------------------------------------


class ProwlerRemediationOut(BaseModel):
    """Prowler's own remediation code, kept apart from the prose on findings."""

    cli: str
    terraform: str
    native_iac: str
    other: str
    url: str


class ProwlerCheckOut(BaseModel):
    """A Prowler rule: which check, which release."""

    check_id: str
    service: str
    prowler_version: str
    resource_type: str
    categories: list[str]
    remediation: ProwlerRemediationOut
    additional_urls: list[str]


class ProwlerCrossCheckOut(BaseModel):
    """A native rule some Prowler checks answer too, and why they may disagree."""

    cross_checked_by: list[str]
    divergence_note: str | None


#: No field says which: the two share no key, and each has keys the other lacks.
ProwlerDetailOut = ProwlerCheckOut | ProwlerCrossCheckOut


# -- The rule ------------------------------------------------------------------


class RuleOut(BaseModel):
    """A row of the ``rules`` mirror, with what only the registry can say.

    The mirror's own columns are plain strings, severity aside: a rule removed
    from the registry stays in the mirror disabled, and a value renamed since
    would otherwise turn the whole list into a 500.
    """

    rule_id: str
    name: str
    description: str
    category: str
    provider: str
    severity: Severity
    version: str
    exploitability: int
    scope: str
    applies_to: list[str]
    enabled: bool
    remediation: str
    rationale: str
    estimated_effort_minutes: int
    compliance_mappings: dict[str, list[str]]
    # Read from the registry rather than the mirror, because it is code, not a
    # row: a policy stored in the database could outlive the rule that
    # generated it. ``None`` for a rule with no declaration yet.
    remediation_spec: RemediationSpecOut | None
    engine: str
    engine_version: str | None
    prowler: ProwlerDetailOut | None
