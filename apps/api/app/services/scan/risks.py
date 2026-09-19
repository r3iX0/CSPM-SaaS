"""What a risk row should contain, for one finding or for a group of them.

Pure decisions about the row, apart from adding a new one to the session and
deleting the ones a group supersedes. The caller reads every existing risk
once and passes it in, so nothing here queries.
"""

from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import Level
from app.domain.resource import CloudResource
from app.models.finding import Finding
from app.models.risk import Risk
from app.risk.scorer import ScoredRisk
from app.risk.triage import finding_risk_status
from app.rules.base import SecurityRule

# One failing check, everything the risk layer needs to write it down:
# the finding row, the rule that raised it, the asset it is about, the score,
# and the sentence. Named because two things now consume it -- a risk per
# finding, and a risk per group of them.
PendingFinding = tuple[Finding, SecurityRule, CloudResource | None, ScoredRisk, str]


def group_key(rule_id: str) -> str:
    """What makes a rule's group risk the same risk between scans.

    Reuses ``scenario_key`` -- the column that already answers "what
    identifies a risk that is not identified by a single finding" -- and
    namespaces itself for the same reason the escalation template does: the
    unique index covers (organization, key) across every kind.
    """
    return f"group:{rule_id}"


async def upsert_group_risk(
    session: AsyncSession,
    org_id: UUID,
    members: list[PendingFinding],
    *,
    existing: Risk | None,
    linked_risks: dict[UUID, Risk],
    risk_by_finding: dict[UUID, UUID],
) -> list[tuple[Risk, Finding]]:
    """One risk for a rule that groups, with every failing asset in it.

    Scored as the worst member, exactly as a scenario is: a group cannot be
    less serious than the most serious thing in it, and it must not be more
    serious either -- forty accounts missing MFA is one policy that was
    never written, not forty times the problem. Summing them would be the
    arithmetic that pins a security score at zero over a single mistake,
    which is the reason this exists.

    The breakdown is the worst member's, so "why is this 84?" still names
    real components measured on a real asset rather than an average of
    forty. What the group adds is the count, which is in the title.

    Returns the (risk, finding) pairs still needing a junction row.
    """
    rule = members[0][1]
    grouping = rule.risk_grouping
    assert grouping is not None  # only rules that declare one reach here

    worst_finding, _, worst_resource, worst_scored, _ = max(
        members, key=lambda entry: entry[3].score
    )

    # Risks each member used to have to itself, from before this rule
    # grouped -- or from before the declaration was added. Deleted rather
    # than resolved, which is the opposite of what happens to a route that
    # closes, and for the opposite reason: nothing here ended. The same
    # accounts are still failing the same check, and a resolved duplicate
    # would show a customer a fixed MFA risk sitting beside an open one for
    # the same people. The findings keep every event they ever had.
    key = group_key(rule.rule_id)
    for finding, *_ in members:
        superseded = risk_by_finding.get(finding.id)
        if superseded is None:
            continue
        risk = linked_risks.get(superseded)
        if risk is not None and risk.scenario_key != key:
            await session.delete(risk)
            linked_risks.pop(superseded, None)
            risk_by_finding.pop(finding.id, None)

    risk = upsert_risk(
        session,
        org_id,
        worst_finding,
        rule,
        worst_resource,
        worst_scored,
        grouping.title(len(members)),
        existing,
    )
    risk.scenario_key = key
    # One row for every member, so the sentence is the rule's, not the
    # worst member's -- which would name one asset on a row about forty.
    risk.description = rule.rationale or rule.description
    # Every member has a say, not only the worst one the row was scored from.
    risk.status = finding_risk_status(
        [finding.status for finding, *_ in members], risk.status
    )

    # A risk being inserted has no id yet, so every member needs a link.
    # An existing one keeps the links it already has.
    return [
        (risk, finding)
        for finding, *_ in members
        if risk.id is None or risk_by_finding.get(finding.id) != risk.id
    ]


def upsert_risk(
    session: AsyncSession,
    org_id: UUID,
    finding: Finding,
    rule: SecurityRule,
    resource: CloudResource | None,
    scored: ScoredRisk,
    title: str,
    risk: Risk | None,
) -> Risk:
    """One risk per finding for the MVP, joined through ``risk_findings``.

    Grouping several findings into a single risk later is a change in this
    method, not a migration -- which is exactly why the junction table is
    there from the start (RISK_ENGINE.md section 2).

    ``risk`` is passed in rather than looked up: the caller reads every
    existing risk for the organization once, so this stays a pure decision
    about what the row should contain.
    """
    values = {
        "title": title,
        # What was found on this asset, not why the rule exists. The
        # rationale is the same sentence on every row a rule raises, so a
        # queue of them read as one row repeated; the finding's own
        # message names the asset and what it holds.
        "description": finding.description or rule.rationale or rule.description,
        "risk_score": scored.score,
        "risk_level": scored.level,
        "known_risk_level": scored.known_level,
        "severity": rule.severity.value,
        "asset_criticality": resource.criticality if resource else Level.UNKNOWN,
        "data_sensitivity": resource.data_sensitivity if resource else Level.UNKNOWN,
        "internet_exposure": resource.public_exposure if resource else Level.UNKNOWN,
        # From the scored inputs, not from the rule: the two differ whenever
        # a result stepped its own exploitability down, and reading the
        # class tag here would show a number the score was not computed
        # from on the one page that exists to explain the score.
        "exploitability": scored.inputs.exploitability,
        "business_impact": scored.business_impact,
        "score_breakdown": scored.breakdown,
    }

    if risk is None:
        # Fully populated before the flush: several of these columns are
        # NOT NULL, so an empty insert would never reach the database.
        risk = Risk(organization_id=org_id, **values)
        session.add(risk)
    else:
        for key, value in values.items():
            setattr(risk, key, value)

    # From the finding rather than forced to OPEN. Every scan used to reset
    # this whenever the finding was open *or in progress*, so a risk marked
    # in progress was back in the untriaged queue the next morning.
    risk.status = finding_risk_status([finding.status], risk.status)
    if finding.status.is_open:
        risk.resolved_at = None

    return risk
