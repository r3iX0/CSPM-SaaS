"""How to make a cut (DECISIONS.md section 246).

Wherever the attack-path page shows a cut -- the fix plan, a hop being read, a
change in the simulator -- it used to stop at "what if": a cut was simulated and
never said how to make it. This answers the next question in three parts: the
change in one neutral sentence, the open findings on the link's two ends (each a
fix somebody can track), and, where the provider names exactly one thing to
remove, its commands, from the connector (``CloudConnector.cut_commands``).

The findings are the ones *on the two assets*, and are said to be that, never
"what this change resolves": a finding is about an asset's configuration, and
whether removing a role assignment also resolves a finding on the identity is
the rule's question, which only the next scan answers.
"""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.connectors.registry import get_connector_class
from app.core.enums import FindingStatus, RelationshipType, RemediationStatus, Severity
from app.core.errors import NotConfigured
from app.domain.resource import CloudResource
from app.graph import AssetGraph, PathStep
from app.graph.access import role_entries
from app.graph.severance import cut_cost, removable
from app.models.finding import Finding
from app.models.iac import IacIndex, IacIndexEntry
from app.models.remediation import RemediationTask
from app.schemas.attack_path import CutCodeOut, CutEndOut, CutFindingOut, CutFixOut
from app.services import graph as graph_service

#: Open findings listed for one cut. Two assets rarely carry more; past this the
#: asset's own page lists the rest.
FINDINGS_LIMIT = 20

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}


def _listed(names: tuple[str, ...]) -> str:
    """ "Owner", "Owner and Reader", "Owner, Reader and Contributor"."""
    if len(names) <= 1:
        return "".join(names)
    return f"{', '.join(names[:-1])} and {names[-1]}"


def cut_sentence(step: PathStep) -> str:
    """The change, said the way a person would ask for it.

    Built from the link's own facts (``graph/facts.py``) -- the role, the
    directory role, the kind of identity -- and the two assets' names. Neutral
    words only: a role is a role in every cloud (DECISIONS.md section 78).
    """
    source, target, facts = step.source.name, step.target.name, step.facts
    relationship = step.relationship
    if relationship in {RelationshipType.GRANTS_ROLE, RelationshipType.CAN_GRANT_ROLES}:
        if not facts:
            return f"Remove the role assignments that give {source} access to {target}."
        noun = "role" if len(facts) == 1 else "roles"
        return f"Remove the {_listed(facts)} {noun} from {source} on {target}."
    if relationship is RelationshipType.HAS_IDENTITY:
        return (
            f"Stop {source} running as {target}, or remove the roles {target} holds "
            "where the route goes next."
        )
    if relationship is RelationshipType.NETWORK_ACCESS:
        return f"Close the network path from {source} to {target}."
    if relationship is RelationshipType.MEMBER_OF:
        return f"Remove {source} from the group {target}."
    if relationship is RelationshipType.CAN_ACT_AS:
        reason = f" ({facts[0]})" if facts else ""
        return f"Remove what lets {source} sign in as {target}{reason}."
    if relationship is RelationshipType.CAN_TAKE_OVER:
        held = f"the {facts[0]} role" if facts else "its directory role"
        return f"Take {held} away from {source}."
    return f"Remove the link from {source} to {target}."


def _end(resource: CloudResource, asset_id: UUID | None) -> CutEndOut:
    return CutEndOut(
        id=resource.provider_resource_id,
        name=resource.name,
        resource_type=resource.resource_type,
        asset_id=asset_id,
    )


def _commands(step: PathStep) -> list[str]:
    """The provider's commands for this cut, from its connector; none for a
    provider with no connector here."""
    try:
        connector = get_connector_class(step.source.provider)
    except NotConfigured:
        return []
    return connector.cut_commands(step.source, step.relationship, step.target)


async def cut_fix(
    session: AsyncSession,
    organization_id: UUID,
    graph: AssetGraph,
    link: tuple[str, RelationshipType, str],
) -> CutFixOut | None:
    """How to make one cut; ``None`` for a link not in the estate or not removable."""
    raw_source, relationship, raw_target = link
    source, target = graph.resolve(raw_source), graph.resolve(raw_target)
    if not removable(relationship) or (source, relationship, target) not in set(graph.links()):
        return None
    step = PathStep(graph.nodes[source], relationship, graph.nodes[target])

    ids = await graph_service.asset_ids(session, organization_id, [source, target])
    names = {ids.get(source): step.source.name, ids.get(target): step.target.name}
    findings = await _open_findings(
        session, organization_id, [row for row in names if row is not None]
    )
    severed = graph.link_severance().get(graph.removal_key(source, relationship, target), ())

    return CutFixOut(
        sentence=cut_sentence(step),
        description=step.describe(),
        detail=step.detail(),
        relationship=relationship,
        source=_end(step.source, ids.get(source)),
        target=_end(step.target, ids.get(target)),
        provider=step.source.provider,
        cost=cut_cost(relationship),
        severs=len(severed),
        commands=_commands(step),
        code=await _code_homes(session, organization_id, step),
        findings=[
            CutFindingOut(
                id=finding.id,
                rule_id=finding.rule_id,
                title=finding.title,
                severity=finding.severity,
                status=finding.status,
                asset_name=names.get(finding.resource_id, ""),
                asset_id=finding.resource_id,
                tracked=tracked,
            )
            for finding, tracked in findings
        ],
    )


async def _open_findings(
    session: AsyncSession, organization_id: UUID, resource_ids: list[UUID]
) -> list[tuple[Finding, bool]]:
    """Open findings on these assets, worst first, and whether a live task tracks each."""
    if not resource_ids:
        return []
    found = sorted(
        (
            await session.execute(
                select(Finding).where(
                    Finding.organization_id == organization_id,
                    Finding.resource_id.in_(resource_ids),
                    Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_PROGRESS]),
                )
            )
        ).scalars(),
        key=lambda each: (_SEVERITY_ORDER.get(each.severity, 9), each.title),
    )[:FINDINGS_LIMIT]
    if not found:
        return []
    tracked = set(
        (
            await session.execute(
                select(RemediationTask.finding_id).where(
                    RemediationTask.organization_id == organization_id,
                    RemediationTask.finding_id.in_([each.id for each in found]),
                    RemediationTask.status != RemediationStatus.CANCELLED,
                )
            )
        ).scalars()
    )
    return [(each, each.id in tracked) for each in found]


async def _code_homes(
    session: AsyncSession, organization_id: UUID, step: PathStep
) -> list[CutCodeOut]:
    """Where the role assignments a cut removes are defined in the customer's Terraform.

    Read from the assignments the principal records at the scope (their ARM ids)
    and the organization's state index (section 229). Empty for a link that is
    not a role assignment, and for one no indexed repository defines.
    """
    if step.relationship not in {RelationshipType.GRANTS_ROLE, RelationshipType.CAN_GRANT_ROLES}:
        return []
    ids = {
        str(entry["assignment_id"]).lower()
        for entry in role_entries(step.source, step.target.provider_resource_id)
        if entry.get("assignment_id")
    }
    if not ids:
        return []
    rows = await session.execute(
        select(
            IacIndexEntry.resource_id,
            IacIndex.repository,
            IacIndex.working_directory,
            IacIndexEntry.address,
        )
        .join(IacIndex, IacIndex.id == IacIndexEntry.index_id)
        .where(
            IacIndexEntry.organization_id == organization_id,
            IacIndexEntry.resource_id.in_(ids),
        )
        .order_by(IacIndex.repository, IacIndexEntry.address)
    )
    return [
        CutCodeOut(
            assignment_id=assignment_id,
            repository=repository,
            working_directory=working_directory,
            address=address,
        )
        for assignment_id, repository, working_directory, address in rows.tuples().all()
    ]
