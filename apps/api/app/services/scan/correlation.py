"""Routes through an environment, turned into risks.

Two templates share one discipline: a route with no failing check on it
creates nothing, a route that closes is resolved rather than deleted, and a
route seen again keeps the risk it already had.
"""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select

from app.connectors.base import NormalizedState
from app.core.enums import FindingStatus, Level, RiskKind, RiskStatus, Severity
from app.domain.resource import CloudResource
from app.graph import AssetGraph, Path
from app.models.finding import Finding
from app.models.resource import ResourceRecord
from app.models.risk import Risk, RiskFinding
from app.risk.scorer import default_scorer
from app.risk.triage import route_status_on_observation
from app.services.scan.context import AnalyzeContext
from app.services.scan.scope import asset_scope
from app.services.scan.writer import ScanWriter


async def correlate_paths(
    ctx: AnalyzeContext, merged: NormalizedState, id_map: dict[str, UUID]
) -> None:
    """Turn each route through this environment into one risk.

    Five findings across a jump box, an identity and a storage account rank
    by severity and get worked top-down, which is the right order for "what
    is wrong" and the wrong one for "what is wrong together". The same five
    as a route rank by how few hops separate the internet from customer
    data, and name the one change that severs it.

    **Only where the route has at least one failing check on it.** A path
    with nothing misconfigured along it is architecture rather than a
    mistake, and minting a risk for it would mean inventing a severity for
    something no rule objected to -- the made-up number this engine exists
    to avoid.

    Built from this scan's own normalized state rather than from the
    database, so the route and the findings it groups describe one reading
    of one environment.
    """
    session, org_id = ctx.session, ctx.org_id
    graph = AssetGraph.build(merged.resources, merged.relationships)

    # Every open finding on each asset, not one of them. Keyed by asset
    # alone, a host with five failing checks kept whichever row the database
    # returned last, so the route was scored from an arbitrary member and
    # could move between scans without anything in the environment moving.
    open_findings: dict[UUID, list[Finding]] = {}
    for finding in (
        await session.execute(
            select(Finding).where(
                Finding.organization_id == org_id,
                Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_PROGRESS]),
                Finding.resource_id.is_not(None),
            )
        )
    ).scalars():
        if finding.resource_id is not None:
            open_findings.setdefault(finding.resource_id, []).append(finding)

    await _correlate_template(
        ctx,
        graph,
        id_map,
        open_findings,
        kind=RiskKind.ATTACK_PATH,
        paths=graph.attack_paths(),
    )
    # The second template. A route to an identity that can hand out roles is
    # a different question from a route to data -- not what an attacker
    # reaches, but what they could be given once they arrive -- so it is
    # correlated separately and ranks on its own.
    await _correlate_template(
        ctx,
        graph,
        id_map,
        open_findings,
        kind=RiskKind.ESCALATION,
        paths=graph.escalation_chains(),
    )
    await ctx.writer.commit()


async def _correlate_template(
    ctx: AnalyzeContext,
    graph: AssetGraph,
    id_map: dict[str, UUID],
    open_findings: dict[UUID, list[Finding]],
    *,
    kind: RiskKind,
    paths: list[Path],
) -> None:
    """One correlation template: routes of a kind, in and out of existence.

    Shared by both templates rather than written twice, because everything
    except the sentence and the score is the same discipline -- a route with
    no failing check on it creates nothing, a route that closes is resolved
    rather than deleted, and a route seen again keeps the risk it already
    had.

    A new route's risk is given its id as it is built rather than by a flush,
    so its member links can be queued for the writer straight away. Each
    route used to flush on its own to learn an id the next line needed.
    """
    session, org_id = ctx.session, ctx.org_id
    existing = {
        risk.scenario_key: risk
        for risk in (
            await session.execute(
                select(Risk).where(
                    Risk.organization_id == org_id,
                    Risk.kind == kind,
                )
            )
        )
        .scalars()
        .all()
        if risk.scenario_key
    }

    seen: set[str] = set()
    for path in paths:
        key = _scenario_key(kind, path)
        members = _members_on(path, open_findings, id_map)
        if not members:
            # Nothing on this route is misconfigured. Real reach, and not a
            # finding -- it stays on the attack-paths page and creates no
            # risk here.
            continue

        seen.add(key)
        # What is at stake at the far end. For a route to data that is the
        # data; for an escalation it is the most sensitive thing under the
        # scope being escalated over, because that is what the escalation
        # would be an escalation *to*. Read from the graph rather than
        # assumed, and UNKNOWN where the scope holds nothing CloudGuard can
        # put a level on.
        target_sensitivity = (
            path.target.data_sensitivity
            if kind is RiskKind.ATTACK_PATH
            else _sensitivity_under(graph, path.target)
        )
        scored = default_scorer.scenario_score(
            [float(m.risk_score or 0) for m in members],
            hops=path.hops,
            entry_exposure=path.entry.public_exposure,
            target_sensitivity=target_sensitivity,
        )
        risk = existing.get(key)
        if risk is None:
            risk = Risk(
                id=uuid4(),
                organization_id=org_id,
                kind=kind,
                scenario_key=key,
            )
            session.add(risk)

        step = path.cheapest_break()
        if kind is RiskKind.ATTACK_PATH:
            risk.title = f"{path.entry.name} can reach {path.target.name}"
            risk.description = (
                f"{path.entry.name} is reachable from the internet and, in "
                f"{path.hops} steps, reaches {path.target.name}. "
                + (f"Severing it: {step.describe()}." if step else "")
            )
        else:
            risk.title = (
                f"{path.entry.name} leads to control of {path.target.name}"
            )
            risk.description = (
                f"{path.entry.name} is reachable from the internet and, in "
                f"{path.hops} steps, reaches an identity that can assign "
                f"roles over {path.target.name} -- so whatever it holds "
                "today is not the limit of what it could hold. "
                + (f"Severing it: {step.describe()}." if step else "")
            )
        risk.path = [
            {
                "source": s.source.name,
                "source_id": s.source.provider_resource_id,
                "relationship": s.relationship.value,
                "target": s.target.name,
                "target_id": s.target.provider_resource_id,
                "description": s.describe(),
            }
            for s in path.steps
        ]
        risk.risk_score = scored.score
        risk.risk_level = scored.level
        # None, and deliberately. A scenario is a statement about a route
        # rather than about one asset's context, and it never reaches the
        # org security score -- the findings it groups are already counted
        # there. A second band for it would be a number nobody claimed.
        risk.known_risk_level = scored.known_level
        risk.severity = Severity.HIGH.value
        risk.asset_criticality = path.target.criticality
        risk.data_sensitivity = target_sensitivity
        risk.internet_exposure = path.entry.public_exposure
        risk.exploitability = 0
        risk.business_impact = scored.business_impact
        risk.score_breakdown = scored.breakdown
        # Reopened if it had closed, and otherwise left as somebody decided.
        # Forcing OPEN here undid every acceptance on the next scan.
        risk.status = route_status_on_observation(risk.status)
        risk.resolved_at = None
        # Which reading saw it. Written on every observation rather than
        # only at creation: the useful question about a route is not when it
        # first appeared but whether anything has looked since, and a value
        # frozen at creation would answer the first while looking like the
        # second.
        risk.observed_scan_id = ctx.scan.id

        _link_members(ctx.writer, risk, members)

    # Routes that are gone. Resolved rather than deleted: a scenario that
    # was closed is the record of a fix, exactly as a resolved finding is,
    # and deleting it would erase the evidence that the remediation worked.
    #
    # Only routes this scan could have seen. The risks above are the whole
    # organization's, while the graph is this scan's scope -- so a rescan of
    # one subscription used to close every route in every other one, and
    # the next full scan opened them again, leaving a fix in the history
    # that nobody made.
    unseen = [
        risk
        for key, risk in existing.items()
        if key not in seen and risk.status != RiskStatus.RESOLVED
    ]
    outside = await _outside_scope(
        ctx, {node for risk in unseen for node in _route_nodes(risk)}
    )
    now = datetime.now(UTC)
    for risk in unseen:
        if outside is None or outside & _route_nodes(risk):
            continue
        risk.status = RiskStatus.RESOLVED
        risk.resolved_at = now


def _route_nodes(risk: Risk) -> set[str]:
    """Every asset a stored route passes through, by provider id."""
    nodes: set[str] = set()
    for step in risk.path or []:
        nodes.update(
            str(step[end]) for end in ("source_id", "target_id") if step.get(end)
        )
    return nodes


async def _outside_scope(ctx: AnalyzeContext, nodes: set[str]) -> set[str] | None:
    """The assets among these that belong to a scope this scan did not read.

    A route with any such asset on it is not this scan's to close: its
    absence from this graph says only that the graph never contained that
    part of the estate. An asset with no row left at all is inside by
    default, because it is gone, and so is every route through it.

    ``None`` when the scan covers nothing, which can close nothing.
    """
    scope = asset_scope(ctx.account_ids, ctx.connection_id)
    if scope is None:
        return None
    if not nodes:
        return set()
    inside: set[str] = set()
    known: set[str] = set()
    for provider_id, in_scope in (
        await ctx.session.execute(
            select(ResourceRecord.provider_resource_id, scope).where(
                ResourceRecord.organization_id == ctx.org_id,
                ResourceRecord.provider_resource_id.in_(nodes),
            )
        )
    ).all():
        known.add(provider_id)
        if in_scope:
            inside.add(provider_id)
    return known - inside


def _scenario_key(kind: RiskKind, path: Path) -> str:
    """What makes a route the same route between scans.

    Namespaced per template, except for attack paths, which keep the bare
    form they were written with. The unique index covers (organization,
    key) across every kind, so a second template needs its own namespace --
    and re-keying the first would orphan every scenario risk a customer
    already has, resolving them all and raising identical new ones with no
    history.
    """
    ends = f"{path.entry.provider_resource_id}->{path.target.provider_resource_id}"
    return ends if kind is RiskKind.ATTACK_PATH else f"{kind.value.lower()}:{ends}"


def _sensitivity_under(graph: AssetGraph, scope: CloudResource) -> Level:
    """The most sensitive thing a scope holds.

    What an escalation over that scope would reach. Taken over known levels
    only: an UNKNOWN is CloudGuard failing to work out a sensitivity, and
    letting it win here would score a scope full of unclassified assets
    above one holding a database everyone agrees is critical.
    """
    levels = [
        asset.data_sensitivity
        for asset in graph.contained_by(scope.provider_resource_id)
        if asset.data_sensitivity.is_known
    ]
    return max(levels, key=lambda level: level.rank, default=Level.UNKNOWN)


def _members_on(
    path: "Path",
    open_findings: dict[UUID, list[Finding]],
    id_map: dict[str, UUID],
) -> list[Finding]:
    """The open findings sitting on any asset this route passes through.

    Every node, not just the ends. A route is only as real as the weakest
    thing along it, and the misconfiguration that makes it walkable is
    frequently in the middle -- the over-broad role assignment rather than
    the exposed host or the sensitive store.
    """
    node_ids = {path.entry.provider_resource_id, path.target.provider_resource_id}
    for step in path.steps:
        node_ids.add(step.source.provider_resource_id)
        node_ids.add(step.target.provider_resource_id)

    members: list[Finding] = []
    for provider_id in node_ids:
        resource_uuid = id_map.get(provider_id)
        if resource_uuid is not None:
            members.extend(open_findings.get(resource_uuid, []))
    return members


def _link_members(writer: ScanWriter, risk: Risk, members: list[Finding]) -> None:
    """Join a scenario to the findings it is made of.

    The junction has always allowed this -- ``RiskFinding`` was built as a
    junction precisely so several findings could become one risk later
    without a migration. This is that later.

    Every member is queued, the ones already linked included. The link is a
    fact that is either recorded or not, and the writer inserts it with
    ``ON CONFLICT DO NOTHING`` -- which is what the per-route read of the
    existing links was for.
    """
    for member in members:
        writer.add(RiskFinding, risk_id=risk.id, finding_id=member.id)
