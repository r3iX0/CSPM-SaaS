"""Findings: this scan's failures written down, scored, and cited.

A finding's risk is written in the same pass, because the score is computed
from the same inputs in the same loop; ``risks.py`` holds the decision about
what a risk row should contain.
"""

from uuid import UUID

from sqlalchemy import delete, select

from app.core.enums import FindingEvent, FindingStatus, Level, Severity
from app.domain.resource import CloudResource
from app.models.finding import Finding, FindingEvidence
from app.models.history import FindingEventRecord
from app.models.resource import ResourceRecord
from app.models.risk import Risk, RiskFinding
from app.models.scan import Evidence
from app.risk.scorer import RiskInputs, default_scorer
from app.rules.base import RuleResult
from app.rules.engine import EvaluationReport
from app.services.scan.context import AnalyzeContext
from app.services.scan.risks import (
    PendingFinding,
    group_key,
    upsert_group_risk,
    upsert_risk,
)
from app.services.scan.scope import finding_scope


async def would_be_open_count(
    ctx: AnalyzeContext, report: EvaluationReport, id_map: dict[str, UUID]
) -> int:
    """How many failures a real scan would have counted as open findings.

    ``persist_findings`` returns the number of *open* findings, so a plain
    ``len(report.failures)`` would report a larger number for identical
    state: a finding someone has accepted is still a FAIL, and still not
    something the scans list should count. RESOLVED and FALSE_POSITIVE are
    counted, because a real scan reopens both on re-detection.
    """
    keys = {
        (
            f.rule.rule_id,
            id_map.get(f.resource.provider_resource_id) if f.resource else None,
        )
        for f in report.failures
    }
    if not keys:
        return 0

    accepted = {
        (row.rule_id, row.resource_id)
        for row in (
            await ctx.session.execute(
                select(Finding).where(
                    Finding.organization_id == ctx.org_id,
                    Finding.status == FindingStatus.ACCEPTED_RISK,
                )
            )
        )
        .scalars()
        .all()
    }
    return len(keys - accepted)


async def persist_findings(
    ctx: AnalyzeContext, report: EvaluationReport, id_map: dict[str, UUID]
) -> int:
    """Write this scan's failures as findings, and score each one.

    Everything the loop needs is read up front. It used to issue a lookup
    per failure for the finding, another for its risk link and a third for
    the risk itself, plus a flush each time round -- four round trips per
    failing check, which a tenant-wide scan multiplies by every subscription
    it covers. The reads are two queries whatever the size of the tenant,
    and the writes flush twice.

    Two queries, but no longer two queries over the whole tenant. They
    selected every finding and every risk link the organization had, so the
    cost of writing one subscription's findings rose with every other
    subscription the customer owned. Scoped to what this scan covers, they
    grow with the work instead.

    The findings and risks are ORM rows, because this pass reads them back
    and changes them in place. Their events and junction rows are not, and go
    through the writer.
    """
    session, org_id, scan, now = ctx.session, ctx.org_id, ctx.scan, ctx.observed_at
    scope = finding_scope(ctx.account_ids, ctx.connection_id)

    # Identity is (organization, rule, resource), so that is the key.
    # Outer-joined rather than filtered on ``Finding``: the scope is
    # expressed over the asset a finding is about, and an AGGREGATE finding
    # has no asset -- it needs to be in hand all the same, or the scan would
    # insert a second row for a key the unique index already holds.
    in_scope = (
        select(Finding)
        .outerjoin(ResourceRecord, ResourceRecord.id == Finding.resource_id)
        .where(Finding.organization_id == org_id, scope)
    )
    existing_findings = {
        (f.rule_id, f.resource_id): f
        for f in (await session.execute(in_scope)).scalars().all()
    }
    risk_by_finding = {
        link.finding_id: link.risk_id
        for link in (
            await session.execute(
                select(RiskFinding).where(
                    RiskFinding.organization_id == org_id,
                    RiskFinding.finding_id.in_(
                        [f.id for f in existing_findings.values()]
                    ),
                )
            )
        )
        .scalars()
        .all()
    }

    # Keyed on the finding's identity, not appended per failure. A rule can
    # report the same resource twice in one scan -- AZ-CMP-001 does, when a
    # VM is guarded by the same NSG through two NICs -- and findings are
    # unique on (organization, rule, resource). Two entries for one row
    # meant two INSERTs of the same key.
    pending: dict[tuple[str, UUID | None], PendingFinding] = {}
    # (finding, what happened, the status it left, the sentence). Held
    # until the flush, because a finding raised by this scan has no primary
    # key for an event to point at until then.
    events: list[tuple[Finding, FindingEvent, FindingStatus | None, str]] = []

    for failure in report.failures:
        rule = failure.rule
        resource = failure.resource
        resource_uuid = id_map.get(resource.provider_resource_id) if resource else None
        key = (rule.rule_id, resource_uuid)

        finding = existing_findings.get(key)
        title = _title(rule.name, resource)
        description = failure.result.message or rule.description

        if finding is None:
            finding = Finding(
                organization_id=org_id,
                rule_id=rule.rule_id,
                resource_id=resource_uuid,
                first_detected_at=now,
                status=FindingStatus.OPEN,
            )
            session.add(finding)
            # Registered immediately so a second failure on the same key
            # updates this row rather than creating a rival for it.
            existing_findings[key] = finding
            events.append((finding, FindingEvent.DETECTED, None, title))

        elif finding.status in {FindingStatus.RESOLVED, FindingStatus.FALSE_POSITIVE}:
            # It came back. Reopen rather than leaving a stale RESOLVED --
            # a regression is not a historical record.
            events.append(
                (
                    finding,
                    FindingEvent.REOPENED,
                    finding.status,
                    "The check failed again after being resolved.",
                )
            )
            finding.status = FindingStatus.OPEN
            finding.resolved_at = None
            finding.resolved_by_scan_id = None

        finding.scan_id = scan.id
        finding.severity = rule.severity
        finding.title = title
        finding.description = description
        finding.evidence = _evidence_with_controls(failure.result)
        # Snapshot-copied so later edits to the rule's guidance do not
        # rewrite the history of findings already raised.
        finding.remediation = rule.remediation
        finding.rule_version = rule.version
        # Never moved backwards. A replay carries the snapshot's own
        # capture time, which can predate a detection already recorded.
        finding.last_detected_at = max(finding.last_detected_at or now, now)

        scored = default_scorer.score(
            RiskInputs(
                severity=Severity(rule.severity),
                asset_criticality=resource.criticality if resource else Level.UNKNOWN,
                data_sensitivity=resource.data_sensitivity if resource else Level.UNKNOWN,
                internet_exposure=resource.public_exposure if resource else Level.UNKNOWN,
                # The rule's tag unless this instance earned a lower one.
                exploitability=rule.effective_exploitability(failure.result),
            )
        )
        finding.risk_score = scored.score
        pending[key] = (finding, rule, resource, scored, title)

    # Counted per finding, not per failure: one row is one finding however
    # many times the rules named it.
    open_count = sum(1 for entry in pending.values() if entry[0].status.is_open)

    # One flush for every new finding, rather than one per finding.
    await session.flush()

    await _link_evidence(ctx, pending)

    for finding, event, previous, detail in events:
        ctx.writer.add(
            FindingEventRecord,
            finding_id=finding.id,
            scan_id=scan.id,
            event=event,
            previous_status=previous,
            current_status=finding.status,
            detail=detail,
            observed_at=now,
        )

    linked_ids = [
        risk_by_finding[f.id] for f, *_ in pending.values() if f.id in risk_by_finding
    ]
    risks = (
        {
            risk.id: risk
            for risk in (
                await session.execute(select(Risk).where(Risk.id.in_(linked_ids)))
            )
            .scalars()
            .all()
        }
        if linked_ids
        else {}
    )

    # Failures from a rule that groups them: one risk for the rule, with
    # every failing asset as a member.
    grouped: dict[str, list[PendingFinding]] = {}
    for entry in pending.values():
        if entry[1].risk_grouping is not None:
            grouped.setdefault(entry[1].rule_id, []).append(entry)

    # Looked up by key rather than reached through the junction. A group
    # risk outlives every one of its members closing, so the scan that
    # reopens one has to find the existing row -- and inserting a second
    # for a key the unique index already holds would fail the whole scan.
    group_risks: dict[str, Risk] = {}
    if grouped:
        group_risks = {
            risk.scenario_key: risk
            for risk in (
                await session.execute(
                    select(Risk).where(
                        Risk.organization_id == org_id,
                        Risk.scenario_key.in_(
                            [group_key(rule_id) for rule_id in grouped]
                        ),
                    )
                )
            )
            .scalars()
            .all()
            if risk.scenario_key
        }

    # Risks whose junction row does not exist yet. The link needs both ids,
    # so it is written after the risks are flushed rather than inside the
    # loop -- ``RiskFinding`` has no ORM relationships, only the two columns.
    unlinked: list[tuple[Risk, Finding]] = []
    for finding, rule, resource, scored, title in pending.values():
        if rule.risk_grouping is not None:
            continue
        linked = risk_by_finding.get(finding.id)
        risk = upsert_risk(
            session,
            org_id,
            finding,
            rule,
            resource,
            scored,
            title,
            risks.get(linked) if linked else None,
        )
        if linked is None:
            unlinked.append((risk, finding))

    for rule_id, members in grouped.items():
        unlinked.extend(
            await upsert_group_risk(
                session,
                org_id,
                members,
                existing=group_risks.get(group_key(rule_id)),
                linked_risks=risks,
                risk_by_finding=risk_by_finding,
            )
        )

    if unlinked:
        # The new risks' ids, which the links are built from.
        await session.flush()
        for risk, finding in unlinked:
            ctx.writer.add(RiskFinding, risk_id=risk.id, finding_id=finding.id)

    await ctx.writer.commit()
    return open_count


async def _link_evidence(
    ctx: AnalyzeContext, pending: dict[tuple[str, UUID | None], PendingFinding]
) -> None:
    """Cite the readings each finding rests on.

    The finding already carries an excerpt of its evidence. This records
    where that came from: which listing, taken when, under which
    permissions, and the hash of the payload. An excerpt cannot be
    re-verified; a citation can.

    **Read from the scan that collected, not the scan that concluded.** A
    replay evaluates a capture some earlier scan took and writes no evidence
    rows of its own, so resolving against ``scan.id`` would find nothing and
    delete every link it touched -- silently, on the path that exists to
    verify fixes. ``replay_of_scan_id`` is the scan that did the reading.

    Rewritten rather than accumulated. A citation describes what a finding
    rests on *now*; what it used to rest on is ``finding_events``' job.
    """
    if not pending:
        return

    session, org_id, account_of = ctx.session, ctx.org_id, ctx.account_of
    source_scan_id = ctx.scan.replay_of_scan_id or ctx.scan.id
    wanted = {
        key.value
        for _finding, rule, *_rest in pending.values()
        for key in rule.requires_evidence
    }
    if not wanted:
        # Every rule that failed reads nothing it declared. Nothing to cite,
        # and no rows to clear -- a finding cannot have acquired a citation
        # for a key its rule never asked for.
        return

    rows = (
        (
            await session.execute(
                select(Evidence).where(
                    Evidence.organization_id == org_id,
                    Evidence.scan_id == source_scan_id,
                    Evidence.evidence_key.in_(wanted),
                )
            )
        )
        .scalars()
        .all()
    )
    # (account, key) -> reading. The directory's readings are filed under
    # None, which is how ``Evidence`` records them: a tenant-wide read did
    # not happen *in* a subscription, and naming one would attribute it to a
    # scope that is fine.
    by_scope: dict[tuple[UUID | None, str], Evidence] = {
        (row.cloud_account_id, row.evidence_key): row for row in rows
    }

    finding_ids = [finding.id for finding, *_ in pending.values()]
    await session.execute(
        delete(FindingEvidence).where(
            FindingEvidence.organization_id == org_id,
            FindingEvidence.finding_id.in_(finding_ids),
        )
    )

    for finding, rule, resource, *_rest in pending.values():
        account_id = (
            account_of.get(resource.provider_resource_id) if resource else None
        )
        for key in rule.requires_evidence:
            # The asset's own subscription first, then the directory. Both
            # arms are needed rather than one: an aggregate rule reads only
            # tenant-wide listings, while a per-resource rule may read a
            # directory listing beside its subscription's.
            row = by_scope.get((account_id, key.value)) or by_scope.get(
                (None, key.value)
            )
            if row is None:
                # No reading of this key reached this scope. That is not an
                # error and not a gap to record here -- the rule degrades to
                # UNKNOWN through ``collection_errors`` and never becomes a
                # finding, so a FAIL citing a key with no reading means the
                # rule read something it did not declare, which the evidence
                # tests catch at their own layer.
                continue
            ctx.writer.add(
                FindingEvidence,
                finding_id=finding.id,
                evidence_key=row.evidence_key,
                evidence_id=row.id,
                content_hash=row.content_hash,
                # The provider's read time, which for a carried reading
                # is older than this scan. Copied rather than joined so
                # the age survives the reading's deletion.
                collected_at=row.collected_at,
                # The scan that read the provider. For a carried
                # reading that is an earlier scan than the one holding
                # this row, which is the distinction this field exists
                # to make and could not make while it was copied from
                # ``row.scan_id``.
                source_scan_id=row.source_scan_id or row.scan_id,
            )


def _evidence_with_controls(result: RuleResult) -> dict:
    """The rule's evidence, plus why its score was lowered.

    Merged here rather than left to each rule, so the key cannot be spelled
    two ways by two authors -- and so a customer asking why an
    administrator without MFA is not scored as a Critical has the answer on
    the finding rather than in a scoring formula they cannot see.
    """
    evidence = dict(result.evidence or {})
    if result.controls:
        evidence["compensating_controls"] = [
            control.as_evidence() for control in result.controls
        ]
    return evidence


def _title(rule_name: str, resource: CloudResource | None) -> str:
    """Plain language, naming the asset.

    "Internet-exposed RDP on production-vm-01", not "NSG rule ID 94 permits
    0.0.0.0/0:3389" (PRODUCT_SPEC.md section 4).
    """
    if resource is None:
        return rule_name
    return f"{rule_name} — {resource.name}"
