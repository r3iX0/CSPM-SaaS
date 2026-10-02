from functools import partial
from typing import Any, Literal
from uuid import UUID

import anyio
from fastapi import APIRouter, Query, Request, Response, UploadFile, status

from app.api.links import accepted
from app.core.deps import Costly, DbSession, Tenant
from app.core.enums import FindingStatus, ScanStatus, Severity
from app.core.errors import QueueUnavailable
from app.graph import Path
from app.remediation.iac.terraform import MAX_BYTES as IAC_MAX_BYTES
from app.rules.registry import get_rule
from app.schemas.common import (
    ERROR_RESPONSES,
    Envelope,
    NoMeta,
    PageMeta,
    error_responses,
)
from app.schemas.finding import (
    AcceptRiskRequest,
    EvidenceCitationOut,
    FindingAttackPathOut,
    FindingAttackPathsMeta,
    FindingDetail,
    FindingEventOut,
    FindingOut,
    FindingProvenanceMeta,
    FindingProvenanceOut,
    IacDiffOut,
    RescanQueuedOut,
    ResourceSummary,
    RiskOut,
    VerificationOut,
)
from app.services import findings as service
from app.services import graph as graph_service
from app.services import iac as iac_service
from app.services import rescan as rescan_service
from app.services import scans as scans_service
from app.services.graph import serialize_path
from app.workers.scan_tasks import run_scan

router = APIRouter(prefix="/findings", tags=["findings"], responses=ERROR_RESPONSES)


@router.get("")
async def list_findings(
    session: DbSession,
    tenant: Tenant,
    severity: Severity | None = None,
    finding_status: FindingStatus | None = Query(default=None, alias="status"),
    rule_id: str | None = None,
    resource_id: UUID | None = None,
    evidence_id: UUID | None = None,
    environment: str | None = None,
    search: str | None = None,
    sort: str = Query(default="risk", pattern="^(risk|severity|recent)$"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Envelope[list[FindingOut], PageMeta]:
    """Findings, filtered and ordered by the database rather than by the client.

    ``search`` and ``sort`` are here because the alternative is worse than a
    missing feature. A page that filters and orders the rows it happens to hold
    searches one page of an estate and reports "nothing matches" for the rest --
    a false negative wearing an answer's clothes, in the one product where that
    is least acceptable.
    """
    rows, total = await service.list_findings(
        session,
        tenant,
        severity=severity,
        status=finding_status,
        rule_id=rule_id,
        resource_id=resource_id,
        evidence_id=evidence_id,
        environment=environment,
        search=search,
        sort=sort,
        limit=limit,
        offset=offset,
    )

    payload = []
    for finding, resource in rows:
        item = FindingOut.model_validate(finding)
        item.resource = ResourceSummary.model_validate(resource) if resource else None
        payload.append(item)

    return Envelope(data=payload, meta=PageMeta(total=total, limit=limit, offset=offset))


@router.get("/{finding_id}/attack-paths")
async def finding_attack_paths(
    finding_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[list[FindingAttackPathOut], FindingAttackPathsMeta]:
    """The routes this finding's asset sits on, if any.

    Its own endpoint rather than a field on the finding, because it costs a
    graph build and the finding page must not wait on one to say what is wrong.
    The page asks for this after it has rendered, and a reader who never scrolls
    to it has paid nothing.

    Membership is asked of the whole route, not of its endpoints: a person
    looking at a misconfiguration on the jump box at the start and a person
    looking at one on the storage account at the end are looking at the same
    problem, and both deserve to be told it is a route rather than an isolated
    fault.
    """
    finding = await service.get_finding(session, tenant, finding_id)

    # A tenant-wide finding has no asset, so it cannot be on a route. Answered
    # as an empty list rather than a 404: "this finding is on no path" is a
    # true and useful answer, and the page renders it as one.
    resource = await service.resource_of(session, finding)
    if resource is None:
        return Envelope(data=[], meta=FindingAttackPathsMeta(total=0, asset=None))

    graph = await graph_service.load_graph(session, tenant.organization_id)
    paths = graph.paths_through(resource.provider_resource_id)

    return Envelope(
        data=[
            # Where on the route this asset sits, which changes what the reader
            # should do about it: an entry point is how somebody gets in, a
            # target is what they are coming for, and a hop in between is the
            # link most likely worth cutting.
            FindingAttackPathOut(
                **serialize_path(path).model_dump(),
                asset_role=_role_on_path(path, resource.provider_resource_id),
            )
            for path in paths
        ],
        meta=FindingAttackPathsMeta(total=len(paths), asset=resource.provider_resource_id),
    )


@router.get("/{finding_id}/provenance")
async def finding_provenance(
    finding_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[FindingProvenanceOut, FindingProvenanceMeta]:
    """How CloudGuard knows: the readings this finding rests on.

    The finding already carries an *excerpt* of its evidence. This is the
    citation -- which listing, taken when, under which permissions, and the hash
    of the bytes -- which is the difference between a claim a customer has to
    accept and one they can check.

    Its own endpoint rather than a field on the finding, for the same reason
    ``/attack-paths`` is: the page answering "what is wrong" must not wait on a
    question most readers never ask.

    ``evidence: null`` means no citation was recorded, which for a finding
    raised before this existed is a fact about CloudGuard rather than about the
    finding. An empty list would say the rule reads nothing, and the two must
    not be answered the same way -- a product that cannot tell them apart is
    back to asking to be believed.
    """
    finding = await service.get_finding(session, tenant, finding_id)
    citations = await service.load_provenance(session, tenant, finding)

    return Envelope(
        data=FindingProvenanceOut(
            rule_id=finding.rule_id,
            # The rule as it was when this finding was raised, not as it is now.
            # A citation to evidence read by a rule that has since changed its
            # mind is a different claim, and the version is what says so.
            rule_version=finding.rule_version,
            evidence=(
                [EvidenceCitationOut(**row) for row in citations] if citations is not None else None
            ),
        ),
        meta=FindingProvenanceMeta(
            total=len(citations) if citations is not None else 0,
            recorded=citations is not None,
        ),
    )


def _role_on_path(path: Path, resource_id: str) -> Literal["ENTRY", "STEP", "TARGET"]:
    if path.entry.provider_resource_id == resource_id:
        return "ENTRY"
    if path.target.provider_resource_id == resource_id:
        return "TARGET"
    return "STEP"


@router.get("/{finding_id}")
async def get_finding(
    finding_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[FindingDetail, NoMeta]:
    finding = await service.get_finding(session, tenant, finding_id)
    detail = await service.load_detail(session, tenant, finding)

    payload: dict[str, Any] = {
        **FindingOut.model_validate(finding).model_dump(),
        "resource": (
            ResourceSummary.model_validate(detail["resource"]) if detail["resource"] else None
        ),
        "risk": RiskOut.model_validate(detail["risk"]) if detail["risk"] else None,
        "priority": detail["priority"],
        "estimated_effort_minutes": detail["estimated_effort_minutes"],
        "timeline": [FindingEventOut.model_validate(event) for event in detail["timeline"]],
        "verification": (
            VerificationOut.model_validate(detail["verification"])
            if detail["verification"]
            else None
        ),
        "accepted_until": await service.accepted_until(session, finding),
    }
    # The registry's say, which replaces the effort estimate with the rule's
    # own where the rule is still registered.
    payload.update(service.rule_metadata(finding.rule_id))
    return Envelope(data=FindingDetail.model_validate(payload), meta=NoMeta())


@router.post("/{finding_id}/accept-risk", responses=error_responses(403))
async def accept_risk(
    finding_id: UUID, payload: AcceptRiskRequest, session: DbSession, tenant: Tenant
) -> Envelope[FindingOut, NoMeta]:
    tenant.require_write()
    finding = await service.get_finding(session, tenant, finding_id)
    finding = await service.accept_risk(
        session, tenant, finding, payload.reason, payload.expires_at
    )
    return Envelope(data=FindingOut.model_validate(finding), meta=NoMeta())


@router.post("/{finding_id}/status", responses=error_responses(403))
async def set_finding_status(
    finding_id: UUID,
    new_status: FindingStatus,
    session: DbSession,
    tenant: Tenant,
) -> Envelope[FindingOut, NoMeta]:
    tenant.require_write()
    finding = await service.get_finding(session, tenant, finding_id)
    finding = await service.set_status(session, tenant, finding, new_status)
    return Envelope(data=FindingOut.model_validate(finding), meta=NoMeta())


@router.post(
    "/{finding_id}/rescan",
    status_code=status.HTTP_202_ACCEPTED,
    responses=error_responses(403, 409, 503),
)
async def rescan_finding(
    finding_id: UUID, request: Request, response: Response, session: DbSession, tenant: Tenant
) -> Envelope[RescanQueuedOut, NoMeta]:
    """Re-check the environment after a fix.

    This is the verification step, and it is a full scan rather than a
    single-rule re-check: fixing one thing frequently changes another, and a
    narrow re-check would report a fix that a wider view would contradict. If
    the rule now passes, the pipeline resolves the finding on its own.
    """
    tenant.require_write()
    finding = await service.get_finding(session, tenant, finding_id)
    scan = await rescan_service.request_rescan(session, tenant, finding)
    await session.commit()

    await scans_service.enqueue_or_fail(run_scan.delay, scan, tenant.user.id)
    if scan.status == ScanStatus.FAILED:
        # Unlike a scan started from the scans page, nothing here shows the
        # scan record, so the refusal is the answer rather than a row to find.
        raise QueueUnavailable(scan.error_message)
    accepted(request, response, "get_scan_detail", scan_id=scan.id)
    return Envelope(
        data=RescanQueuedOut(
            scan_id=scan.id,
            finding_id=finding.id,
            message=(
                "Rescan queued. If the issue is fixed, Cleave will resolve this "
                "finding automatically when the scan completes."
            ),
        ),
        meta=NoMeta(),
    )


@router.post("/{finding_id}/iac-diff", responses=error_responses(404), dependencies=[Costly])
async def finding_iac_diff(
    finding_id: UUID,
    session: DbSession,
    tenant: Tenant,
    file: UploadFile,
    lockfile: UploadFile | None = None,
) -> Envelope[IacDiffOut, NoMeta]:
    """This finding's fix, written into a Terraform file the customer uploads.

    Returns a unified diff that changes one argument in the block defining the
    asset, or a decline with its reason -- an answer, not an error, when the
    edit would need a guess (DECISIONS.md §190). ``lockfile`` is the optional
    ``.terraform.lock.hcl``, which lets the answer say which azurerm release it
    holds. Nothing uploaded is stored, and the finding is not changed, so a
    viewer and the demo organization may ask.
    """
    # One byte past the cap, so an oversized file is declined on its size.
    source = await file.read(IAC_MAX_BYTES + 1)
    lock = await lockfile.read(IAC_MAX_BYTES + 1) if lockfile is not None else None

    finding = await service.get_finding(session, tenant, finding_id)
    resource = await service.resource_of(session, finding)
    rule = get_rule(finding.rule_id)
    resource_name = resource.name if resource is not None else None
    # Everything the edit needs is in hand, so the connection goes back to the
    # pool before the parse rather than idling through it (§158).
    await session.close()

    result = await anyio.to_thread.run_sync(
        partial(
            iac_service.propose_terraform_fix,
            rule,
            resource_name,
            filename=iac_service.upload_filename(file.filename),
            source=source,
            lockfile=lock,
            # The customer chose this file for this finding (§190).
            sole_block=True,
        )
    )
    return Envelope(data=result, meta=NoMeta())
