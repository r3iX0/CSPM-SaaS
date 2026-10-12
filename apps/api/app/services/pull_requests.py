"""Fix-as-Code pull requests: asked for, opened by the worker, and claimed on merge (§232).

**Asking** is a member's, and touches only the database: the rule's open
findings are matched to the organization's state indexes, and one request is
queued per repository the index places them in. A finding no index names is
counted and said, not guessed at.

**Opening** is the worker's sweep, every minute, as webhook deliveries are
(§164): a queued request is claimed under a lease, everything it needs is read
from the database, the session is closed, and only then is GitHub asked. The
repository's Terraform is read, the plan made (``remediation.iac.pull_request``),
and the edited files committed on a new branch with a pull request to the
default branch. The result is written in a fresh session.

**Merging** claims the fix for every finding the pull request edited, through
the existing verification, and marks their tasks done. A merge is not an apply,
so the finding stays open until a scan observes the change (§18, §190).
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import service_session
from app.core.deps import TenantContext
from app.core.enums import FindingStatus, RemediationStatus
from app.core.errors import CodeHostError, NotFound, ValidationFailed
from app.core.logging import get_logger
from app.integrations import github
from app.models.finding import Finding
from app.models.fix_pull_request import FixPullRequest, FixPullRequestFinding
from app.models.iac import IacIndex, IacIndexEntry
from app.models.remediation import RemediationTask
from app.models.resource import ResourceRecord
from app.remediation.iac.pull_request import Plan, Target, block_key, plan
from app.remediation.iac.terraform import Declined, RuleChanges
from app.rules.registry import get_rule
from app.services import audit, cut_pull_requests
from app.services import verification as verification_service
from app.services.iac import rule_edit

log = get_logger(__name__)

LIVE = ("QUEUED", "OPENING", "OPEN")
LEASE = timedelta(minutes=10)
MAX_ATTEMPTS = 3
SWEEP_BATCH = 5
_OPEN_FINDINGS = (FindingStatus.OPEN, FindingStatus.IN_PROGRESS)


def _require_offered() -> None:
    if not settings.github_offered:
        raise NotFound("GitHub is not offered on this deployment")


def _rule_changes(rule_id: str) -> RuleChanges:
    edit = rule_edit(get_rule(rule_id))
    if isinstance(edit, Declined):
        raise ValidationFailed(edit.detail)
    return edit


# ----------------------------------------------------------------- asking
async def request(
    session: AsyncSession, tenant: TenantContext, rule_id: str
) -> tuple[list[FixPullRequest], int]:
    """Queue one pull request per repository holding the rule's failing assets.

    Answers the requests, existing ones included, and how many failing findings
    no state index names. Refused when none is indexed: there is nothing to edit.
    """
    tenant.require_write()
    _require_offered()
    _rule_changes(rule_id)

    rows = (
        await session.execute(
            select(Finding.id, IacIndex.repository_id, IacIndex.repository, IacIndexEntry.address)
            .join(ResourceRecord, ResourceRecord.id == Finding.resource_id)
            .outerjoin(
                IacIndexEntry,
                (IacIndexEntry.organization_id == Finding.organization_id)
                & (IacIndexEntry.resource_id == func.lower(ResourceRecord.provider_resource_id)),
            )
            .outerjoin(IacIndex, IacIndex.id == IacIndexEntry.index_id)
            .where(
                Finding.organization_id == tenant.organization_id,
                Finding.rule_id == rule_id,
                Finding.status.in_(_OPEN_FINDINGS),
            )
        )
    ).all()

    by_repository: dict[int, tuple[str, dict[UUID, str]]] = {}
    indexed: set[UUID] = set()
    everyone: set[UUID] = set()
    for finding_id, repository_id, repository, address in rows:
        everyone.add(finding_id)
        if repository_id is None:
            continue
        indexed.add(finding_id)
        _, findings = by_repository.setdefault(repository_id, (repository, {}))
        # One entry per finding and repository: another workspace's entry is the same block.
        findings.setdefault(finding_id, address)
    if not by_repository:
        raise ValidationFailed("None of this rule's failing assets is in an uploaded state index")

    requests = []
    for repository_id, (repository, findings) in sorted(by_repository.items()):
        live = (
            await session.execute(
                select(FixPullRequest).where(
                    FixPullRequest.organization_id == tenant.organization_id,
                    FixPullRequest.rule_id == rule_id,
                    FixPullRequest.repository_id == repository_id,
                    FixPullRequest.state.in_(LIVE),
                )
            )
        ).scalar_one_or_none()
        if live is not None:
            requests.append(live)
            continue
        queued = FixPullRequest(
            organization_id=tenant.organization_id,
            rule_id=rule_id,
            repository_id=repository_id,
            repository=repository,
            requested_by=tenant.user.id,
        )
        session.add(queued)
        await session.flush()
        session.add_all(
            FixPullRequestFinding(
                organization_id=tenant.organization_id,
                pull_request_id=queued.id,
                finding_id=finding_id,
                address=address,
            )
            for finding_id, address in findings.items()
        )
        await audit.record(
            session,
            tenant,
            "fix_pull_request.requested",
            "fix_pull_request",
            queued.id,
            {"rule_id": rule_id, "repository": repository, "findings": len(findings)},
        )
        requests.append(queued)
    await session.flush()
    return requests, len(everyone - indexed)


async def for_rule(
    session: AsyncSession, tenant: TenantContext, rule_id: str | None
) -> list[tuple[FixPullRequest, list[FixPullRequestFinding]]]:
    """The organization's pull requests, newest first, narrowed to a rule when given."""
    query = select(FixPullRequest).where(
        FixPullRequest.organization_id == tenant.organization_id, FixPullRequest.kind == "RULE"
    )
    if rule_id is not None:
        query = query.where(FixPullRequest.rule_id == rule_id)
    requests = list(
        (await session.execute(query.order_by(FixPullRequest.created_at.desc()).limit(50)))
        .scalars()
        .all()
    )
    findings: dict[UUID, list[FixPullRequestFinding]] = defaultdict(list)
    if requests:
        for row in (
            await session.execute(
                select(FixPullRequestFinding).where(
                    FixPullRequestFinding.pull_request_id.in_([r.id for r in requests])
                )
            )
        ).scalars():
            findings[row.pull_request_id].append(row)
    return [(r, findings[r.id]) for r in requests]


# ---------------------------------------------------------------- opening
@dataclass(frozen=True)
class Job:
    """Everything one pull request needs, read before GitHub is asked."""

    pull_request_id: UUID
    organization_id: UUID
    rule_id: str
    repository: str
    attempts: int
    targets: list[Target]
    instances: dict[tuple[str, str], set[str]]
    failing: set[str]
    installations: set[int]


@dataclass(frozen=True)
class Result:
    plan: Plan
    declined: str | None = None
    branch: str | None = None
    opened: github.OpenedPullRequest | None = None


async def open_due() -> dict[str, int]:
    """The worker's sweep: claim queued requests under a lease and open each."""
    if not settings.github_offered:
        return {"opened": 0}
    async with service_session() as session:
        claimed = (
            (
                await session.execute(
                    text(
                        "UPDATE fix_pull_requests SET state = 'OPENING', "
                        "attempts = attempts + 1, updated_at = now(), "
                        "claimed_until = now() + make_interval(mins => :lease) "
                        "WHERE id IN (SELECT id FROM fix_pull_requests "
                        "WHERE state = 'QUEUED' OR (state = 'OPENING' AND claimed_until < now()) "
                        "ORDER BY created_at LIMIT :batch FOR UPDATE SKIP LOCKED) "
                        "RETURNING id, kind"
                    ),
                    {"lease": int(LEASE.total_seconds() // 60), "batch": SWEEP_BATCH},
                )
            )
            .tuples()
            .all()
        )
        await session.commit()
    for pull_request_id, kind in claimed:
        if kind == "CUT":
            # A cut's request deletes role assignment blocks (§258): its own
            # reading and plan, under this sweep's lease and attempts.
            await cut_pull_requests.open_claimed(pull_request_id, max_attempts=MAX_ATTEMPTS)
            continue
        job = await _read_job(pull_request_id)
        if job is None:
            continue
        try:
            result = await open_on_github(job)
        except CodeHostError as exc:
            await _settle(job, failed=str(exc))
            continue
        await _settle(job, result=result)
    return {"opened": len(claimed)}


async def _read_job(pull_request_id: UUID) -> Job | None:
    async with service_session() as session:
        pr = await session.get(FixPullRequest, pull_request_id)
        if pr is None or pr.state != "OPENING" or pr.rule_id is None:
            return None
        org = pr.organization_id
        covered = (
            await session.execute(
                select(FixPullRequestFinding.finding_id, FixPullRequestFinding.address).where(
                    FixPullRequestFinding.pull_request_id == pr.id
                )
            )
        ).all()
        resource_of: dict[UUID, str] = dict(
            (
                await session.execute(
                    select(Finding.id, func.lower(ResourceRecord.provider_resource_id))
                    .join(ResourceRecord, ResourceRecord.id == Finding.resource_id)
                    .where(Finding.id.in_([finding_id for finding_id, _ in covered]))
                )
            ).tuples()
        )
        failing = set(
            (
                await session.execute(
                    select(func.lower(ResourceRecord.provider_resource_id))
                    .join(Finding, Finding.resource_id == ResourceRecord.id)
                    .where(
                        Finding.organization_id == org,
                        Finding.rule_id == pr.rule_id,
                        Finding.status.in_(_OPEN_FINDINGS),
                    )
                )
            ).scalars()
        )
        entries = (
            await session.execute(
                select(IacIndexEntry.address, IacIndexEntry.resource_id, IacIndex.working_directory)
                .join(IacIndex, IacIndex.id == IacIndexEntry.index_id)
                .where(IacIndex.organization_id == org, IacIndex.repository_id == pr.repository_id)
            )
        ).all()
        installations = set(
            (
                await session.execute(
                    text(
                        "SELECT installation_id FROM code_integrations WHERE organization_id = :o"
                    ),
                    {"o": org},
                )
            ).scalars()
        )
        rule_id, repository, attempts = pr.rule_id, pr.repository, pr.attempts

    instances: dict[tuple[str, str], set[str]] = defaultdict(set)
    directory_of: dict[tuple[str, str], str] = {}
    for address, resource_id, working_directory in entries:
        instances[block_key(working_directory, address)].add(resource_id)
        directory_of.setdefault((address, resource_id), working_directory)
    targets = []
    for finding_id, address in covered:
        resource_id = resource_of.get(finding_id, "")
        targets.append(
            Target(finding_id, resource_id, address, directory_of.get((address, resource_id), ""))
        )
    return Job(
        pull_request_id=pull_request_id,
        organization_id=org,
        rule_id=rule_id,
        repository=repository,
        attempts=attempts,
        targets=targets,
        instances=dict(instances),
        failing=failing,
        installations=installations,
    )


async def open_on_github(job: Job) -> Result:
    """Read the repository, plan the edits, and open the pull request if any was made."""
    installation_id = await github.repository_installation(job.repository)
    if installation_id is None or installation_id not in job.installations:
        return Result(
            Plan(), declined="Cleave's GitHub App is no longer linked to this repository."
        )
    repository = await github.repository(job.repository, installation_id)
    token = await github.installation_token(installation_id)
    read = await github.terraform_files(repository.full_name, repository.default_branch, token)
    if isinstance(read, str):
        return Result(Plan(), declined=read)
    head, files = read

    planned = plan(
        files, job.targets, _rule_changes(job.rule_id), instances=job.instances, failing=job.failing
    )
    if not planned.files:
        return Result(planned, declined="No block this pull request covers could be edited.")
    rule = get_rule(job.rule_id)
    branch = f"cloudguard/fix-{job.rule_id.lower()}-{str(job.pull_request_id)[:8]}"
    opened = await github.open_pull_request(
        repository.full_name,
        token=token,
        base=repository.default_branch,
        base_sha=head,
        branch=branch,
        files=planned.files,
        title=f"Cleave: {rule.name if rule else job.rule_id}",
        body=pull_request_body(job, planned),
    )
    return Result(planned, branch=branch, opened=opened)


def pull_request_body(job: Job, planned: Plan) -> str:
    """What the reviewer reads: the rule, what was edited where, and what was not and why."""
    rule = get_rule(job.rule_id)
    address_of = {target.finding_id: target.address for target in job.targets}
    edited = planned.edited
    declined = [outcome for outcome in planned.outcomes if not outcome.edited]
    lines = [
        f"Cleave found **{job.rule_id}** failing on {len(planned.outcomes)} assets this "
        f"repository defines, and edited the blocks of {len(edited)}.",
        "",
    ]
    if rule is not None and rule.remediation_spec is not None:
        lines += [f"- {state.describes}" for state in rule.remediation_spec.expected] + [""]
    if edited:
        lines += ["**Edited**", ""]
        lines += [f"- `{address_of[o.finding_id]}` in `{o.path}`" for o in edited] + [""]
    if declined:
        lines += ["**Not edited**", ""]
        lines += [f"- `{address_of[o.finding_id]}`: {o.reason}. {o.detail}" for o in declined]
        lines += [""]
    lines.append(
        "Merging records a claimed fix for the edited assets. Cleave closes each finding only "
        "when a scan observes the change, after it is applied."
    )
    if settings.app_url:
        link = f"{settings.app_url.rstrip('/')}/remediation?rule={job.rule_id}"
        lines += ["", f"[Open in Cleave]({link})"]
    return "\n".join(lines)


async def _settle(job: Job, *, result: Result | None = None, failed: str | None = None) -> None:
    async with service_session() as session:
        pr = await session.get(FixPullRequest, job.pull_request_id)
        if pr is None:
            return
        pr.claimed_until = None
        if failed is not None:
            pr.state = "FAILED" if job.attempts >= MAX_ATTEMPTS else "QUEUED"
            pr.detail = failed
            log.warning("fix_pr.github_failed", pull_request_id=str(pr.id), attempts=job.attempts)
        elif result is not None:
            outcome_of = {o.finding_id: o for o in result.plan.outcomes}
            rows = await session.execute(
                select(FixPullRequestFinding).where(FixPullRequestFinding.pull_request_id == pr.id)
            )
            for row in rows.scalars():
                outcome = outcome_of.get(row.finding_id)
                if outcome is not None:
                    row.outcome = "EDITED" if outcome.edited else "DECLINED"
                    row.reason, row.path, row.line = outcome.reason, outcome.path, outcome.line
            if result.opened is None:
                pr.state, pr.decline_reason = "DECLINED", "nothing_editable"
                pr.detail = result.declined
            else:
                pr.state, pr.branch = "OPEN", result.branch
                pr.pr_number, pr.pr_url = result.opened.number, result.opened.url
        await session.commit()


# ---------------------------------------------------------------- merging
async def pull_request_closed(repository_id: int, number: int, *, merged: bool) -> None:
    """GitHub says a pull request closed: a merge claims the fix for what it edited."""
    async with service_session() as session:
        pr = (
            await session.execute(
                select(FixPullRequest).where(
                    FixPullRequest.repository_id == repository_id,
                    FixPullRequest.pr_number == number,
                    FixPullRequest.state == "OPEN",
                )
            )
        ).scalar_one_or_none()
        if pr is None:
            return
        pr.state = "MERGED" if merged else "CLOSED"
        # A cut's merge only marks it made: no finding is claimed, and the next
        # scan's ledger shows whether its routes closed (§258).
        if merged and pr.kind == "RULE":
            await _claim(session, pr)
        await session.commit()


async def _claim(session: AsyncSession, pr: FixPullRequest) -> None:
    edited = (
        await session.execute(
            select(FixPullRequestFinding.finding_id).where(
                FixPullRequestFinding.pull_request_id == pr.id,
                FixPullRequestFinding.outcome == "EDITED",
            )
        )
    ).scalars()
    now = datetime.now(UTC)
    for finding_id in list(edited):
        finding = await session.get(Finding, finding_id)
        if finding is None or finding.status not in _OPEN_FINDINGS:
            continue
        task = (
            await session.execute(
                select(RemediationTask).where(
                    RemediationTask.finding_id == finding_id,
                    RemediationTask.status != RemediationStatus.CANCELLED,
                )
            )
        ).scalar_one_or_none()
        if task is not None and task.status in (
            RemediationStatus.TODO,
            RemediationStatus.IN_PROGRESS,
        ):
            task.status, task.completed_at = RemediationStatus.DONE, now
        await verification_service.open_verification(
            session,
            organization_id=pr.organization_id,
            finding=finding,
            task=task,
            claimed_by_user_id=pr.requested_by,
            now=now,
        )
