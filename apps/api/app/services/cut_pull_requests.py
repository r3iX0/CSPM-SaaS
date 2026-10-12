"""A cut as a pull request: delete the role assignment blocks it removes (DECISIONS.md §258).

The second kind of Fix-as-Code request (§232). A rule's request edits arguments
on the assets that fail it; a cut's deletes the ``azurerm_role_assignment``
blocks that one link of the attack-path graph stands for.

**Asking** is a member's, and touches only the database: the link's role
assignments, by their ARM ids (recorded on the principal, §257), are matched to
the organization's state indexes, and one request is queued per repository that
defines any of them. An assignment no index names is counted and said.

**Opening** is the worker's, in the same sweep and under the same lease as a
rule's request: everything is read from the database first, the session closed,
and only then is GitHub asked. The repository's Terraform is read, the deletions
planned (``remediation.iac.cut``), and the changed files committed on a new
branch with a pull request to the default branch.

**Merging** marks the cut made, never proved. The assignment goes on the next
apply, and only a scan that no longer sees the link -- the route ledger closing
its routes (§244) -- shows the cut worked.
"""

from collections import defaultdict
from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.db import service_session
from app.core.deps import TenantContext
from app.core.enums import RelationshipType
from app.core.errors import CodeHostError, NotFound, ValidationFailed
from app.core.logging import get_logger
from app.graph import AssetGraph, PathStep
from app.graph.access import role_entries
from app.integrations import github
from app.models.fix_pull_request import FixPullRequest, FixPullRequestAssignment
from app.models.iac import IacIndex, IacIndexEntry
from app.remediation.iac.cut import AssignmentTarget, Removal, plan_removal
from app.remediation.iac.pull_request import block_key
from app.services import audit
from app.services.cut_fix import cut_key, cut_sentence

log = get_logger(__name__)

LIVE = ("QUEUED", "OPENING", "OPEN")

#: The links a pull request can remove: a role assignment, and the escalation
#: line that is the same assignment (§127).
CUTTABLE = frozenset({RelationshipType.GRANTS_ROLE, RelationshipType.CAN_GRANT_ROLES})


def assignment_ids(step: PathStep) -> set[str]:
    """The ARM ids of every role assignment the link stands for, lower-cased as indexes are."""
    return {
        str(entry["assignment_id"]).lower()
        for entry in role_entries(step.source, step.target.provider_resource_id)
        if entry.get("assignment_id")
    }


# ----------------------------------------------------------------- asking
async def request(
    session: AsyncSession,
    tenant: TenantContext,
    graph: AssetGraph,
    link: tuple[str, RelationshipType, str],
) -> tuple[list[FixPullRequest], int]:
    """Queue one pull request per repository defining the cut's role assignments.

    Answers the requests, existing ones included, and how many of the
    assignments no state index names. Refused for a link that is not a role
    assignment, and where no index names any of them: there is nothing to delete.
    """
    tenant.require_write()
    if not settings.github_offered:
        raise NotFound("GitHub is not offered on this deployment")
    raw_source, relationship, raw_target = link
    source, target = graph.resolve(raw_source), graph.resolve(raw_target)
    if (source, relationship, target) not in set(graph.links()):
        raise NotFound("No link here that can be removed")
    if relationship not in CUTTABLE:
        raise ValidationFailed("Only a role assignment can be removed in code")
    step = PathStep(graph.nodes[source], relationship, graph.nodes[target])
    ids = assignment_ids(step)
    if not ids:
        raise ValidationFailed(
            "Cleave holds no assignment ids for this role; the next scan records them"
        )

    rows = (
        await session.execute(
            select(
                IacIndexEntry.resource_id,
                IacIndexEntry.address,
                IacIndex.working_directory,
                IacIndex.repository_id,
                IacIndex.repository,
            )
            .join(IacIndex, IacIndex.id == IacIndexEntry.index_id)
            .where(
                IacIndexEntry.organization_id == tenant.organization_id,
                IacIndexEntry.resource_id.in_(ids),
            )
        )
    ).all()
    by_repository: dict[int, tuple[str, dict[str, tuple[str, str]]]] = {}
    for assignment_id, address, working_directory, repository_id, repository in rows:
        _, assignments = by_repository.setdefault(repository_id, (repository, {}))
        assignments.setdefault(assignment_id, (address, working_directory))
    if not by_repository:
        raise ValidationFailed(
            "None of the role assignments this cut removes is in an uploaded state index"
        )
    indexed = {aid for _, found in by_repository.values() for aid in found}

    key = cut_key(source, relationship, target)
    cut = {
        "source": source,
        "relationship": relationship.value,
        "target": target,
        "sentence": cut_sentence(step),
        "detail": step.detail(),
    }
    requests = []
    for repository_id, (repository, assignments) in sorted(by_repository.items()):
        live = (
            await session.execute(
                select(FixPullRequest).where(
                    FixPullRequest.organization_id == tenant.organization_id,
                    FixPullRequest.kind == "CUT",
                    FixPullRequest.cut_key == key,
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
            kind="CUT",
            cut_key=key,
            cut=cut,
            repository_id=repository_id,
            repository=repository,
            requested_by=tenant.user.id,
        )
        session.add(queued)
        await session.flush()
        session.add_all(
            FixPullRequestAssignment(
                organization_id=tenant.organization_id,
                pull_request_id=queued.id,
                assignment_id=assignment_id,
                address=address,
                working_directory=working_directory,
            )
            for assignment_id, (address, working_directory) in sorted(assignments.items())
        )
        await audit.record(
            session,
            tenant,
            "fix_pull_request.requested",
            "fix_pull_request",
            queued.id,
            {"cut": key, "repository": repository, "assignments": len(assignments)},
        )
        requests.append(queued)
    await session.flush()
    return requests, len(ids - indexed)


async def for_cut(
    session: AsyncSession, tenant: TenantContext, key: str | None
) -> list[tuple[FixPullRequest, list[FixPullRequestAssignment]]]:
    """The organization's cut pull requests, newest first, narrowed to one link when given."""
    query = select(FixPullRequest).where(
        FixPullRequest.organization_id == tenant.organization_id, FixPullRequest.kind == "CUT"
    )
    if key is not None:
        query = query.where(FixPullRequest.cut_key == key)
    requests = list(
        (await session.execute(query.order_by(FixPullRequest.created_at.desc()).limit(50)))
        .scalars()
        .all()
    )
    assignments: dict[UUID, list[FixPullRequestAssignment]] = defaultdict(list)
    if requests:
        for row in (
            await session.execute(
                select(FixPullRequestAssignment).where(
                    FixPullRequestAssignment.pull_request_id.in_([r.id for r in requests])
                )
            )
        ).scalars():
            assignments[row.pull_request_id].append(row)
    return [(r, assignments[r.id]) for r in requests]


# ---------------------------------------------------------------- opening
@dataclass(frozen=True)
class Job:
    """Everything one cut's pull request needs, read before GitHub is asked."""

    pull_request_id: UUID
    repository: str
    attempts: int
    cut: dict[str, str]
    targets: list[AssignmentTarget]
    instances: dict[tuple[str, str], set[str]]
    installations: set[int]


@dataclass(frozen=True)
class Result:
    removal: Removal
    declined: str | None = None
    branch: str | None = None
    opened: github.OpenedPullRequest | None = None


async def open_claimed(pull_request_id: UUID, *, max_attempts: int) -> None:
    """Open one claimed cut request: read, ask GitHub, and write the outcome."""
    job = await _read_job(pull_request_id)
    if job is None:
        return
    try:
        result = await open_on_github(job)
    except CodeHostError as exc:
        await _settle(job, failed=str(exc), max_attempts=max_attempts)
        return
    await _settle(job, result=result, max_attempts=max_attempts)


async def _read_job(pull_request_id: UUID) -> Job | None:
    async with service_session() as session:
        pr = await session.get(FixPullRequest, pull_request_id)
        if pr is None or pr.state != "OPENING" or pr.kind != "CUT" or pr.cut is None:
            return None
        org = pr.organization_id
        targets = [
            AssignmentTarget(row.assignment_id, row.address, row.working_directory)
            for row in (
                await session.execute(
                    select(FixPullRequestAssignment).where(
                        FixPullRequestAssignment.pull_request_id == pr.id
                    )
                )
            ).scalars()
        ]
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
        repository, attempts, cut = pr.repository, pr.attempts, dict(pr.cut)

    instances: dict[tuple[str, str], set[str]] = defaultdict(set)
    for address, resource_id, working_directory in entries:
        instances[block_key(working_directory, address)].add(resource_id)
    return Job(
        pull_request_id=pull_request_id,
        repository=repository,
        attempts=attempts,
        cut={key: str(value) for key, value in cut.items()},
        targets=targets,
        instances=dict(instances),
        installations=installations,
    )


async def open_on_github(job: Job) -> Result:
    """Read the repository, plan the deletions, and open the pull request if any was made."""
    installation_id = await github.repository_installation(job.repository)
    if installation_id is None or installation_id not in job.installations:
        return Result(
            Removal(), declined="Cleave's GitHub App is no longer linked to this repository."
        )
    repository = await github.repository(job.repository, installation_id)
    token = await github.installation_token(installation_id)
    read = await github.terraform_files(repository.full_name, repository.default_branch, token)
    if isinstance(read, str):
        return Result(Removal(), declined=read)
    head, files = read

    removal = plan_removal(files, job.targets, instances=job.instances)
    if not removal.files:
        return Result(
            removal, declined="No role assignment block this cut covers could be deleted."
        )
    branch = f"cloudguard/cut-{str(job.pull_request_id)[:8]}"
    title = f"Cleave: {job.cut.get('sentence', 'Remove a role assignment').rstrip('.')}"
    opened = await github.open_pull_request(
        repository.full_name,
        token=token,
        base=repository.default_branch,
        base_sha=head,
        branch=branch,
        files=removal.files,
        title=title[:250],
        body=pull_request_body(job, removal),
    )
    return Result(removal, branch=branch, opened=opened)


def pull_request_body(job: Job, removal: Removal) -> str:
    """What the reviewer reads: the cut, what was deleted where, and what was not and why."""
    address_of = {target.assignment_id: target.address for target in job.targets}
    removed = [outcome for outcome in removal.outcomes if outcome.removed]
    kept = [outcome for outcome in removal.outcomes if not outcome.removed]
    lines = [
        f"Cleave's attack-path analysis asks for one change: {job.cut.get('sentence', '')}",
        "",
        f"It removes the link `{job.cut.get('detail', '')}`, which routes from the internet "
        "to sensitive data cross. Removing it in code means deleting the role assignment "
        "blocks below.",
        "",
    ]
    if removed:
        lines += ["**Deleted**", ""]
        lines += [
            f"- `{address_of.get(o.assignment_id, o.assignment_id)}` in `{o.path}`" for o in removed
        ] + [""]
    if kept:
        lines += ["**Not deleted**", ""]
        lines += [
            f"- `{address_of.get(o.assignment_id, o.assignment_id)}`: {o.reason}. {o.detail}"
            for o in kept
        ] + [""]
    lines.append(
        "Merging marks the cut made. The assignment goes on the next apply, and Cleave shows "
        "the routes closed only when a scan no longer sees the link."
    )
    if settings.app_url:
        lines += ["", f"[Open in Cleave]({settings.app_url.rstrip('/')}/attack-paths)"]
    return "\n".join(lines)


async def _settle(
    job: Job, *, max_attempts: int, result: Result | None = None, failed: str | None = None
) -> None:
    async with service_session() as session:
        pr = await session.get(FixPullRequest, job.pull_request_id)
        if pr is None:
            return
        pr.claimed_until = None
        if failed is not None:
            pr.state = "FAILED" if job.attempts >= max_attempts else "QUEUED"
            pr.detail = failed
            log.warning("cut_pr.github_failed", pull_request_id=str(pr.id), attempts=job.attempts)
        elif result is not None:
            outcome_of = {o.assignment_id: o for o in result.removal.outcomes}
            rows = await session.execute(
                select(FixPullRequestAssignment).where(
                    FixPullRequestAssignment.pull_request_id == pr.id
                )
            )
            for row in rows.scalars():
                outcome = outcome_of.get(row.assignment_id)
                if outcome is not None:
                    row.outcome = "REMOVED" if outcome.removed else "DECLINED"
                    row.reason, row.path, row.line = outcome.reason, outcome.path, outcome.line
            if result.opened is None:
                pr.state, pr.decline_reason = "DECLINED", "nothing_removable"
                pr.detail = result.declined
            else:
                pr.state, pr.branch = "OPEN", result.branch
                pr.pr_number, pr.pr_url = result.opened.number, result.opened.url
        await session.commit()
