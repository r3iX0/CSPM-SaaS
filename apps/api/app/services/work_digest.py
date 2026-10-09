"""The weekly digest and the overdue escalation (DECISIONS.md section 237).

Two notifications about the work rather than the estate. Every Monday, one digest says what is
overdue and what is due in the week ahead, by owner, and how many fixes a scan verified in the
week before. Every day, one escalation names the fixes whose last day was yesterday. Both go
where every notification goes: the bell, and any Slack, Teams or signed webhook that asked for
their kind (section 164). The escalation reaches "the security lead" by that route: an owner or
an admin points the lead's channel at it.

Derived, like a due date (section 225) and an owner (section 236), from what the work is now:
an open finding is due on its task's date where a person set one and otherwise by the policy,
and is owned by the person assigned or else by the ownership rule its asset matches. Untracked
findings are counted too, and said apart: the clock starts at detection, so leaving work
untracked must not hide it from the person it is overdue for.

One message per organization, never one per finding or per owner. Per-owner messages to a
shared channel would be ten posts saying one thing; the digest names each owner on one line.

The composers below read no database and no clock, so each rule is proven by a unit test;
``derive`` reads what they need, once, and writes through ``notifications.write``.
"""

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta
from uuid import UUID

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.enums import (
    FindingStatus,
    NotificationKind,
    OrganizationMode,
    RemediationStatus,
    Severity,
)
from app.models.finding import Finding
from app.models.notification import Notification
from app.models.organization import Organization, OrganizationMember
from app.models.remediation import RemediationTask
from app.models.resource import ResourceRecord
from app.services import deadlines, notifications, ownership
from app.services import remediation as remediation_service

#: The hour, in UTC, both are sent in. The notification sweep runs every five minutes, so within
#: the hour a failed sweep is tried again; a worker down for the whole hour skips that day, and
#: the next digest still counts what it would have said.
SEND_HOUR = 7
#: Monday, as ``date.weekday`` counts.
DIGEST_WEEKDAY = 0
#: How many owners a line names, and how many fixes the escalation lists, before "more".
NAMED = 5
#: Where both link: the queue, which narrows to one person's work by itself.
LINK = "/remediation"

_RANK = {severity: rank for rank, severity in enumerate(deadlines.SEVERITY_ORDER)}


@dataclass(frozen=True)
class Work:
    """One open finding, as the digest counts it: when it is due and who has it."""

    finding_id: UUID
    title: str
    asset: str | None
    severity: Severity
    due_on: date | None
    owner_id: UUID | None
    tracked: bool


@dataclass(frozen=True)
class Said:
    """What one notification says."""

    title: str
    detail: str | None


def slot(now: datetime) -> datetime | None:
    """The send time ``now`` falls in, or None outside the sending hour."""
    now = now.astimezone(UTC)
    if now.hour != SEND_HOUR:
        return None
    return datetime.combine(now.date(), time(SEND_HOUR), tzinfo=UTC)


def _who(owner_id: UUID | None, names: Mapping[UUID, str]) -> str:
    if owner_id is None:
        return "nobody"
    # A member's address is copied from their token at sign-in, so one who has not signed in
    # since has none yet; their id's head still tells two of them apart.
    return names.get(owner_id) or f"member {str(owner_id)[:8]}"


def _by_owner(items: Sequence[Work], names: Mapping[UUID, str]) -> str:
    """``ana@example.com 3, ben@example.com 1, nobody 1``: most first, nobody last of a tie."""
    counts = Counter(item.owner_id for item in items)
    ordered = sorted(
        counts.items(),
        key=lambda pair: (-pair[1], pair[0] is None, _who(pair[0], names)),
    )
    shown = [f"{_who(owner_id, names)} {count}" for owner_id, count in ordered[:NAMED]]
    if len(ordered) > NAMED:
        shown.append(f"{len(ordered) - NAMED} more")
    return ", ".join(shown)


def digest(
    work: Sequence[Work],
    fixed: int,
    today: date,
    names: Mapping[UUID, str],
    *,
    solo: bool,
) -> Said | None:
    """Monday's summary, or None when there is nothing to say.

    Overdue is due before today; due this week is due today or in the six days after. A solo
    organization's work is all its one person's, so it is not split by owner.
    """
    week_end = today + timedelta(days=7)
    overdue = [item for item in work if item.due_on is not None and item.due_on < today]
    due_soon = [
        item for item in work if item.due_on is not None and today <= item.due_on < week_end
    ]
    if not overdue and not due_soon and not fixed:
        return None

    parts = [f"{len(overdue)} overdue" if overdue else "nothing overdue"]
    if due_soon:
        parts.append(f"{len(due_soon)} due this week")
    if fixed:
        parts.append(f"{fixed} fixed last week")

    sentences = []
    if not solo and overdue:
        sentences.append(f"Overdue by owner: {_by_owner(overdue, names)}.")
    if not solo and due_soon:
        sentences.append(f"Due this week by owner: {_by_owner(due_soon, names)}.")
    untracked = sum(1 for item in overdue if not item.tracked)
    if untracked:
        verb = "is" if untracked == 1 else "are"
        sentences.append(f"{untracked} of the overdue {verb} not tracked yet.")
    return Said(title=f"This week: {', '.join(parts)}", detail=" ".join(sentences) or None)


def _line(item: Work, names: Mapping[UUID, str], *, solo: bool) -> str:
    where = f" on {item.asset}" if item.asset else ""
    owner = "" if solo else f", {_who(item.owner_id, names)}"
    return f"{item.severity.value.title()}: {item.title}{where}{owner}."


def overdue(
    work: Sequence[Work],
    today: date,
    names: Mapping[UUID, str],
    *,
    solo: bool,
) -> Said | None:
    """The fixes whose last day was yesterday, worst first; None when there are none.

    Only those that lapsed yesterday, not everything overdue: the escalation is news, and the
    digest is where the standing count is said. So a policy set today, which makes old findings
    overdue all at once, does not arrive as one enormous escalation.
    """
    yesterday = today - timedelta(days=1)
    lapsed = sorted(
        (item for item in work if item.due_on == yesterday),
        key=lambda item: (_RANK[item.severity], item.title, str(item.finding_id)),
    )
    if not lapsed:
        return None
    if len(lapsed) == 1:
        first = lapsed[0]
        where = f" on {first.asset}" if first.asset else ""
        title = f"Overdue: {first.title}{where}"
    else:
        title = f"{len(lapsed)} fixes went overdue today"
    sentences = [_line(item, names, solo=solo) for item in lapsed[:NAMED]]
    if len(lapsed) > NAMED:
        sentences.append(f"And {len(lapsed) - NAMED} more.")
    # The column holds 400 characters; a finding's title alone may approach that.
    return Said(title=title[:400], detail=" ".join(sentences))


# ------------------------------------------------------------------ reading


async def open_work(session: AsyncSession, organization_id: UUID) -> list[Work]:
    """Every open finding, with its deadline and its owner as the queue would derive them."""
    rows = (
        await session.execute(
            select(
                Finding.id,
                Finding.title,
                Finding.severity,
                Finding.first_detected_at,
                ResourceRecord.name,
                ResourceRecord.cloud_account_id,
                ResourceRecord.provider_resource_id,
                ResourceRecord.resource_metadata["tags"],
                RemediationTask.id,
                RemediationTask.due_date,
                RemediationTask.assigned_to,
            )
            .outerjoin(ResourceRecord, ResourceRecord.id == Finding.resource_id)
            # At most one task per finding is not cancelled (``create_task``).
            .outerjoin(
                RemediationTask,
                and_(
                    RemediationTask.finding_id == Finding.id,
                    RemediationTask.status != RemediationStatus.CANCELLED,
                ),
            )
            .where(
                Finding.organization_id == organization_id,
                Finding.status.in_([FindingStatus.OPEN, FindingStatus.IN_PROGRESS]),
            )
        )
    ).all()
    policy = await remediation_service.fix_within(session, organization_id)
    route = await ownership.router(session, organization_id)

    work = []
    for (
        finding_id,
        title,
        severity,
        first_detected_at,
        asset,
        account_id,
        provider_id,
        tags,
        task_id,
        due_date,
        assigned_to,
    ) in rows:
        routed = route(ownership.placement_of(account_id, provider_id, tags))
        work.append(
            Work(
                finding_id=finding_id,
                title=title,
                asset=asset,
                severity=severity,
                due_on=deadlines.deadline(due_date, severity, first_detected_at, policy).due_on,
                owner_id=assigned_to or (routed.owner_id if routed else None),
                tracked=task_id is not None,
            )
        )
    return work


async def _names(session: AsyncSession, organization_id: UUID) -> dict[UUID, str]:
    rows = await session.execute(
        select(OrganizationMember.user_id, OrganizationMember.email).where(
            OrganizationMember.organization_id == organization_id,
            OrganizationMember.email.isnot(None),
        )
    )
    return {user_id: email for user_id, email in rows.tuples() if email}


async def _fixed(
    session: AsyncSession, organization_id: UUID, start: datetime, end: datetime
) -> int:
    """Findings a scan resolved in ``[start, end)``: verified fixes, as progress counts them."""
    return int(
        (
            await session.execute(
                select(func.count())
                .select_from(Finding)
                .where(
                    Finding.organization_id == organization_id,
                    Finding.status == FindingStatus.RESOLVED,
                    Finding.resolved_at >= start,
                    Finding.resolved_at < end,
                )
            )
        ).scalar_one()
    )


async def _said(
    session: AsyncSession, organization_id: UUID, kind: NotificationKind, subject_id: str
) -> bool:
    found = await session.execute(
        select(Notification.id).where(
            Notification.organization_id == organization_id,
            Notification.kind == kind,
            Notification.subject_id == subject_id,
        )
    )
    return found.first() is not None


async def derive(session: AsyncSession, organization_id: UUID, now: datetime) -> int:
    """Write today's escalation and, on a Monday, the week's digest, once each.

    Does nothing outside the sending hour, and nothing once both are written. Within the hour a
    day with nothing overdue is looked at again each sweep, which costs one read of the open
    findings, a dozen times a day at most.
    """
    at = slot(now)
    if at is None:
        return 0
    today = at.date()
    owed: list[tuple[NotificationKind, str]] = []
    escalation = f"overdue:{today.isoformat()}"
    if not await _said(session, organization_id, NotificationKind.WORK_OVERDUE, escalation):
        owed.append((NotificationKind.WORK_OVERDUE, escalation))
    week = today.isocalendar()
    summary = f"digest:{week.year}-W{week.week:02d}"
    if today.weekday() == DIGEST_WEEKDAY and not await _said(
        session, organization_id, NotificationKind.WORK_DIGEST, summary
    ):
        owed.append((NotificationKind.WORK_DIGEST, summary))
    if not owed:
        return 0

    org = await session.get(Organization, organization_id)
    if org is None:
        return 0
    solo = org.mode is OrganizationMode.SOLO
    work = await open_work(session, organization_id)
    names = await _names(session, organization_id)

    written = 0
    for kind, subject_id in owed:
        if kind is NotificationKind.WORK_OVERDUE:
            said = overdue(work, today, names, solo=solo)
        else:
            fixed = await _fixed(session, organization_id, at - timedelta(days=7), at)
            said = digest(work, fixed, today, names, solo=solo)
        if said is None:
            continue
        written += await notifications.write(
            session,
            organization_id,
            kind=kind,
            subject_id=subject_id,
            event_at=at,
            title=said.title,
            detail=said.detail,
            link=LINK,
        )
    return written
