"""What a risk's triage status is, decided without a database.

The risks list is the triage queue, so ``Risk.status`` has to mean the same
thing on every row. It did not: a finding risk took whatever the last write
happened to say -- ACCEPTED when one member was accepted, OPEN whenever a scan
saw a member open or in progress -- and a route was set back to OPEN by every
scan that saw it, which undid a decision the moment the next reading arrived.

Two rules, kept here so the scanner and the workflow actions apply the same
ones (DECISIONS.md §103).
"""

from collections.abc import Iterable
from datetime import UTC, datetime

from app.core.enums import FindingStatus, RiskStatus

#: Member statuses that still ask somebody for a decision or record one. A
#: resolved finding is over and a false positive was never a problem, so neither
#: has a say in what the risk's status is.
_LIVE = {FindingStatus.OPEN, FindingStatus.IN_PROGRESS, FindingStatus.ACCEPTED_RISK}


def finding_risk_status(
    members: Iterable[FindingStatus], current: RiskStatus
) -> RiskStatus:
    """A finding risk's status, read from its findings.

    The finding is where the decision is recorded -- compliance cites it, the
    exception row hangs off it -- so the risk reports what its members say
    rather than holding an opinion of its own.

    The least-settled member wins. A group of forty accounts with thirty-nine
    accepted still has one nobody has decided about, and a queue that called
    the group Accepted would hide exactly that one.

    With no live member the current status stands: whether the risk is still
    listed is the live filter's question (§40), and a status invented from
    nothing would be the worse answer.
    """
    live = {status for status in members if status in _LIVE}
    if not live:
        return current
    if FindingStatus.OPEN in live:
        return RiskStatus.OPEN
    if FindingStatus.IN_PROGRESS in live:
        return RiskStatus.IN_PROGRESS
    return RiskStatus.ACCEPTED


def route_status_on_observation(current: RiskStatus) -> RiskStatus:
    """A route's status when a scan sees it again.

    A route that had closed and is back is open again. Anything else keeps the
    decision somebody made about it: accepting a route says "this reach is by
    design", and the next scan finding the same reach is not news about that.
    """
    return RiskStatus.OPEN if current == RiskStatus.RESOLVED else current


def finding_status_for(status: RiskStatus) -> FindingStatus:
    """The finding status a decision on a finding risk is written to its members as.

    RESOLVED has no entry on purpose: nothing is resolved by hand, on a finding
    or on a risk. A scan resolves it once it observes the fix.
    """
    return {
        RiskStatus.OPEN: FindingStatus.OPEN,
        RiskStatus.IN_PROGRESS: FindingStatus.IN_PROGRESS,
        RiskStatus.ACCEPTED: FindingStatus.ACCEPTED_RISK,
    }[status]


def acceptance_expiry(expires_at: datetime | None, now: datetime) -> datetime | None:
    """An acceptance's end date, checked, in UTC.

    A date already past is refused rather than stored: the sweep would reopen
    the risk within minutes of it being accepted, and the person accepting it
    would see their decision undone with no idea why (DECISIONS.md §104). A
    naive timestamp is taken as UTC, which is what the API documents.
    """
    if expires_at is None:
        return None
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if expires_at <= now:
        raise ValueError("An acceptance has to end in the future")
    return expires_at.astimezone(UTC)
