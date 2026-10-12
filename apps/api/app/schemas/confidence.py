"""How sure Cleave is, as the API says it (DECISIONS.md §262)."""

from datetime import datetime
from typing import Self

from pydantic import BaseModel

from app.core.enums import Confidence, ConfidenceReason, Freshness
from app.risk.confidence import Assessment


class ConfidenceReasonOut(BaseModel):
    code: ConfidenceReason
    #: Which context fields a context reason is about (``criticality``,
    #: ``data_sensitivity``). Empty for an evidence reason.
    fields: list[str] = []


class ConfidenceOut(BaseModel):
    """How current a finding or route is, and how settled its rank.

    The dates travel with the level so a client can say "read 9 days ago,
    current until Tuesday" without holding the thresholds itself: the server
    alone decides what current means, against each connection's own schedule.
    """

    level: Confidence
    freshness: Freshness
    #: When the provider was read. For a finding, its oldest citation; for a
    #: route, its least recently seen hop.
    observed_at: datetime
    fresh_until: datetime
    stale_at: datetime
    #: Empty at HIGH. Ordered: evidence first, then context.
    reasons: list[ConfidenceReasonOut]

    @classmethod
    def of(cls, assessment: Assessment) -> Self:
        return cls(
            level=assessment.level,
            freshness=assessment.freshness,
            observed_at=assessment.window.observed_at,
            fresh_until=assessment.window.fresh_until,
            stale_at=assessment.window.stale_at,
            reasons=[
                ConfidenceReasonOut(code=reason.code, fields=list(reason.fields))
                for reason in assessment.reasons
            ],
        )
