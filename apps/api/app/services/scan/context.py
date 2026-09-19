"""What every stage of an analysis is working within.

The stages used to be methods on one class, and each took the same six or nine
arguments -- the session, the organization, the scan, when the reading was
taken, which subscriptions and which connection it covered, and which
subscription each asset came from -- threaded by hand from the driver through
every helper it called. One object says it once.
"""

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan import Scan
from app.services.scan.writer import ScanWriter


@dataclass(frozen=True)
class AnalyzeContext:
    """One analysis: the scan, what it covered, and where its rows go.

    ``account_ids`` and ``connection_id`` are the scan's scope -- what it is
    entitled to touch -- and every query a stage makes for existing rows is
    bounded by them (``scope.py``), so the cost of a scan tracks what it read
    rather than how large the customer has grown.

    ``account_of`` is which subscription each asset came from, taken before the
    subscriptions' states were merged. After the merge a tenant-wide scan's
    resources are one list, and a finding citing its evidence needs to know
    whose readings are its own.
    """

    writer: ScanWriter
    scan: Scan
    observed_at: datetime
    account_ids: list[UUID] = field(default_factory=list)
    connection_id: UUID | None = None
    account_of: dict[str, UUID] = field(default_factory=dict)

    @property
    def session(self) -> AsyncSession:
        return self.writer.session

    @property
    def org_id(self) -> UUID:
        return self.scan.organization_id
