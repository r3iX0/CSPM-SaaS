"""Where a scan's rows go on their way to the database.

Two jobs, and they belong together because both happen at the commit.

**Bulk writes.** Most of what a scan writes is appended and never read back
before the transaction ends: a change event per moved asset, a finding event
per transition, a coverage row per rule, a citation per reading a finding rests
on, a junction row per link. Handed to the ORM one object at a time, every one
of them sat in the identity map, took a trip through the unit of work, and was
emitted as its own parameter set -- tens of thousands of objects on a large
tenant, none of which anything would ever look up. Buffered here as plain rows,
they are written per table as one ``executemany`` at the next flush.

**The fence.** A step's lease is renewed on a clock, so a worker whose step was
reclaimed learnt it up to a third of a lease later -- and everything it
committed in that window was written by a worker that no longer owned the step.
:meth:`ScanWriter.commit` asks the step row, inside the transaction about to
commit, whether it is still this attempt's, and rolls back when it is not
(DECISIONS.md section 108).

Rows that the scan *does* read back -- assets, findings, risks, whose ids the
next stage needs and whose columns it updates in place -- stay on the ORM. The
writer takes only the tables listed in :data:`APPEND_ONLY`, and refuses the rest
rather than accepting them and leaving two ways to write one row.
"""

from typing import Any, cast
from uuid import UUID

from sqlalchemy import Table
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.base import Base
from app.models.finding import FindingEvidence
from app.models.history import AssetChangeEvent, FindingEventRecord
from app.models.resource import ResourceRelationship
from app.models.risk import RiskFinding
from app.models.scan import Evidence, ScanEvaluationGap, ScanRuleResult
from app.services.scan.errors import StepLeaseLost
from app.services.scan.lease import StepFence

# Tables the writer takes, and whether a repeated row is a conflict or a no-op.
#
# ``True`` means set semantics: the row states a fact that is either recorded or
# not, and recording it twice is not an error. An edge between two assets and a
# risk's link to one of its findings are both that -- and both used to be read
# back first so the scan could skip what already existed, which was a query per
# stage whose only purpose was to avoid a unique violation ``ON CONFLICT DO
# NOTHING`` avoids for free.
#
# ``False`` for everything else, where a duplicate would mean the scan wrote one
# thing twice and should fail loudly rather than quietly keep the first.
APPEND_ONLY: dict[type[Base], bool] = {
    AssetChangeEvent: False,
    Evidence: False,
    FindingEventRecord: False,
    FindingEvidence: False,
    ResourceRelationship: True,
    RiskFinding: True,
    ScanEvaluationGap: False,
    ScanRuleResult: False,
}


class ScanWriter:
    """Buffers a scan's append-only rows and commits them under its fence.

    One per session. ``fence`` is ``None`` for work that no step owns -- a
    replay is one task rather than a set of steps, and a test driving a stage
    directly has no lease to lose -- and a commit is then a plain commit.
    """

    def __init__(
        self,
        session: AsyncSession,
        organization_id: UUID,
        *,
        fence: StepFence | None = None,
    ) -> None:
        self.session = session
        self.organization_id = organization_id
        self.fence = fence
        self._pending: dict[type[Base], list[dict[str, Any]]] = {}

    def add(self, model: type[Base], **values: Any) -> None:
        """Queue one row. Written at the next :meth:`flush` or :meth:`commit`.

        ``organization_id`` is filled in when absent and refused when it names
        another tenant. The worker's session is already held to one
        organization by RLS; this is the same boundary stated where the row is
        built, so a mistake fails here with a sentence rather than as a policy
        violation on a statement carrying a thousand rows.
        """
        if model not in APPEND_ONLY:
            raise TypeError(
                f"{model.__name__} is not an append-only table; write it through "
                "the session, where the scan can read it back"
            )
        organization_id = values.setdefault("organization_id", self.organization_id)
        if organization_id != self.organization_id:
            raise ValueError(
                f"a {model.__name__} row for organization {organization_id} was "
                f"queued by a scan of {self.organization_id}"
            )
        self._pending.setdefault(model, []).append(values)

    def pending(self, model: type[Base]) -> int:
        """How many rows of this table are queued and not yet written."""
        return len(self._pending.get(model, ()))

    async def flush(self) -> None:
        """Write the ORM's pending objects, then every queued row.

        In that order, because the queued rows point at them: a finding event
        needs its finding's id, and a new finding has none until the ORM has
        flushed it.

        Grouped by the columns each row sets, because one ``executemany``
        compiles one statement, and a row that leaves a column to its default
        would otherwise be sent an explicit NULL for it.
        """
        await self.session.flush()
        pending, self._pending = self._pending, {}
        for model, rows in pending.items():
            by_columns: dict[frozenset[str], list[dict[str, Any]]] = {}
            for row in rows:
                by_columns.setdefault(frozenset(row), []).append(row)
            # The table rather than the mapped class: an ORM-enabled insert
            # would route the rows back through the unit of work this exists
            # to keep them out of.
            table = cast(Table, model.__table__)
            for batch in by_columns.values():
                statement = pg_insert(table)
                if APPEND_ONLY[model]:
                    statement = statement.on_conflict_do_nothing()
                await self.session.execute(statement, batch)

    async def commit(self) -> None:
        """Flush, check the fence, and commit -- or roll back and stop.

        The fence is asked last, after every write, so the lock it takes on the
        step row is held for the length of a commit rather than of a stage.
        """
        await self.flush()
        if self.fence is not None:
            try:
                await self.fence.hold(self.session)
            except StepLeaseLost:
                await self.session.rollback()
                raise
        await self.session.commit()
