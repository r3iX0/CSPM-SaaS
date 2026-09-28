"""What the second engine said, and where it disagreed with the first.

Two tables, both written once per scan and never updated.

``assessment_captures`` is the ASSESS step's output: one row per scope, holding
Prowler's results verbatim. It is the second engine's counterpart of
``cloud_snapshots`` -- stored before anything is interpreted, so ANALYZE reads it
back exactly as it reads a native capture, and a replay can re-interpret it
under today's catalogue. Written by the scanner service (``apps/scanner``),
which does not import this module; the columns here are the contract it writes
to, and ``tests/unit/test_prowler_engine.py`` holds the two to the same list.

``engine_divergences`` is the audit. Where a native rule and the Prowler checks
that answer the same question reached different verdicts on the same asset,
one row says so. It is how the two engines check each other rather than merely
coexisting (DECISIONS.md section 150).
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.enums import Provider
from app.core.errors import SnapshotUnavailable
from app.core.payloads import decompress
from app.models.base import Base, StrEnumType, TenantOwned, UUIDPrimaryKey


class AssessmentCapture(UUIDPrimaryKey, TenantOwned, Base):
    """One scope's Prowler run, stored before it is interpreted."""

    __tablename__ = "assessment_captures"
    __table_args__ = (
        UniqueConstraint(
            "scan_id",
            "cloud_account_id",
            name="uq_assessment_captures_scan_account",
            # NULL is the directory run, and one scan has at most one.
            postgresql_nulls_not_distinct=True,
        ),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    # The subscription or account the run covered. NULL for the directory run,
    # which reads the tenant rather than any scope beneath it.
    cloud_account_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cloud_accounts.id", ondelete="CASCADE")
    )
    connection_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cloud_connections.id", ondelete="CASCADE")
    )
    provider: Mapped[Provider] = mapped_column(StrEnumType(Provider, 16), nullable=False)
    engine: Mapped[str] = mapped_column(String(16), nullable=False, default="prowler")
    # The Prowler release that ran. A capture is only interpretable against a
    # catalogue built from the same one; ANALYZE refuses a mismatch rather than
    # reading check ids under a meaning they may no longer have.
    engine_version: Mapped[str] = mapped_column(String(32), nullable=False)
    # COMPLETE, PARTIAL (it ran, and some services or checks errored), FAILED
    # (it could not run at all -- the provider would not authenticate).
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    checks_requested: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    checks_completed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    result_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Why a verdict may be missing, in the words Prowler logged:
    # ``{"fatal": str | None, "services": {service: [message]},
    #    "checks": {check_id: message}}``. Kept out of the payload so the API can
    # show it without decompressing the results.
    errors: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    # ``{"requested": [check_id], "completed": [check_id], "results": [...]}``,
    # canonical JSON through zlib -- the same encoding ``EvidenceBlob`` uses
    # (``app/core/payloads.py``).
    payload_compressed: Mapped[bytes | None] = mapped_column(LargeBinary)
    content_hash: Mapped[str | None] = mapped_column(String(64))
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    stored_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    @property
    def content(self) -> dict:
        """The stored run, decompressed.

        Raises rather than answering with an empty run when the bytes are gone:
        "Prowler found nothing" and "the record of what Prowler found was pruned"
        are different claims, and only the first is a verdict.
        """
        if self.payload_compressed is None:
            raise SnapshotUnavailable(
                "this assessment's results are no longer stored, so there is "
                "nothing to interpret"
            )
        return decompress(self.payload_compressed)


class EngineDivergence(UUIDPrimaryKey, TenantOwned, Base):
    """A native rule and its Prowler counterpart disagreeing about one asset."""

    __tablename__ = "engine_divergences"
    __table_args__ = (Index("ix_engine_divergences_scan", "scan_id", "rule_id"),)

    scan_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False
    )
    rule_id: Mapped[str] = mapped_column(String(128), nullable=False)
    check_id: Mapped[str] = mapped_column(String(128), nullable=False)
    # NULL where the disagreement is about the scope as a whole -- the rule is
    # aggregate, or the two engines named the asset in ways that do not join.
    resource_id: Mapped[uuid.UUID | None] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cloud_resources.id", ondelete="CASCADE")
    )
    provider_resource_id: Mapped[str | None] = mapped_column(Text)
    native_state: Mapped[str] = mapped_column(String(16), nullable=False)
    prowler_state: Mapped[str] = mapped_column(String(16), nullable=False)
    # Which way round: NATIVE_MISSED (Prowler failed what Cleave passed),
    # PROWLER_MISSED (the reverse), NATIVE_UNKNOWN or PROWLER_UNKNOWN (one
    # engine could not tell).
    kind: Mapped[str] = mapped_column(String(24), nullable=False)
    # Whether curation.json records this pair as disagreeing by design. An
    # expected divergence is still recorded -- it is evidence the difference
    # still exists -- and the audit view lists it apart.
    expected: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    detail: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
