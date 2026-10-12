"""Fix-as-Code pull requests (migrations 0056 and 0065, DECISIONS.md §232, §258)."""

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TenantOwned, UUIDPrimaryKey


class FixPullRequest(UUIDPrimaryKey, TenantOwned, Base):
    """One rule's fix, or one cut, asked for as a pull request on one repository."""

    __tablename__ = "fix_pull_requests"

    # RULE edits a rule's failing assets; CUT deletes the role assignments one
    # link of the attack-path graph stands for (§258).
    kind: Mapped[str] = mapped_column(String(8), nullable=False, default="RULE")
    rule_id: Mapped[str | None] = mapped_column(String(128))
    # A cut's link as the page names it (``source|relationship|target``), and the
    # link with its sentence, for the pull request's title and body.
    cut_key: Mapped[str | None] = mapped_column(Text)
    cut: Mapped[dict | None] = mapped_column(JSONB)
    repository_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    repository: Mapped[str] = mapped_column(String(200), nullable=False)
    # QUEUED, OPENING, OPEN, MERGED, CLOSED, DECLINED or FAILED.
    state: Mapped[str] = mapped_column(String(16), nullable=False, default="QUEUED")
    branch: Mapped[str | None] = mapped_column(String(200))
    pr_number: Mapped[int | None] = mapped_column(Integer)
    pr_url: Mapped[str | None] = mapped_column(Text)
    decline_reason: Mapped[str | None] = mapped_column(String(64))
    detail: Mapped[str | None] = mapped_column(Text)
    requested_by: Mapped[uuid.UUID] = mapped_column(PGUUID(as_uuid=True), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    claimed_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now()
    )


class FixPullRequestFinding(UUIDPrimaryKey, TenantOwned, Base):
    """A finding a pull request covers, and whether its block was edited."""

    __tablename__ = "fix_pull_request_findings"

    pull_request_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("fix_pull_requests.id", ondelete="CASCADE"), nullable=False
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("findings.id", ondelete="CASCADE"), nullable=False
    )
    address: Mapped[str] = mapped_column(Text, nullable=False)
    # PENDING, EDITED or DECLINED.
    outcome: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING")
    reason: Mapped[str | None] = mapped_column(String(64))
    path: Mapped[str | None] = mapped_column(Text)
    line: Mapped[int | None] = mapped_column(Integer)


class FixPullRequestAssignment(UUIDPrimaryKey, TenantOwned, Base):
    """A role assignment a cut's pull request removes, and whether its block was deleted."""

    __tablename__ = "fix_pull_request_assignments"

    pull_request_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("fix_pull_requests.id", ondelete="CASCADE"), nullable=False
    )
    assignment_id: Mapped[str] = mapped_column(Text, nullable=False)
    address: Mapped[str] = mapped_column(Text, nullable=False)
    working_directory: Mapped[str] = mapped_column(Text, nullable=False, default="")
    # PENDING, REMOVED or DECLINED.
    outcome: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING")
    reason: Mapped[str | None] = mapped_column(String(64))
    path: Mapped[str | None] = mapped_column(Text)
    line: Mapped[int | None] = mapped_column(Integer)
