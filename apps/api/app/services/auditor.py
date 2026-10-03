"""An auditor reads one sealed package through the grant they were given.

The auditor is not a member of any organization, so nothing here goes through a tenant: every
read is a ``SECURITY DEFINER`` function that begins by checking the grant is this user's, for the
address on their verified token, unrevoked and unexpired (DECISIONS.md section 211). This module
only calls them and says what their refusals mean. The archive and the verification are the
owner's, over the same builder (section 208), fed from those functions instead of the tables.

A refusal raises inside the function and rolls its own writes back, so it leaves no event. It is
logged instead (``auditor.refused``), with the reason and the account and never the token.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.base import Executable

from app.compliance import package as manifest_module
from app.core.errors import ConflictError, NotFound, PermissionDenied
from app.core.logging import get_logger
from app.core.security import AuthenticatedUser
from app.models.audit_package import AuditPackage, AuditPackageItem
from app.services import audit_packages
from app.services.audit_packages import ArchiveInputs, Verification
from app.services.team import token_hash

log = get_logger(__name__)


@dataclass(frozen=True)
class AuditorGrant:
    """A grant as the auditor it is for sees it."""

    id: UUID
    package_id: UUID
    package_name: str
    organization_name: str
    email: str
    opened_at: datetime
    expires_at: datetime


# What the functions raise, and what the caller is told. A grant that is somebody else's and one
# that does not exist are both "not found", so a stranger learns nothing from the difference.
_REFUSALS: tuple[tuple[str, type[Exception], str], ...] = (
    ("grant not found", NotFound, "This link is not valid"),
    (
        "grant not open",
        ConflictError,
        "This grant was withdrawn. Ask the person who sent it for a new one.",
    ),
    (
        "grant expired",
        ConflictError,
        "This grant has expired. Ask the person who sent it for a new one.",
    ),
    (
        "grant is for another address",
        PermissionDenied,
        "This grant was made for a different email address. Sign in with that address to open it.",
    ),
    (
        "grant already opened",
        ConflictError,
        "This link has already been opened by another account. Ask for a new one.",
    ),
)


async def _execute(
    session: AsyncSession,
    user: AuthenticatedUser,
    statement: Executable,
    params: dict[str, Any] | None = None,
) -> Any:
    """Run one statement, turning a function's refusal into the answer the caller is given."""
    try:
        return await session.execute(statement, params)
    except DBAPIError as exc:
        reason = str(exc.orig)
        for fragment, error, message in _REFUSALS:
            if fragment in reason:
                log.warning("auditor.refused", reason=fragment, user_id=str(user.id))
                raise error(message) from exc
        raise


def _grant(row: Any) -> AuditorGrant:
    return AuditorGrant(
        id=row["grant_id"],
        package_id=row["package_id"],
        package_name=row["package_name"],
        organization_name=row["organization_name"],
        email=row["email"],
        opened_at=row["opened_at"],
        expires_at=row["expires_at"],
    )


async def open_grant(session: AsyncSession, user: AuthenticatedUser, token: str) -> AuditorGrant:
    """Spend a link: bind its grant to this account and say what it gives.

    Checked inside ``app.open_audit_grant``: the grant is open, unexpired, and made for the
    address on the caller's own verified token. Opening it again, as the same account, is fine.
    """
    result = await _execute(
        session,
        user,
        text("SELECT app.open_audit_grant(:hash)"),
        {"hash": token_hash(token)},
    )
    return await grant_header(session, user, result.scalar_one())


async def grant_header(
    session: AsyncSession, user: AuthenticatedUser, grant_id: UUID
) -> AuditorGrant:
    result = await _execute(
        session,
        user,
        text("SELECT * FROM app.audit_grant_header(:grant)"),
        {"grant": grant_id},
    )
    row = result.mappings().first()
    if row is None:  # pragma: no cover -- the function raises before it returns nothing
        raise NotFound("This link is not valid")
    return _grant(row)


async def list_grants(session: AsyncSession, user: AuthenticatedUser) -> list[AuditorGrant]:
    """The grants this account has opened and that are still live, newest first."""
    result = await _execute(session, user, text("SELECT * FROM app.my_audit_grants()"))
    return [_grant(row) for row in result.mappings().all()]


async def get_package(
    session: AsyncSession, user: AuthenticatedUser, grant_id: UUID
) -> tuple[AuditPackage, list[AuditPackageItem]]:
    """The granted package and its readings, or the refusal the grant's state calls for."""
    packages = await _execute(
        session,
        user,
        select(AuditPackage).from_statement(
            text("SELECT * FROM app.audit_grant_package(:grant)").bindparams(grant=grant_id)
        ),
    )
    package = packages.scalars().first()
    if package is None:  # pragma: no cover -- the function raises before it returns nothing
        raise NotFound("This link is not valid")
    items = await _execute(
        session,
        user,
        select(AuditPackageItem).from_statement(
            text("SELECT * FROM app.audit_grant_items(:grant)").bindparams(grant=grant_id)
        ),
    )
    return package, list(items.scalars().all())


async def payload_availability(
    session: AsyncSession,
    user: AuthenticatedUser,
    grant_id: UUID,
    items: list[AuditPackageItem],
) -> tuple[int, int]:
    """How many distinct payloads the readings name, and how many are still stored."""
    named = audit_packages.payload_hashes(items)
    if not named:
        return 0, 0
    held = await _execute(
        session,
        user,
        text("SELECT content_hash FROM app.audit_grant_held_hashes(:grant)"),
        {"grant": grant_id},
    )
    return len(named), len(held.all())


async def verify(session: AsyncSession, user: AuthenticatedUser, grant_id: UUID) -> Verification:
    """Whether the stored rows still give the hash the package was sealed under."""
    package, items = await get_package(session, user, grant_id)
    recomputed = manifest_module.recompute(package, items)
    return Verification(
        matches=recomputed == package.manifest_sha256,
        sealed_sha256=package.manifest_sha256,
        recomputed_sha256=recomputed,
    )


async def archive_inputs(
    session: AsyncSession, user: AuthenticatedUser, grant_id: UUID
) -> ArchiveInputs:
    """Read the package and the payloads it names, and record that they are being taken.

    The same refusal for an archive too large as the owner's, before any payload is read. The
    event is written by ``app.record_audit_grant_download`` in this transaction, and the route
    commits it before the build: a record of access and not of success, as the owner's is.
    """
    package, items = await get_package(session, user, grant_id)
    audit_packages.guard_archive_size(items)

    hashes = audit_packages.payload_hashes(items)
    stored: dict[str, bytes] = {}
    for start in range(0, len(hashes), audit_packages.BLOB_BATCH):
        rows = await _execute(
            session,
            user,
            text(
                "SELECT content_hash, payload_compressed, payload "
                "FROM app.audit_grant_blobs(:grant, :hashes)"
            ),
            {"grant": grant_id, "hashes": hashes[start : start + audit_packages.BLOB_BATCH]},
        )
        audit_packages.keep_stored(stored, rows.all())

    await _execute(
        session,
        user,
        text("SELECT app.record_audit_grant_download(:grant)"),
        {"grant": grant_id},
    )
    return ArchiveInputs(package=package, items=items, stored_payloads=stored)
