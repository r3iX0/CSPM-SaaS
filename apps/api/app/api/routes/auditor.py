"""What an auditor reads: one sealed package, through the grant they were given.

An auditor is not a member of any organization, so none of these depends on ``Tenant`` --
``get_tenant`` answers ``404`` to a caller with no membership. They take the signed-in user and
a grant id, and every read is a database function that checks the grant is this account's, for
the address on its verified token, unrevoked and unexpired (DECISIONS.md section 211).

``POST /grants/open`` spends the link, as ``POST /invitations/accept`` spends an invitation: the
token goes in the body, and after it the grant's id is the handle, useless to any other account.
Reading is a ``GET`` and records nothing; the archive records, as the owner's does.
"""

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from app.api.archives import archive_response
from app.api.routes.audit_packages import package_detail
from app.core.deps import Costly, CurrentUser, DbSession
from app.schemas.audit_grant import AuditorGrantOut, GrantToken
from app.schemas.audit_package import AuditPackageDetailOut, VerificationOut
from app.schemas.common import ERROR_RESPONSES, Envelope, NoMeta, error_responses
from app.services import auditor as service
from app.services.auditor import AuditorGrant

router = APIRouter(prefix="/auditor", tags=["auditor"], responses=ERROR_RESPONSES)

# What the grant's state can answer: no longer open or expired (409), made for another address
# (403). A grant that is not this account's is a 404, which every route here already documents.
GRANTED = error_responses(403, 409)


def _out(grant: AuditorGrant) -> AuditorGrantOut:
    return AuditorGrantOut(
        id=grant.id,
        package_id=grant.package_id,
        package_name=grant.package_name,
        organization_name=grant.organization_name,
        email=grant.email,
        opened_at=grant.opened_at,
        expires_at=grant.expires_at,
    )


@router.post("/grants/open", responses=GRANTED)
async def open_grant(
    payload: GrantToken, user: CurrentUser, session: DbSession
) -> Envelope[AuditorGrantOut, NoMeta]:
    """Open a grant link as the signed-in account, which must be the address it was made for.

    Binds the grant to this account the first time, and writes the first entry in its event log.
    Opening it again, as the same account, is fine. ``403`` for another address, ``409`` for a
    grant that was withdrawn, has expired, or was opened by another account, and ``404`` for a
    link that is not valid.
    """
    grant = await service.open_grant(session, user, payload.token)
    return Envelope(data=_out(grant), meta=NoMeta())


@router.get("/grants")
async def list_my_grants(
    user: CurrentUser, session: DbSession
) -> Envelope[list[AuditorGrantOut], NoMeta]:
    """The grants this account has opened and that are still live, newest first."""
    grants = await service.list_grants(session, user)
    return Envelope(data=[_out(grant) for grant in grants], meta=NoMeta())


@router.get("/grants/{grant_id}", responses=GRANTED)
async def get_my_grant(
    grant_id: UUID, user: CurrentUser, session: DbSession
) -> Envelope[AuditorGrantOut, NoMeta]:
    """One grant: which package, whose, and until when."""
    return Envelope(data=_out(await service.grant_header(session, user, grant_id)), meta=NoMeta())


@router.get("/grants/{grant_id}/package", responses=GRANTED)
async def get_granted_package(
    grant_id: UUID, user: CurrentUser, session: DbSession
) -> Envelope[AuditPackageDetailOut, NoMeta]:
    """The package's header, how each framework's controls came out, and what they rest on.

    The owner's view of the same package (``GET /audit-packages/{id}``). The controls themselves
    are in the archive. How many payloads are still stored is answered live.
    """
    package, items = await service.get_package(session, user, grant_id)
    payloads = await service.payload_availability(session, user, grant_id, items)
    return Envelope(data=package_detail(package, items, payloads), meta=NoMeta())


@router.get("/grants/{grant_id}/verification", responses=GRANTED)
async def verify_granted_package(
    grant_id: UUID, user: CurrentUser, session: DbSession
) -> Envelope[VerificationOut, NoMeta]:
    """Whether the stored rows still give the hash the package was sealed under.

    A read, and idempotent. Both digests are given so the answer can be checked and not only
    believed; the archive lets an auditor check it without trusting this endpoint at all.
    """
    result = await service.verify(session, user, grant_id)
    return Envelope(
        data=VerificationOut(
            verified=result.matches,
            sealed_sha256=result.sealed_sha256,
            recomputed_sha256=result.recomputed_sha256,
            checked_at=datetime.now(UTC),
        ),
        meta=NoMeta(),
    )


@router.get(
    "/grants/{grant_id}/archive",
    response_class=StreamingResponse,
    dependencies=[Costly],
    responses={
        200: {
            "description": (
                "The package as a zip: the manifest, one CSV of controls per framework, the "
                "gaps, the readings, the captured payloads and a SHA256SUMS that checks them."
            ),
            "content": {"application/zip": {}},
        },
        **GRANTED,
    },
)
async def download_granted_archive(
    grant_id: UUID, user: CurrentUser, session: DbSession
) -> StreamingResponse:
    """The package, and the evidence it names, as files that can be checked without Cleave.

    The same archive the owner downloads, sharing one build limit with it. The download is
    written to the grant's event log, which makes this a ``GET`` that records an entry: evidence
    leaving the system belongs on the trail, and the entry is an append-only record and not state
    a repeat changes. ``409`` when the evidence is more than one archive holds.
    """
    inputs = await service.archive_inputs(session, user, grant_id)
    return await archive_response(session, inputs)
