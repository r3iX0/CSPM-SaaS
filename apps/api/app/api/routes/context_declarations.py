"""Every context declaration in the organization at once (DECISIONS.md section 207).

One subscription's declaration is read, replaced and withdrawn under
``/cloud-accounts/{id}/context``. This is the collection of them, so a screen
that shows every subscription with what was said about it asks once.
"""

from fastapi import APIRouter

from app.core.deps import DbSession, Tenant
from app.schemas.common import ERROR_RESPONSES, Envelope, NoMeta
from app.schemas.context import ContextDeclarationOut
from app.services import context as service

router = APIRouter(
    prefix="/context-declarations", tags=["cloud-accounts"], responses=ERROR_RESPONSES
)


@router.get("")
async def list_context_declarations(
    session: DbSession, tenant: Tenant
) -> Envelope[list[ContextDeclarationOut], NoMeta]:
    """What has been declared about each subscription that has a declaration.

    Not paged: there is at most one per subscription, and the subscriptions
    themselves (``GET /cloud-accounts``) are not paged either.
    """
    records = await service.list_declarations(session, tenant)
    return Envelope(
        data=[ContextDeclarationOut.model_validate(record) for record in records],
        meta=NoMeta(),
    )
