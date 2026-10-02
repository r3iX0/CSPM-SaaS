from uuid import UUID

from fastapi import APIRouter

from app.core.deps import DbSession, Tenant
from app.models.cloud_account import CloudAccount
from app.schemas.cloud_account import AzurePermissionsOut, CloudAccountOut
from app.schemas.common import ERROR_RESPONSES, Envelope, NoMeta, error_responses
from app.schemas.context import ContextDeclarationIn, ContextDeclarationOut
from app.services import cloud_accounts as service
from app.services import context as context_service

# Per route rather than on the router: the permissions list is public.
router = APIRouter(prefix="/cloud-accounts", tags=["cloud-accounts"])
WRITE = {**ERROR_RESPONSES, **error_responses(403)}

# Read-only on purpose. A cloud account is no longer something a customer
# registers -- it is a subscription *discovered* beneath a cloud connection
# (app/services/cloud_connections.py), so there is nothing here to create,
# consent to, or validate. Those endpoints moved to /cloud-connections, and
# removing rather than keeping them is deliberate: the create path accepted a
# tenant id from the request body, and validation checked only whether Azure
# answered. Since CloudGuard's service principal exists in every tenant that
# ever consented, that combination let one organization name another's tenant
# and verify successfully against an environment it had no claim to.
#
# Scoping a discovered subscription in or out is a PATCH on the connection that
# found it, not a delete here -- a deleted row would simply come back on the
# next discovery run.


def _serialize(account: CloudAccount) -> CloudAccountOut:
    data = CloudAccountOut.model_validate(account)
    data.is_scannable = account.is_scannable
    return data


@router.get("/azure/permissions")
async def azure_permissions() -> Envelope[AzurePermissionsOut, NoMeta]:
    """What CloudGuard will be able to see, shown before anyone consents."""
    permissions = service.required_permissions()
    return Envelope(data=AzurePermissionsOut.model_validate(permissions), meta=NoMeta())


@router.get("", responses=ERROR_RESPONSES)
async def list_cloud_accounts(
    session: DbSession, tenant: Tenant
) -> Envelope[list[CloudAccountOut], NoMeta]:
    """The subscriptions discovered under this organization's connections."""
    rows = await service.list_cloud_accounts(session, tenant)
    return Envelope(data=[_serialize(a) for a in rows], meta=NoMeta())


@router.get("/{account_id}", responses=ERROR_RESPONSES)
async def get_cloud_account(
    account_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[CloudAccountOut, NoMeta]:
    account = await service.get_cloud_account(session, tenant, account_id)
    return Envelope(data=_serialize(account), meta=NoMeta())


# --- what the customer says about a subscription ---------------------------
# The one write path here, on an otherwise read-only router, and the exception
# is principled: everything else about a cloud account is a record of what
# Azure said, while a declaration is a record of what a person said. A customer
# marking a subscription "production" beats any amount of tag inference, and
# there was previously nowhere to put the answer.


def _declaration(record: object | None) -> ContextDeclarationOut | None:
    if record is None:
        return None
    return ContextDeclarationOut.model_validate(record)


@router.get("/{account_id}/context", responses=ERROR_RESPONSES)
async def get_account_context(
    account_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[ContextDeclarationOut | None, NoMeta]:
    """What has been declared about this subscription, or null if nothing has."""
    record = await context_service.get_declaration(session, tenant, account_id)
    return Envelope(data=_declaration(record), meta=NoMeta())


@router.put("/{account_id}/context", responses=WRITE)
async def declare_account_context(
    account_id: UUID, payload: ContextDeclarationIn, session: DbSession, tenant: Tenant
) -> Envelope[ContextDeclarationOut | None, NoMeta]:
    """Declare the environment, criticality or data sensitivity of a subscription.

    A full replacement rather than a patch: a field left out is one the customer
    is no longer claiming, and a body claiming nothing at all clears the
    declaration entirely.

    Applied by the next evaluation of this subscription -- the next scan, or a
    replay of its latest capture. Deliberately not rescored here: a risk score
    is what a scan concluded, and rewriting stored scores from an API call would
    leave findings carrying numbers no observation ever produced.
    """
    tenant.require_write()
    record = await context_service.declare(
        session,
        tenant,
        account_id,
        environment=payload.environment,
        criticality=payload.criticality,
        data_sensitivity=payload.data_sensitivity,
        note=payload.note,
    )
    await session.commit()
    return Envelope(data=_declaration(record), meta=NoMeta())


@router.delete("/{account_id}/context", responses=WRITE)
async def clear_account_context(
    account_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[None, NoMeta]:
    """Withdraw the declaration, leaving CloudGuard to infer as it did before."""
    tenant.require_write()
    await context_service.declare(
        session,
        tenant,
        account_id,
        environment=None,
        criticality=None,
        data_sensitivity=None,
        note=None,
    )
    await session.commit()
    return Envelope(data=None, meta=NoMeta())
