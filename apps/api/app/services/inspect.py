"""What the inspector reads about one asset beyond the drawing (DECISIONS.md section 254).

An engineer handed a cut wants to check it, and the drawing says only how an
asset is wired. This answers two more questions, from what Cleave already holds:
where the asset is defined in code (the customer's Terraform state index,
section 229), and what has happened to it lately (its change events, and for an
account its last sign-in). Cleave reads configuration and runs no agent, so it
has no process, traffic or exploit telemetry, and nothing here pretends to.
"""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import TenantContext
from app.core.enums import ResourceType
from app.domain.resource import CloudResource
from app.models.history import AssetChangeEvent
from app.models.resource import ResourceRecord
from app.schemas.attack_path import CodeHomeOut, InspectChangeOut, InspectOut, SignInOut
from app.services.iac_index import managed_in_code

#: Change events listed for one asset. The asset's own page lists the rest.
CHANGES_LIMIT = 10

_ACCOUNTS = {ResourceType.USER, ResourceType.SERVICE_PRINCIPAL}


def sign_in(resource: CloudResource) -> SignInOut | None:
    """An account's last sign-in, as the capture recorded it; ``None`` for anything else.

    ``read`` false means the capture holds no sign-in reading for the account:
    the tenant's licence may not allow it (section 196), and it is said rather
    than shown as "never signed in", which is a different, stronger fact.
    """
    if resource.resource_type not in _ACCOUNTS:
        return None
    metadata = resource.metadata
    if not metadata.get("sign_in_activity_read"):
        return SignInOut(read=False, last_sign_in=None, days_since=None)
    days = metadata.get("days_since_sign_in")
    last = metadata.get("last_sign_in")
    return SignInOut(
        read=True,
        last_sign_in=last if isinstance(last, str) else None,
        days_since=days if isinstance(days, int) else None,
    )


async def inspect(
    session: AsyncSession, tenant: TenantContext, resource: CloudResource
) -> InspectOut:
    """Where an asset is defined in code, and what has happened to it lately."""
    row = (
        await session.execute(
            select(ResourceRecord).where(
                ResourceRecord.organization_id == tenant.organization_id,
                ResourceRecord.provider_resource_id == resource.provider_resource_id,
            )
        )
    ).scalar_one_or_none()
    changes: list[InspectChangeOut] = []
    if row is not None:
        changes = [
            InspectChangeOut(
                change=event.change,
                previous_value=event.previous_value,
                current_value=event.current_value,
                observed_at=event.observed_at,
            )
            for event in (
                await session.execute(
                    select(AssetChangeEvent)
                    .where(
                        AssetChangeEvent.organization_id == tenant.organization_id,
                        AssetChangeEvent.resource_id == row.id,
                    )
                    .order_by(AssetChangeEvent.observed_at.desc())
                    .limit(CHANGES_LIMIT)
                )
            ).scalars()
        ]
    homes = await managed_in_code(session, tenant, row)
    return InspectOut(
        asset_id=row.id if row is not None else None,
        defined_in=[
            CodeHomeOut(
                repository=index.repository,
                working_directory=index.working_directory,
                address=entry.address,
            )
            for index, entry in homes
        ],
        changes=changes,
        sign_in=sign_in(resource),
    )
