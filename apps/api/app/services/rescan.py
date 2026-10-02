"""Re-checking the environment after a fix: the scan that verifies it.

Its own module because it reaches across three others -- the finding, the account that holds its
asset, and the scan queue -- and ``findings`` cannot import ``scans`` without a cycle
(``scans`` reads ``risks``, which reads ``findings``).
"""

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.deps import TenantContext
from app.core.enums import ScanStatus
from app.core.errors import ConflictError, ValidationFailed
from app.core.vocabulary import words
from app.models.finding import Finding
from app.models.scan import Scan
from app.services import cloud_accounts as accounts_service
from app.services import findings as findings_service
from app.services import scans as scans_service


async def request_rescan(session: AsyncSession, tenant: TenantContext, finding: Finding) -> Scan:
    """Add a queued scan of the subscription that holds this finding's asset.

    Returns the new row uncommitted: the route commits, then puts the scan on the queue, so the
    worker never sees an id the database has not got. The lock on the scan target is taken
    before the in-flight check and held until that commit, so two clicks a moment apart do not
    both read "nothing running".
    """
    resource = await findings_service.resource_of(session, finding)
    if resource is None:
        raise ValidationFailed(
            "This finding is not tied to a single resource. Run a full scan instead."
        )

    # A directory asset lives in the tenant and in no subscription, so there is
    # no account id on it to rescan. Any scannable subscription under the same
    # connection does the job: a scan resolves its connection from whichever
    # account it covers and reads the directory once through that, so the
    # cheapest scan available still re-reads the thing this finding is about.
    if resource.cloud_account_id is None:
        account = await accounts_service.first_scannable_account(
            session, tenant, resource.connection_id
        )
        if account is None:
            scope_words = words(resource.provider)
            raise ValidationFailed(
                f"This finding is about the {scope_words.directory}, and the "
                f"connection it came from has no {scope_words.account} ready to "
                "scan. Validate the connection, then try again."
            )
    else:
        account = await accounts_service.get_cloud_account(
            session, tenant, resource.cloud_account_id
        )
    if not account.is_scannable:
        raise ValidationFailed("This connection is not ready to scan")

    await scans_service.lock_scan_target(
        session, tenant.organization_id, account.connection_id, account.id
    )
    if await scans_service.scan_in_flight(
        session, tenant.organization_id, account.connection_id, account.id
    ):
        raise ConflictError("A scan is already running for this connection")

    # Deliberately narrowed to the one subscription this finding lives in, even
    # when the connection spans several. Re-reading a whole tenant to verify one
    # fix is a cost the customer did not ask for, and the auto-resolve path only
    # needs the subscription that holds the resource.
    scan = Scan(
        organization_id=tenant.organization_id,
        cloud_account_id=account.id,
        status=ScanStatus.QUEUED,
    )
    session.add(scan)
    await findings_service.record_audit(
        session,
        tenant,
        action="finding.rescan_requested",
        resource_type="finding",
        resource_id=finding.id,
        metadata={"rule_id": finding.rule_id},
    )
    return scan
