"""Which rows a scan is entitled to read and write.

The predicates every hot-path query in the analysis shares. Pure functions of
the scan's coverage -- the subscriptions it read and the connection it read the
directory through -- so they can be asked from any stage without a session.
"""

from uuid import UUID

from sqlalchemy import and_, or_
from sqlalchemy.sql.elements import ColumnElement

from app.models.finding import Finding
from app.models.resource import ResourceRecord
from app.models.verification import RemediationVerification


def asset_scope(
    account_ids: list[UUID], connection_id: UUID | None
) -> ColumnElement[bool] | None:
    """Which assets this scan is entitled to read and write.

    The one predicate every hot-path query in the pipeline shares, and the
    reason it exists is that they used to share the *organization* instead.
    ``persist_findings`` read every finding in the tenant, its risk links
    read every link, and ``_persist_relationships`` read the whole edge
    table -- on every scan, including a single-subscription rescan of one
    finding in a tenant of fifty. All three grew with the customer rather
    than with the work, which is the shape that fails first and fails as a
    timeout inside a task with no retry.

    Two scopes, because assets have two. A subscription's assets are keyed
    by account; the tenant's directory assets have no account and are keyed
    by connection. ``None`` when a scan covers neither, which is a scan with
    nothing to do.
    """
    scopes: list[ColumnElement[bool]] = []
    if account_ids:
        scopes.append(ResourceRecord.cloud_account_id.in_(account_ids))
    if connection_id is not None:
        scopes.append(
            and_(
                ResourceRecord.cloud_account_id.is_(None),
                ResourceRecord.connection_id == connection_id,
            )
        )
    if not scopes:
        return None
    return or_(*scopes)


def finding_scope(
    account_ids: list[UUID], connection_id: UUID | None
) -> ColumnElement[bool]:
    """The same scope, expressed over findings.

    Used with an outer join to ``cloud_resources``. The third arm is not
    decoration: an AGGREGATE rule's finding is about the tenant and carries
    no resource at all, so a scope built only from asset columns would leave
    those findings invisible to the scan that is meant to re-detect or
    resolve them -- and an invisible open finding is one that gets inserted
    again, against a unique index that will not have it.
    """
    assets = asset_scope(account_ids, connection_id)
    aggregate = Finding.resource_id.is_(None)
    return aggregate if assets is None else or_(assets, aggregate)


def verification_scope(
    account_ids: list[UUID], connection_id: UUID | None
) -> ColumnElement[bool]:
    """The verifications this scan is entitled to have an opinion about."""
    clauses: list[ColumnElement[bool]] = []
    if account_ids:
        clauses.append(RemediationVerification.cloud_account_id.in_(account_ids))
    if connection_id is not None:
        # Directory findings belong to no subscription. They are settled by
        # any scan that read the tenant through the same connection, which
        # is every scan under it.
        clauses.append(
            and_(
                RemediationVerification.cloud_account_id.is_(None),
                RemediationVerification.connection_id == connection_id,
            )
        )
    if not clauses:
        return RemediationVerification.id.is_(None)
    return or_(*clauses) if len(clauses) > 1 else clauses[0]
