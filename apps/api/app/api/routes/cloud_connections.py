import json
from urllib.parse import quote
from uuid import UUID

from fastapi import APIRouter, Query, status
from fastapi.responses import JSONResponse, RedirectResponse

from app.core.config import settings
from app.core.db import service_session
from app.core.deps import DbSession, Tenant
from app.core.enums import ConsentStatus, Provider, Role
from app.core.errors import CloudAccountNotFound, ValidationFailed
from app.core.signing import Purpose, SignedStateError, verify_state
from app.models.cloud_account import CloudAccount
from app.models.cloud_connection import CloudConnection
from app.schemas.cloud_connection import (
    AppRegistrationOut,
    ChangeEventSetupOut,
    ChangeEventsUpdate,
    CloudConnectionCreate,
    CloudConnectionOut,
    ConnectionDeletedOut,
    DiscoveredSubscription,
    ProviderOptionOut,
    RevocationCheckOut,
    RevocationOut,
    ScheduleUpdate,
    ScopeSelection,
)
from app.schemas.common import ERROR_RESPONSES, Envelope, NoMeta, error_responses
from app.services import cloud_connections as service

router = APIRouter(
    prefix="/cloud-connections", tags=["cloud-connections"], responses=ERROR_RESPONSES
)
# Refused to a read-only role, and to anybody in the demo.
WRITE = error_responses(403)

# Applied to the ARM template endpoint only, not to the API at large. The
# global CORS policy names this product's own frontend; Azure Portal is a
# third-party origin fetching one deliberately public, token-gated document.
TEMPLATE_CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Cache-Control": "no-store",
}

# What of a connection's provider reference reaches the browser.
#
# An allow-list rather than a denylist: this column is where a provider-shaped
# field lands, and the next one added should have to be named here before a
# customer can see it. Both entries are things the customer needs in front of
# them -- the role ARN to check what they deployed, the external id to check
# their own trust policy requires it. Neither is a credential; the external id
# means nothing without a role that demands it.
VISIBLE_PROVIDER_REF = frozenset({"role_arn", "external_id"})


def _serialize(
    connection: CloudConnection,
    subscription_count: int = 0,
    subscriptions: list[CloudAccount] | None = None,
    consent_url: str | None = None,
) -> CloudConnectionOut:
    data = CloudConnectionOut.model_validate(connection)
    data.is_verified = connection.is_verified
    data.scope_path = service.scope_path(connection)
    # Filtered rather than passed through. ``provider_ref`` is where a future
    # field could land that a viewer should not see, and a serializer that
    # forwarded the whole blob would carry it to the browser without anybody
    # deciding to.
    data.provider_ref = {
        key: value
        for key, value in (connection.provider_ref or {}).items()
        if key in VISIBLE_PROVIDER_REF
    }
    data.subscription_count = subscription_count
    data.template_url = service.deployment_url(connection)
    # Lets the card stop showing a spinner once waiting has stopped being a
    # plausible explanation for the silence.
    data.deploy_stalled = service.deploy_stalled(connection)
    data.role_upgrade_available = service.grant_upgrade_available(connection)
    # What to redeploy to, and what is lost until they do. The boolean above
    # says a newer role exists; on its own it can only produce "something is
    # out of date", which is a notification rather than a decision. These two
    # turn it into a sentence a customer can act on -- "database and secrets
    # checks report UNKNOWN until you redeploy" -- and the categories come from
    # the same function the scanner uses to explain the gaps, so the screen and
    # the scan cannot disagree about which checks are affected.
    data.role_required_version = service.required_grant_version(connection)
    # A redeploy prompt on a current role, for the Reader the extended checks
    # read through. Its own field, so the panel does not print "v8, behind (v8)".
    data.extended_checks_blocked = service.extended_checks_blocked(connection)
    data.degraded_categories = sorted(
        category.value for category in service.degraded_categories(connection)
    )
    # Both grants proven is not the same as having something to scan, and the
    # card said "Ready to scan: Yes" over an empty connection because it read
    # ``is_verified``. Readiness needs a subscription CloudGuard can actually
    # look at. Only meaningful when the caller passed the subscriptions in;
    # endpoints that do not are reporting on a connection mid-setup.
    data.is_ready_to_scan = connection.is_verified and any(
        a.is_scannable for a in (subscriptions or [])
    )
    # Whether this environment reports its own changes, and when it last did,
    # read off the row by the model (``change_events_enabled`` coerced there,
    # because a connection built in memory has not had the column default
    # applied). Sent with the connection rather than left to the change-events
    # endpoint: the list states how often each environment is read, and a clock
    # is only half of that answer -- fetching the other half would be one
    # request per row to render one line.

    # Passed in rather than minted here, and only by a handler that has
    # established the caller may complete onboarding. A consent link is a
    # bearer credential for an endpoint that binds this connection to a
    # directory: minting one for every reader handed the action to roles the
    # API otherwise refuses it to, read-only members included.
    if consent_url:
        data.consent_url = consent_url
    if subscriptions is not None:
        data.subscriptions = [_serialize_subscription(a) for a in subscriptions]
    return data


def _serialize_subscription(account: CloudAccount) -> DiscoveredSubscription:
    data = DiscoveredSubscription.model_validate(account)
    data.is_scannable = account.is_scannable
    return data


# Literal paths before parameterised ones — FastAPI matches in declaration
# order, so `/{connection_id}` would otherwise swallow these.


@router.get("/{connection_id}/template", include_in_schema=False)
async def arm_template(
    connection_id: UUID, token: str = Query(default="")
) -> JSONResponse:
    """Serve the ARM template for the Deploy to Azure button.

    Unauthenticated, and readable from any origin. Both are requirements rather
    than conveniences.

    Azure Portal fetches this **from the customer's browser**, not server-side,
    so the response needs CORS headers naming an origin CloudGuard does not
    control and cannot enumerate (portal.azure.com has regional and sovereign
    variants). Without them the portal reports only "There was an error
    downloading the template ... ensure the template is publicly accessible and
    that the publisher has enabled CORS policy on the endpoint" -- which reads
    as an outage, while the endpoint answers 200 to anything that is not a
    browser.

    A wildcard is safe here specifically. Nothing served is secret: the template
    names a service principal object id the customer's own directory already
    lists, and a set of read permissions they are about to review in the portal.
    Access is gated by the HMAC-signed, time-limited token in the query string,
    not by the origin of the request -- so allowing every origin gives away
    nothing that the token does not already control.
    """
    try:
        payload = verify_state(
            token,
            purpose=Purpose.TEMPLATE,
            max_age_seconds=service.TEMPLATE_TOKEN_TTL_SECONDS,
        )
    except SignedStateError as exc:
        return JSONResponse(
            {"error": str(exc)}, status_code=400, headers=TEMPLATE_CORS_HEADERS
        )

    if str(connection_id) != payload.get("cloud_connection_id"):
        return JSONResponse(
            {"error": "Token does not match connection"},
            status_code=400,
            headers=TEMPLATE_CORS_HEADERS,
        )

    async with service_session() as session:
        connection = await session.get(CloudConnection, connection_id)
        if connection is None:
            raise CloudAccountNotFound("Connection not found")
        artifact = service.render_artifact(connection)

    return JSONResponse(
        content=json.loads(artifact.body),
        media_type=artifact.media_type,
        headers={
            "Content-Disposition": f'inline; filename="{artifact.filename}"',
            **TEMPLATE_CORS_HEADERS,
        },
    )


@router.get("/providers")
async def list_providers(tenant: Tenant) -> Envelope[list[ProviderOptionOut], NoMeta]:
    """Which clouds this deployment can connect, and why not.

    Behind authentication because it describes the deployment's configuration,
    and read by the wizard's first step. Unavailable providers come back with a
    reason rather than being omitted -- a picker that silently held an option
    would answer "does this support AWS?" with nothing.
    """
    assert tenant  # authenticated; the answer is the same for every tenant
    return Envelope(
        data=[ProviderOptionOut.model_validate(p) for p in service.available_providers()],
        meta=NoMeta(),
    )


@router.get("/azure/app-registration", responses=WRITE)
async def app_registration(tenant: Tenant) -> Envelope[AppRegistrationOut | None, NoMeta]:
    """What CloudGuard's own Entra app registration must declare.

    The other half of the deployment. The ARM template grants subscription
    access in the *customer's* tenant; directory access comes from application
    permissions on CloudGuard's registration in its own tenant, which no
    template a customer runs can touch. That half has only ever existed as a
    list in a code comment, which is why a registration missing seven of nine
    permissions still produced a consent screen that looked entirely normal.

    Returned as the manifest fragment plus the command that applies it, so the
    registration can be diffed against what is deployed instead of inspected by
    eye in a portal.
    """
    tenant.require_role(Role.OWNER, Role.ADMIN)
    registration = service.self_registration(Provider.AZURE)
    return Envelope(
        data=AppRegistrationOut.model_validate(registration) if registration else None,
        meta=NoMeta(),
    )


@router.get("/azure/consent/callback", include_in_schema=False)
async def consent_callback(
    state: str = Query(default=""),
    tenant: str = Query(default=""),
    admin_consent: str = Query(default=""),
    error: str = Query(default=""),
    error_description: str = Query(default=""),
) -> RedirectResponse:
    """Entra redirects the customer's browser here after admin consent.

    Redirects into the setup wizard for this connection, which is where the
    customer left off. Failures land on the same page rather than on the
    connections list: the state parameter comes back on a denial too, so the
    reason can be shown against the step it belongs to, next to the button that
    starts consent again.

    The list is the fallback for the one case where there is no connection to
    return to -- a state that is missing, tampered with, or expired.

    Nothing outside ``state`` is trusted. ``tenant`` is a plain query parameter
    on a redirect anyone can construct -- Entra's admin-consent response is not
    a token and proves nothing by itself -- so the binding it asks for is
    accepted only once, against a link this connection issued and has not yet
    spent. Both checks live in the service, with the write they guard.
    """
    frontend = settings.app_url.rstrip("/")

    try:
        payload = verify_state(state, purpose=Purpose.CONSENT)
        connection_id = UUID(str(payload["cloud_connection_id"]))
        nonce = str(payload["nonce"])
    except (SignedStateError, KeyError, ValueError) as exc:
        # Never ``error_description`` here. Without a verified state nothing
        # says Entra sent this request -- anyone can build the URL -- and the
        # text lands on CloudGuard's own page, where a sentence of the
        # stranger's choosing ("your tenant is compromised, call ...") reads as
        # CloudGuard's (DECISIONS.md section 160). Entra's own reason is shown
        # below, where a state this API signed vouches for the round trip.
        return RedirectResponse(
            f"{frontend}/connections?consent_error={quote(_consent_link_problem(exc))}"
        )

    setup = f"{frontend}/connections/{connection_id}/setup"

    if error:
        return RedirectResponse(
            f"{setup}?consent_error={quote(error_description or error)}"
        )

    if admin_consent.lower() not in {"true", "1", ""}:
        return RedirectResponse(
            f"{setup}?consent_error={quote('Admin consent was not granted')}"
        )

    async with service_session() as session:
        try:
            await service.record_consent(session, connection_id, tenant, nonce=nonce)
        except (ValidationFailed, CloudAccountNotFound) as exc:
            return RedirectResponse(f"{setup}?consent_error={quote(str(exc))}")

    return RedirectResponse(setup)


def _consent_link_problem(exc: Exception) -> str:
    """What to show a customer standing on the callback with a bad link.

    A malformed or tampered state says nothing more than that: the reason a
    signature failed is not information a customer can act on, and it is
    information an attacker can. An expired one is different -- it names
    something they can fix by asking for another link.
    """
    if isinstance(exc, SignedStateError):
        return str(exc)
    return "This consent link is not valid. Open the connection and send a fresh one."


@router.post("", status_code=status.HTTP_201_CREATED, responses=WRITE)
async def create_connection(
    payload: CloudConnectionCreate, session: DbSession, tenant: Tenant
) -> Envelope[CloudConnectionOut, NoMeta]:
    """Create a connection and return it with the consent redirect URL."""
    tenant.require_role(Role.OWNER, Role.ADMIN)
    connection, consent_url = await service.create_connection(session, tenant, payload)
    await session.commit()
    return Envelope(data=_serialize(connection, consent_url=consent_url), meta=NoMeta())


@router.get("")
async def list_connections(
    session: DbSession, tenant: Tenant
) -> Envelope[list[CloudConnectionOut], NoMeta]:
    rows = await service.list_connections(session, tenant)
    return Envelope(data=[_serialize(c, len(subs), subs) for c, subs in rows], meta=NoMeta())


@router.get("/{connection_id}")
async def get_connection(
    connection_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[CloudConnectionOut, NoMeta]:
    """Get a connection with subscriptions. Triggers auto-validation if needed.

    The consent link comes back only for a caller who may actually complete the
    grant. The wizard polls this endpoint, so this is also where a link that has
    expired is replaced -- and where one that is still live is returned
    unchanged, so that the copy a customer already sent to their administrator
    keeps working.
    """
    connection, subscriptions = await service.get_connection_with_subscriptions(
        session, tenant, connection_id
    )
    # Auto-validate during polling — silent failures mean "not deployed yet".
    # Never in the demo: its connection was recorded, not granted, and a probe
    # would call a real provider about a tenant that is not there -- then write
    # the failure into a row every visitor reads.
    if not tenant.is_demo:
        connection = await service.try_auto_validate(session, connection)
    # Re-fetch subscriptions in case auto-discover just ran
    if connection.last_discovery_at:
        _, subscriptions = await service.get_connection_with_subscriptions(
            session, tenant, connection_id
        )

    consent_url: str | None = None
    if tenant.may_administer and connection.consent_status != ConsentStatus.GRANTED:
        consent_url, problem = service.issue_consent_url(connection)
        if problem:
            connection.status_detail = problem

    return Envelope(
        data=_serialize(connection, len(subscriptions), subscriptions, consent_url=consent_url),
        meta=NoMeta(),
    )


@router.post("/{connection_id}/discover", responses=WRITE)
async def rediscover(
    connection_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[CloudConnectionOut, NoMeta]:
    """Look for subscriptions again.

    Discovery normally runs by itself, once, while the connections page polls.
    That leaves no way back from the case where verification succeeded and the
    discovery call immediately after it did not: the page stops polling a
    verified connection, so nothing ever asks again. This is the ask-again.
    """
    tenant.require_write()
    connection, subscriptions = await service.rediscover_subscriptions(
        session, tenant, connection_id
    )
    return Envelope(data=_serialize(connection, len(subscriptions), subscriptions), meta=NoMeta())


@router.post("/{connection_id}/recheck", responses=WRITE)
async def recheck_access(
    connection_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[CloudConnectionOut, NoMeta]:
    """Ask Azure again what this connection is allowed to do.

    A real probe, which is what the access panel's button has always said it
    was. The GET only validates a connection that is not verified yet, so on a
    working connection re-checking read the same row back -- and the role
    version on it had not been looked at since the connection was created.
    """
    tenant.require_write()
    connection, subscriptions = await service.recheck_access(
        session, tenant, connection_id
    )
    return Envelope(data=_serialize(connection, len(subscriptions), subscriptions), meta=NoMeta())


@router.patch("/{connection_id}/subscriptions", responses=WRITE)
async def set_scope(
    connection_id: UUID, payload: ScopeSelection, session: DbSession, tenant: Tenant
) -> Envelope[list[DiscoveredSubscription], NoMeta]:
    """Include or exclude discovered subscriptions from scanning."""
    tenant.require_write()
    accounts = await service.set_subscription_scope(
        session, tenant, connection_id, payload.in_scope
    )
    return Envelope(data=[_serialize_subscription(a) for a in accounts], meta=NoMeta())


@router.patch("/{connection_id}/schedule", responses=WRITE)
async def set_schedule(
    connection_id: UUID, payload: ScheduleUpdate, session: DbSession, tenant: Tenant
) -> Envelope[CloudConnectionOut, NoMeta]:
    """Read this environment on a schedule, or stop.

    Every connection starts unscheduled. Turning a customer's cloud into a
    recurring API cost without being asked would be a surprise on their Azure
    bill as much as on ours, so continuous scanning is something they switch on
    rather than something they discover.
    """
    tenant.require_write()
    connection = await service.set_scan_schedule(
        session, tenant, connection_id, payload.scan_interval_hours
    )
    return Envelope(data=_serialize(connection), meta=NoMeta())


@router.get("/{connection_id}/change-events")
async def get_change_events(
    connection_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[ChangeEventSetupOut, NoMeta]:
    """Whether this connection reacts to change, and how to wire it up.

    The commands are the deliverable. CloudGuard cannot create the Event Grid
    subscription itself -- that is a write in the customer's tenant, and holding
    no write permission anywhere is the strongest security claim this product
    makes -- so it generates what the customer runs, one per subscription,
    because that is how Event Grid is scoped.
    """
    connection = await service.get_connection(session, tenant, connection_id)
    setup = await service.change_event_setup(session, connection)
    return Envelope(data=ChangeEventSetupOut.model_validate(setup), meta=NoMeta())


@router.patch("/{connection_id}/change-events", responses=WRITE)
async def set_change_events(
    connection_id: UUID, payload: ChangeEventsUpdate, session: DbSession, tenant: Tenant
) -> Envelope[ChangeEventSetupOut, NoMeta]:
    """Open or close the webhook for this connection.

    Opening it wires nothing up on its own; closing it takes effect at once,
    before the customer has deleted anything in Azure. That is the right way
    round -- a switch that appears to stop something and does not is worse than
    one that leaves a subscription delivering to an endpoint now refusing it.
    """
    tenant.require_write()
    connection = await service.set_change_events(
        session, tenant, connection_id, payload.enabled
    )
    setup = await service.change_event_setup(session, connection)
    return Envelope(data=ChangeEventSetupOut.model_validate(setup), meta=NoMeta())


@router.post("/{connection_id}/cancel", responses=WRITE)
async def cancel_setup(
    connection_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[CloudConnectionOut, NoMeta]:
    """Stop the setup process without discarding the connection."""
    tenant.require_write()
    connection = await service.set_setup_cancelled(
        session, tenant, connection_id, cancelled=True
    )
    return Envelope(data=_serialize(connection), meta=NoMeta())


@router.post("/{connection_id}/resume", responses=WRITE)
async def resume_setup(
    connection_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[CloudConnectionOut, NoMeta]:
    """Pick setup back up where it was left."""
    tenant.require_write()
    connection = await service.set_setup_cancelled(
        session, tenant, connection_id, cancelled=False
    )
    return Envelope(data=_serialize(connection), meta=NoMeta())


@router.get("/{connection_id}/revocation")
async def revocation(
    connection_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[RevocationOut, NoMeta]:
    """What to run in Azure to take CloudGuard's access away.

    Generated rather than performed: CloudGuard has no write permission in a
    customer tenant and deliberately never asks for one, so revocation is the
    customer's action. See ``service.revocation_steps``.
    """
    connection = await service.get_connection(session, tenant, connection_id)
    steps = service.revocation_steps(connection)
    return Envelope(data=RevocationOut.model_validate(steps), meta=NoMeta())


@router.post("/{connection_id}/check-revoked", responses=WRITE)
async def check_revoked(
    connection_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[RevocationCheckOut, NoMeta]:
    """Confirm by trying: revocation is verified by the access failing."""
    tenant.require_write()
    connection = await service.get_connection(session, tenant, connection_id)
    result = await service.check_access_revoked(connection)
    return Envelope(data=RevocationCheckOut.model_validate(result), meta=NoMeta())


@router.delete("/{connection_id}", status_code=status.HTTP_200_OK, responses=WRITE)
async def delete_connection(
    connection_id: UUID, session: DbSession, tenant: Tenant
) -> Envelope[ConnectionDeletedOut, NoMeta]:
    tenant.require_role(Role.OWNER, Role.ADMIN)
    await service.delete_connection(session, tenant, connection_id)
    return Envelope(data=ConnectionDeletedOut(deleted=connection_id), meta=NoMeta())
