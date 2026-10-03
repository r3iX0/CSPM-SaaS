from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.enums import (
    CloudAccountStatus,
    ConnectionScope,
    ConsentStatus,
    Provider,
)
from app.models.cloud_connection import CloudConnection
from app.schemas.common import ClosedModel, RequestModel


class CloudConnectionCreate(RequestModel):
    """Starting a connection needs a name and a decision about scope.

    Note what is absent: no tenant id, no subscription id, no client id, no
    secret. The tenant comes from Entra's consent callback, subscriptions come
    from discovery, and CloudGuard never holds a customer credential at all
    (AZURE_INTEGRATION.md 2).
    """

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [{"name": "Production", "provider": "azure", "scope_type": "TENANT_ROOT"}]
        }
    )

    name: str = Field(min_length=1, max_length=200)
    # Required: a client that left it out got an Azure connection whatever it
    # meant to connect, with nothing said (DECISIONS.md section 209).
    provider: Provider
    scope_type: ConnectionScope = ConnectionScope.TENANT_ROOT
    # Required for MANAGEMENT_GROUP and SUBSCRIPTION; meaningless for
    # TENANT_ROOT, whose scope is not knowable until consent completes.
    scope_id: str | None = Field(default=None, max_length=200)


class CloudConnectionOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    provider: Provider
    name: str
    scope_type: ConnectionScope
    scope_id: str | None = None
    scope_path: str | None = None
    role_version: str
    tenant_id: str | None = None
    service_principal_object_id: str | None = None
    consent_status: ConsentStatus
    consented_at: datetime | None = None
    # What consent left out, read from the grant. NULL is "not checked", and an
    # empty list is "nothing missing" -- ``consent_status`` alone is only
    # Entra's word that an administrator clicked.
    missing_permissions: list[str] | None = None
    rbac_verified_at: datetime | None = None
    status: CloudAccountStatus
    status_detail: str | None = None
    last_discovery_at: datetime | None = None
    # How often this environment is re-read. NULL means manual only.
    scan_interval_hours: int | None = None
    created_at: datetime
    is_verified: bool = False
    subscription_count: int = 0
    subscriptions: list["DiscoveredSubscription"] = Field(default_factory=list)
    # Only for a caller who may complete the grant, and only while it is not
    # granted: a consent link is a bearer credential.
    consent_url: str | None = None
    template_url: str | None = None
    # What only this connection's cloud has a word for, filtered to what a
    # customer is meant to read. The external id is here on purpose: they have
    # to see it to check their own trust policy, and it is not a credential --
    # it means nothing without a role that requires it.
    provider_ref: dict[str, Any] = Field(default_factory=dict)

    @field_validator("provider_ref", mode="before")
    @classmethod
    def _reference_or_empty(cls, value: object) -> object:
        """A connection built in memory has not had the column default applied.

        Empty rather than null, so no reader has to decide what the absence of
        a provider reference means before looking a key up in it.
        """
        return value if isinstance(value, dict) else {}

    # True once the deployment has been outstanding long enough that "still in
    # progress" no longer explains it.
    deploy_stalled: bool = False
    # True when CloudGuard's scanner role has moved on since this connection
    # deployed it. Checks needing the newer permissions cannot be evaluated
    # until the customer redeploys, so this drives a prompt rather than leaving
    # them to wonder why a rule reports UNKNOWN.
    role_upgrade_available: bool = False
    # The grant version a redeploy would bring this connection to.
    role_required_version: str | None = None
    # Categories whose checks report UNKNOWN until the grant is redeployed.
    degraded_categories: list[str] = Field(default_factory=list)
    # Verified *and* holding at least one subscription that can be scanned.
    # ``is_verified`` alone says both grants work, which is true of a connection
    # with nothing beneath it.
    is_ready_to_scan: bool = False
    # Whether this environment reports its own changes, and when it last did.
    change_events_enabled: bool = False
    last_change_event_at: datetime | None = None

    @field_validator("change_events_enabled", mode="before")
    @classmethod
    def _unset_is_off(cls, value: object) -> bool:
        """A connection built in memory has not had the column default applied,
        and ``None`` here means the default: off."""
        return bool(value)


class DiscoveredSubscription(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    subscription_id: str | None = None
    display_name: str | None = None
    in_scope: bool
    scope_changed_at: datetime | None = None
    status: CloudAccountStatus
    discovered_at: datetime | None = None
    last_scan_at: datetime | None = None
    is_scannable: bool = False


class ScheduleUpdate(RequestModel):
    """How often this environment should be re-read.

    ``None`` turns scheduling off and leaves the connection scannable by hand,
    which is where every connection starts: turning a customer's cloud into a
    recurring API cost without being asked would be a surprise on their bill.
    """

    scan_interval_hours: int | None = Field(
        default=None,
        ge=CloudConnection.MIN_INTERVAL_HOURS,
        le=CloudConnection.MAX_INTERVAL_HOURS,
        description=(
            "Read this environment at least this often. Omit or send null for manual scanning only."
        ),
    )


class ScopeSelection(RequestModel):
    """Which discovered subscriptions to actually scan, keyed by subscription id."""

    in_scope: dict[str, bool]


class ChangeEventsUpdate(RequestModel):
    """Turn change-triggered scanning on or off.

    A bare boolean, because there is nothing else for the customer to choose:
    the quiet period and the minimum interval between change-triggered scans are
    CloudGuard's judgement about not turning a deployment into a scan storm, not
    a preference.
    """

    enabled: bool


class ProviderOptionOut(ClosedModel):
    """A cloud this deployment can connect, or why it cannot."""

    id: Provider
    name: str
    available: bool
    #: Why not, where it is not, in the customer's words; ``None`` where it is.
    unavailable_reason: str | None
    #: The same, for whoever runs the deployment: the variable to set or the
    #: checklist to finish. Kept apart so a customer is not handed an
    #: environment variable as an instruction (DECISIONS.md section 186).
    operator_detail: str | None


class AppRegistrationOut(ClosedModel):
    """What CloudGuard's own app registration must declare, and the commands
    that apply and check it."""

    required_permissions: list[str]
    #: ``requiredResourceAccess`` in Entra's own manifest format.
    required_resource_access: list[dict[str, Any]]
    lookup_command: str
    apply_command: str
    verify_command: str
    grant_command: str
    note: str


class EventCommandOut(ClosedModel):
    subscription_id: str
    command: str


class ChangeEventSetupOut(ClosedModel):
    """Whether a connection reacts to change, and what the customer runs to
    wire it up -- one command per subscription, as Event Grid is scoped."""

    enabled: bool
    #: ``None`` until the webhook can be addressed.
    webhook_url: str | None
    pending_since: datetime | None
    last_event_at: datetime | None
    quiet_period_minutes: int
    minimum_interval_minutes: int
    #: Empty until the webhook is open.
    commands: list[EventCommandOut]


class RevocationStepOut(ClosedModel):
    title: str
    detail: str
    command: str


class RevocationOut(ClosedModel):
    """What the customer runs to take CloudGuard's access away, filled in for
    one connection. Generated by each provider's onboarding; the last three
    fields are where a provider has them, and ``None`` otherwise."""

    principal_id: str | None
    scope_path: str | None
    role_name: str
    tenant_id: str | None
    steps: list[RevocationStepOut]
    why_manual: str
    portal_url: str
    #: Where the grant is gated by an external id: that it needs no rotating.
    external_id_note: str | None = None
    #: The account the grant was deployed to, where it is one account.
    account_id: str | None = None
    #: Managed policies attached beside the role, where there are any.
    managed_policies: list[str] | None = None


class RevocationCheckOut(ClosedModel):
    """Revocation, confirmed by the access failing."""

    revoked: bool
    detail: str


class ConnectionDeletedOut(BaseModel):
    deleted: UUID
