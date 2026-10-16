"""Provider lookup.

The one place that maps a stored ``provider`` string to an implementation. Each
cloud declares itself once, as a :class:`ProviderAdapter` in its own package;
adding a cloud is that adapter plus a line in :data:`ADAPTERS`.
"""

from typing import Any

from app.connectors.aws.adapter import AWS
from app.connectors.azure.adapter import AZURE
from app.connectors.base import CloudConnector
from app.connectors.onboarding import ProviderOnboarding
from app.connectors.provider import ChangeFeed, ProviderAdapter
from app.core.enums import Provider
from app.core.errors import NotConfigured

ADAPTERS: dict[Provider, ProviderAdapter] = {adapter.provider: adapter for adapter in (AZURE, AWS)}


def get_adapter(provider: Provider | str) -> ProviderAdapter:
    """Everything declared for a provider, or :class:`NotConfigured`.

    Refused rather than defaulted: handing back Azure for a cloud nobody
    implemented would be a scan that appears to work and reads the wrong cloud.
    """
    resolved = Provider(provider)
    adapter = ADAPTERS.get(resolved)
    if adapter is None:
        raise NotConfigured(f"No adapter is implemented for {resolved.value}.")
    return adapter


def get_connector_class(provider: Provider | str) -> type[CloudConnector]:
    """The implementation for a provider, without building one.

    Separate from :func:`get_connector` because several questions -- what
    permissions this provider asks for, which evidence keys a category holds --
    are properties of the *provider* rather than of a connection to one, and
    answering them should not require the tenant and subscription ids a
    constructor wants.
    """
    return get_adapter(provider).connector


def get_connector(provider: Provider | str, **kwargs: Any) -> CloudConnector:
    return get_connector_class(provider)(**kwargs)  # type: ignore[abstract]


def get_onboarding(provider: Provider | str) -> ProviderOnboarding:
    """How this provider's access is granted, checked and revoked.

    Separate from the connector because it is asked before one can exist: the
    whole point of onboarding is the period when there is no verified access to
    build a connector against.
    """
    return get_adapter(provider).onboarding()


def get_change_feed(provider: Provider | str) -> ChangeFeed:
    """How this provider says its environment changed.

    Separate from the connector because it is answered without one: a webhook
    arrives before any connection has been resolved, and deciding whether the
    delivery is worth reading must not require credentials to the environment it
    is about.
    """
    return get_adapter(provider).change_feed
