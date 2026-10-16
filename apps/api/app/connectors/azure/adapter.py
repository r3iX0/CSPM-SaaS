"""Azure, declared once for the registry."""

from app.connectors.azure import change_events
from app.connectors.azure.connector import AzureConnector
from app.connectors.azure.onboarding import AzureOnboarding
from app.connectors.provider import ProviderAdapter
from app.core.config import settings
from app.core.enums import Provider


def _problem(api_base: str | None) -> str | None:
    """Why consent cannot start here.

    The public address is not Azure's concern: consent carries its own host in
    ``AZURE_REDIRECT_URI``.
    """
    return settings.azure_consent_problem


AZURE = ProviderAdapter(
    provider=Provider.AZURE,
    name="Microsoft Azure",
    connector=AzureConnector,
    onboarding=AzureOnboarding,
    change_feed=change_events,
    problem=_problem,
)
