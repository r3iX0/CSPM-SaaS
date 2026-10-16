"""AWS, declared once for the registry.

Whether this deployment may offer AWS lives here rather than in the onboarding
service, because every reason it may not is about AWS: an identity to assume
roles from, the unrun live checklist, and a public address CloudFormation and
SNS can reach.
"""

from app.connectors.aws import change_events
from app.connectors.aws.connector import AwsConnector
from app.connectors.aws.onboarding import AwsOnboarding
from app.connectors.provider import ProviderAdapter
from app.core.config import settings
from app.core.enums import Provider


def _problem(api_base: str | None) -> str | None:
    """Why AWS cannot be chosen here, in the order a reader can act on.

    The second reason is the honest one and is not a configuration error: the
    connector has never been run against a live account, and until
    ``docs/AWS_INTEGRATION.md`` section 1 has been completed, offering it would
    be claiming to scan a cloud nobody has scanned.
    """
    if not settings.aws_configured:
        return (
            "Cleave has no AWS identity on this deployment. Set "
            "AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY and AWS_PRINCIPAL_ARN "
            "(docs/AWS_INTEGRATION.md §2)."
        )
    if not settings.aws_enabled:
        return (
            "AWS support is built but has not been verified against a live "
            "account yet. Complete the checklist in docs/AWS_INTEGRATION.md §1, "
            "then set AWS_ENABLED=true."
        )
    if api_base is None:
        # Azure gets this host from AZURE_REDIRECT_URI, which consent forces to
        # be correct. AWS has no consent round trip and therefore no such
        # value, so API_URL stops being optional -- and a customer allowed to
        # reach the deploy step would find a Launch Stack link with no template
        # behind it, which reads as a broken product rather than a missing
        # variable.
        return (
            "This deployment has no public API address configured, so there is "
            "nowhere for CloudFormation to fetch the stack from or for AWS to "
            "deliver change events to. Set API_URL."
        )
    return None


def _explain_unavailable() -> str | None:
    """AWS not yet verified is "coming", as the environments page says it."""
    if not settings.aws_offered:
        return "Coming soon. Cleave does not connect AWS accounts yet."
    return None


AWS = ProviderAdapter(
    provider=Provider.AWS,
    name="Amazon Web Services",
    connector=AwsConnector,
    onboarding=AwsOnboarding,
    change_feed=change_events,
    problem=_problem,
    explain_unavailable=_explain_unavailable,
)
