"""One cloud, declared once: what the neutral half may ask of a provider.

A provider used to be three registrations kept in step by hand -- a connector
class, an onboarding flow and a change-feed module, each in its own dict -- and
a fourth fact, whether this deployment can offer it at all, written inline in
the onboarding service. Nothing made the four agree, and the change feed was a
bare module, so every caller cast what it returned.

:class:`ProviderAdapter` is the one declaration. Each cloud builds one in its
own package and the registry lists them; adding a cloud is a new adapter and a
line in that list, not a pass through every module that might name a provider.

Not here, deliberately: the nouns a sentence needs (``app/core/vocabulary.py``,
DECISIONS.md section 78), and anything that needs a connection to answer.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from app.connectors.base import CloudConnector
from app.connectors.onboarding import ProviderOnboarding
from app.core.enums import Provider


@runtime_checkable
class ChangeFeed(Protocol):
    """How a cloud says its environment changed, read without a connection.

    Answered before any connection is resolved: a webhook arrives first, and
    deciding whether the delivery is worth reading must not require credentials
    to the environment it is about. Each cloud's ``change_events`` module
    satisfies this as it stands, which is why it is a protocol rather than a
    base class.
    """

    def is_validation(self, event: dict[str, Any]) -> bool: ...

    def validation_response(self, event: dict[str, Any]) -> dict[str, str] | None: ...

    def confirmation_url(self, event: dict[str, Any]) -> str | None:
        """Where a subscription is activated, for a cloud that activates out of band.

        Azure echoes a code in the response and answers ``None`` here; SNS
        hands over a URL that has to be fetched. Asked of the provider rather
        than decided by the endpoint, so the neutral half never learns which
        cloud does which.

        The provider is also what refuses an unsafe URL. Fetching one named in
        an inbound payload is an SSRF unless the host is checked, and the check
        belongs with the cloud that knows what its own hosts look like.
        """
        ...

    def is_relevant(self, event: dict[str, Any]) -> bool: ...

    def subscription_command(self, scope_id: str, endpoint: str) -> str: ...


def _nothing_more() -> str | None:
    return None


@dataclass(frozen=True)
class ProviderAdapter:
    """Everything the neutral half needs from one cloud, in one place."""

    provider: Provider
    #: The cloud's own product name, for the picker. Not a noun a sentence
    #: needs, which is ``vocabulary.words`` (section 78).
    name: str
    connector: type[CloudConnector]
    onboarding: type[ProviderOnboarding]
    change_feed: ChangeFeed
    #: Why this deployment cannot offer the cloud, for whoever runs it, or
    #: ``None`` when it can (DECISIONS.md section 186). Takes the deployment's
    #: public API address, which lives with the onboarding service and would be
    #: an import cycle to fetch from here.
    problem: Callable[[str | None], str | None]
    #: What to tell a customer instead of the generic sentence, where this
    #: cloud has something more honest to say. ``None`` keeps the generic one.
    explain_unavailable: Callable[[], str | None] = _nothing_more

    def customer_reason(self) -> str:
        """Why the cloud cannot be chosen, in words for the customer choosing it.

        The problem itself names environment variables and a checklist -- what
        whoever runs the deployment needs, and noise to anyone else. It stays in
        ``operator_detail``; this is the sentence the picker shows.
        """
        return (
            self.explain_unavailable()
            or f"Not set up on this deployment yet, so {self.name} cannot be connected here."
        )
