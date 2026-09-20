"""Signed state that travels through somebody else's system and comes back.

Three places hand a customer -- or Microsoft -- a URL that returns to this API
carrying a claim about which connection it is for: the consent round trip, the
ARM template the Azure Portal fetches, and the Event Grid webhook. None of them
can be authenticated by a session, because the caller is a browser mid-redirect,
a portal fetching server-side, or Microsoft's own infrastructure.

So the claim is signed, and the signature is the whole guard. Without it a
returning callback could name any connection and bind a stranger's tenant to it.

Provider-neutral, and that is why it lives here rather than beside the Azure
connector where it was written. Nothing in it knows what a tenant is: it signs a
dictionary and hands back a string. An AWS onboarding flow that needs the same
round trip would otherwise have imported ``connectors.azure.auth`` to get it,
which is the seam leaking through a utility.

``purpose`` is enforced here, and it is a required argument on both sides. The
tokens are signed with one secret, so two of them differ *only* by that field:
a caller that verified the signature and skipped the purpose would accept the
other one, and the token it accepted might be a webhook URL a customer pasted
into a shell command a year ago.

Leaving each caller to check its own was the earlier arrangement, and one of
three did not -- the consent callback, which was also the one that wrote the
tenant binding. A rule every caller must remember is a rule that will eventually
be forgotten by whichever caller matters most, so the check moved in here where
it cannot be skipped: ``sign_state`` stamps the purpose and ``verify_state``
demands it, both as keyword arguments with no default.
"""

import base64
import hashlib
import hmac
import json
import time
from enum import StrEnum
from typing import Any

from app.core.config import settings

_PURPOSE_KEY = "purpose"


class Purpose(StrEnum):
    """What a token may be presented to.

    The values are wire format: they are inside tokens customers already hold,
    including Event Grid webhook URLs that live in their infrastructure for a
    year. Renaming one silently stops that customer's change feed, so the
    strings stay as they are even where a better name suggests itself.
    """

    CONSENT = "azure_consent"
    TEMPLATE = "template"
    EVENT_FEED = "event_grid"


class SignedStateError(ValueError):
    """The state did not verify, was malformed, or has expired."""


def sign_state(payload: dict[str, Any], *, purpose: Purpose) -> str:
    """Sign a claim, stamped with the one thing it may be presented to."""
    body = base64.urlsafe_b64encode(
        json.dumps({**payload, _PURPOSE_KEY: purpose.value}).encode()
    ).decode().rstrip("=")
    return f"{body}.{_mac(body)}"


def verify_state(
    state: str, *, purpose: Purpose, max_age_seconds: int = 1800
) -> dict[str, Any]:
    """Verify a token and return its claim, or raise.

    Signature, purpose and age, in that order: a caller learns nothing about a
    token whose signature did not verify.
    """
    try:
        body, mac = state.rsplit(".", 1)
    except ValueError as exc:
        raise SignedStateError("Malformed state token") from exc

    # Constant time: a token is a credential, and a comparison that returns
    # early tells an attacker how much of one they have guessed.
    if not hmac.compare_digest(mac, _mac(body)):
        raise SignedStateError("State signature does not verify")

    padding = "=" * (-len(body) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(body + padding))
    except (ValueError, json.JSONDecodeError) as exc:
        raise SignedStateError("Malformed state token") from exc
    if not isinstance(payload, dict):
        raise SignedStateError("Malformed state token")

    # Signed by us, for something else. Refused rather than honoured: every
    # token here is signed with one secret, so this field is the only thing
    # standing between a webhook URL and the endpoint that binds a tenant.
    if payload.get(_PURPOSE_KEY) != purpose.value:
        raise SignedStateError("This link was issued for something else")

    issued_at = payload.get("issued_at")
    if not isinstance(issued_at, int | float):
        raise SignedStateError("State token carries no issue time")
    if time.time() - issued_at > max_age_seconds:
        raise SignedStateError("This link has expired — please start again")
    return dict(payload)


def _mac(body: str) -> str:
    return hmac.new(
        settings.azure_consent_state_secret.encode(), body.encode(), hashlib.sha256
    ).hexdigest()[:32]
