"""The response envelope as types (API.md section 2, DECISIONS.md section 157).

A route declares ``-> Envelope[ItsData, ItsMeta]`` and FastAPI takes that as
the response model: the body is validated on the way out, and the published
schema says what ``data`` and ``meta`` hold rather than "an object". ``meta``
is a type parameter of its own because it is where a list says how big the
whole set is, which a client pages by and must not have to guess the name of.

Errors never pass through these. They are written by the exception handlers in
``app/core/errors.py``, outside the route, which is why ``ERROR_RESPONSES``
documents them separately.
"""

from typing import Any

from pydantic import BaseModel, ConfigDict


class ClosedModel(BaseModel):
    """An output model validated from a dict a service built.

    Where a service accumulates its answer as a dict -- because a report or a
    test reads the same dict -- the route validates the finished dict against a
    model. A model that ignored unknown keys would drop a field the service
    added and nobody declared; this one refuses it, so the omission fails where
    a missing required field would.
    """

    model_config = ConfigDict(extra="forbid")


class RequestModel(BaseModel):
    """A request body: what a client may send, and nothing else.

    Pydantic ignores an unknown key by default, so a client that misspells an
    optional field (``severty``) or sends one the server owns (``organization_id``)
    gets a ``200`` that did something other than what it asked. This one answers
    ``422`` and names the field, which is the answer a client can act on
    (API_GUIDELINES.md section 4).
    """

    model_config = ConfigDict(extra="forbid")


class NoMeta(BaseModel):
    """``meta`` on a response with nothing to say beside its data: always ``{}``."""


class PageMeta(BaseModel):
    """What a paged list says about the whole set it was cut from."""

    total: int
    limit: int
    offset: int


class TotalMeta(BaseModel):
    """How many there are in all, where the list may be cut short."""

    total: int


class Envelope[DataT, MetaT](BaseModel):
    """A success: ``{"data": ..., "error": null, "meta": {...}}``."""

    data: DataT
    error: None = None
    meta: MetaT


class ErrorOut(BaseModel):
    code: str
    message: str


class ErrorEnvelope(BaseModel):
    """A refusal: ``{"data": null, "error": {"code", "message"}, "meta": {...}}``.

    ``meta`` is open because one error carries something in it -- a 422 lists
    the fields that failed under ``errors``.
    """

    data: None = None
    error: ErrorOut
    meta: dict[str, Any]


def error_responses(*codes: int) -> dict[int | str, dict[str, Any]]:
    """The error envelope, documented for the status codes a route can answer.

    Given for 422 as well, because FastAPI otherwise publishes its own
    ``HTTPValidationError`` there -- a shape this API never sends.
    """
    return {code: {"model": ErrorEnvelope} for code in codes}


#: What any route behind the tenant dependency can answer besides its own
#: success: no or a bad token, a session that skipped its user's second factor
#: (403 ``MFA_REQUIRED``, DECISIONS.md section 217), no membership, and a
#: parameter that failed validation. A write's 403 is also a read-only role, or
#: the demo.
ERROR_RESPONSES = error_responses(401, 403, 404, 422)
