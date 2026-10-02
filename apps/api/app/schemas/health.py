from typing import Literal

from pydantic import BaseModel


class HealthOut(BaseModel):
    """The process is up, and nothing else: the endpoint is public."""

    status: Literal["ok"]


class ReadyOut(BaseModel):
    """The process is up, its database answers and the task broker does too.

    A dependency that does not answer is not a field here: the endpoint answers ``503`` with the
    error envelope instead, so ``"ok"`` is the only value there is to read.
    """

    status: Literal["ready"]
    database: Literal["ok"]
    queue: Literal["ok"]
