from typing import Literal

from pydantic import BaseModel


class HealthOut(BaseModel):
    """The process is up, and nothing else: the endpoint is public."""

    status: Literal["ok"]


class ReadyOut(BaseModel):
    """The process is up and its database answers."""

    status: Literal["ready"]
    database: Literal["ok"]
