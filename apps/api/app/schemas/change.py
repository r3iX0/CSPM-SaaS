from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel

from app.core.enums import AssetChange


class ChangedAssetOut(BaseModel):
    """The asset a change is about, enough of it for the row to read on its own."""

    id: UUID
    name: str
    resource_type: str
    environment: str | None
    #: Set while the asset is missing, which is what turns a DISAPPEARED row
    #: from history into something to act on.
    absent_since: datetime | None


class ChangeOut(BaseModel):
    """One transition an asset went through."""

    id: UUID
    change: AssetChange
    #: What the setting was and became, as stored; either is ``None`` for an
    #: asset that appeared or disappeared.
    previous_value: Any
    current_value: Any
    observed_at: datetime
    scan_id: UUID | None
    asset: ChangedAssetOut


class ChangesMeta(BaseModel):
    """The window the feed covers, and the page of it."""

    days: int
    limit: int
    offset: int
