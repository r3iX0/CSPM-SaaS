from pydantic import BaseModel, Field

from app.core.enums import RelationshipType

#: Links one simulation may remove. Each is weighed against the rest by
#: rebuilding the estate without it, so the cost grows with the plan -- and a
#: plan longer than this is a project, not a what-if.
MAX_SIMULATED_CUTS = 10


class SimulatedLink(BaseModel):
    """One link, named the way a drawn edge names it."""

    source: str = Field(min_length=1, max_length=2048)
    relationship: RelationshipType
    target: str = Field(min_length=1, max_length=2048)


class SimulationRequest(BaseModel):
    """Links to remove together. A body rather than a query string, because
    ten Azure ids three times over do not fit in a URL every proxy accepts."""

    cuts: list[SimulatedLink] = Field(min_length=1, max_length=MAX_SIMULATED_CUTS)
