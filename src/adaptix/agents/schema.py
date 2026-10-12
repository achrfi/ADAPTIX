from typing import Literal
from pydantic import BaseModel, Field


class Action(BaseModel):
    tool: Literal['httpx', 'nuclei', 'playwright']
    target: str = Field(..., description='URL atau host, harus sudah ada di state')
    reason: str
    priority: int = Field(ge=1, le=5, default=3)


class PlannerDecision(BaseModel):
    actions: list[Action]
    rationale: str
