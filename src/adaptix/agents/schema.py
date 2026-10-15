from typing import Literal
from pydantic import BaseModel, Field, ConfigDict, field_validator

class ReflectionReview(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    goal_status: Literal['in_progress', 'achieved', 'blocked', 'uncertain']
    evidence_refs: list[str]
    uncertainty: str
    failure: str
    decision_change: str = Field(min_length=1)

class Priority(BaseModel):
    model_config = ConfigDict(extra='forbid', allow_inf_nan=False)
    goal_relevance: float = Field(ge=0, le=1)
    information_gain: float = Field(ge=0, le=1)
    evidence_value: float = Field(ge=0, le=1)
    confidence: float = Field(ge=0, le=1, description='Confidence in the benefit estimate, never vulnerability verification')
    estimated_tokens: int = Field(ge=1, description='Marginal observation/context tokens expected from this action; exclude current planning overhead')
    estimated_seconds: float = Field(gt=0)
    estimated_requests: int = Field(ge=1)

class Action(BaseModel):
    model_config = ConfigDict(extra='forbid')
    tool: str
    target: str
    reason: str
    priority: Priority

class PlannerDecision(BaseModel):
    model_config = ConfigDict(extra='forbid')
    actions: list[Action] = Field(description='Competing candidate actions, not an ordered attack plan; only one executes')
    rationale: str
    reflection: str = Field(min_length=1)
    review: ReflectionReview | None = None
    advance_scope: bool = Field(default=False, description='With no actions, defer this window and consider the next part of scope')

    @field_validator('reflection')
    @classmethod
    def meaningful_reflection(cls, value):
        if not value.strip():
            raise ValueError('Reflection must contain non-whitespace text')
        return value.strip()
