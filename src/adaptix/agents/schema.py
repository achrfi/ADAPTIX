from typing import Literal
from pydantic import BaseModel, Field, ConfigDict, field_validator

# Response-envelope bounds. They constrain how much the model may write per planning
# pass, never what it may decide: a local provider decodes a few tokens per second, so
# an unbounded envelope cannot finish inside one call window and the decision is lost
# to truncation. Grammar-constrained providers enforce these, so a decision always
# completes instead of being cut off mid-object.

class ReflectionReview(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    goal_status: Literal['in_progress', 'achieved', 'blocked', 'uncertain']
    evidence_refs: list[str] = Field(max_length=4)
    uncertainty: str = Field(max_length=240)
    failure: str = Field(max_length=240)
    decision_change: str = Field(min_length=1, max_length=240)

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
    tool: str = Field(max_length=64)
    target: str = Field(max_length=300)
    reason: str = Field(max_length=240)
    priority: Priority
    method: str = Field(default='GET', max_length=16, description='HTTP method for http_request; GET/HEAD are non-destructive')
    body: str | None = Field(default=None, max_length=600, description='Optional request body for an approved state-changing http_request')
    hypothesis: str | None = Field(default=None, max_length=80, description='Category of the hypothesis this action tests, if any')


class Hypothesis(BaseModel):
    model_config = ConfigDict(extra='forbid')
    category: str = Field(min_length=1, max_length=80, description='Vulnerability class the evidence may support, e.g. sql_injection or cross_site_scripting')
    target: str = Field(min_length=1, max_length=300)
    rationale: str = Field(min_length=1, max_length=240)
    evidence_refs: list[str] = Field(default_factory=list, max_length=4)


class PlannerDecision(BaseModel):
    model_config = ConfigDict(extra='forbid')
    actions: list[Action] = Field(max_length=3, description='Competing candidate actions, not an ordered attack plan; only one executes')
    rationale: str = Field(max_length=400)
    reflection: str = Field(min_length=1, max_length=400)
    review: ReflectionReview | None = None
    hypotheses: list[Hypothesis] = Field(default_factory=list, max_length=3, description='Evidence-grounded candidate vulnerability categories to investigate; never findings')
    advance_scope: bool = Field(default=False, description='With no actions, defer this window and consider the next part of scope')

    @field_validator('reflection')
    @classmethod
    def meaningful_reflection(cls, value):
        if not value.strip():
            raise ValueError('Reflection must contain non-whitespace text')
        return value.strip()
