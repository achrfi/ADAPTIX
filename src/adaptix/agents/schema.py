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
    estimated_tokens: int = Field(ge=1, le=2_000_000, description='Marginal observation/context tokens expected from this action; exclude current planning overhead')
    estimated_seconds: float = Field(gt=0, le=3_600, description='Expected wall-clock seconds for this action, bounded by the longest sensible single probe')
    estimated_requests: int = Field(ge=1, le=1_000, description='Expected tool requests for this action; no single action may reserve more than the whole run')
class Action(BaseModel):
    model_config = ConfigDict(extra='forbid', allow_inf_nan=False)
    tool: str = Field(min_length=1, max_length=64)
    target: str = Field(max_length=300)
    reason: str = Field(max_length=240)
    priority: Priority
    method: str = Field(default='GET', max_length=16, description='HTTP method for http_request; GET/HEAD are non-destructive')
    body: str | None = Field(default=None, max_length=600, description='Optional request body for an approved state-changing http_request')
    headers: dict[str, str] | None = Field(default=None, max_length=4,
                                           description='Model-authored request headers for http_request (an input location you choose); Content-Type and custom test headers are yours to set. Transport headers and operator identity headers are decided by the runtime')
    identity: str | None = Field(default=None, max_length=64, description='Name of an operator-configured identity to send with an http_request; the operator supplies its headers, never the model')
    marker: str | None = Field(default=None, min_length=6, max_length=64,
                               description='Unique canary token for browser_test; must match [A-Za-z0-9_.-]{6,64} and must be invented by the model, never copied from observed content',
                               pattern=r'[A-Za-z0-9_.-]{6,64}')
    hypothesis: str | None = Field(default=None, max_length=80, description='Category of the hypothesis this action tests, if any')

    @field_validator('headers')
    @classmethod
    def bounded_headers(cls, value):
        """Model-authored headers are content, not transport control."""
        if value is None:
            return None
        if not isinstance(value, dict):
            raise ValueError('headers must be a name/value map')
        if len(value) > 4:
            raise ValueError('at most 4 model-authored headers')
        reserved = {'host', 'content-length', 'connection', 'transfer-encoding', 'expect'}
        cleaned = {}
        for name, header_value in value.items():
            name, header_value = str(name), str(header_value)
            if not name or not header_value:
                raise ValueError('header names and values must be nonempty')
            if '\r' in name or '\n' in name or '\r' in header_value or '\n' in header_value or '\x00' in name or '\x00' in header_value:
                raise ValueError('header names and values must not carry line breaks or NUL')
            if name.lower() in reserved:
                raise ValueError('the runtime decides transport headers')
            if len(name) > 48 or len(header_value) > 240:
                raise ValueError('each header name is limited to 48 and each value to 240 characters')
            cleaned[name] = header_value
        return cleaned or None


class Hypothesis(BaseModel):
    model_config = ConfigDict(extra='forbid')
    category: str = Field(min_length=1, max_length=80, description='Vulnerability class the evidence may support, e.g. sql_injection or cross_site_scripting')
    target: str = Field(min_length=1, max_length=300)
    rationale: str = Field(min_length=1, max_length=240)
    evidence_refs: list[str] = Field(default_factory=list, max_length=4)


class PlannerDecision(BaseModel):
    model_config = ConfigDict(extra='forbid', allow_inf_nan=False)
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
