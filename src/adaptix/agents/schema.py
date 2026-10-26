import json
from typing import Literal
from pydantic import BaseModel, Field, ConfigDict, field_validator

# Response-envelope bounds. They constrain how much the model may write per planning
# pass, never what it may decide: a local provider decodes a few tokens per second, so
# an unbounded envelope cannot finish inside one call window and the decision is lost
# to truncation. Grammar-constrained providers enforce these, so a decision always
# completes instead of being cut off mid-object.

def _as_text(value):
    """Coerce a model-written value that should be a short string into one.

    On a provider that cannot enforce the response schema (json_object mode, or a
    gateway that accepts json_schema then ignores it) the model is free to write a
    list where the schema says string. Measured on glm-5.3: ``uncertainty`` came
    back as a list on one pass and a string on the next. Rejecting the whole
    decision over shape wastes two planning passes and can end a run with zero
    actions, so a list of short strings becomes one joined string instead.
    """
    if value is None:
        return ''
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        parts = [_as_text(item).strip() for item in value]
        return '; '.join(part for part in parts if part)
    if isinstance(value, dict):
        return '; '.join(f'{k}: {_as_text(v).strip()}' for k, v in value.items())
    return str(value)


def _as_text_list(value, limit=4):
    """Coerce a value that should be a short list of strings into one."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, dict):
        value = list(value.keys())
    if isinstance(value, (list, tuple)):
        out = []
        for item in value:
            if isinstance(item, (list, tuple, dict)):
                item = _as_text(item)
            item = str(item).strip()
            if item:
                out.append(item)
        return out[:limit]
    return [str(value)]


class ReflectionReview(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    goal_status: Literal['in_progress', 'achieved', 'blocked', 'uncertain']
    evidence_refs: list[str] = Field(max_length=4)
    uncertainty: str = Field(max_length=240)
    failure: str = Field(max_length=240)
    decision_change: str = Field(min_length=1, max_length=240)

    @field_validator('evidence_refs', mode='before')
    @classmethod
    def refs_shaped(cls, value):
        return _as_text_list(value, 4)

    @field_validator('uncertainty', 'failure', 'decision_change', mode='before')
    @classmethod
    def text_shaped(cls, value):
        return _as_text(value)

def salvage_truncated_json(text):
    """Recover the complete part of a decision that a provider cut off mid-object.

    Measured on a gateway that ignores ``max_tokens`` and hard-caps output: the
    model was asked for 850 tokens, was stopped at 2048, and the JSON ended inside
    a string. Both planning passes were lost and the run ended with zero actions,
    even though every action it had finished writing was usable.

    Truncation is a transport fact, not a wrong decision. This keeps the actions
    that completed and closes the document, so a run retains the work that
    survived instead of discarding it. It never invents an action: with nothing
    complete it returns None and the caller fails as before.
    """
    if not isinstance(text, str) or not text.strip():
        return None
    start = text.find('{')
    if start < 0:
        return None
    body = text[start:]

    # Only truncated documents are salvageable. A complete document that fails
    # validation is a model error and must take the normal reject/retry path, where
    # field feedback teaches the next attempt; salvaging it would silently accept
    # a decision the schema refused (an empty reflection, for instance).
    try:
        json.loads(body)
        return None
    except json.JSONDecodeError:
        pass

    # Find where each element of the top-level "actions" array closes.
    in_string = False
    escape = False
    depth = 0
    closes = []
    for index, ch in enumerate(body):
        if in_string:
            if escape:
                escape = False
            elif ch == '\\':
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in '{[':
            depth += 1
        elif ch in '}]':
            # An action object closes at depth 3: document -> actions array -> object.
            if ch == '}' and depth == 3:
                closes.append(index)
            depth -= 1

    if not closes:
        return None

    tail = (',"rationale":"recovered after provider truncation",'
            '"reflection":"Recovered after provider truncated the decision",'
            '"advance_scope":false}')
    for close in reversed(closes):
        candidate = body[:close + 1] + ']' + tail
        try:
            PlannerDecision.model_validate_json(candidate)
            return candidate
        except Exception:
            continue
    return None


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
    profile: str | None = Field(default=None, max_length=32,
                                description='Named wordlist profile for static_discovery (common, raft-small-dirs, api, backup). Ignored by other tools')

    @field_validator('body', 'identity', 'marker', 'hypothesis', 'profile', mode='before')
    @classmethod
    def empty_optional_is_absent(cls, value):
        """An empty string for an optional field means "not used".

        A provider that cannot enforce the schema writes ``""`` for every optional
        field it does not want; the model did exactly that for ``marker``, whose
        pattern then rejected the whole decision. Treating "" as absent is what the
        model meant, and it cannot weaken anything: an absent field is the default.
        """
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator('headers', mode='before')
    @classmethod
    def bounded_headers(cls, value):
        """Model-authored headers are content, not transport control."""
        if value is None:
            return None
        # A provider that cannot enforce the schema writes "" for an absent map
        # (measured on glm-5.3). An empty string means "no headers", not a bad
        # request, so it is normalised rather than thrown away.
        if isinstance(value, str) and not value.strip():
            return None
        if isinstance(value, (list, tuple)):
            # Some providers emit header pairs as a list of two-item arrays.
            if not value:
                return None
            value = {str(pair[0]): str(pair[1]) for pair in value
                     if isinstance(pair, (list, tuple)) and len(pair) == 2}
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

    @field_validator('evidence_refs', mode='before')
    @classmethod
    def refs_shaped(cls, value):
        return _as_text_list(value, 4)


class PlannerDecision(BaseModel):
    model_config = ConfigDict(extra='forbid', allow_inf_nan=False)
    actions: list[Action] = Field(max_length=3, description='Competing candidate actions, not an ordered attack plan; only one executes')
    rationale: str = Field(max_length=400)
    reflection: str = Field(min_length=1, max_length=400)
    review: ReflectionReview | None = None
    hypotheses: list[Hypothesis] = Field(default_factory=list, max_length=3, description='Evidence-grounded candidate vulnerability categories to investigate; never findings')
    advance_scope: bool = Field(default=False, description='With no actions, defer this window and consider the next part of scope')

    @field_validator('reflection', 'rationale', mode='before')
    @classmethod
    def meaningful_reflection(cls, value):
        """Coerce first, then require substance.

        Measured: the model sometimes returns `reflection` as a list of sentences or as
        an object, which fails the `str` check before any validator runs — a complete,
        well-shaped decision was discarded over the container type of one prose field.
        Coercion here is the same one the nested review fields already use.
        """
        text = _as_text(value)
        if not text.strip():
            raise ValueError('Reflection must contain non-whitespace text')
        return text.strip()

def strip_code_fence(text):
    """Return the JSON body of a fenced code block, or the text unchanged.

    Measured on a real gateway: with `json_object` requested and "no prose" in the
    prompt, the model still wrapped its decision in ```json fences on some attempts.
    The object was complete and valid inside; only the fence made it unparseable, so a
    usable decision was discarded for presentation alone.
    """
    body = (text or '').strip()
    if not body.startswith('```'):
        return body
    # Drop the opening fence and its optional language tag.
    newline = body.find('\n')
    if newline == -1:
        return body
    body = body[newline + 1:]
    closing = body.rstrip()
    if closing.endswith('```'):
        body = closing[:-3]
    return body.strip()
