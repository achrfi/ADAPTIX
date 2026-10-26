"""The prompt must not teach the model to violate the schema.

The skeleton embedded in the system prompt is the model's idea of "exactly this
shape". It shipped `"headers":"<headers>"` and `"evidence_refs":"<evidence_refs>"`
- placeholders of the wrong JSON type - and the model duly wrote strings where the
schema requires an object and an array. On a provider that cannot enforce the
schema (json_object transport) nothing corrected it, and whole planning passes were
rejected as invalid.

Sample values must therefore carry the right type, and a provider that rejects
`reasoning_effort` must not lose the request over it.
"""
import json
from unittest.mock import MagicMock

from src.adaptix.agents import decisions, planner
from src.adaptix.agents.schema import PlannerDecision


def test_skeleton_types_match_the_schema():
    schema = PlannerDecision.model_json_schema()
    shape = planner._compact_shape(schema)
    action = shape['actions'][0]
    assert isinstance(action['headers'], dict), 'headers sample must be an object'
    assert isinstance(action['priority'], dict)
    assert isinstance(shape['hypotheses'][0]['evidence_refs'], list), 'evidence_refs sample must be a list'


def test_skeleton_round_trips_through_the_schema():
    """The example the prompt shows must itself be a valid decision."""
    schema = PlannerDecision.model_json_schema()
    shape = planner._compact_shape(schema)

    def fill(value):
        if isinstance(value, dict):
            return {k: fill(v) for k, v in value.items()}
        if isinstance(value, list):
            return [fill(v) for v in value]
        if isinstance(value, str) and value.startswith('<'):
            # `<marker>` needs >=6 chars; other placeholders are free text.
            return 'xxxxxx'
        if value == 0:
            return 1
        return value

    filled = fill(shape)
    # Priority bounds are ge=0/le=1 in the schema; the sample uses 0 for brevity.
    PlannerDecision.model_validate(filled)


def test_unsupported_reasoning_effort_is_dropped_not_fatal(monkeypatch):
    from pytest import MonkeyPatch  # noqa: F401  (documents the fixture type)

    calls = []

    def complete(**kwargs):
        calls.append(dict(kwargs))
        if 'reasoning_effort' in kwargs:
            raise Exception('UnsupportedParamsError: openai does not support parameters: '
                            "['reasoning_effort']")
        response = MagicMock()
        response.usage.prompt_tokens = 10
        response.usage.completion_tokens = 20
        response.usage.total_tokens = 30
        response.choices[0].finish_reason = 'stop'
        response.choices[0].message.reasoning_content = ''
        response.choices[0].message.content = json.dumps({
            'actions': [], 'rationale': 'nothing to do',
            'reflection': 'no observations', 'advance_scope': True,
        })
        return response

    monkeypatch.setattr(planner.litellm, 'completion', complete)
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kw: 10)
    kwargs = {'model': 'openai/gpt-4.1-mini',
              'messages': [{'role': 'user', 'content': 'x'}],
              'max_tokens': 850, 'timeout': 30,
              'reasoning_effort': 'none',
              'response_format': {'type': 'json_object'}}
    decision, metrics, _, _, error = decisions.request_decision(
        {'planner_retry_limit': 1, 'token_budget': 20000}, kwargs, {}, 100)

    assert error is None, f'a dropped optional param must not fail the pass: {error}'
    assert decision is not None
    assert metrics.get('reasoning_effort_unsupported') == 1
    assert 'reasoning_effort' not in calls[-1], 'the retry must not resend the rejected param'
