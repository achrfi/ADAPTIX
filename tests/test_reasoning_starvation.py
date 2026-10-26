"""Reasoning starvation must be retried, not reported as a schema failure.

Measured against a real gateway with a 37 KB planning prompt: with
``reasoning_effort=none`` the same request returned

    attempt 1: 4336 chars reasoning, 0 chars content, finish=length
    attempt 2: 4321 chars reasoning, 0 chars content, finish=length
    attempt 3: 739 chars content,    finish=length
    attempt 4: 1038 chars content,   finish=stop

so the failure is intermittent at the provider, not caused by the prompt. It must
not consume the operator's retry budget, and it must not alter the envelope: the
envelope was never the problem.
"""
import json
from unittest.mock import MagicMock

from src.adaptix.agents import decisions, planner


def _response(content, reasoning='', finish='stop', tokens=100):
    response = MagicMock()
    response.usage.prompt_tokens = 50
    response.usage.completion_tokens = tokens
    response.usage.total_tokens = 50 + tokens
    response.choices[0].finish_reason = finish
    response.choices[0].message.content = content
    response.choices[0].message.reasoning_content = reasoning
    return response


VALID = json.dumps({
    'actions': [],
    'rationale': 'nothing to test yet',
    'reflection': 'no observations captured',
    'advance_scope': True,
})


def test_starvation_is_retried_beyond_the_operator_budget(monkeypatch):
    """Two empty answers then a valid one, with planner_retry_limit=0."""
    seen = []

    def complete(**kwargs):
        seen.append(kwargs.get('max_tokens'))
        if len(seen) < 3:
            return _response('', reasoning='deliberating ' * 200, finish='length')
        return _response(VALID)

    monkeypatch.setattr(planner.litellm, 'completion', complete)
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kw: 10)
    kwargs = {'model': 'test', 'messages': [{'role': 'user', 'content': 'x'}],
              'max_tokens': 850, 'timeout': 30}
    decision, metrics, _, ledger, error = decisions.request_decision(
        {'planner_retry_limit': 0, 'token_budget': 5000}, kwargs, {}, 100)

    assert decision is not None, f'starvation should be retried, error={error}'
    assert error is None
    assert len(seen) == 3
    assert metrics.get('provider_starvation') == 2
    # The envelope never changed: starvation is not an output-size problem.
    assert set(seen) == {850}


def test_starvation_is_bounded(monkeypatch):
    """A permanently starved provider must not loop forever."""
    calls = []

    def complete(**kwargs):
        calls.append(1)
        return _response('', reasoning='thinking ' * 100, finish='length')

    monkeypatch.setattr(planner.litellm, 'completion', complete)
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kw: 10)
    kwargs = {'model': 'test', 'messages': [{'role': 'user', 'content': 'x'}],
              'max_tokens': 850, 'timeout': 30}
    decision, metrics, _, _, error = decisions.request_decision(
        {'planner_retry_limit': 0, 'token_budget': 50000}, kwargs, {}, 100)

    assert decision is None
    assert error is not None
    assert len(calls) <= 4, 'starvation allowance must be small and fixed'


def test_empty_content_without_reasoning_is_not_starvation(monkeypatch):
    """An empty answer with no reasoning is a different fault; no allowance."""
    calls = []

    def complete(**kwargs):
        calls.append(1)
        return _response('', reasoning='', finish='stop')

    monkeypatch.setattr(planner.litellm, 'completion', complete)
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kw: 10)
    kwargs = {'model': 'test', 'messages': [{'role': 'user', 'content': 'x'}],
              'max_tokens': 850, 'timeout': 30}
    decision, metrics, _, _, error = decisions.request_decision(
        {'planner_retry_limit': 0, 'token_budget': 50000}, kwargs, {}, 100)

    assert decision is None
    assert metrics.get('provider_starvation') is None
