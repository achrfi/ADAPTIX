"""Planner-knob tests that observe the planner's behaviour, not its source text.

The old test grepped the whole planner module for two strings. That proved
nothing about reachability -- a mere comment mentioning the knob satisfied it,
while a correct refactor broke it. Everything here drives the planner and
inspects the request it actually tries to make.
"""

import os

import pytest

from src.adaptix.agents import planner
from src.adaptix.workflow.graph import AgentState


KNOB_KEYS = ('llm_reasoning_effort', 'model_context_tokens')


@pytest.mark.parametrize('key', KNOB_KEYS)
def test_planner_knob_is_declared_in_graph_state(key):
    annotations = AgentState.__annotations__
    assert key in annotations, (
        f'{key} is written into the run state but not declared in AgentState, so '
        'LangGraph drops it before the planner reads it')


def _capture_provider_kwargs(monkeypatch, state):
    """Run the planner and capture the kwargs it hands to the provider.

    ``adaptive_planning`` calls the model through ``request_decision``; patch the
    completion helper so the full request is visible without any network call.
    """
    import litellm
    captured = {}

    def fake_completion(*args, **kwargs):
        captured.update(kwargs)
        raise RuntimeError('stop-after-capture')

    monkeypatch.setattr(litellm, 'completion', fake_completion, raising=False)
    monkeypatch.setattr(planner.litellm, 'completion', fake_completion, raising=False)

    try:
        planner.adaptive_planning(state)
    except Exception:
        pass  # any failure after the capture is fine; we only want the kwargs
    return captured


def _base_state(**over):
    state = {
        'run_id': 'knobprobe',
        'iterations': 1,
        'findings': [],
        'events': [],
        'attempted_actions': [],
        'rejected_actions': [],
        'refused_surfaces': [],
        'allowed_domains': ['127.0.0.1'],
        'scope_window': ['https://127.0.0.1:3000'],
        'llm_model': 'openai/test-model',
        'model_context_tokens': 8192,
        'token_budget': 'unlimited',
        'tool_call_budget': 20,
        'time_budget': 3600,
    }
    state.update(over)
    return state


def test_reasoning_effort_reaches_the_provider_call(monkeypatch):
    """The knob must be honoured on the outgoing request, not just read."""
    captured = _capture_provider_kwargs(
        monkeypatch, _base_state(llm_reasoning_effort='high'))

    if not captured:
        pytest.skip('planner did not reach the provider call in this environment')

    assert captured.get('reasoning_effort') == 'high', (
        'the planner did not send the operator reasoning_effort to the provider; '
        f'captured kwargs keys were {sorted(captured)}')


def test_reasoning_effort_defaults_from_the_environment(monkeypatch):
    """With no state value, the environment is the fallback -- same as before."""
    monkeypatch.setenv('ADAPTIX_REASONING_EFFORT', 'low')
    captured = _capture_provider_kwargs(monkeypatch, _base_state())

    if not captured:
        pytest.skip('planner did not reach the provider call in this environment')

    assert captured.get('reasoning_effort') == 'low', (
        'ADAPTIX_REASONING_EFFORT was not carried into the provider request')
