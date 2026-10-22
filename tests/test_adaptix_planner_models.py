"""Model-agnostic provider support: one honest capability contract per family.

Every test asserts the kwargs a provider would actually receive: native
JSON-Schema response_format only for families with that contract, no silent
parameter injection elsewhere, explicit operator overrides honored, and the
compatibility fallback (stripping a refused response_format) recorded - never
silent.
"""
import json
import time
import os
from unittest.mock import MagicMock

from src.adaptix.agents import decisions
from src.adaptix.agents import planner


def _registry():
    return {'httpx': {'enabled': True, 'path': '/bin/httpx'},
            'nuclei': {'enabled': True, 'path': '/bin/nuclei'},
            'playwright': {'enabled': True, 'path': 'python-module'}}


def _fake_response(data):
    msg = MagicMock()
    msg.content = json.dumps(data)
    usage = MagicMock(prompt_tokens=50, completion_tokens=20, total_tokens=70)
    return MagicMock(choices=[MagicMock(message=msg)], usage=usage)


_DECISION = {'actions': [],
             'reflection': 'point at the honest limits of the current evidence',
             'rationale': 'no discovery needed for this shape assertion'}


def _state(model, **extra):
    state = {'hosts': ['127.0.0.1'],
             'services': [{'host': '127.0.0.1', 'port': 18080, 'service': 'http', 'tunnel': ''}],
             'max_iterations': 2, 'tool_call_budget': 20, 'token_budget': 50000,
             'llm_model': model}
    state.update(extra)
    return state


def _capture(monkeypatch, completion):
    captured = {}
    def wrapper(**kwargs):
        captured.update(kwargs)
        return completion(**kwargs)
    monkeypatch.setattr(planner, 'tool_registry', _registry)
    monkeypatch.setattr(planner.litellm, 'completion', wrapper)
    monkeypatch.delenv('ADAPTIX_API_BASE', raising=False)
    monkeypatch.delenv('ADAPTIX_API_KEY', raising=False)
    return captured


def test_openai_family_gets_native_json_schema(monkeypatch):
    captured = _capture(monkeypatch, lambda **kw: _fake_response(_DECISION))
    planner.adaptive_planning(_state('openai/gpt-4o'))
    assert captured['response_format']['type'] == 'json_schema'
    assert captured['response_format']['json_schema']['name'] == 'PlannerDecision'
    assert 'api_base' not in captured  # a remote family never gets a local default


def test_anthropic_family_omits_response_format_entirely(monkeypatch):
    captured = _capture(monkeypatch, lambda **kw: _fake_response(_DECISION))
    planner.adaptive_planning(_state('anthropic/claude-4-sonnet'))
    assert 'response_format' not in captured


def test_unknown_family_omits_response_format_entirely(monkeypatch):
    captured = _capture(monkeypatch, lambda **kw: _fake_response(_DECISION))
    planner.adaptive_planning(_state('custom-lab/model-x'))
    assert 'response_format' not in captured


def test_native_json_on_override_forces_schema_even_for_no_format_families(monkeypatch):
    captured = _capture(monkeypatch, lambda **kw: _fake_response(_DECISION))
    planner.adaptive_planning(_state('anthropic/claude-4-sonnet', llm_native_json='on'))
    assert captured['response_format']['type'] == 'json_schema'


def test_native_json_off_downgrades_json_families_to_json_object(monkeypatch):
    captured = _capture(monkeypatch, lambda **kw: _fake_response(_DECISION))
    planner.adaptive_planning(_state('ollama_chat/qwen3:14b', llm_native_json='off'))
    # The override disables the native grammar; a family with a json_object
    # contract keeps relaxed-mode JSON, never free-form text.
    assert captured['response_format']['type'] == 'json_object'


def test_api_base_and_api_key_passthrough(monkeypatch):
    captured = _capture(monkeypatch, lambda **kw: _fake_response(_DECISION))
    planner.adaptive_planning(_state('openai/gpt-4o',
                                     llm_api_base='https://edge.example.com/v1',
                                     llm_api_key='sk-run-secret'))
    assert captured['api_base'] == 'https://edge.example.com/v1'
    assert captured['api_key'] == 'sk-run-secret'


def test_env_api_base_wins_for_remote_families_without_state(monkeypatch):
    captured = _capture(monkeypatch, lambda **kw: _fake_response(_DECISION))
    monkeypatch.setenv('ADAPTIX_API_BASE', 'https://gw.example.com')
    monkeypatch.setenv('ADAPTIX_API_KEY', 'sk-env-secret')
    planner.adaptive_planning(_state('openai/gpt-4o'))
    assert captured['api_base'] == 'https://gw.example.com'
    assert captured['api_key'] == 'sk-env-secret'


def test_anthropic_receives_no_ollama_default_base(monkeypatch):
    captured = _capture(monkeypatch, lambda **kw: _fake_response(_DECISION))
    monkeypatch.delenv('ADAPTIX_API_BASE', raising=False)
    planner.adaptive_planning(_state('anthropic/claude-4-sonnet'))
    assert 'api_base' not in captured


def test_model_native_supported_answers_by_family_and_override():
    assert planner.model_native_supported('ollama_chat/qwen3:14b', {}) is True
    assert planner.model_native_supported('openai/gpt-4o', {}) is True
    assert planner.model_native_supported('anthropic/claude-4-sonnet', {}) is False
    assert planner.model_native_supported('custom/model', {}) is False
    assert planner.model_native_supported('custom/model', {'llm_native_json': 'on'}) is True
    assert planner.model_native_supported('ollama_chat/x', {'llm_native_json': 'off'}) is False
    assert planner.model_native_supported('custom/model', {'llm_native_json': True}) is True


def test_response_format_refusal_strips_once_and_is_recorded(monkeypatch):
    calls = []
    state = {'hosts': ['127.0.0.1'], 'services': [], 'max_iterations': 2,
             'tool_call_budget': 20, 'token_budget': 50000, 'llm_model': 'openai/gpt-4o',
             'model_context_tokens': 8192, 'planner_cache': {}, 'token_ledger': [],
             'planner_retry_limit': 1, 'start_time': time.monotonic(), 'time_budget_seconds': 600}

    def failing_then_ok(**kwargs):
        calls.append(dict(kwargs))
        if 'response_format' in kwargs:
            raise RuntimeError("litellm.BadRequestError: response_format is not supported by this model")
        return _fake_response(_DECISION)

    monkeypatch.setattr(decisions.litellm, 'completion', failing_then_ok)
    metrics = {}
    kwargs = {'model': 'openai/gpt-4o', 'messages': [{'role': 'user', 'content': 'x'}],
              'max_tokens': 300, 'timeout': 90, 'response_format': {'type': 'json_object'}, 'temperature': 0.1,
              'api_base': 'https://api.openai.com'}
    decision, metrics, cache, ledger_out, error = decisions.request_decision(state, kwargs, metrics, 50, lambda parameters, attempt: parameters)
    assert metrics.get('response_format_compat_fallback') == 1
    assert len(calls) == 2
    assert 'response_format' in calls[0] and 'response_format' not in calls[1]
    assert decision is not None and error is None
    assert any(entry.get('result') == 'compat_fallback' for entry in ledger_out)
