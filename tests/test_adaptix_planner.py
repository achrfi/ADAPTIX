import json
from unittest.mock import MagicMock
from src.adaptix.agents import planner


def _fake_response(data):
    msg = MagicMock()
    msg.content = json.dumps(data)
    usage = MagicMock(prompt_tokens=50, completion_tokens=20)
    return MagicMock(choices=[MagicMock(message=msg)], usage=usage)


def _registry():
    return {'httpx': {'enabled': True, 'path': '/bin/httpx'},
            'nuclei': {'enabled': True, 'path': '/bin/nuclei'},
            'playwright': {'enabled': True, 'path': 'python-module'}}


def _state(port=18080):
    return {'hosts': ['127.0.0.1'],
            'services': [{'host': '127.0.0.1', 'port': port,
                          'service': 'http', 'tunnel': ''}],
            'max_iterations': 3, 'tool_call_budget': 20, 'token_budget': 50000}


def test_llm_uses_local_ollama_by_default_and_returns_actions(monkeypatch):
    monkeypatch.delenv('ADAPTIX_LLM_MODEL', raising=False)
    monkeypatch.setattr(planner, 'tool_registry', _registry)
    captured = {}
    def fake_completion(**kw):
        captured.update(kw)
        return _fake_response({'actions': [{'tool': 'nuclei',
            'target': 'http://127.0.0.1:18080', 'reason': 'follow HTTP check', 'priority': 2}],
            'rationale': 'review web service'})
    monkeypatch.setattr(planner.litellm, 'completion', fake_completion)
    result = planner.adaptive_planning(_state())
    assert captured['model'] == 'ollama_chat/qwen3:14b'
    assert captured['api_base'].startswith('http://127.0.0.1:11434')
    assert [action['tool'] for action in result['planned_actions']] == ['httpx', 'nuclei']
    assert result['planner_metrics']['tokens_used'] == 70
    assert result['planner_metrics']['llm_calls'] == 1


def test_llm_priority_and_target_scope(monkeypatch):
    monkeypatch.setattr(planner, 'tool_registry', _registry)
    monkeypatch.setattr(planner.litellm, 'completion', lambda **kw: _fake_response({
        'actions': [{'tool': 'httpx', 'target': 'http://127.0.0.1:18080', 'reason': 'ok', 'priority': 5},
                    {'tool': 'httpx', 'target': 'http://evil.invalid:18080', 'reason': 'bad', 'priority': 1},
                    {'tool': 'playwright', 'target': 'http://127.0.0.1:18080', 'reason': 'inspect', 'priority': 1}],
        'rationale': 'inspect'}))
    result = planner.adaptive_planning(_state())
    assert len(result['planned_actions']) == 2
    assert all('evil.invalid' not in x['target'] for x in result['planned_actions'])


def test_budget_stops_scanning_not_fallback(monkeypatch):
    monkeypatch.setattr(planner, 'tool_registry', _registry)
    monkeypatch.setattr(planner.litellm, 'completion', lambda **kw: (_ for _ in ()).throw(
        AssertionError('LLM should not be called')))
    state = {**_state(), 'iterations': 3}
    result = planner.adaptive_planning(state)
    assert result['planned_actions'] == []
    assert result['stop_reason'] == 'budget_exhausted'
    assert result['planner_metrics']['mode'] == 'stopped_budget_exhausted'


def test_failed_llm_attempt_charged_once_with_local_fallback(monkeypatch):
    monkeypatch.setattr(planner, 'tool_registry', _registry)
    monkeypatch.setattr(planner.litellm, 'completion', lambda **kw: (_ for _ in ()).throw(
        RuntimeError('Ollama unavailable')))
    result = planner.adaptive_planning(_state())
    assert result['planner_metrics']['llm_calls'] == 1
    assert result['planner_metrics']['mode'] == 'fallback_llm_error'
    assert len(result['planned_actions']) == 3


def test_repeated_actions_terminate_without_scanning_again(monkeypatch):
    monkeypatch.setattr(planner, 'tool_registry', _registry)
    monkeypatch.setattr(planner.litellm, 'completion', lambda **kw: _fake_response({
        'actions': [{'tool': 'httpx', 'target': 'http://127.0.0.1:18080', 'reason': 'again', 'priority': 1}],
        'rationale': 'try again'}))
    state = {**_state(), 'attempted_actions': [
        {'tool': 'httpx', 'target': 'http://127.0.0.1:18080'}]}
    result = planner.adaptive_planning(state)
    assert result['stop_reason'] == 'no_new_actions'
    assert result['planned_actions'] == []
