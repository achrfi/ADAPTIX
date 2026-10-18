import json
from unittest.mock import MagicMock
from src.adaptix.agents import planner


def _fake_response(data):
    msg = MagicMock()
    msg.content = json.dumps(data)
    usage = MagicMock(prompt_tokens=50, completion_tokens=20, total_tokens=70)
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
            'target': 'http://127.0.0.1:18080', 'reason': 'follow HTTP check', 'priority': {'goal_relevance': 0.8, 'information_gain': 0.7, 'evidence_value': 0.6, 'confidence': 0.9, 'estimated_tokens': 100, 'estimated_seconds': 1, 'estimated_requests': 1}}],
            'reflection': 'Assess current evidence and limits before deciding', 'rationale': 'review web service'})
    monkeypatch.setattr(planner.litellm, 'completion', fake_completion)
    result = planner.adaptive_planning(_state())
    assert captured['model'] == 'ollama_chat/qwen3:14b'
    assert captured['api_base'].startswith('http://127.0.0.1:11434')
    assert [action['tool'] for action in result['planned_actions']] == ['nuclei']
    assert result['planner_metrics']['tokens_used'] == 70
    assert result['planner_metrics']['llm_calls'] == 1


def test_llm_priority_and_target_scope(monkeypatch):
    monkeypatch.setattr(planner, 'tool_registry', _registry)
    monkeypatch.setattr(planner.litellm, 'completion', lambda **kw: _fake_response({
        'actions': [{'tool': 'httpx', 'target': 'http://evil.invalid:18080', 'reason': 'bad', 'priority': {'goal_relevance': 0.8, 'information_gain': 0.7, 'evidence_value': 0.6, 'confidence': 0.9, 'estimated_tokens': 100, 'estimated_seconds': 1, 'estimated_requests': 1}}],
        'reflection': 'Assess current evidence and limits before deciding', 'rationale': 'inspect'}))
    result = planner.adaptive_planning(_state())
    assert result['planned_actions'] == []
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


def test_failed_llm_attempt_charged_without_fallback(monkeypatch):
    monkeypatch.setattr(planner, 'tool_registry', _registry)
    monkeypatch.setattr(planner.litellm, 'completion', lambda **kw: (_ for _ in ()).throw(
        RuntimeError('Ollama unavailable')))
    result = planner.adaptive_planning(_state())
    assert result['planner_metrics']['llm_calls'] == 1
    assert result['planner_metrics']['mode'] == 'llm_error'
    assert result['planned_actions'] == []
    # One provider failure records the error and lets the run try again; a failed
    # decision still authorizes nothing.
    assert result['stop_reason'] is None
    assert result['consecutive_provider_failures'] == 1
    assert any('provider call failed' in message for message in result['errors'])


def test_repeated_provider_failures_stop_the_run(monkeypatch):
    monkeypatch.setattr(planner, 'tool_registry', _registry)
    monkeypatch.setattr(planner.litellm, 'completion', lambda **kw: (_ for _ in ()).throw(
        RuntimeError('Ollama unavailable')))
    state = {**_state(), 'consecutive_provider_failures': 1}
    result = planner.adaptive_planning(state)
    assert result['stop_reason'] == 'planner_unavailable'
    assert result['planned_actions'] == []


def test_repeated_actions_terminate_without_scanning_again(monkeypatch):
    monkeypatch.setattr(planner, 'tool_registry', _registry)
    monkeypatch.setattr(planner.litellm, 'completion', lambda **kw: _fake_response({
        'actions': [{'tool': 'httpx', 'target': 'http://127.0.0.1:18080', 'reason': 'again', 'priority': {'goal_relevance': 0.8, 'information_gain': 0.7, 'evidence_value': 0.6, 'confidence': 0.9, 'estimated_tokens': 100, 'estimated_seconds': 1, 'estimated_requests': 1}}],
        'reflection': 'Assess current evidence and limits before deciding', 'rationale': 'try again'}))
    state = {**_state(), 'attempted_actions': [
        {'tool': 'httpx', 'target': 'http://127.0.0.1:18080'}]}
    result = planner.adaptive_planning(state)
    assert result['stop_reason'] is None
    assert result['policy_feedback']
    assert result['planned_actions'] == []
