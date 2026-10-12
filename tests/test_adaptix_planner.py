import json
from unittest.mock import MagicMock
from src.adaptix.agents import planner


def _fake_response(actions_json):
    msg = MagicMock()
    msg.content = json.dumps(actions_json)
    usage = MagicMock(prompt_tokens=50, completion_tokens=20)
    return MagicMock(choices=[MagicMock(message=msg)], usage=usage)


def test_planner_differs_on_different_services(monkeypatch):
    monkeypatch.setattr(planner, 'tool_registry', lambda: {
        'httpx': {'enabled': True, 'path': '/bin/httpx'},
        'nuclei': {'enabled': True, 'path': '/bin/nuclei'},
        'playwright': {'enabled': True, 'path': 'python-module'},
    })
    state_a = {'hosts': ['127.0.0.1'], 'services': [{'host': '127.0.0.1', 'port': 18080, 'service': 'http', 'tunnel': ''}],
               'max_iterations': 8, 'tool_call_budget': 20, 'token_budget': 50000}
    state_b = {**state_a, 'services': [{'host': '127.0.0.1', 'port': 443, 'service': 'https', 'tunnel': 'ssl'}]}

    monkeypatch.setattr(planner.litellm, 'completion', lambda **kw: _fake_response(
        {'actions': [{'tool': 'httpx', 'target': 'http://127.0.0.1:18080', 'reason': 'open http', 'priority': 3}],
         'rationale': 'scan A'}))
    result_a = planner.adaptive_planning(state_a)

    monkeypatch.setattr(planner.litellm, 'completion', lambda **kw: _fake_response(
        {'actions': [{'tool': 'httpx', 'target': 'https://127.0.0.1:443', 'reason': 'tls svc', 'priority': 4}],
         'rationale': 'scan B'}))
    result_b = planner.adaptive_planning(state_b)

    assert result_a['planned_urls'] != result_b['planned_urls']
    assert result_a['planner_metrics']['mode'] == 'llm'
    assert result_a['planner_metrics']['tokens_used'] == 70


def test_planner_stops_calling_llm_when_budget_exhausted(monkeypatch):
    called = {'n': 0}
    def fail_if_called(**kw):
        called['n'] += 1
        raise AssertionError('should not call LLM when budget exhausted')
    monkeypatch.setattr(planner.litellm, 'completion', fail_if_called)
    state = {'hosts': ['127.0.0.1'], 'services': [], 'iterations': 8, 'max_iterations': 8}
    result = planner.adaptive_planning(state)
    assert called['n'] == 0
    assert result['planner_metrics']['mode'] == 'fallback_budget_exhausted'
