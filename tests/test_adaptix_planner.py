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
    # The out-of-scope proposal is denied as a security rejection; an in-scope
    # recovery pair may run, but nothing ever touches the invented host.
    assert all('evil.invalid' not in x['target'] for x in result['planned_actions'])
    security = [row for row in result['policy_feedback'] if row.get('kind') == 'security']
    assert security and 'url_outside_scope' == security[0]['code']
    assert all('http.invalid' not in row['target']
               for row in security[0].get('alternatives', []))


def test_budget_stops_scanning_not_fallback(monkeypatch):
    monkeypatch.setattr(planner, 'tool_registry', _registry)
    monkeypatch.setattr(planner.litellm, 'completion', lambda **kw: (_ for _ in ()).throw(
        AssertionError('LLM should not be called')))
    state = {**_state(), 'iterations': 3}
    result = planner.adaptive_planning(state)
    assert result['planned_actions'] == []
    assert result['stop_reason'] == 'iteration_budget_exhausted'
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
    # The completed fetch is never re-scanned: the recovery tier executes a
    # different, unattempted input instead of any action with that identity.
    denial = next(row for row in result['policy_feedback'] if row.get('code') == 'already_completed')
    assert denial['action']['target'] == 'http://127.0.0.1:18080'
    recovery = result['planned_actions']
    assert recovery and all(row['action_source'] == 'policy_recovery' for row in recovery)
    from src.adaptix.agents.action_identity import execution_identity
    assert all(execution_identity(row, state) != execution_identity(
        {'tool': 'httpx', 'target': 'http://127.0.0.1:18080'}, state) for row in recovery)


def _truncated_response():
    msg = MagicMock()
    msg.content = '{"actions": [{"tool": "httpx", "target": "/api/Users", "reason": "trunc'
    usage = MagicMock(prompt_tokens=50, completion_tokens=20, total_tokens=70)
    return MagicMock(choices=[MagicMock(message=msg)], usage=usage)


def _valid_action_response():
    return _fake_response({'actions': [{'tool': 'httpx', 'target': 'http://127.0.0.1:18080/api/Users',
        'reason': 'probe observed API route', 'priority': {'goal_relevance': 0.8, 'information_gain': 0.7,
        'evidence_value': 0.6, 'confidence': 0.9, 'estimated_tokens': 100, 'estimated_seconds': 1,
        'estimated_requests': 1}}], 'reflection': 'Observed API route is an input surface to test', 'rationale': 'test API'})


def test_native_schema_invalid_decision_falls_back_to_plain_structured_output(monkeypatch):
    # A provider whose grammar-constrained (native JSON-Schema) decoding returns
    # truncated JSON must not be asked the same doomed question until the run
    # dies. The failed native pass records the degradation and disables native
    # JSON for subsequent passes; the next pass then produces a valid, executable
    # action through plain instructions plus local validation.
    monkeypatch.setattr(planner, 'tool_registry', _registry)
    monkeypatch.setattr(planner, 'litellm', planner.litellm)
    calls = {'n': 0, 'native_flags': []}
    def fake_completion(**kw):
        calls['n'] += 1
        calls['native_flags'].append('response_format' in kw and
            isinstance(kw['response_format'], dict) and kw['response_format'].get('type') == 'json_schema')
        return _truncated_response() if calls['n'] == 1 else _valid_action_response()
    monkeypatch.setattr(planner.litellm, 'completion', fake_completion)
    state = {**_state(), 'llm_native_json': 'on', 'web_routes': [
        {'url': 'http://127.0.0.1:18080/api/Users'}]}
    first = planner.adaptive_planning(state)
    # Pass 1: native schema attempted, validation failed, fallback recorded.
    assert calls['native_flags'][0] is True
    assert first['planned_actions'] == []
    assert first['llm_native_json'] == 'off'
    assert first['planner_metrics'].get('native_schema_fallback') == 1
    assert any('native JSON-Schema' in message for message in first['errors'])
    # Pass 2 threads the fallback state: no native schema, valid action executes.
    second = planner.adaptive_planning({**state, **first, 'iterations': 1})
    assert calls['native_flags'][1] is False
    assert [action['tool'] for action in second['planned_actions']] == ['httpx']
    assert second['planned_actions'][0]['target'].endswith('/api/Users')
