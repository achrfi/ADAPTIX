import json
from unittest.mock import MagicMock
from src.adaptix.agents import planner
from src.adaptix.workflow.graph import graph
from src.adaptix.workflow import nodes
from src.adaptix.tools import registry, idor


def test_free_prompt_observations_and_reflection_drive_next_action(monkeypatch):
    catalog = {'playwright': {'enabled': True, 'path': 'module'},
               'httpx': {'enabled': True, 'path': 'cli'}}
    monkeypatch.setattr(planner, 'tool_registry', lambda: catalog)
    monkeypatch.setattr(registry, 'tool_registry', lambda: catalog)
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kw: 100)
    seen = []
    def completion(**kw):
        context = json.loads(kw['messages'][1]['content'])
        assert context['user_request'] == 'Periksa alur login dan jelaskan keterbatasannya'
        seen.append(context)
        if len(seen) == 1:
            action = {'tool': 'playwright', 'target': 'http://127.0.0.1:18080/login', 'reason': 'observe UI', 'priority': {'goal_relevance': 0.8, 'information_gain': 0.7, 'evidence_value': 0.6, 'confidence': 0.9, 'estimated_tokens': 100, 'estimated_seconds': 1, 'estimated_requests': 1}}
        else:
            assert context['reflection']['progress'] == 1
            assert context['observations']['browser_evidence']
            action = None
        response = MagicMock()
        response.usage.total_tokens = 130
        response.choices[0].message.content = json.dumps({'actions': [action] if action else [],
            'rationale': 'objective considered', 'reflection': 'UI observed; no authorization proof'})
        return response
    monkeypatch.setattr(planner.litellm, 'completion', completion)
    calls = []
    def browser(state):
        calls.append('playwright')
        return {'browser_evidence': [{'url': state['planned_actions'][0]['target']}],
                'execution_metrics': {'tool_calls_used': 1}}
    monkeypatch.setattr(registry, 'tool_handlers', lambda: {'playwright': browser})
    result = graph.invoke({'target': ['127.0.0.1'], 'authorization_confirmed': True,
        'user_prompt': 'Periksa alur login dan jelaskan keterbatasannya', 'max_iterations': 5})
    assert calls == ['playwright']
    assert len(seen) == 2
    assert result['report']['self_reflection'] == 'UI observed; no authorization proof'


def test_execution_gate_rejects_outside_scope(monkeypatch):
    monkeypatch.setattr(registry, 'tool_registry', lambda: {'httpx': {'enabled': True, 'path': 'cli'}})
    result = nodes.execute_action({'status': 'scope_ok', 'authorization': {'type': 'local_loopback'},
        'target': ['127.0.0.1'], 'hosts': ['127.0.0.1'], 'planned_actions': [{'tool': 'httpx', 'target': 'http://example.com', 'reason': 'bad', 'priority': {'goal_relevance': 0.8, 'information_gain': 0.7, 'evidence_value': 0.6, 'confidence': 0.9, 'estimated_tokens': 100, 'estimated_seconds': 1, 'estimated_requests': 1}}]})
    assert result['stop_reason'] == 'policy_rejected'


def test_idor_budget_reserves_two_requests(monkeypatch):
    class Client:
        def __enter__(self): return self
        def __exit__(self, *args): pass
        def request(self, *args, **kwargs): raise AssertionError('must not send request')
    monkeypatch.setattr(idor.httpx_lib, 'Client', lambda **kw: Client())
    scenario = {'name': 'object', 'base_url': 'http://127.0.0.1:8080',
                'path_template': '/objects/{object_id}', 'object_id': '1',
                'owner_identity': {'headers': {}}, 'other_identity': {'headers': {}}}
    result = idor.idor_test({'hosts': ['127.0.0.1'], 'idor_scenarios': [scenario], 'tool_call_budget': 1})
    assert result['idor_findings'] == []
    assert any('budget' in e for e in result['errors'])


def test_multiple_candidates_execute_only_one(monkeypatch):
    monkeypatch.setattr(planner, 'tool_registry', lambda: {'httpx': {'enabled': True, 'path': 'cli'}})
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kw: 100)
    response = MagicMock()
    response.usage.total_tokens = 120
    action = {'tool': 'httpx', 'target': 'http://127.0.0.1', 'reason': 'probe', 'priority': {'goal_relevance': 0.8, 'information_gain': 0.7, 'evidence_value': 0.6, 'confidence': 0.9, 'estimated_tokens': 100, 'estimated_seconds': 1, 'estimated_requests': 1}}
    response.choices[0].message.content = json.dumps({'actions': [action, action], 'reflection': 'Assess current evidence and limits before deciding', 'rationale': 'pipeline'})
    monkeypatch.setattr(planner.litellm, 'completion', lambda **kw: response)
    result = planner.adaptive_planning({'hosts': ['127.0.0.1']})
    assert len(result['planned_actions']) == 1
    assert result['stop_reason'] is None


def test_failed_completion_reserves_token_budget(monkeypatch):
    monkeypatch.setattr(planner, 'tool_registry', lambda: {'httpx': {'enabled': True, 'path': 'cli'}})
    monkeypatch.setattr(planner.litellm, 'completion', lambda **kw: (_ for _ in ()).throw(RuntimeError('offline')))
    result = planner.adaptive_planning({'hosts': ['127.0.0.1'], 'token_budget': 2000})
    assert result['planner_metrics']['tokens_used'] == 1124
    assert result['planned_actions'] == []


def test_prompt_budget_prevents_model_call(monkeypatch):
    monkeypatch.setattr(planner, 'tool_registry', lambda: {'httpx': {'enabled': True, 'path': 'cli'}})
    monkeypatch.setattr(planner.litellm, 'token_counter', lambda **kw: 5000)
    monkeypatch.setattr(planner.litellm, 'completion', lambda **kw: (_ for _ in ()).throw(AssertionError('no call')))
    result = planner.adaptive_planning({'hosts': ['127.0.0.1'], 'token_budget': 2000})
    assert result['stop_reason'] in ('budget_exhausted', 'context_budget_exhausted')


def test_policy_feedback_drives_replanning_without_external_execution(monkeypatch):
    catalog = {'httpx': {'enabled': True, 'path': 'cli'}}
    monkeypatch.setattr(planner, 'tool_registry', lambda: catalog)
    contexts = []
    def completion(**kw):
        context = json.loads(kw['messages'][1]['content'])
        contexts.append(context)
        response = MagicMock()
        response.usage.total_tokens = 130
        if len(contexts) == 1:
            decision = {'actions': [{'tool': 'httpx', 'target': 'http://evil.invalid', 'reason': 'bad', 'priority': {'goal_relevance': 0.8, 'information_gain': 0.7, 'evidence_value': 0.6, 'confidence': 0.9, 'estimated_tokens': 100, 'estimated_seconds': 1, 'estimated_requests': 1}}], 'reflection': 'Assess current evidence and limits before deciding', 'rationale': 'bad'}
        else:
            assert context['policy_feedback']
            decision = {'actions': [], 'reflection': 'Assess current evidence and limits before deciding', 'rationale': 'outside scope; stop'}
        response.choices[0].message.content = json.dumps(decision)
        return response
    monkeypatch.setattr(planner.litellm, 'completion', completion)
    result = graph.invoke({'target': ['127.0.0.1'], 'authorization_confirmed': True, 'max_iterations': 3})
    assert len(contexts) == 2
    assert result.get('attempted_actions', []) == []
    assert result['report']['stop_reason'] == 'no_new_actions'


def test_empty_model_reflection_cannot_authorize_tool_execution(monkeypatch):
    monkeypatch.setattr(planner, 'tool_registry', lambda: {'httpx': {'enabled': True, 'path': 'cli'}})
    response = MagicMock()
    response.usage.total_tokens = 130
    response.choices[0].message.content = json.dumps({'actions': [{'tool': 'httpx', 'target': 'http://127.0.0.1', 'reason': 'probe', 'priority': {'goal_relevance': 0.8, 'information_gain': 0.7, 'evidence_value': 0.6, 'confidence': 0.9, 'estimated_tokens': 100, 'estimated_seconds': 1, 'estimated_requests': 1}}], 'rationale': 'probe', 'reflection': ''})
    monkeypatch.setattr(planner.litellm, 'completion', lambda **kw: response)
    result = planner.adaptive_planning({'hosts': ['127.0.0.1']})
    assert result['planned_actions'] == []
    assert result['stop_reason'] == 'planner_unavailable'
